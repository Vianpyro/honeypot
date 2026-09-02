//! The dashboard's read API, ported from the Worker's `stats.js`.
//!
//! THE JSON SHAPE IS A CONTRACT with a dashboard this repository does not
//! deploy (docs/, served from GitHub Pages). Every key below is spelled the way
//! `stats.js` spelled it -- `c` for counts, `d` for days, `created_at` for what
//! PostgreSQL calls `observed_at`. Renaming any of them is a broken chart, not
//! a compile error, so they are pinned by a test.
//!
//! PUBLIC READS ARE UNAUTHENTICATED, and that is deliberate rather than
//! careless. This service is reachable only through the tunnel, and only from
//! the Worker's VPC binding -- there is no path from the internet to it. Adding
//! a signature to a read that only one caller can make would have meant signing
//! the request PATH, which the ingest endpoint hardcodes; changing that is a
//! flag-day between two independently deployed components, and a window where
//! every event 403s. The exposure it would buy is zero.
//!
//! THE PRIVATE SCOPE IS DIFFERENT. It returns source addresses and the
//! credentials the honeypot captured, so it is gated on a token of its own --
//! not on the ingest signing key, which is a MAC key and has no business
//! travelling as a password. Empty token, no private scope: it fails closed.

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
};
use chrono::{DateTime, NaiveDate, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::PgPool;

use crate::{ApiError, AppState};

/// The window the dashboard defaults to, and the ceiling. 100 matches the
/// retention window: asking for more can only return the same data.
const DEFAULT_DAYS: i64 = 30;
const MAX_DAYS: i64 = 100;
const DEFAULT_LIMIT: i64 = 100;
const MAX_LIMIT: i64 = 1000;

#[derive(Debug, Deserialize)]
pub struct StatsQuery {
    days: Option<i64>,
    limit: Option<i64>,
}

pub async fn handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<StatsQuery>,
) -> Result<Json<Value>, ApiError> {
    let days = query.days.unwrap_or(DEFAULT_DAYS).clamp(1, MAX_DAYS);
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    let mut payload = public(&state.db, days).await.map_err(storage)?;

    if is_private(&state, &headers) {
        let private = private(&state.db, days, limit).await.map_err(storage)?;
        if let (Some(object), Some(extra)) = (payload.as_object_mut(), private.as_object()) {
            object.extend(extra.clone());
        }
    }

    Ok(Json(payload))
}

fn storage(error: sqlx::Error) -> ApiError {
    tracing::error!(%error, "stats query failed");
    ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable")
}

/// Constant-time comparison, and a token that must be non-empty on BOTH sides.
///
/// An unconfigured deployment has an empty token; without the length check a
/// caller sending no header at all would compare empty against empty and be
/// handed every captured credential.
fn is_private(state: &AppState, headers: &HeaderMap) -> bool {
    let expected = state.stats_token.as_bytes();
    if expected.is_empty() {
        return false;
    }
    let presented = headers
        .get("X-Honeypot-Stats-Token")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .as_bytes();
    // Length is not secret; the bytes are. Comparing unequal lengths with a
    // fixed-length loop would read past one of them.
    presented.len() == expected.len()
        && presented.iter().zip(expected).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

/// Everything the public dashboard shows, read from the daily rollups rather
/// than from `events` -- which is the entire reason `stats_daily` exists.
async fn public(db: &PgPool, days: i64) -> Result<Value, sqlx::Error> {
    // `day < current_date` everywhere: today is not rolled up yet (see
    // aggregate.rs), so including it would draw a partial bar that shrinks the
    // chart's last point every time somebody reloads.
    let volume: Vec<(NaiveDate, i64)> = sqlx::query_as(
        "SELECT day, count FROM stats_daily
         WHERE dim = 'volume' AND day >= current_date - $1::int AND day < current_date
         ORDER BY day ASC",
    )
    .bind(days as i32)
    .fetch_all(db)
    .await?;

    let campaign_volume: Vec<(NaiveDate, i64)> = sqlx::query_as(
        "SELECT day, count FROM stats_daily
         WHERE dim = 'campaign_volume' AND day >= current_date - $1::int AND day < current_date
         ORDER BY day ASC",
    )
    .bind(days as i32)
    .fetch_all(db)
    .await?;

    let totals: (Option<i64>, i64, i64, i64) = sqlx::query_as(
        "SELECT
             (SELECT sum(count) FROM stats_daily
              WHERE dim = 'volume' AND day >= current_date - $1::int AND day < current_date),
             (SELECT count(DISTINCT key) FROM stats_daily
              WHERE dim = 'country' AND day >= current_date - $1::int AND day < current_date),
             (SELECT count(DISTINCT key) FROM stats_daily
              WHERE dim = 'service' AND day >= current_date - $1::int AND day < current_date),
             (SELECT count(DISTINCT key) FROM stats_daily
              WHERE dim = 'username' AND day >= current_date - $1::int AND day < current_date)",
    )
    .bind(days as i32)
    .fetch_one(db)
    .await?;

    let asns: Vec<(String, Option<String>, i64)> = sqlx::query_as(
        "SELECT key, max(extra), sum(count)::bigint FROM stats_daily
         WHERE dim = 'asn' AND day >= current_date - $1::int AND day < current_date
         GROUP BY key ORDER BY 3 DESC LIMIT 10",
    )
    .bind(days as i32)
    .fetch_all(db)
    .await?;

    Ok(json!({
        "meta": {
            "days": days,
            "total": totals.0.unwrap_or(0),
            "total_countries": totals.1,
            "total_services": totals.2,
            "total_usernames": totals.3,
            "generated_at": Utc::now().to_rfc3339(),
        },
        "volume": volume.iter().map(|(d, c)| json!({ "d": d, "c": c })).collect::<Vec<_>>(),
        "campaign_volume":
            campaign_volume.iter().map(|(d, c)| json!({ "d": d, "c": c })).collect::<Vec<_>>(),
        "top_countries": top(db, "country", "country", days, 10).await?,
        "top_services": top(db, "service", "service", days, 10).await?,
        "top_paths": top(db, "path", "path", days, 10).await?,
        "top_usernames": top(db, "username", "username", days, 10).await?,
        "top_tls": top(db, "tls", "tls_version", days, 6).await?,
        "top_protocols": top(db, "protocol", "http_protocol", days, 6).await?,
        "top_asns": asns
            .iter()
            .map(|(key, org, count)| json!({
                // The dashboard renders this as a number, as it did when the
                // query said CAST(key AS INTEGER).
                "asn": key.parse::<i64>().unwrap_or(0),
                "as_organization": org,
                "c": count,
            }))
            .collect::<Vec<_>>(),
    }))
}

/// One "top N by count" list. Every dimension but `asn` has this exact shape,
/// differing only in the JSON key the dashboard reads it under -- which is why
/// that key is a parameter and the rest is not repeated eight times.
async fn top(
    db: &PgPool,
    dim: &str,
    field: &str,
    days: i64,
    limit: i64,
) -> Result<Vec<Value>, sqlx::Error> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT key, sum(count)::bigint FROM stats_daily
         WHERE dim = $1 AND day >= current_date - $2::int AND day < current_date
         GROUP BY key ORDER BY 2 DESC LIMIT $3",
    )
    .bind(dim)
    .bind(days as i32)
    .bind(limit)
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|(key, count)| json!({ field: key, "c": count })).collect())
}

/// The private additions: individual events, source addresses and captured
/// credentials. Read from `events` directly, because no rollup keeps them --
/// deliberately, since a rollup of a password is a password.
async fn private(db: &PgPool, days: i64, limit: i64) -> Result<Value, sqlx::Error> {
    type Recent = (
        String,
        Option<String>,
        Option<String>,
        Option<i64>,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        DateTime<Utc>,
    );
    // `host(ip)` rather than the INET itself: the dashboard wants the address,
    // not PostgreSQL's textual representation with a prefix length.
    let recent: Vec<Recent> = sqlx::query_as(
        "SELECT host(ip), country, host, asn, method, path, service, username, password, ua,
                observed_at
         FROM events WHERE observed_at >= now() - make_interval(days => $1)
         ORDER BY observed_at DESC LIMIT $2",
    )
    .bind(days as i32)
    .bind(limit)
    .fetch_all(db)
    .await?;

    let top_ips: Vec<(String, Option<String>, Option<i64>, i64)> = sqlx::query_as(
        "SELECT host(ip), max(country), max(asn), count(*) FROM events
         WHERE observed_at >= now() - make_interval(days => $1)
         GROUP BY ip ORDER BY 4 DESC LIMIT 20",
    )
    .bind(days as i32)
    .fetch_all(db)
    .await?;

    let top_creds: Vec<(String, Option<String>, i64)> = sqlx::query_as(
        "SELECT username, password, count(*) FROM events
         WHERE observed_at >= now() - make_interval(days => $1) AND username IS NOT NULL
         GROUP BY username, password ORDER BY 3 DESC LIMIT 50",
    )
    .bind(days as i32)
    .fetch_all(db)
    .await?;

    let top_hosts: Vec<(Option<String>, i64)> = sqlx::query_as(
        "SELECT host, count(*) FROM events
         WHERE observed_at >= now() - make_interval(days => $1)
         GROUP BY host ORDER BY 2 DESC",
    )
    .bind(days as i32)
    .fetch_all(db)
    .await?;

    Ok(json!({
        "recent": recent
            .into_iter()
            .map(|r| json!({
                "ip": r.0, "country": r.1, "host": r.2, "asn": r.3, "method": r.4,
                "path": r.5, "service": r.6, "username": r.7, "password": r.8, "ua": r.9,
                // Spelled `created_at` because that is what the dashboard reads,
                // even though the column has been `observed_at` since 0001.
                "created_at": r.10.to_rfc3339(),
            }))
            .collect::<Vec<_>>(),
        "top_ips": top_ips
            .into_iter()
            .map(|(ip, country, asn, c)| json!({ "ip": ip, "country": country, "asn": asn, "c": c }))
            .collect::<Vec<_>>(),
        "top_creds": top_creds
            .into_iter()
            .map(|(u, p, c)| json!({ "username": u, "password": p, "c": c }))
            .collect::<Vec<_>>(),
        "top_hosts": top_hosts
            .into_iter()
            .map(|(host, c)| json!({ "host": host, "c": c }))
            .collect::<Vec<_>>(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    async fn pool() -> Option<PgPool> {
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            eprintln!("SKIPPED: TEST_DATABASE_URL is not set");
            return None;
        };
        let db = PgPoolOptions::new().max_connections(4).connect(&url).await.unwrap();
        sqlx::migrate!("./migrations").run(&db).await.unwrap();
        Some(db)
    }

    fn token_header(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("X-Honeypot-Stats-Token", value.parse().unwrap());
        headers
    }

    fn state(db: PgPool, token: &str) -> AppState {
        AppState {
            db,
            auth: std::sync::Arc::new(
                crate::auth::AuthKeys::from_env(
                    "v1:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY",
                )
                .unwrap(),
            ),
            stats_token: std::sync::Arc::new(token.to_owned()),
        }
    }

    /// THE CONTRACT. These keys are read by a dashboard this repository does not
    /// deploy, so a rename is a broken chart rather than a compile error. The
    /// spellings come from the Worker's stats.js, which this replaces.
    #[tokio::test]
    async fn the_public_payload_has_exactly_the_keys_the_dashboard_reads() {
        let Some(db) = pool().await else { return };
        let body = public(&db, 30).await.unwrap();
        let object = body.as_object().unwrap();

        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "campaign_volume", "meta", "top_asns", "top_countries", "top_paths",
                "top_protocols", "top_services", "top_tls", "top_usernames", "volume",
            ]
        );

        let mut meta: Vec<&str> = object["meta"].as_object().unwrap().keys().map(String::as_str).collect();
        meta.sort_unstable();
        assert_eq!(
            meta,
            vec!["days", "generated_at", "total", "total_countries", "total_services", "total_usernames"]
        );

        // Empty lists are arrays, never null: the dashboard iterates them.
        for key in ["volume", "campaign_volume", "top_countries", "top_asns"] {
            assert!(object[key].is_array(), "{key} is not an array");
        }
    }

    /// Each "top" list spells its value under the key the dashboard expects,
    /// and its count under `c`.
    #[tokio::test]
    async fn every_top_list_uses_the_field_names_the_dashboard_expects() {
        let Some(db) = pool().await else { return };
        let day = (Utc::now() - chrono::Duration::days(3)).date_naive();
        for (dim, key, extra) in [
            ("country", "CA", None),
            ("service", "wordpress", None),
            ("path", "/wp-login.php", None),
            ("username", "admin", None),
            ("tls", "TLSv1.3", None),
            ("protocol", "HTTP/2", None),
            ("asn", "64500", Some("EXAMPLE, INC")),
        ] {
            sqlx::query(
                "INSERT INTO stats_daily (day, dim, key, extra, count) VALUES ($1, $2, $3, $4, 7)
                 ON CONFLICT (day, dim, key) DO UPDATE SET count = 7, extra = excluded.extra",
            )
            .bind(day)
            .bind(dim)
            .bind(key)
            .bind(extra)
            .execute(&db)
            .await
            .unwrap();
        }

        let body = public(&db, 30).await.unwrap();
        for (list, field, value) in [
            ("top_countries", "country", "CA"),
            ("top_services", "service", "wordpress"),
            ("top_paths", "path", "/wp-login.php"),
            ("top_usernames", "username", "admin"),
            ("top_tls", "tls_version", "TLSv1.3"),
            ("top_protocols", "http_protocol", "HTTP/2"),
        ] {
            let found = body[list]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row[field] == value)
                .unwrap_or_else(|| panic!("{list} has no row with {field} = {value}"));
            assert!(found["c"].is_i64(), "{list} count is not a number");
        }

        // The ASN row is the one with a different shape: a numeric asn and the
        // organisation carried alongside it.
        let asn = body["top_asns"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["asn"] == 64500)
            .expect("top_asns has no 64500");
        assert_eq!(asn["as_organization"], "EXAMPLE, INC");
        assert!(asn["c"].is_i64());
    }

    /// The private scope adds four keys and nothing else.
    #[tokio::test]
    async fn the_private_scope_adds_exactly_the_four_private_keys() {
        let Some(db) = pool().await else { return };
        let body = private(&db, 30, 10).await.unwrap();
        let mut keys: Vec<&str> = body.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["recent", "top_creds", "top_hosts", "top_ips"]);
    }

    /// `recent` carries the address as a bare string and the timestamp under
    /// the name the dashboard reads, which is NOT the column's name.
    #[tokio::test]
    async fn recent_events_are_shaped_the_way_the_dashboard_reads_them() {
        let Some(db) = pool().await else { return };
        sqlx::query(
            "INSERT INTO events (ingest_id, observed_at, ip, country, host, asn, method, path,
                                 service, username, password, ua)
             VALUES (gen_random_uuid(), now(), '203.0.113.55'::inet, 'CA', 'wp.example', 64500,
                     'POST', '/wp-login.php', 'wordpress', 'admin', 'hunter2', 'curl/8.5.0')",
        )
        .execute(&db)
        .await
        .unwrap();

        let body = private(&db, 30, 1000).await.unwrap();
        let row = body["recent"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["ip"] == "203.0.113.55")
            .expect("the planted event is not in `recent`");

        // A plain address, not PostgreSQL's INET text with a prefix length.
        assert_eq!(row["ip"], "203.0.113.55");
        assert_eq!(row["username"], "admin");
        assert_eq!(row["password"], "hunter2");
        // `created_at`, not `observed_at`: the column was renamed in 0001, the
        // dashboard's field name was not.
        assert!(row["created_at"].is_string(), "created_at is missing or not a string");
        assert!(row.get("observed_at").is_none(), "the column name leaked into the payload");
    }

    // --- The token gate ----------------------------------------------------

    #[tokio::test]
    async fn an_unconfigured_token_disables_the_private_scope_entirely() {
        let Some(db) = pool().await else { return };
        let state = state(db, "");
        // Fails closed: no header, and an empty header, are both refused. The
        // second is the one that matters -- without the length check, empty
        // would compare equal to empty and hand over every credential.
        assert!(!is_private(&state, &HeaderMap::new()));
        assert!(!is_private(&state, &token_header("")));
        assert!(!is_private(&state, &token_header("anything")));
    }

    #[tokio::test]
    async fn the_private_scope_needs_the_exact_token() {
        let Some(db) = pool().await else { return };
        let state = state(db, "s3cret-token");
        assert!(is_private(&state, &token_header("s3cret-token")));
        assert!(!is_private(&state, &HeaderMap::new()));
        assert!(!is_private(&state, &token_header("")));
        assert!(!is_private(&state, &token_header("s3cret-toke")));
        assert!(!is_private(&state, &token_header("s3cret-tokenn")));
        assert!(!is_private(&state, &token_header("S3CRET-TOKEN")));
    }

    /// Without the token the response must not contain a single private key --
    /// this is the assertion that a refactor of `handler` cannot quietly break.
    #[tokio::test]
    async fn the_handler_withholds_private_data_without_the_token() {
        let Some(db) = pool().await else { return };
        let with_token = handler(
            State(state(db.clone(), "s3cret-token")),
            token_header("s3cret-token"),
            Query(StatsQuery { days: Some(7), limit: Some(5) }),
        )
        .await
        .unwrap();
        assert!(with_token.0.get("recent").is_some());

        let without = handler(
            State(state(db, "s3cret-token")),
            HeaderMap::new(),
            Query(StatsQuery { days: Some(7), limit: Some(5) }),
        )
        .await
        .unwrap();
        for key in ["recent", "top_ips", "top_creds", "top_hosts"] {
            assert!(without.0.get(key).is_none(), "{key} leaked without a token");
        }
    }

    #[tokio::test]
    async fn the_window_and_the_row_limit_are_clamped() {
        let Some(db) = pool().await else { return };
        let huge = handler(
            State(state(db.clone(), "")),
            HeaderMap::new(),
            Query(StatsQuery { days: Some(100_000), limit: Some(100_000) }),
        )
        .await
        .unwrap();
        assert_eq!(huge.0["meta"]["days"], MAX_DAYS);

        let negative = handler(
            State(state(db, "")),
            HeaderMap::new(),
            Query(StatsQuery { days: Some(-5), limit: None }),
        )
        .await
        .unwrap();
        assert_eq!(negative.0["meta"]["days"], 1);
    }
}
