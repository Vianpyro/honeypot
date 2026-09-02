//! HoneyLab ingest API.
//!
//! One endpoint that matters: `POST /v1/events`, called by the Cloudflare
//! Worker through a tunnel. It is HMAC-authenticated, idempotent on
//! `event_id`, and writes to PostgreSQL. Nothing else is exposed.
//!
//! IDEMPOTENCE IS THE POINT, not a nicety. The Worker logs with
//! `ctx.waitUntil()`; when that times out on the edge, the same event can be
//! sent again after PostgreSQL has already committed it. The write is therefore
//! `INSERT ... ON CONFLICT (ingest_id) DO NOTHING RETURNING id` against a
//! UNIQUE column, which decides in ONE statement -- a `SELECT` followed by an
//! `INSERT` would leave the window between them open to exactly the duplicate
//! it is meant to prevent, under two concurrent retries.

mod auth;

use std::{env, net::IpAddr, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tokio::net::TcpListener;
use tower_http::{limit::RequestBodyLimitLayer, timeout::TimeoutLayer, trace::TraceLayer};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::auth::{AuthError, AuthKeys};

/// 8 KiB. The largest legitimate event -- a long UA, a full query string and a
/// 2000-character captured body -- is well under 4 KiB; the rest is headroom.
/// Enforced by the layer, so an oversized body is refused while it streams
/// rather than after it has been buffered.
const MAX_REQUEST_BYTES: usize = 8 * 1024;

/// Whole-request deadline. Bounds a wedged PostgreSQL: without it a stalled
/// query holds its pool connection AND its task until TCP gives up, and the
/// pool is the scarce resource.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
struct AppState {
    db: PgPool,
    auth: Arc<AuthKeys>,
}

/// `deny_unknown_fields`: a Worker that starts sending a field this schema does
/// not know about gets a loud 400 rather than silently dropping the data.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventPayload {
    event_id: Uuid,
    observed_at: DateTime<Utc>,
    ip: IpAddr,
    country: Option<String>,
    asn: Option<i64>,
    as_organization: Option<String>,
    tls_version: Option<String>,
    http_protocol: Option<String>,
    client_tcp_rtt: Option<i32>,
    ua: Option<String>,
    method: String,
    path: String,
    query: Option<String>,
    host: Option<String>,
    service: String,
    body: Option<String>,
    username: Option<String>,
    password: Option<String>,
}

#[derive(Serialize)]
struct EventResponse {
    status: &'static str,
}

/// Every message here is a fixed string chosen by this file. Nothing derived
/// from the request, from PostgreSQL or from the key material reaches the
/// client -- a database error text can quote the offending value, and the
/// values this service handles are captured credentials.
#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: &'static str,
}

impl ApiError {
    const fn new(status: StatusCode, message: &'static str) -> Self {
        Self { status, message }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(serde_json::json!({ "error": self.message }))).into_response()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `try_from_default_env` and NOT `from_default_env`: the latter silently
    // yields an EMPTY filter when RUST_LOG is unset, which is a service that
    // logs nothing at all in production and looks like a working deploy.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "honeypot_api=info,tower_http=warn".into()),
        )
        .json()
        .init();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let hmac_keys = env::var("HONEYPOT_HMAC_KEYS").expect("HONEYPOT_HMAC_KEYS must be set");
    let auth = AuthKeys::from_env(&hmac_keys).expect("invalid HONEYPOT_HMAC_KEYS");
    let bind = env::var("HONEYPOT_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_owned());
    let retention_days = env_number("HONEYPOT_RETENTION_DAYS", 100);

    // `max_connections` stays well under the container's `max_connections=100`:
    // several API replicas plus a psql session for a restore must all still fit.
    // `acquire_timeout` is the load-shedding knob -- past it a request fails
    // fast with 503 instead of queueing until the client gives up, which is
    // what turns a slow database into an unbounded task pile-up.
    let db = PgPoolOptions::new()
        .max_connections(env_number("HONEYPOT_DB_MAX_CONNECTIONS", 16) as u32)
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(2))
        .connect(&database_url)
        .await?;

    // Migrations run HERE, not in a sidecar container or an Ansible task: one
    // process owns the schema, it holds an advisory lock while it runs, and a
    // restarted container converges by itself. The files are embedded at
    // compile time, so this needs no database to BUILD -- only to run.
    sqlx::migrate!("./migrations").run(&db).await?;
    info!("migrations applied");

    tokio::spawn(retention_task(db.clone(), retention_days));

    let app = router(AppState { db, auth: Arc::new(auth) });
    let listener = TcpListener::bind(&bind).await?;
    info!(%bind, "honeypot API listening");
    axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await?;
    Ok(())
}

fn env_number(name: &str, default: i64) -> i64 {
    env::var(name).ok().and_then(|value| value.parse().ok()).unwrap_or(default)
}

/// Docker sends SIGTERM on `compose up -d` and on a host reboot. Without this,
/// in-flight ingests are killed mid-write and the Worker retries them -- which
/// is survivable only because the insert is idempotent. Draining first means it
/// does not have to be.
async fn shutdown_signal() {
    let ctrl_c = async { tokio::signal::ctrl_c().await.ok() };
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut stream) => stream.recv().await,
            Err(_) => std::future::pending().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<Option<()>>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    info!("shutdown signal received, draining");
}

/// Retention, run in-process on a daily tick.
///
/// ponytail: a tokio interval rather than a systemd timer or pg_cron. It is one
/// statement that has to run once a day on a database only this process talks
/// to; a unit file, its Ansible task and its own credentials would be three
/// more things to keep in sync for that. The ceiling is honest -- with several
/// API replicas each would run it, which is harmless here (the DELETE is
/// idempotent) and is the point at which to move it out.
///
/// `campaign_events` and `pending_campaign_events` cascade on the deleted rows,
/// so the campaign bookkeeping never outlives the events it points at.
async fn retention_task(db: PgPool, days: i64) {
    if days <= 0 {
        warn!("retention disabled (HONEYPOT_RETENTION_DAYS <= 0)");
        return;
    }
    let mut ticker = tokio::time::interval(Duration::from_secs(24 * 60 * 60));
    loop {
        ticker.tick().await;
        let deleted = sqlx::query("DELETE FROM events WHERE observed_at < now() - make_interval(days => $1)")
            .bind(days as i32)
            .execute(&db)
            .await;
        match deleted {
            Ok(result) => info!(rows = result.rows_affected(), days, "retention sweep"),
            Err(error) => error!(%error, "retention sweep failed"),
        }
    }
}

fn router(state: AppState) -> Router {
    Router::new()
        // Liveness only, and deliberately not a database probe: this is what
        // the container healthcheck calls, and a Postgres blip should show up
        // as failed ingests in the logs, not as an API marked unhealthy that
        // Compose then refuses to consider a dependency of anything.
        .route("/healthz", get(|| async { StatusCode::NO_CONTENT }))
        .route("/v1/events", post(ingest_event))
        // A REQUEST THAT MATCHED NO ROUTE IS WORTH A LINE. Without this it is a
        // silent 404 from axum's own fallback -- and "the caller reached this
        // service and nothing happened" is precisely the failure that is
        // impossible to diagnose from the outside. It catches a proxy or a
        // tunnel that rewrites or drops the path, which is a real possibility
        // for a binding whose routing this service does not control.
        //
        // Method and path only, both bounded by hyper's own header limits, and
        // no body: this endpoint is reachable by anything that gets onto the
        // tunnel, so it must not become a way to write arbitrary text into logs.
        .fallback(|method: Method, uri: axum::http::Uri| async move {
            warn!(%method, path = uri.path(), "request to an unknown route");
            (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "unknown route" })))
        })
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BYTES))
        // 503, not the layer's default 408: a deadline blown here means this
        // service could not serve in time, and a Worker retry is the correct
        // reaction. 408 tells the client its own request was too slow.
        .layer(TimeoutLayer::with_status_code(StatusCode::SERVICE_UNAVAILABLE, REQUEST_TIMEOUT))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Logs every rejection, then returns it unchanged.
///
/// THIS EXISTS BECAUSE ITS ABSENCE COST A DAY. The tunnel's own metrics count a
/// connection that was established, not a request that succeeded -- so a Worker
/// whose events were all being refused showed up as "1k connections, 0 errors"
/// on the Cloudflare side and an empty table here, with nothing anywhere saying
/// why. An ingest service that silently drops authenticated-looking traffic is
/// not observable at all.
///
/// The status and the fixed reason string only. Both are chosen by this file;
/// nothing derived from the request, the payload or the key material is logged,
/// because the payloads here are captured credentials.
async fn ingest_event(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<EventResponse>), ApiError> {
    let outcome = ingest(State(state), headers, body).await;
    if let Err(error) = &outcome {
        warn!(status = error.status.as_u16(), reason = error.message, "event rejected");
    }
    outcome
}

async fn ingest(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<EventResponse>), ApiError> {
    // AUTHENTICATE BEFORE PARSING. Everything below this line is work done on
    // behalf of an unauthenticated caller otherwise.
    verify_request(&state.auth, &headers, &body)?;

    let payload: EventPayload = serde_json::from_slice(&body)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid JSON payload"))?;
    validate_event(&payload, Utc::now())?;

    // Bound parameters throughout -- the statement is a constant and no value
    // is ever concatenated into it, so there is no SQL injection surface here
    // even though every field is attacker-controlled by design.
    //
    // `$3::inet` with the address as text rather than an `IpAddr` bind: sqlx
    // 0.9 only implements the INET codec behind its `ipnet`/`ipnetwork`
    // features, and serde has already parsed this into an `IpAddr`, so the cast
    // cannot fail and the crate does not have to be pulled in for one column.
    let inserted = sqlx::query_scalar::<_, i64>(
        r#"
        INSERT INTO events (
          ingest_id, observed_at, ip, country, asn, as_organization, tls_version,
          http_protocol, client_tcp_rtt, ua, method, path, query, host, service,
          body, username, password
        ) VALUES (
          $1, $2, $3::inet, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
          $16, $17, $18
        )
        ON CONFLICT (ingest_id) DO NOTHING
        RETURNING id
        "#,
    )
    .bind(payload.event_id)
    .bind(payload.observed_at)
    .bind(payload.ip.to_string())
    .bind(payload.country)
    .bind(payload.asn)
    .bind(payload.as_organization)
    .bind(payload.tls_version)
    .bind(payload.http_protocol)
    .bind(payload.client_tcp_rtt)
    .bind(payload.ua)
    .bind(payload.method)
    .bind(payload.path)
    .bind(payload.query)
    .bind(payload.host)
    .bind(payload.service)
    .bind(payload.body)
    .bind(payload.username)
    .bind(payload.password)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| {
        // The event id is safe to log (it is a UUID the Worker minted); the
        // payload is not, and is not logged anywhere.
        error!(%error, event_id = %payload.event_id, "event insert failed");
        ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "storage unavailable")
    })?;

    // 201 for a row that was written, 200 for one that was already there. The
    // Worker treats both as success; the distinction exists so a retry storm is
    // visible in the access log rather than indistinguishable from real volume.
    Ok(if inserted.is_some() {
        (StatusCode::CREATED, Json(EventResponse { status: "created" }))
    } else {
        (StatusCode::OK, Json(EventResponse { status: "duplicate" }))
    })
}

fn verify_request(auth: &AuthKeys, headers: &HeaderMap, body: &[u8]) -> Result<(), ApiError> {
    let key_id = header(headers, "X-Honeypot-Key-Id")?;
    let timestamp = header(headers, "X-Honeypot-Timestamp")?;
    let signature = header(headers, "X-Honeypot-Signature")?;
    let verdict = auth.verify(
        key_id,
        timestamp,
        signature,
        Method::POST.as_str(),
        "/v1/events",
        body,
        Utc::now(),
    );
    // THE CLIENT LEARNS LESS THAN THE OPERATOR DOES, and that asymmetry is the
    // whole point of this block.
    //
    // The three 403 causes share one response body on purpose: telling a prober
    // whether its key id exists is a free oracle. But sharing one LOG line too
    // was simply a mistake -- the first real deployment returned 403 to every
    // event the Worker sent, and nothing on either side could say whether the
    // key id was wrong, the secret was wrong, or the header was malformed.
    // Three different fixes, one indistinguishable symptom.
    if let Err(reason) = &verdict {
        warn!(
            reason = match reason {
                AuthError::Expired => "timestamp outside the +/-60s window (check both clocks)",
                AuthError::MalformedTimestamp => "X-Honeypot-Timestamp is not RFC3339",
                AuthError::MalformedSignature => "X-Honeypot-Signature is not unpadded base64url",
                AuthError::UnknownKey => "no such key id in HONEYPOT_HMAC_KEYS",
                AuthError::InvalidSignature => "signature does not verify: the secrets differ",
            },
            // The presented id, sanitised. It is not a secret -- we choose it --
            // and it is the one value that separates "wrong id" from "wrong
            // secret" at a glance. Bounded and filtered because this is
            // attacker-controlled input reaching a log file.
            key_id = key_id.chars().filter(char::is_ascii_alphanumeric).take(16).collect::<String>(),
            "authentication failed"
        );
    }

    match verdict {
        Ok(()) => Ok(()),
        // 401 for "your request is not authenticated yet, fix the headers or
        // your clock"; 403 for "it is authenticated and wrong". Both bodies are
        // fixed strings: which of the two a probe gets already tells it nothing
        // it did not send itself.
        Err(AuthError::Expired) => {
            Err(ApiError::new(StatusCode::UNAUTHORIZED, "timestamp outside the accepted window"))
        }
        Err(AuthError::MalformedTimestamp) => {
            Err(ApiError::new(StatusCode::UNAUTHORIZED, "invalid authentication headers"))
        }
        Err(AuthError::UnknownKey | AuthError::InvalidSignature | AuthError::MalformedSignature) => {
            Err(ApiError::new(StatusCode::FORBIDDEN, "invalid signature"))
        }
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<&'a str, ApiError> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "missing authentication header"))
}

/// Field-level validation, mirroring the CHECK constraints in the migration.
///
/// It exists in BOTH places on purpose: the database is the authority (a future
/// writer that is not this binary still cannot corrupt the table), and this
/// function is what turns a rejection into a 422 instead of a 503 from a
/// constraint violation the client cannot act on.
fn validate_event(event: &EventPayload, now: DateTime<Utc>) -> Result<(), ApiError> {
    let ok = text(Some(&event.method), 16)
        && !event.method.is_empty()
        && event.method.bytes().all(|byte| byte.is_ascii_uppercase())
        && text(Some(&event.path), 2048)
        && event.path.starts_with('/')
        && text(Some(&event.service), 64)
        && !event.service.is_empty()
        && event.country.as_deref().is_none_or(is_country_code)
        // 32-bit AS numbers. Negative is impossible in the wire format and the
        // column rejects it too.
        && event.asn.is_none_or(|asn| (0..=u32::MAX as i64).contains(&asn))
        && event.client_tcp_rtt.is_none_or(|rtt| rtt >= 0)
        && text(event.as_organization.as_deref(), 512)
        && text(event.tls_version.as_deref(), 32)
        && text(event.http_protocol.as_deref(), 32)
        && text(event.ua.as_deref(), 2048)
        && text(event.query.as_deref(), 2048)
        && text(event.host.as_deref(), 253)
        && text(event.body.as_deref(), 2000)
        && text(event.username.as_deref(), 2000)
        && text(event.password.as_deref(), 2000)
        // The request itself is already pinned to within a minute of now by the
        // HMAC timestamp; this bounds what the AUTHENTICATED caller may claim
        // about when it observed the event, so a leaked key cannot backfill or
        // post-date the whole time series in one pass. A week of slack covers
        // any plausible replay of a queued Worker batch.
        && (now - chrono::Duration::days(7)..now + chrono::Duration::days(1))
            .contains(&event.observed_at);

    if ok {
        Ok(())
    } else {
        Err(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid event fields"))
    }
}

fn is_country_code(country: &str) -> bool {
    country.len() == 2 && country.bytes().all(|byte| byte.is_ascii_uppercase())
}

/// Length in CHARACTERS, not bytes, matching PostgreSQL's `char_length`, plus
/// the one byte PostgreSQL cannot store at all.
///
/// A NUL inside a JSON string is legal (` `) and TEXT cannot hold it. Let
/// through, it becomes a driver error at INSERT time -- a 503 for a request the
/// caller could have fixed, and one that looks like a database outage.
fn text(value: Option<&str>, limit: usize) -> bool {
    value.is_none_or(|value| value.chars().count() <= limit && !value.contains('\0'))
}


#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    use tower::ServiceExt;

    const KEY: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY";

    /// A fresh event id per test, per RUN.
    ///
    /// Fixed ids looked tidier and were wrong twice over: `cargo test` runs
    /// these in parallel against ONE database, and it is run repeatedly against
    /// a database that is NOT reset between runs -- so the second `cargo test`
    /// found the first one's rows and every "expect 201" became a 200. Nothing
    /// here truncates a shared table for the same reason: that would delete
    /// rows out from under whichever test is mid-flight.
    fn fresh() -> String {
        Uuid::now_v7().to_string()
    }

    fn signature(timestamp: &str, body: &[u8]) -> String {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&URL_SAFE_NO_PAD.decode(KEY).unwrap()).unwrap();
        mac.update(auth::canonical_request("POST", "/v1/events", timestamp, body).as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    fn payload(event_id: &str) -> serde_json::Value {
        serde_json::json!({
            "event_id": event_id,
            "observed_at": Utc::now().to_rfc3339(),
            "ip": "203.0.113.7",
            "country": "CA",
            "asn": 13335,
            "as_organization": "CLOUDFLARENET",
            "tls_version": "TLSv1.3",
            "http_protocol": "HTTP/2",
            "client_tcp_rtt": 42,
            "ua": "curl/8.5.0",
            "method": "POST",
            "path": "/wp-login.php",
            "query": "redirect_to=%2Fwp-admin",
            "host": "honeypot.example",
            "service": "wordpress",
            "body": "log=admin&pwd=hunter2",
            "username": "admin",
            "password": "hunter2",
        })
    }

    fn signed(body: &serde_json::Value) -> Request<axum::body::Body> {
        let raw = serde_json::to_vec(body).unwrap();
        let timestamp = Utc::now().to_rfc3339();
        request(&timestamp, &signature(&timestamp, &raw), raw)
    }

    fn request(timestamp: &str, signature: &str, body: Vec<u8>) -> Request<axum::body::Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/events")
            .header("content-type", "application/json")
            .header("X-Honeypot-Key-Id", "active")
            .header("X-Honeypot-Timestamp", timestamp)
            .header("X-Honeypot-Signature", signature)
            .body(axum::body::Body::from(body))
            .unwrap()
    }

    /// Every database test runs against a REAL PostgreSQL, because what they
    /// check -- the UNIQUE index deciding a duplicate, the CHECK constraints,
    /// the cascade -- has no meaning against a mock.
    ///
    /// Skipped, loudly, when TEST_DATABASE_URL is unset, so `cargo test` on a
    /// machine with no database still runs the whole auth and validation suite
    /// rather than failing for the wrong reason. See api/README.md for the
    /// one-line throwaway container.
    async fn pool() -> Option<PgPool> {
        let url = match env::var("TEST_DATABASE_URL") {
            Ok(url) => url,
            Err(_) => {
                eprintln!("SKIPPED: TEST_DATABASE_URL is not set (see api/README.md)");
                return None;
            }
        };
        let db = PgPoolOptions::new().max_connections(4).connect(&url).await.unwrap();
        // Migrating on every test run is itself the "migrations are repeatable"
        // check: the second and later runs find their versions already applied
        // and must do nothing. Against an EMPTY database it is the "from
        // scratch" check, which is what CI and a rebuilt host exercise.
        sqlx::migrate!("./migrations").run(&db).await.unwrap();
        Some(db)
    }

    fn app(db: PgPool) -> Router {
        let auth = AuthKeys::from_env(&format!("active:{KEY}")).unwrap();
        router(AppState { db, auth: Arc::new(auth) })
    }

    async fn status(db: &PgPool, request: Request<axum::body::Body>) -> StatusCode {
        app(db.clone()).oneshot(request).await.unwrap().status()
    }

    /// Rows belonging to ONE event id -- never `count(*)`. See `fresh`.
    async fn rows(db: &PgPool, event_id: &str) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM events WHERE ingest_id = $1::uuid")
            .bind(event_id)
            .fetch_one(db)
            .await
            .unwrap()
    }

    macro_rules! db_test {
        ($name:ident, $db:ident, $body:block) => {
            #[tokio::test]
            async fn $name() {
                let Some($db) = pool().await else { return };
                $body
            }
        };
    }

    #[tokio::test]
    async fn healthz_needs_no_authentication_and_no_database() {
        // A pool pointing nowhere: /healthz is liveness, so it must answer
        // without touching PostgreSQL. Lazily connected, so this never dials.
        let db = PgPoolOptions::new().connect_lazy("postgres://unreachable:5432/none").unwrap();
        let response = app(db)
            .oneshot(Request::builder().uri("/healthz").body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    // --- Authentication, over the real HTTP surface -------------------------

    db_test!(rejects_missing_authentication_headers, db, {
        let id = fresh();
        let raw = serde_json::to_vec(&payload(&id)).unwrap();
        let bare = Request::builder()
            .method("POST")
            .uri("/v1/events")
            .body(axum::body::Body::from(raw))
            .unwrap();
        assert_eq!(status(&db, bare).await, StatusCode::UNAUTHORIZED);
        assert_eq!(rows(&db, &id).await, 0);
    });

    db_test!(rejects_an_unknown_key_id, db, {
        let id = fresh();
        let raw = serde_json::to_vec(&payload(&id)).unwrap();
        let timestamp = Utc::now().to_rfc3339();
        let mut req = request(&timestamp, &signature(&timestamp, &raw), raw);
        req.headers_mut().insert("X-Honeypot-Key-Id", "ghost".parse().unwrap());
        assert_eq!(status(&db, req).await, StatusCode::FORBIDDEN);
        assert_eq!(rows(&db, &id).await, 0);
    });

    db_test!(rejects_a_malformed_signature, db, {
        let id = fresh();
        let raw = serde_json::to_vec(&payload(&id)).unwrap();
        let timestamp = Utc::now().to_rfc3339();
        assert_eq!(
            status(&db, request(&timestamp, "not-base64-!!!", raw)).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(rows(&db, &id).await, 0);
    });

    db_test!(rejects_an_expired_timestamp, db, {
        let id = fresh();
        let raw = serde_json::to_vec(&payload(&id)).unwrap();
        let stale = (Utc::now() - chrono::Duration::seconds(120)).to_rfc3339();
        assert_eq!(
            status(&db, request(&stale, &signature(&stale, &raw), raw)).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(rows(&db, &id).await, 0);
    });

    db_test!(rejects_a_timestamp_in_the_future, db, {
        let id = fresh();
        let raw = serde_json::to_vec(&payload(&id)).unwrap();
        let ahead = (Utc::now() + chrono::Duration::seconds(120)).to_rfc3339();
        assert_eq!(
            status(&db, request(&ahead, &signature(&ahead, &raw), raw)).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(rows(&db, &id).await, 0);
    });

    // The signed bytes and the sent bytes differ by one captured credential --
    // which is exactly the edit anyone on the path would want to make.
    db_test!(rejects_a_body_modified_after_signing, db, {
        let id = fresh();
        let signed_body = serde_json::to_vec(&payload(&id)).unwrap();
        let timestamp = Utc::now().to_rfc3339();
        let sig = signature(&timestamp, &signed_body);
        let mut tampered = payload(&id);
        tampered["password"] = serde_json::json!("something-else");
        let sent = serde_json::to_vec(&tampered).unwrap();
        assert_eq!(status(&db, request(&timestamp, &sig, sent)).await, StatusCode::FORBIDDEN);
        assert_eq!(rows(&db, &id).await, 0);
    });

    // --- Ingestion ----------------------------------------------------------

    db_test!(accepts_a_valid_event_once_and_is_idempotent_after, db, {
        let id = fresh();
        let event = payload(&id);
        assert_eq!(status(&db, signed(&event)).await, StatusCode::CREATED);
        // Same event_id, freshly signed: the Worker's retry after a waitUntil
        // timeout. One row, and a 200 rather than a 201.
        assert_eq!(status(&db, signed(&event)).await, StatusCode::OK);
        assert_eq!(status(&db, signed(&event)).await, StatusCode::OK);
        assert_eq!(rows(&db, &id).await, 1);
    });

    db_test!(stores_two_distinct_events_separately, db, {
        let (first, second) = (fresh(), fresh());
        assert_eq!(status(&db, signed(&payload(&first))).await, StatusCode::CREATED);
        assert_eq!(status(&db, signed(&payload(&second))).await, StatusCode::CREATED);
        assert_eq!(rows(&db, &first).await, 1);
        assert_eq!(rows(&db, &second).await, 1);
    });

    db_test!(round_trips_every_captured_field, db, {
        let id = fresh();
        assert_eq!(status(&db, signed(&payload(&id))).await, StatusCode::CREATED);
        let (ip, service, username, password, asn): (String, String, String, String, i64) =
            sqlx::query_as(
                "SELECT host(ip), service, username, password, asn
                 FROM events WHERE ingest_id = $1::uuid",
            )
            .bind(&id)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!((ip.as_str(), service.as_str()), ("203.0.113.7", "wordpress"));
        assert_eq!((username.as_str(), password.as_str(), asn), ("admin", "hunter2", 13335));
    });

    db_test!(rejects_invalid_json, db, {
        let timestamp = Utc::now().to_rfc3339();
        let raw = b"{ not json".to_vec();
        assert_eq!(
            status(&db, request(&timestamp, &signature(&timestamp, &raw), raw)).await,
            StatusCode::BAD_REQUEST
        );
    });

    db_test!(rejects_unknown_fields, db, {
        let id = fresh();
        let mut event = payload(&id);
        event["surprise"] = serde_json::json!("field");
        assert_eq!(status(&db, signed(&event)).await, StatusCode::BAD_REQUEST);
        assert_eq!(rows(&db, &id).await, 0);
    });

    db_test!(rejects_a_missing_required_field, db, {
        let id = fresh();
        let mut event = payload(&id);
        event.as_object_mut().unwrap().remove("service");
        assert_eq!(status(&db, signed(&event)).await, StatusCode::BAD_REQUEST);
        assert_eq!(rows(&db, &id).await, 0);
    });

    db_test!(rejects_invalid_field_values, db, {
        let cases: Vec<(&str, serde_json::Value)> = vec![
            ("path", serde_json::json!("wp-login.php")),
            ("path", serde_json::json!("/".repeat(3000))),
            ("method", serde_json::json!("post")),
            ("method", serde_json::json!("")),
            ("country", serde_json::json!("CAN")),
            ("country", serde_json::json!("ca")),
            ("ip", serde_json::json!("999.1.1.1")),
            ("ip", serde_json::json!("not-an-ip")),
            ("asn", serde_json::json!(-1)),
            ("client_tcp_rtt", serde_json::json!(-5)),
            ("body", serde_json::json!("x".repeat(2001))),
            ("username", serde_json::json!("x".repeat(2001))),
            ("host", serde_json::json!("h".repeat(300))),
            ("service", serde_json::json!("")),
            // A NUL is legal JSON and impossible in a PostgreSQL TEXT column.
            ("username", serde_json::json!("admin\u{0}")),
            // Backdating the whole series with an otherwise valid key.
            ("observed_at", serde_json::json!("2020-01-01T00:00:00Z")),
        ];
        for (field, value) in cases {
            let id = fresh();
            let mut event = payload(&id);
            event[field] = value.clone();
            let got = status(&db, signed(&event)).await;
            // 400 when serde itself cannot build the type (a bad IP), 422 when
            // it parsed and the value is out of range. Never 5xx, which is what
            // an unvalidated field reaching a CHECK constraint would produce.
            assert!(
                got == StatusCode::UNPROCESSABLE_ENTITY || got == StatusCode::BAD_REQUEST,
                "{field}={value} produced {got}"
            );
            assert_eq!(rows(&db, &id).await, 0, "{field}={value} was stored anyway");
        }
    });

    db_test!(rejects_a_payload_over_the_limit, db, {
        let id = fresh();
        let mut event = payload(&id);
        event["ua"] = serde_json::json!("A".repeat(MAX_REQUEST_BYTES));
        assert_eq!(status(&db, signed(&event)).await, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(rows(&db, &id).await, 0);
    });

    // --- Schema -------------------------------------------------------------

    db_test!(ingest_id_is_unique_at_the_database_level, db, {
        let id = fresh();
        assert_eq!(status(&db, signed(&payload(&id))).await, StatusCode::CREATED);
        // Bypassing the API entirely: the guarantee has to hold for any writer,
        // not only for the one that goes through ON CONFLICT DO NOTHING.
        let duplicate = sqlx::query(
            "INSERT INTO events (ingest_id, observed_at, ip, method, path, service)
             VALUES ($1::uuid, now(), '203.0.113.7'::inet, 'GET', '/', 'x')",
        )
        .bind(&id)
        .execute(&db)
        .await;
        assert!(duplicate.is_err(), "a second row with the same ingest_id was accepted");
        assert_eq!(rows(&db, &id).await, 1);
    });

    db_test!(check_constraints_reject_bad_rows_from_any_writer, db, {
        // Literal statements rather than one `format!`: sqlx 0.9 refuses a
        // non-'static SQL string outright (`SqlSafeStr`), which is a guard rail
        // worth keeping even in a test.
        let bad_rows: [&'static str; 5] = [
            // lowercase method
            "INSERT INTO events (ingest_id, observed_at, ip, method, path, service)
             VALUES (gen_random_uuid(), now(), '203.0.113.7'::inet, 'get', '/', 'x')",
            // path without a leading slash
            "INSERT INTO events (ingest_id, observed_at, ip, method, path, service)
             VALUES (gen_random_uuid(), now(), '203.0.113.7'::inet, 'GET', 'no-slash', 'x')",
            // three-letter country code
            "INSERT INTO events (ingest_id, observed_at, ip, method, path, service, country)
             VALUES (gen_random_uuid(), now(), '203.0.113.7'::inet, 'GET', '/', 'x', 'CAN')",
            // negative ASN
            "INSERT INTO events (ingest_id, observed_at, ip, method, path, service, asn)
             VALUES (gen_random_uuid(), now(), '203.0.113.7'::inet, 'GET', '/', 'x', -1)",
            // empty service
            "INSERT INTO events (ingest_id, observed_at, ip, method, path, service)
             VALUES (gen_random_uuid(), now(), '203.0.113.7'::inet, 'GET', '/', '')",
        ];
        for statement in bad_rows {
            let inserted = sqlx::query(statement).execute(&db).await;
            assert!(inserted.is_err(), "constraint did not reject: {statement}");
        }
    });

    db_test!(campaign_events_cascades_when_an_event_is_deleted, db, {
        // Its own campaign row, so the assertions below never see another
        // test's links. Two md5s are 64 hex characters, which is what the
        // profile_hash CHECK wants.
        let campaign_id: i64 = sqlx::query_scalar(
            "INSERT INTO campaigns (profile_hash, bucket_start, first_seen_at, last_seen_at, event_count)
             VALUES (md5(random()::text) || md5(random()::text), now(), now(), now(), 1)
             RETURNING id",
        )
        .fetch_one(&db)
        .await
        .unwrap();
        let event_id: i64 = sqlx::query_scalar(
            "INSERT INTO events (ingest_id, observed_at, ip, method, path, service)
             VALUES (gen_random_uuid(), now(), '203.0.113.7'::inet, 'GET', '/', 'x') RETURNING id",
        )
        .fetch_one(&db)
        .await
        .unwrap();
        sqlx::query("INSERT INTO campaign_events (campaign_id, event_id) VALUES ($1, $2)")
            .bind(campaign_id)
            .bind(event_id)
            .execute(&db)
            .await
            .unwrap();

        // A foreign key that does not point at a real event must be refused...
        let orphan =
            sqlx::query("INSERT INTO campaign_events (campaign_id, event_id) VALUES ($1, $2)")
                .bind(campaign_id)
                .bind(i64::MAX)
                .execute(&db)
                .await;
        assert!(orphan.is_err(), "campaign_events accepted a dangling event_id");

        // ...and the retention sweep must not leave one behind either.
        sqlx::query("DELETE FROM events WHERE id = $1").bind(event_id).execute(&db).await.unwrap();
        let links: i64 =
            sqlx::query_scalar("SELECT count(*) FROM campaign_events WHERE campaign_id = $1")
                .bind(campaign_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(links, 0, "campaign_events did not cascade");
    });

    // The 100-day sweep, against rows this test plants itself: one old enough
    // to go and one that must stay.
    db_test!(retention_deletes_only_rows_past_the_window, db, {
        let (old, recent) = (fresh(), fresh());
        for (id, age_days) in [(&old, 200), (&recent, 10)] {
            sqlx::query(
                "INSERT INTO events (ingest_id, observed_at, ip, method, path, service)
                 VALUES ($1::uuid, now() - make_interval(days => $2), '203.0.113.7'::inet,
                         'GET', '/', 'x')",
            )
            .bind(id)
            .bind(age_days)
            .execute(&db)
            .await
            .unwrap();
        }
        sqlx::query("DELETE FROM events WHERE observed_at < now() - make_interval(days => $1)")
            .bind(100)
            .execute(&db)
            .await
            .unwrap();
        assert_eq!(rows(&db, &old).await, 0, "an event past the window survived");
        assert_eq!(rows(&db, &recent).await, 1, "an event inside the window was deleted");
    });
}
