//! HoneyLab AbuseIPDB reporter.
//!
//! Reads PostgreSQL, aggregates the last N hours of events per source address,
//! and submits the result as one bulk report. Replaces the Worker's D1-backed
//! `reporter.js`, which cannot survive D1 being retired.
//!
//! WHY IT IS ITS OWN CONTAINER AND NOT PART OF THE API.
//!
//! The API has NO ROUTE OFF THE HOST -- both of its networks are
//! `internal: true`, which is the structural answer to SSRF and exfiltration on
//! a service that ingests attacker-controlled data all day. Reporting to
//! AbuseIPDB is, by definition, an outbound call. Putting it in the API would
//! trade that property away for a job that runs four times a day.
//!
//! So the outbound capability lives here instead, in a process that:
//!   - listens on nothing, and is on no network any request can arrive from;
//!   - talks to exactly one external host;
//!   - shares the API's image and build, so it is not a second thing to deploy.
//!
//! THE RATE LIMIT IS ABUSEIPDB'S, NOT OURS. The Webmaster tier allows 10
//! bulk-report calls per day. Running locally removes Cloudflare's budget from
//! the picture but not that one, and re-reporting the same address more often
//! is worse than useless -- AbuseIPDB deduplicates, and a noisy account gets
//! flagged. The default six-hour interval is four calls a day. What running
//! locally actually buys is analysis depth: arbitrary SQL over the full
//! retention window, with no CPU budget to respect.

use std::{collections::HashSet, env, time::Duration};

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use tracing::{error, info, warn};

/// Scanners that announce themselves and are not attacking anything. Reporting
/// them is how a honeypot loses its credibility as a source.
const ALLOWLIST_ASNS: &[i64] = &[
    13335,  // Cloudflare
    132892, // Cloudflare
    20473,  // Shodan (Vultr)
    398705, // Censys
    15169,  // Google
];

/// Scanners that share an ASN with real attackers, so the ASN cannot separate
/// them. LeakIX rotates addresses inside DigitalOcean and announces itself in
/// the User-Agent; UptimeRobot is this deployment's own monitoring.
///
/// ponytail: substring match on a spoofable header. A spoofer's reward is not
/// being reported, which costs nothing -- they still get logged, and they are
/// still hitting a honeypot. Tighten to published address ranges only if
/// somebody starts doing it on purpose.
const ALLOWLIST_UA: &[&str] = &["l9scan/", "uptimerobot"];

const CAT_HACKING: u8 = 15;
const CAT_BRUTE_FORCE: u8 = 18;
const CAT_BAD_WEB_BOT: u8 = 19;
const CAT_WEB_APP_ATTACK: u8 = 21;

const BULK_URL: &str = "https://api.abuseipdb.com/api/v2/bulk-report";

/// AbuseIPDB's own ceiling for one bulk report.
const MAX_ROWS_PER_REPORT: usize = 10_000;

/// One aggregated attacker, as the SQL below produces it.
#[derive(Debug)]
struct Candidate {
    ip: String,
    asn: Option<i64>,
    as_organization: Option<String>,
    event_count: i64,
    services: Vec<String>,
    paths: Vec<String>,
    methods: Vec<String>,
    ua: Option<String>,
    first_seen_at: DateTime<Utc>,
    duration_minutes: i64,
    submitted_credentials: bool,
    used_encoding: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "honeypot_reporter=info".into()),
        )
        .json()
        .init();

    let args: Vec<String> = env::args().collect();
    let dry_run = args.iter().any(|a| a == "--dry-run");
    let once = args.iter().any(|a| a == "--once") || dry_run;

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    // Absent in dry-run so the CSV can be inspected on a host that has no key.
    let api_key = env::var("ABUSEIPDB_KEY").unwrap_or_default();
    if api_key.is_empty() && !dry_run {
        warn!("ABUSEIPDB_KEY is empty: nothing will be submitted");
    }

    let window_hours = env_number("HONEYPOT_REPORT_WINDOW_HOURS", 48);
    let min_events = env_number("HONEYPOT_REPORT_MIN_EVENTS", 5);
    let interval_hours = env_number("HONEYPOT_REPORT_INTERVAL_HOURS", 6);

    // Two connections is plenty for a job that runs four times a day, and it
    // leaves the API's sixteen alone under PostgreSQL's default ceiling.
    let db = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await?;

    if once {
        return run_once(&db, &api_key, window_hours, min_events, dry_run)
            .await
            .map_err(Into::into);
    }

    info!(interval_hours, window_hours, min_events, "reporter started");
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_hours as u64 * 3600));
    loop {
        ticker.tick().await;
        // A failed cycle must not kill the loop: AbuseIPDB being down for an
        // hour is not a reason to stop reporting for good. The next tick
        // retries, and the deduplication makes that safe.
        if let Err(error) = run_once(&db, &api_key, window_hours, min_events, false).await {
            error!(%error, "report cycle failed");
        }
    }
}

fn env_number(name: &str, default: i64) -> i64 {
    env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

async fn run_once(
    db: &PgPool,
    api_key: &str,
    window_hours: i64,
    min_events: i64,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let candidates = fetch_candidates(db, window_hours, min_events).await?;
    let already = fetch_recently_submitted(db).await?;
    let extra_allowlist = allowlist_from_env();

    // EVERY CANDIDATE IS ACCOUNTED FOR, and the counters exist because the
    // first real cycle reported "candidates 17, already_reported 4, selected 0"
    // -- leaving thirteen addresses that vanished with no explanation anywhere.
    // A dry run whose whole purpose is showing what would be sent has to say
    // where the rest went.
    //
    // `already_reported` counts the RECENT SUBMISSIONS TABLE, not this batch,
    // so it does not add up with the rest either. The three below do:
    // candidates = skipped_recent + allowlisted + selected.
    let mut skipped_recent = 0usize;
    let mut allowlisted = 0usize;
    let mut selected: Vec<&Candidate> = Vec::new();
    for candidate in &candidates {
        if already.contains(&candidate.ip) {
            skipped_recent += 1;
        } else if is_allowlisted(candidate, &extra_allowlist) {
            allowlisted += 1;
        } else if selected.len() < MAX_ROWS_PER_REPORT {
            selected.push(candidate);
        }
    }

    info!(
        candidates = candidates.len(),
        skipped_recent,
        allowlisted,
        selected = selected.len(),
        already_reported = already.len(),
        "report cycle"
    );

    // Which addresses were spared, and why, at DEBUG. Not at INFO: this is one
    // line per allowlisted attacker every six hours, and the counter above is
    // what a healthy run needs. Turn it on to answer "why was THAT one not
    // reported" -- REPORTER_LOG=honeypot_reporter=debug.
    if allowlisted > 0 {
        for candidate in candidates.iter().filter(|c| !already.contains(&c.ip)) {
            if is_allowlisted(candidate, &extra_allowlist) {
                tracing::debug!(
                    ip = candidate.ip,
                    asn = candidate.asn,
                    ua = candidate.ua.as_deref().unwrap_or(""),
                    "allowlisted, not reported"
                );
            }
        }
    }

    if selected.is_empty() {
        return Ok(());
    }

    let csv = build_csv(&selected);
    if dry_run {
        // The CSV holds attacker addresses and paths, which is exactly what a
        // dry run is for inspecting, and it is printed only on explicit request.
        println!("{csv}");
        info!(rows = selected.len(), "dry run: nothing submitted");
        return Ok(());
    }
    if api_key.is_empty() {
        warn!(rows = selected.len(), "no ABUSEIPDB_KEY: nothing submitted");
        return Ok(());
    }

    let saved = submit(&csv, api_key).await?;
    info!(saved, rows = selected.len(), "bulk report accepted");
    record_submissions(db, &selected).await?;
    Ok(())
}

/// The Worker's D1 query, translated. The differences from SQLite are not
/// cosmetic and each one is a place a naive port goes wrong:
///
///   GROUP_CONCAT(DISTINCT x)  -> array_agg(DISTINCT x)   (SQLite's cannot take
///                                a separator AND DISTINCT together)
///   julianday(a) - julianday(b) -> EXTRACT(EPOCH FROM a - b) / 60
///   datetime('now', '-2 days')  -> now() - make_interval(hours => $1)
///   ip != 'unknown'             -> unnecessary: `ip` is INET here, and the
///                                  Worker drops unusable addresses before
///                                  they are ever sent.
async fn fetch_candidates(
    db: &PgPool,
    window_hours: i64,
    min_events: i64,
) -> Result<Vec<Candidate>, sqlx::Error> {
    let rows = sqlx::query(
        r#"
        SELECT
            host(ip)                                    AS ip,
            max(asn)                                    AS asn,
            max(as_organization)                        AS as_organization,
            count(*)                                    AS event_count,
            array_agg(DISTINCT service)                 AS services,
            (array_agg(DISTINCT path))[1:5]             AS paths,
            array_agg(DISTINCT method)                  AS methods,
            max(ua)                                     AS ua,
            min(observed_at)                            AS first_seen_at,
            (EXTRACT(EPOCH FROM (max(observed_at) - min(observed_at))) / 60)::bigint
                                                        AS duration_minutes,
            bool_or(username IS NOT NULL)               AS submitted_credentials,
            -- A LITERAL PERCENT followed by an encoded character, which is what
            -- URL-encoding evasion actually looks like. The Worker's version was
            -- `path LIKE '%25%'`, whose leading and trailing `%` are SQLite
            -- wildcards -- so it matched any path merely CONTAINING "25", and
            -- flagged /api/v2/25/foo as an evasion attempt. Deliberate change.
            bool_or(path ~* '%(25|2e|2f)')              AS used_encoding
        FROM events
        WHERE observed_at >= now() - make_interval(hours => $1)
        -- BY ip ALONE. Grouping by (ip, asn) splits one address into several
        -- rows when its announced ASN changes inside the window, and each row
        -- becomes its own line in the CSV -- a duplicate report for one
        -- attacker, which AbuseIPDB rejects.
        GROUP BY ip
        HAVING count(*) >= $2
        ORDER BY count(*) DESC
        "#,
    )
    .bind(window_hours as i32)
    .bind(min_events)
    .fetch_all(db)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| Candidate {
            ip: row.get("ip"),
            asn: row.get("asn"),
            as_organization: row.get("as_organization"),
            event_count: row.get("event_count"),
            services: row.get("services"),
            paths: row.get("paths"),
            methods: row.get("methods"),
            ua: row.get("ua"),
            first_seen_at: row.get("first_seen_at"),
            duration_minutes: row.get("duration_minutes"),
            submitted_credentials: row.get("submitted_credentials"),
            used_encoding: row.get("used_encoding"),
        })
        .collect())
}

/// Two days, matching the Worker's behaviour. This is what stops the same
/// address being reported on every cycle: at a six-hour interval that would be
/// eight duplicate reports a day for one attacker, which AbuseIPDB reads as
/// noise from an unreliable source.
async fn fetch_recently_submitted(db: &PgPool) -> Result<HashSet<String>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT host(ip) AS ip FROM abuseipdb_submissions WHERE submitted_on >= current_date - 2",
    )
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|row| row.get::<String, _>("ip")).collect())
}

/// `HONEYPOT_ALLOWLIST_ASNS`, comma-separated. Exists because the Worker's list
/// included `OWN_ASNS` from a config file that is deliberately not in the
/// repository -- this deployment's own network must never be reported, and that
/// value is the operator's, not the project's.
fn allowlist_from_env() -> HashSet<i64> {
    env::var("HONEYPOT_ALLOWLIST_ASNS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|entry| entry.trim().parse().ok())
        .collect()
}

fn is_allowlisted(candidate: &Candidate, extra: &HashSet<i64>) -> bool {
    if let Some(asn) = candidate.asn
        && (ALLOWLIST_ASNS.contains(&asn) || extra.contains(&asn))
    {
        return true;
    }
    let ua = candidate.ua.as_deref().unwrap_or("").to_ascii_lowercase();
    ALLOWLIST_UA.iter().any(|needle| ua.contains(needle))
}

fn categories_for(services: &[String]) -> Vec<u8> {
    let mut cats = vec![CAT_WEB_APP_ATTACK, CAT_BAD_WEB_BOT];
    for service in services {
        match service.as_str() {
            "login" | "wordpress" | "phpmyadmin" | "admin" | "vpn" | "mail" => {
                if !cats.contains(&CAT_BRUTE_FORCE) {
                    cats.push(CAT_BRUTE_FORCE);
                }
            }
            "catch-all" | "sensitive" | "infra" | "graphql" | "springboot" | "api" => {
                if !cats.contains(&CAT_HACKING) {
                    cats.push(CAT_HACKING);
                }
            }
            _ => {}
        }
    }
    cats.sort_unstable();
    cats
}

/// AbuseIPDB caps a comment at 1024 characters and shows it to humans, so the
/// most identifying facts come first and the truncation lands on the least
/// useful tail.
fn build_comment(candidate: &Candidate) -> String {
    let mut parts = vec![
        format!(
            "Honeypot: {} request(s) in {} min.",
            candidate.event_count, candidate.duration_minutes
        ),
        format!("Paths: {}.", candidate.paths.join(", ")),
        format!("Method(s): {}.", candidate.methods.join(", ")),
    ];
    if let Some(ua) = &candidate.ua
        && !ua.is_empty()
    {
        parts.push(format!("UA: {}.", truncate(ua, 80)));
    }
    parts.push(format!(
        "ASN: {} ({}).",
        candidate.asn.unwrap_or(0),
        candidate.as_organization.as_deref().unwrap_or("unknown")
    ));
    if candidate.submitted_credentials {
        parts.push("Credential stuffing observed.".to_owned());
    }
    if candidate.used_encoding {
        parts.push("URL-encoding WAF evasion detected.".to_owned());
    }
    truncate(&parts.join(" "), 1024)
}

/// Truncates on a CHARACTER boundary. `&s[..n]` panics mid-codepoint, and every
/// string here came from a User-Agent an attacker chose.
fn truncate(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}

/// RFC 4180 quoting. A path or a User-Agent containing a comma or a quote would
/// otherwise shift every following column, which AbuseIPDB reports back as an
/// invalid row -- or, worse, accepts with the comment in the date field.
fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

fn build_csv(candidates: &[&Candidate]) -> String {
    let mut lines = vec!["IP,Categories,ReportDate,Comment".to_owned()];
    for candidate in candidates {
        let categories =
            categories_for(&candidate.services).iter().map(u8::to_string).collect::<Vec<_>>().join(",");
        lines.push(
            [
                csv_field(&candidate.ip),
                csv_field(&categories),
                csv_field(&candidate.first_seen_at.to_rfc3339()),
                csv_field(&build_comment(candidate)),
            ]
            .join(","),
        );
    }
    lines.join("\n")
}

async fn submit(csv: &str, api_key: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let form = reqwest::multipart::Form::new().part(
        "csv",
        reqwest::multipart::Part::text(csv.to_owned())
            .file_name("report.csv")
            .mime_str("text/csv")?,
    );

    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?
        .post(BULK_URL)
        .header("Key", api_key)
        .header("Accept", "application/json")
        .multipart(form)
        .send()
        .await?;

    let status = response.status();
    let body: serde_json::Value = response.json().await.unwrap_or_default();
    if !status.is_success() {
        // The API key is a header, never a field, so it cannot appear here --
        // but the body is a third party's text, so it is bounded before it
        // reaches a log file.
        return Err(format!("AbuseIPDB {}: {}", status, truncate(&body.to_string(), 200)).into());
    }

    let invalid = body["data"]["invalidReports"].as_array().map_or(0, Vec::len);
    if invalid > 0 {
        warn!(invalid, "AbuseIPDB rejected some rows");
    }
    Ok(body["data"]["savedReports"].as_u64().unwrap_or(0))
}

/// Recorded only AFTER a successful submission, so a failed call is retried on
/// the next cycle instead of being silently marked done.
///
/// `ON CONFLICT DO NOTHING` on (ip, submitted_on): two cycles in one day cannot
/// produce a duplicate row, and a partial failure is safe to replay.
async fn record_submissions(db: &PgPool, candidates: &[&Candidate]) -> Result<(), sqlx::Error> {
    for candidate in candidates {
        let categories =
            categories_for(&candidate.services).iter().map(u8::to_string).collect::<Vec<_>>().join(",");
        sqlx::query(
            "INSERT INTO abuseipdb_submissions (ip, submitted_on, event_count, categories)
             VALUES ($1::inet, current_date, $2, $3)
             ON CONFLICT (ip, submitted_on) DO NOTHING",
        )
        .bind(&candidate.ip)
        .bind(candidate.event_count as i32)
        .bind(categories)
        .execute(db)
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate() -> Candidate {
        Candidate {
            ip: "203.0.113.7".to_owned(),
            asn: Some(64500),
            as_organization: Some("EXAMPLE, INC".to_owned()),
            event_count: 42,
            services: vec!["wordpress".to_owned(), "sensitive".to_owned()],
            paths: vec!["/wp-login.php".to_owned(), "/.env".to_owned()],
            methods: vec!["GET".to_owned(), "POST".to_owned()],
            ua: Some("curl/8.5.0".to_owned()),
            first_seen_at: "2026-09-01T12:00:00Z".parse().unwrap(),
            duration_minutes: 17,
            submitted_credentials: true,
            used_encoding: false,
        }
    }

    #[test]
    fn categories_reflect_the_services_that_were_probed() {
        // wordpress -> brute force, sensitive -> hacking, plus the two constants.
        assert_eq!(
            categories_for(&candidate().services),
            vec![CAT_HACKING, CAT_BRUTE_FORCE, CAT_BAD_WEB_BOT, CAT_WEB_APP_ATTACK]
        );
        // An unrecognised service still reports the two that always apply.
        assert_eq!(
            categories_for(&["cdn".to_owned()]),
            vec![CAT_BAD_WEB_BOT, CAT_WEB_APP_ATTACK]
        );
    }

    #[test]
    fn the_allowlists_keep_announced_scanners_out() {
        let mut cloudflare = candidate();
        cloudflare.asn = Some(13335);
        assert!(is_allowlisted(&cloudflare, &HashSet::new()));

        // The operator's own network, from the environment.
        let mine = candidate();
        assert!(is_allowlisted(&mine, &HashSet::from([64500])));
        assert!(!is_allowlisted(&mine, &HashSet::from([64501])));

        // LeakIX shares an ASN with real attackers, so only the UA separates it.
        let mut leakix = candidate();
        leakix.ua = Some("Mozilla/5.0 (l9scan/2.0)".to_owned());
        assert!(is_allowlisted(&leakix, &HashSet::new()));

        // Case-insensitive: UptimeRobot spells itself several ways.
        let mut kuma = candidate();
        kuma.ua = Some("UPTIMEROBOT/2.0".to_owned());
        assert!(is_allowlisted(&kuma, &HashSet::new()));
    }

    #[test]
    fn a_comment_stays_inside_the_1024_character_limit() {
        let mut noisy = candidate();
        noisy.paths = vec!["/".repeat(400), "/b".repeat(400)];
        noisy.ua = Some("A".repeat(9000));
        let comment = build_comment(&noisy);
        assert!(comment.chars().count() <= 1024, "{}", comment.chars().count());
    }

    #[test]
    fn a_multibyte_user_agent_does_not_split_a_codepoint() {
        let mut emoji = candidate();
        // 80 characters of UA, truncated at exactly the limit.
        emoji.ua = Some("\u{1F600}".repeat(200));
        let comment = build_comment(&emoji);
        assert!(comment.contains("\u{1F600}"));
    }

    #[test]
    fn csv_quoting_survives_commas_and_quotes_in_attacker_input() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        // An organisation name with a comma is the everyday case, and it would
        // otherwise shift the ReportDate column into the Comment.
        let csv = build_csv(&[&candidate()]);
        assert_eq!(csv.lines().count(), 2);
        assert!(csv.lines().nth(1).unwrap().starts_with("203.0.113.7,"));
        assert!(csv.contains("\"EXAMPLE, INC\"") || csv.contains("EXAMPLE, INC"));
    }

    #[test]
    fn the_csv_header_is_the_one_abuseipdb_expects() {
        assert_eq!(build_csv(&[]).lines().next().unwrap(), "IP,Categories,ReportDate,Comment");
    }

    #[test]
    fn the_report_date_is_rfc3339() {
        let csv = build_csv(&[&candidate()]);
        assert!(csv.contains("2026-09-01T12:00:00+00:00"));
    }

    /// The SQL is where a port to another dialect goes wrong, so it runs against
    /// a real PostgreSQL. Skipped, loudly, without TEST_DATABASE_URL.
    async fn pool() -> Option<PgPool> {
        let Ok(url) = env::var("TEST_DATABASE_URL") else {
            eprintln!("SKIPPED: TEST_DATABASE_URL is not set (see api/README.md)");
            return None;
        };
        let db = PgPoolOptions::new().max_connections(4).connect(&url).await.unwrap();
        sqlx::migrate!("./migrations").run(&db).await.unwrap();
        Some(db)
    }

    /// Plants events for one address and returns it.
    ///
    /// THE ADDRESS IS RANDOM, not derived from the caller's index. Fixed
    /// addresses made the suite pass once and fail on the second `cargo test`
    /// against the same database: the previous run's events were still inside
    /// the 48-hour window, so a test expecting six found twelve. 198.18.0.0/15
    /// is the benchmarking range -- 128k addresses, and never real traffic.
    async fn plant(db: &PgPool, _octet: i32, count: i32, service: &str, path: &str) -> String {
        let ip: String = sqlx::query_scalar(
            "SELECT '198.18.' || (random() * 255)::int || '.' || (random() * 255)::int",
        )
        .fetch_one(db)
        .await
        .unwrap();
        for index in 0..count {
            sqlx::query(
                "INSERT INTO events (ingest_id, observed_at, ip, asn, as_organization,
                                     ua, method, path, service, username)
                 VALUES (gen_random_uuid(), now() - make_interval(mins => $1), $2::inet,
                         64500, 'EXAMPLE, INC', 'curl/8.5.0', 'GET', $3, $4, $5)",
            )
            .bind(index * 2)
            .bind(&ip)
            .bind(path)
            .bind(service)
            .bind(if index == 0 { Some("admin") } else { None })
            .execute(db)
            .await
            .unwrap();
        }
        ip
    }

    async fn candidate_for(db: &PgPool, ip: &str) -> Option<Candidate> {
        fetch_candidates(db, 48, 5).await.unwrap().into_iter().find(|c| c.ip == ip)
    }

    #[tokio::test]
    async fn the_query_aggregates_one_row_per_address() {
        let Some(db) = pool().await else { return };
        let ip = plant(&db, 11, 6, "wordpress", "/wp-login.php").await;
        let found = candidate_for(&db, &ip).await.expect("address not returned");

        assert_eq!(found.event_count, 6);
        assert_eq!(found.asn, Some(64500));
        assert_eq!(found.as_organization.as_deref(), Some("EXAMPLE, INC"));
        assert_eq!(found.services, vec!["wordpress".to_owned()]);
        assert_eq!(found.methods, vec!["GET".to_owned()]);
        // One event carried a username, so the whole address is flagged.
        assert!(found.submitted_credentials);
        // Events were planted 2 minutes apart.
        assert_eq!(found.duration_minutes, 10);
    }

    #[tokio::test]
    async fn an_address_below_the_threshold_is_not_a_candidate() {
        let Some(db) = pool().await else { return };
        let ip = plant(&db, 12, 4, "login", "/login").await;
        assert!(candidate_for(&db, &ip).await.is_none(), "4 events should be under the floor of 5");
    }

    /// The Worker's heuristic was `path LIKE '%25%'`, whose outer `%` are SQLite
    /// wildcards -- so a path merely containing "25" was flagged as evasion.
    #[tokio::test]
    async fn only_a_real_percent_escape_counts_as_encoding_evasion() {
        let Some(db) = pool().await else { return };
        let innocent = plant(&db, 13, 5, "api", "/api/v2/25/items").await;
        let evading = plant(&db, 14, 5, "sensitive", "/..%2fetc/passwd").await;

        assert!(!candidate_for(&db, &innocent).await.unwrap().used_encoding);
        assert!(candidate_for(&db, &evading).await.unwrap().used_encoding);
    }

    /// One address whose announced ASN changes mid-window must still produce a
    /// single row: two rows would be two CSV lines for one attacker.
    #[tokio::test]
    async fn a_changing_asn_does_not_split_an_address_in_two() {
        let Some(db) = pool().await else { return };
        let ip = plant(&db, 15, 5, "admin", "/admin").await;
        sqlx::query(
            "INSERT INTO events (ingest_id, observed_at, ip, asn, method, path, service)
             VALUES (gen_random_uuid(), now(), $1::inet, 64999, 'POST', '/admin', 'admin')",
        )
        .bind(&ip)
        .execute(&db)
        .await
        .unwrap();

        let all = fetch_candidates(&db, 48, 5).await.unwrap();
        assert_eq!(all.iter().filter(|c| c.ip == ip).count(), 1, "the address was split");
    }

    /// Events older than the window are invisible, which is what stops the same
    /// attacker being re-reported forever from stale rows.
    #[tokio::test]
    async fn events_outside_the_window_are_ignored() {
        let Some(db) = pool().await else { return };
        let ip: String = sqlx::query_scalar(
            "SELECT '198.18.' || (random() * 255)::int || '.' || (random() * 255)::int",
        )
        .fetch_one(&db)
        .await
        .unwrap();
        for _ in 0..6 {
            sqlx::query(
                "INSERT INTO events (ingest_id, observed_at, ip, method, path, service)
                 VALUES (gen_random_uuid(), now() - interval '10 days', $1::inet, 'GET', '/', 'x')",
            )
            .bind(&ip)
            .execute(&db)
            .await
            .unwrap();
        }
        assert!(candidate_for(&db, &ip).await.is_none(), "a 10-day-old burst was reported");
    }

    /// The deduplication that stops eight reports a day for one attacker.
    #[tokio::test]
    async fn a_recorded_submission_is_not_offered_again() {
        let Some(db) = pool().await else { return };
        let ip = plant(&db, 17, 5, "vpn", "/vpn").await;
        let found = candidate_for(&db, &ip).await.expect("address not returned");

        record_submissions(&db, &[&found]).await.unwrap();
        assert!(fetch_recently_submitted(&db).await.unwrap().contains(&ip));

        // Recording twice in one day must not fail: ON CONFLICT DO NOTHING is
        // what makes a retried cycle safe.
        record_submissions(&db, &[&found]).await.unwrap();
    }
}
