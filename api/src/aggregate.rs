//! Daily rollup into `stats_daily`, ported from the Worker's `aggregate.js`.
//!
//! Nine counts per completed day, one row per (day, dimension, key). The
//! dashboard reads these instead of scanning `events`, which is what keeps a
//! hundred days of history cheap to display.
//!
//! IT CATCHES UP, which the cron it replaces could not. `aggregate.js` rolled
//! up exactly yesterday, once, when the Worker's cron fired -- a day the cron
//! missed was never aggregated and the gap was permanent, because the events
//! behind it eventually aged out of retention. Here the days still owed are
//! derived from `job_runs`, so a container that was down for a week fills in
//! the week on its next tick. That is what 0001 created that table for.

use chrono::NaiveDate;
use sqlx::{PgPool, Row};
use tracing::{debug, info};

const JOB: &str = "aggregate_day";

/// The nine dimensions, each as its own INSERT ... SELECT.
///
/// Written out rather than generated, because they are not variations on a
/// theme: `asn` carries an `extra` column, `volume` has no key at all, and
/// `campaign_volume` reads a different table. A loop over a list of column
/// names would have to special-case all three and would read worse than this.
///
/// `$1` is the day in every one of them.
const ROLLUPS: &[&str] = &[
    "INSERT INTO stats_daily (day, dim, key, count)
     SELECT $1, 'volume', '', count(*) FROM events WHERE observed_at::date = $1",
    "INSERT INTO stats_daily (day, dim, key, count)
     SELECT $1, 'country', country, count(*) FROM events
     WHERE observed_at::date = $1 AND country IS NOT NULL GROUP BY country",
    "INSERT INTO stats_daily (day, dim, key, count)
     SELECT $1, 'service', service, count(*) FROM events
     WHERE observed_at::date = $1 GROUP BY service",
    "INSERT INTO stats_daily (day, dim, key, count)
     SELECT $1, 'path', path, count(*) FROM events
     WHERE observed_at::date = $1 GROUP BY path",
    "INSERT INTO stats_daily (day, dim, key, extra, count)
     SELECT $1, 'asn', asn::text, max(as_organization), count(*) FROM events
     WHERE observed_at::date = $1 AND asn IS NOT NULL GROUP BY asn",
    "INSERT INTO stats_daily (day, dim, key, count)
     SELECT $1, 'username', username, count(*) FROM events
     WHERE observed_at::date = $1 AND username IS NOT NULL GROUP BY username",
    "INSERT INTO stats_daily (day, dim, key, count)
     SELECT $1, 'tls', tls_version, count(*) FROM events
     WHERE observed_at::date = $1 AND tls_version IS NOT NULL GROUP BY tls_version",
    "INSERT INTO stats_daily (day, dim, key, count)
     SELECT $1, 'protocol', http_protocol, count(*) FROM events
     WHERE observed_at::date = $1 AND http_protocol IS NOT NULL GROUP BY http_protocol",
    "INSERT INTO stats_daily (day, dim, key, count)
     SELECT $1, 'campaign_volume', '', count(*) FROM campaigns
     WHERE first_seen_at::date = $1",
];

/// Rolls up every completed day inside the retention window that has not been
/// rolled up yet.
///
/// MUST RUN BEFORE THE RETENTION SWEEP. The rollups are derived from `events`,
/// so a day whose events have already been deleted can never be aggregated --
/// its history would be lost permanently, on the one day of the year the
/// container happened to be down. The caller enforces the order.
pub async fn run(db: &PgPool, retention_days: i64) -> Result<u64, sqlx::Error> {
    let owed: Vec<NaiveDate> = sqlx::query(
        // Completed days only: today is still accumulating, and a rollup of a
        // partial day recorded as done would freeze it half-counted.
        "SELECT DISTINCT observed_at::date AS day FROM events
         WHERE observed_at < date_trunc('day', now())
           AND observed_at >= now() - make_interval(days => $1)
         EXCEPT
         SELECT job_key FROM job_runs WHERE job_name = $2
         ORDER BY 1",
    )
    .bind(retention_days as i32)
    .bind(JOB)
    .fetch_all(db)
    .await?
    .into_iter()
    .map(|row| row.get("day"))
    .collect();

    for day in &owed {
        aggregate_day(db, *day).await?;
    }
    if !owed.is_empty() {
        info!(days = owed.len(), first = %owed[0], last = %owed[owed.len() - 1], "rolled up");
    }
    Ok(owed.len() as u64)
}

/// One day, in one transaction.
///
/// DELETE then INSERT, so re-running a day replaces it rather than doubling it.
/// The Worker did the same; what it could not do was be sure the delete and the
/// nine inserts either all happened or none did.
pub async fn aggregate_day(db: &PgPool, day: NaiveDate) -> Result<(), sqlx::Error> {
    let mut tx = db.begin().await?;

    sqlx::query("DELETE FROM stats_daily WHERE day = $1")
        .bind(day)
        .execute(&mut *tx)
        .await?;
    // `*statement`, not `statement`: iterating the slice yields `&&str`, and
    // sqlx 0.9 only accepts `&'static str` -- its guard against SQL built at
    // runtime. Dereferencing keeps that guard rather than working around it.
    for statement in ROLLUPS {
        sqlx::query(*statement).bind(day).execute(&mut *tx).await?;
    }

    // Recorded in the SAME transaction as the rollup it describes. Written
    // afterwards, a crash in between would mark a day done that was never
    // aggregated -- and nothing would ever revisit it.
    sqlx::query(
        "INSERT INTO job_runs (job_name, job_key) VALUES ($1, $2)
         ON CONFLICT (job_name, job_key) DO UPDATE SET completed_at = now()",
    )
    .bind(JOB)
    .bind(day)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    debug!(%day, "day aggregated");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
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

    /// A day nothing else in the suite is using, so the whole-day assertions
    /// below are stable while other tests write to `events`.
    async fn plant(db: &PgPool, day: NaiveDate, count: i32, country: &str, service: &str) {
        for _ in 0..count {
            sqlx::query(
                "INSERT INTO events (ingest_id, observed_at, ip, country, asn, as_organization,
                                     ua, method, path, service, username, tls_version, http_protocol)
                 VALUES (gen_random_uuid(), $1::date + interval '3 hours', '203.0.113.9'::inet,
                         $2, 64500, 'EXAMPLE, INC', 'curl/8.5.0', 'GET', '/wp-login.php', $3,
                         'admin', 'TLSv1.3', 'HTTP/2')",
            )
            .bind(day)
            .bind(country)
            .bind(service)
            .execute(db)
            .await
            .unwrap();
        }
    }

    async fn counts(db: &PgPool, day: NaiveDate, dim: &str) -> Vec<(String, i64)> {
        sqlx::query_as("SELECT key, count FROM stats_daily WHERE day = $1 AND dim = $2 ORDER BY key")
            .bind(day)
            .bind(dim)
            .fetch_all(db)
            .await
            .unwrap()
    }

    /// A day far enough in the past that no other test touches it, and unique
    /// per run so the suite is repeatable against one database.
    async fn free_day(db: &PgPool) -> NaiveDate {
        // 40 to 80 days back: inside the 100-day retention window, outside the
        // few days the reporter's tests use.
        loop {
            let offset: i64 = 40 + (rand_u32(db).await % 40) as i64;
            let day = (Utc::now() - Duration::days(offset)).date_naive();
            let used: i64 = sqlx::query_scalar("SELECT count(*) FROM events WHERE observed_at::date = $1")
                .bind(day)
                .fetch_one(db)
                .await
                .unwrap();
            if used == 0 {
                return day;
            }
        }
    }

    async fn rand_u32(db: &PgPool) -> u32 {
        let value: f64 = sqlx::query_scalar("SELECT random()").fetch_one(db).await.unwrap();
        (value * 1_000_000.0) as u32
    }

    #[tokio::test]
    async fn a_day_is_counted_across_every_dimension() {
        let Some(db) = pool().await else { return };
        let day = free_day(&db).await;
        plant(&db, day, 3, "CA", "wordpress").await;
        plant(&db, day, 2, "FR", "login").await;

        aggregate_day(&db, day).await.unwrap();

        assert_eq!(counts(&db, day, "volume").await, vec![(String::new(), 5)]);
        assert_eq!(
            counts(&db, day, "country").await,
            vec![("CA".to_owned(), 3), ("FR".to_owned(), 2)]
        );
        assert_eq!(
            counts(&db, day, "service").await,
            vec![("login".to_owned(), 2), ("wordpress".to_owned(), 3)]
        );
        assert_eq!(counts(&db, day, "path").await, vec![("/wp-login.php".to_owned(), 5)]);
        assert_eq!(counts(&db, day, "username").await, vec![("admin".to_owned(), 5)]);
        assert_eq!(counts(&db, day, "tls").await, vec![("TLSv1.3".to_owned(), 5)]);
        assert_eq!(counts(&db, day, "protocol").await, vec![("HTTP/2".to_owned(), 5)]);

        // The ASN dimension carries the organisation name in `extra`.
        let (key, extra): (String, String) = sqlx::query_as(
            "SELECT key, extra FROM stats_daily WHERE day = $1 AND dim = 'asn'",
        )
        .bind(day)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!((key.as_str(), extra.as_str()), ("64500", "EXAMPLE, INC"));
    }

    /// Re-running a day replaces it. The cron could fire twice, and a rollup
    /// that doubled its counts would be worse than one that never ran.
    #[tokio::test]
    async fn aggregating_the_same_day_twice_does_not_double_it() {
        let Some(db) = pool().await else { return };
        let day = free_day(&db).await;
        plant(&db, day, 4, "CA", "admin").await;

        aggregate_day(&db, day).await.unwrap();
        aggregate_day(&db, day).await.unwrap();
        assert_eq!(counts(&db, day, "volume").await, vec![(String::new(), 4)]);
    }

    /// The catch-up: days owed come from `job_runs`, so a gap is filled rather
    /// than lost. The Worker's cron rolled up exactly yesterday and nothing
    /// else, so a missed night was permanent.
    #[tokio::test]
    async fn days_already_done_are_not_redone_and_missing_ones_are_caught_up() {
        let Some(db) = pool().await else { return };
        let day = free_day(&db).await;
        plant(&db, day, 6, "CA", "vpn").await;

        // The day is owed, so a run picks it up. The COUNT returned is not
        // asserted: the suite runs in parallel against one database, and a
        // concurrent test's own `run` may legitimately have swept this day up
        // first. What matters is the outcome, not who did it.
        run(&db, 100).await.unwrap();
        assert_eq!(counts(&db, day, "volume").await, vec![(String::new(), 6)]);

        // ...and having been recorded, it is not owed again.
        let done: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM job_runs WHERE job_name = $1 AND job_key = $2",
        )
        .bind(JOB)
        .bind(day)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(done, 1);
    }

    /// Today is still accumulating. Rolling it up and recording it as done
    /// would freeze it half-counted, because it would never be revisited.
    #[tokio::test]
    async fn the_current_day_is_never_rolled_up() {
        let Some(db) = pool().await else { return };
        let today = Utc::now().date_naive();
        plant(&db, today, 2, "CA", "api").await;

        run(&db, 100).await.unwrap();
        let done: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM job_runs WHERE job_name = $1 AND job_key = $2",
        )
        .bind(JOB)
        .bind(today)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(done, 0, "today was rolled up while still in progress");
    }
}
