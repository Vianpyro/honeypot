//! Campaign detection, ported from the Worker's `campaigns.js`.
//!
//! A campaign is a burst of probes sharing one scanner identity inside one
//! ten-minute window. Identity is `(sha256(ua_prefix|asn), bucket_start)`.
//!
//! WHAT THE PORT CHANGES, AND WHY. The D1 version fused three things into one
//! fingerprint -- `ua|asn|bucket` -- and two of its features could not work as
//! a result:
//!
//!   - `is_coordinated` was derived from a set of ASNs collected under a key
//!     that already contained the ASN. The set could never hold more than one
//!     element, so cross-ASN coordination never fired once.
//!   - The adaptive threshold's Welford state was keyed on that same
//!     bucket-bearing hash, so every ten minutes started from n = 0 and
//!     `mean + 2*stddev` was permanently 0. The threshold was always the floor.
//!
//! Here the ASN stays in the campaign identity -- so one very common
//! User-Agent cannot merge unrelated scanners -- while `ua_hash` carries the
//! identity WITHOUT it, and coordination is a separate question asked over that
//! column. The Welford state is keyed on the bucket-free `profile_hash`, so it
//! accumulates across windows and the threshold genuinely adapts.
//!
//! CONCURRENCY. The D1 version had none: two events arriving together could
//! both promote the same pending campaign. Every sequence here runs inside the
//! caller's transaction holding a `campaign_locks` row `FOR UPDATE`, which
//! serialises per scanner and per window rather than globally.

use chrono::{DateTime, DurationRound, TimeDelta, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row};
use tracing::debug;

/// Ten minutes. A campaign that spans two windows is two campaigns, which is
/// what keeps a slow scanner from accumulating into one endless burst.
const BUCKET: TimeDelta = TimeDelta::minutes(10);

/// How much of the User-Agent identifies the scanner. Long enough to separate
/// tools, short enough that a version suffix or a random token does not make
/// every request its own campaign.
const UA_PREFIX_CHARS: usize = 40;

/// The floor under the adaptive threshold. Below this, a "campaign" is noise.
const MIN_EVENTS: i64 = 5;

/// Standard deviations above the mean before a burst is unusual for this
/// scanner. 2.0 is roughly the 97.7th percentile of a normal distribution.
const Z_THRESHOLD: f64 = 2.0;

fn hex_sha256(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// The scanner identity, and the same identity without its ASN.
///
/// Both are full SHA-256 hex: the schema's `CHECK (length(profile_hash) = 64)`
/// says so, and the D1 version's 16-character truncation bought nothing but a
/// collision surface.
fn identity(ua: Option<&str>, asn: i64) -> (String, String) {
    let ua_prefix: String = ua.unwrap_or("").chars().take(UA_PREFIX_CHARS).collect();
    let ua_prefix = ua_prefix.trim();
    (hex_sha256(&format!("{ua_prefix}|{asn}")), hex_sha256(ua_prefix))
}

/// Floors an instant to its ten-minute window.
fn bucket_start(at: DateTime<Utc>) -> DateTime<Utc> {
    at.duration_trunc(BUCKET).unwrap_or(at)
}

/// Sample standard deviation from Welford state. Undefined below two samples,
/// where 0 is the honest answer -- it makes the threshold fall back to the
/// floor rather than to a number invented from one observation.
fn stddev(n: i64, m2: f64) -> f64 {
    if n < 2 { 0.0 } else { (m2 / (n - 1) as f64).sqrt() }
}

/// Runs the whole pipeline for one freshly inserted event.
///
/// Takes the caller's transaction: the event insert and everything below must
/// commit together, or a crash between them leaves an event that belongs to a
/// campaign nothing points at.
pub async fn detect(
    tx: &mut PgConnection,
    event_id: i64,
    ua: Option<&str>,
    asn: Option<i64>,
    observed_at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    let asn = asn.unwrap_or(0);
    let (profile_hash, ua_hash) = identity(ua, asn);
    let bucket = bucket_start(observed_at);

    // The lock row is created on first sight and then taken FOR UPDATE, so
    // every concurrent ingest for this scanner and window queues behind it.
    sqlx::query(
        "INSERT INTO campaign_locks (profile_hash, bucket_start) VALUES ($1, $2)
         ON CONFLICT DO NOTHING",
    )
    .bind(&profile_hash)
    .bind(bucket)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "SELECT 1 FROM campaign_locks WHERE profile_hash = $1 AND bucket_start = $2 FOR UPDATE",
    )
    .bind(&profile_hash)
    .bind(bucket)
    .fetch_one(&mut *tx)
    .await?;

    let confirmed: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM campaigns WHERE profile_hash = $1 AND bucket_start = $2",
    )
    .bind(&profile_hash)
    .bind(bucket)
    .fetch_optional(&mut *tx)
    .await?;

    if let Some(campaign_id) = confirmed {
        sqlx::query(
            "UPDATE campaigns
             SET event_count = event_count + 1, last_seen_at = greatest(last_seen_at, $2)
             WHERE id = $1",
        )
        .bind(campaign_id)
        .bind(observed_at)
        .execute(&mut *tx)
        .await?;
        link(tx, campaign_id, event_id).await?;
        return Ok(());
    }

    accumulate(tx, event_id, &profile_hash, &ua_hash, asn, bucket, observed_at).await
}

/// Adds the event to the pending burst and promotes it if it has grown past
/// this scanner's threshold.
async fn accumulate(
    tx: &mut PgConnection,
    event_id: i64,
    profile_hash: &str,
    ua_hash: &str,
    asn: i64,
    bucket: DateTime<Utc>,
    observed_at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    let count: i64 = sqlx::query_scalar(
        "INSERT INTO pending_campaigns
             (profile_hash, bucket_start, first_seen_at, last_seen_at, event_count)
         VALUES ($1, $2, $3, $3, 1)
         ON CONFLICT (profile_hash, bucket_start) DO UPDATE SET
             event_count  = pending_campaigns.event_count + 1,
             last_seen_at = greatest(pending_campaigns.last_seen_at, excluded.last_seen_at)
         -- ::bigint because the column is INTEGER, and decoding INT4 into an
         -- i64 is a runtime type error rather than a widening. Casting here
         -- keeps every count in this file one type.
         RETURNING event_count::bigint",
    )
    .bind(profile_hash)
    .bind(bucket)
    .bind(observed_at)
    .fetch_one(&mut *tx)
    .await?;

    // The event ids are ROWS, not a JSON array re-serialised on every event as
    // the D1 version did. That array grew with the burst and was rewritten in
    // full each time; this is one insert, and the foreign key means a deleted
    // event cannot leave a dangling id behind.
    sqlx::query(
        "INSERT INTO pending_campaign_events (profile_hash, bucket_start, event_id)
         VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(profile_hash)
    .bind(bucket)
    .bind(event_id)
    .execute(&mut *tx)
    .await?;

    let stats = sqlx::query("SELECT n, mean, m2 FROM campaign_path_stats WHERE profile_hash = $1")
        .bind(profile_hash)
        .fetch_optional(&mut *tx)
        .await?;
    let (n, mean, m2) = stats.map_or((0i64, 0f64, 0f64), |row| {
        (row.get("n"), row.get("mean"), row.get("m2"))
    });

    // Keyed on the bucket-free profile_hash, so `n` is the number of confirmed
    // bursts this scanner has produced across every window -- which is what
    // makes the threshold adaptive at all.
    let threshold = (mean + Z_THRESHOLD * stddev(n, m2)).ceil() as i64;
    let threshold = threshold.max(MIN_EVENTS);

    if count < threshold {
        return Ok(());
    }

    promote(tx, profile_hash, ua_hash, asn, bucket, count, n, mean, m2).await
}

/// Turns a pending burst into a campaign: one row, the links moved over, the
/// pending state dropped, the Welford state updated, and coordination
/// re-evaluated for the User-Agent behind it.
#[allow(clippy::too_many_arguments)]
async fn promote(
    tx: &mut PgConnection,
    profile_hash: &str,
    ua_hash: &str,
    asn: i64,
    bucket: DateTime<Utc>,
    count: i64,
    n: i64,
    mean: f64,
    m2: f64,
) -> Result<(), sqlx::Error> {
    let campaign_id: i64 = sqlx::query_scalar(
        "INSERT INTO campaigns
             (profile_hash, bucket_start, first_seen_at, last_seen_at, event_count,
              ua_hash, asn)
         SELECT profile_hash, bucket_start, first_seen_at, last_seen_at, event_count, $3, $4
         FROM pending_campaigns WHERE profile_hash = $1 AND bucket_start = $2
         RETURNING id",
    )
    .bind(profile_hash)
    .bind(bucket)
    .bind(ua_hash)
    .bind(asn)
    .fetch_one(&mut *tx)
    .await?;

    // Set-based, not a statement per event: the burst can be thousands of rows
    // and the D1 version built one prepared statement for each of them.
    sqlx::query(
        "INSERT INTO campaign_events (campaign_id, event_id)
         SELECT $1, event_id FROM pending_campaign_events
         WHERE profile_hash = $2 AND bucket_start = $3
         ON CONFLICT DO NOTHING",
    )
    .bind(campaign_id)
    .bind(profile_hash)
    .bind(bucket)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE events SET campaign_id = $1
         WHERE id IN (SELECT event_id FROM pending_campaign_events
                      WHERE profile_hash = $2 AND bucket_start = $3)",
    )
    .bind(campaign_id)
    .bind(profile_hash)
    .bind(bucket)
    .execute(&mut *tx)
    .await?;

    // `pending_campaign_events` goes with it, by the foreign key 0001 declared.
    sqlx::query("DELETE FROM pending_campaigns WHERE profile_hash = $1 AND bucket_start = $2")
        .bind(profile_hash)
        .bind(bucket)
        .execute(&mut *tx)
        .await?;

    // Welford, updated ONLY on promotion: the samples are confirmed burst
    // sizes, not the running partial counts of bursts that never became one.
    let new_n = n + 1;
    let delta = count as f64 - mean;
    let new_mean = mean + delta / new_n as f64;
    let new_m2 = m2 + delta * (count as f64 - new_mean);
    sqlx::query(
        "INSERT INTO campaign_path_stats (profile_hash, n, mean, m2) VALUES ($1, $2, $3, $4)
         ON CONFLICT (profile_hash) DO UPDATE SET n = excluded.n, mean = excluded.mean, m2 = excluded.m2",
    )
    .bind(profile_hash)
    .bind(new_n)
    .bind(new_mean)
    .bind(new_m2)
    .execute(&mut *tx)
    .await?;

    let coordinated = mark_coordination(tx, ua_hash, bucket).await?;
    debug!(campaign_id, count, threshold_samples = new_n, coordinated, "campaign promoted");
    Ok(())
}

/// THE FEATURE THAT NEVER WORKED BEFORE.
///
/// One User-Agent seen from several ASNs inside one window is a distributed
/// scan, and it is the signal worth having. It is asked over `ua_hash` -- the
/// identity WITHOUT the ASN -- because the campaign identity deliberately
/// includes it, so no single campaign can ever observe more than one.
///
/// Every campaign sharing that User-Agent and window is marked, not just the
/// one being promoted: coordination is a property of the group.
async fn mark_coordination(
    tx: &mut PgConnection,
    ua_hash: &str,
    bucket: DateTime<Utc>,
) -> Result<bool, sqlx::Error> {
    let updated = sqlx::query(
        "UPDATE campaigns SET is_coordinated = true
         WHERE ua_hash = $1 AND bucket_start = $2 AND NOT is_coordinated
           AND (SELECT count(DISTINCT asn) FROM campaigns
                WHERE ua_hash = $1 AND bucket_start = $2) > 1",
    )
    .bind(ua_hash)
    .bind(bucket)
    .execute(&mut *tx)
    .await?;
    Ok(updated.rows_affected() > 0)
}

async fn link(tx: &mut PgConnection, campaign_id: i64, event_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO campaign_events (campaign_id, event_id) VALUES ($1, $2)
         ON CONFLICT DO NOTHING",
    )
    .bind(campaign_id)
    .bind(event_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE events SET campaign_id = $1 WHERE id = $2")
        .bind(campaign_id)
        .bind(event_id)
        .execute(&mut *tx)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_asn_is_part_of_the_identity_but_not_of_the_user_agent_hash() {
        let (profile_a, ua_a) = identity(Some("curl/8.5.0"), 64500);
        let (profile_b, ua_b) = identity(Some("curl/8.5.0"), 64501);
        // Same tool, different network: different campaigns...
        assert_ne!(profile_a, profile_b);
        // ...but the same User-Agent, which is what makes them comparable and
        // is the whole basis of coordination detection.
        assert_eq!(ua_a, ua_b);
    }

    #[test]
    fn the_identity_holds_no_time_component() {
        // The D1 fingerprint contained the bucket, which is what kept the
        // Welford state permanently empty. Nothing here varies with the clock.
        assert_eq!(identity(Some("curl/8.5.0"), 1), identity(Some("curl/8.5.0"), 1));
    }

    #[test]
    fn the_user_agent_is_truncated_then_trimmed_in_that_order() {
        // TRUNCATE FIRST, TRIM SECOND -- the order the Worker used, kept so the
        // two implementations agree during the dual-write period. It means
        // leading whitespace costs characters from the prefix, which is
        // surprising enough to pin down: 2 spaces + 40 A's truncates to
        // 2 spaces + 38 A's, and trims to 38.
        let long = "A".repeat(200);
        let exactly = "A".repeat(UA_PREFIX_CHARS);
        assert_eq!(identity(Some(&long), 1), identity(Some(&exactly), 1));

        let padded = format!("  {}  ", "A".repeat(UA_PREFIX_CHARS));
        assert_eq!(identity(Some(&padded), 1), identity(Some(&"A".repeat(38)), 1));

        // A missing User-Agent is its own identity, not a crash.
        assert_eq!(identity(None, 1), identity(Some("   "), 1));
    }

    #[test]
    fn hashes_are_full_sha256_as_the_schema_requires() {
        let (profile, ua) = identity(Some("curl"), 1);
        assert_eq!(profile.len(), 64);
        assert_eq!(ua.len(), 64);
    }

    #[test]
    fn buckets_floor_to_ten_minutes() {
        let at = |s: &str| DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc);
        assert_eq!(bucket_start(at("2026-09-02T12:07:59Z")), at("2026-09-02T12:00:00Z"));
        assert_eq!(bucket_start(at("2026-09-02T12:10:00Z")), at("2026-09-02T12:10:00Z"));
        assert_eq!(bucket_start(at("2026-09-02T12:19:59.999Z")), at("2026-09-02T12:10:00Z"));
    }

    #[test]
    fn the_threshold_falls_back_to_the_floor_below_two_samples() {
        assert_eq!(stddev(0, 0.0), 0.0);
        assert_eq!(stddev(1, 0.0), 0.0);
        // Two samples of 10 and 20: variance 50, stddev ~7.07.
        assert!((stddev(2, 50.0) - 50f64.sqrt()).abs() < 1e-9);
    }
}

#[cfg(test)]
mod db_tests {
    use super::*;
    use sqlx::{PgPool, postgres::PgPoolOptions};

    /// Every assertion below is scoped to a User-Agent this test invented, so
    /// the suite stays parallel-safe against one shared database.
    async fn pool() -> Option<PgPool> {
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            eprintln!("SKIPPED: TEST_DATABASE_URL is not set");
            return None;
        };
        let db = PgPoolOptions::new().max_connections(4).connect(&url).await.unwrap();
        sqlx::migrate!("./migrations").run(&db).await.unwrap();
        Some(db)
    }

    fn unique_ua() -> String {
        format!("scanner-{}", uuid::Uuid::now_v7())
    }

    /// One event through the whole pipeline, inside its own transaction.
    async fn ingest(db: &PgPool, ua: &str, asn: i64, at: DateTime<Utc>) -> i64 {
        let mut tx = db.begin().await.unwrap();
        let event_id: i64 = sqlx::query_scalar(
            "INSERT INTO events (ingest_id, observed_at, ip, asn, ua, method, path, service)
             VALUES (gen_random_uuid(), $1, '203.0.113.7'::inet, $2, $3, 'GET', '/', 'x')
             RETURNING id",
        )
        .bind(at)
        .bind(asn)
        .bind(ua)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        detect(&mut tx, event_id, Some(ua), Some(asn), at).await.expect("detect failed");
        tx.commit().await.unwrap();
        event_id
    }

    async fn campaign_of(db: &PgPool, ua: &str, asn: i64) -> Option<(i64, i32, bool)> {
        let (profile_hash, _) = identity(Some(ua), asn);
        sqlx::query_as("SELECT id, event_count, is_coordinated FROM campaigns WHERE profile_hash = $1")
            .bind(profile_hash)
            .fetch_optional(db)
            .await
            .unwrap()
    }

    async fn pending_count(db: &PgPool, ua: &str, asn: i64) -> Option<i32> {
        let (profile_hash, _) = identity(Some(ua), asn);
        sqlx::query_scalar("SELECT event_count FROM pending_campaigns WHERE profile_hash = $1")
            .bind(profile_hash)
            .fetch_optional(db)
            .await
            .unwrap()
    }

    /// Below the floor a burst stays pending, and crossing it promotes exactly
    /// once, carrying every event that had been waiting.
    #[tokio::test]
    async fn a_burst_is_promoted_when_it_crosses_the_threshold() {
        let Some(db) = pool().await else { return };
        let (ua, at) = (unique_ua(), Utc::now());

        for expected in 1..MIN_EVENTS {
            ingest(&db, &ua, 64500, at).await;
            assert_eq!(pending_count(&db, &ua, 64500).await, Some(expected as i32));
            assert!(campaign_of(&db, &ua, 64500).await.is_none(), "promoted too early");
        }

        ingest(&db, &ua, 64500, at).await;
        let (campaign_id, count, coordinated) =
            campaign_of(&db, &ua, 64500).await.expect("never promoted");
        assert_eq!(count, MIN_EVENTS as i32);
        assert!(!coordinated, "a single ASN is not coordination");
        // The pending row is gone, and its events came with it.
        assert_eq!(pending_count(&db, &ua, 64500).await, None);

        let linked: i64 =
            sqlx::query_scalar("SELECT count(*) FROM campaign_events WHERE campaign_id = $1")
                .bind(campaign_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(linked, MIN_EVENTS, "the waiting events were not carried over");

        let tagged: i64 =
            sqlx::query_scalar("SELECT count(*) FROM events WHERE campaign_id = $1")
                .bind(campaign_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(tagged, MIN_EVENTS, "events were not tagged with their campaign");
    }

    /// After promotion the campaign exists, so further events take the fast
    /// path and increment it rather than starting a new pending burst.
    #[tokio::test]
    async fn events_after_promotion_join_the_existing_campaign() {
        let Some(db) = pool().await else { return };
        let (ua, at) = (unique_ua(), Utc::now());
        for _ in 0..MIN_EVENTS + 3 {
            ingest(&db, &ua, 64500, at).await;
        }
        let (_, count, _) = campaign_of(&db, &ua, 64500).await.expect("never promoted");
        assert_eq!(count, MIN_EVENTS as i32 + 3);
        assert_eq!(pending_count(&db, &ua, 64500).await, None, "a second burst was started");
    }

    /// THE FEATURE THAT NEVER FIRED IN THE D1 VERSION. One User-Agent promoted
    /// from two ASNs inside one window marks BOTH campaigns coordinated.
    #[tokio::test]
    async fn one_user_agent_from_two_networks_is_coordination() {
        let Some(db) = pool().await else { return };
        let (ua, at) = (unique_ua(), Utc::now());

        for _ in 0..MIN_EVENTS {
            ingest(&db, &ua, 64500, at).await;
        }
        let (_, _, coordinated) = campaign_of(&db, &ua, 64500).await.unwrap();
        assert!(!coordinated, "one network cannot be coordination");

        for _ in 0..MIN_EVENTS {
            ingest(&db, &ua, 64501, at).await;
        }
        // The second promotion marks the group, including the first campaign
        // which was already confirmed.
        assert!(campaign_of(&db, &ua, 64501).await.unwrap().2, "the new campaign is not marked");
        assert!(campaign_of(&db, &ua, 64500).await.unwrap().2, "the earlier campaign is not marked");
    }

    /// The ASN stays part of the identity, so two networks are two campaigns
    /// even though they are recognised as one coordinated group.
    #[tokio::test]
    async fn two_networks_remain_two_campaigns() {
        let Some(db) = pool().await else { return };
        let (ua, at) = (unique_ua(), Utc::now());
        for _ in 0..MIN_EVENTS {
            ingest(&db, &ua, 64500, at).await;
            ingest(&db, &ua, 64501, at).await;
        }
        let first = campaign_of(&db, &ua, 64500).await.unwrap();
        let second = campaign_of(&db, &ua, 64501).await.unwrap();
        assert_ne!(first.0, second.0);
        assert_eq!(first.1, MIN_EVENTS as i32);
        assert_eq!(second.1, MIN_EVENTS as i32);
    }

    /// A window boundary ends a campaign. The identity is bucket-free, so the
    /// next window starts a new pending burst under the SAME profile_hash --
    /// which is exactly what lets the Welford state accumulate across them.
    #[tokio::test]
    async fn a_new_window_starts_a_new_campaign_and_feeds_the_threshold() {
        let Some(db) = pool().await else { return };
        let ua = unique_ua();
        let first_window = Utc::now();
        let second_window = first_window + TimeDelta::minutes(20);

        for _ in 0..MIN_EVENTS {
            ingest(&db, &ua, 64500, first_window).await;
        }
        let (profile_hash, _) = identity(Some(&ua), 64500);
        let (n, mean): (i64, f64) =
            sqlx::query_as("SELECT n, mean FROM campaign_path_stats WHERE profile_hash = $1")
                .bind(&profile_hash)
                .fetch_one(&db)
                .await
                .unwrap();
        // ONE confirmed burst recorded -- the D1 version could never get here,
        // because its stats key contained the bucket and reset every window.
        assert_eq!(n, 1);
        assert!((mean - MIN_EVENTS as f64).abs() < 1e-9, "mean {mean}");

        for _ in 0..MIN_EVENTS {
            ingest(&db, &ua, 64500, second_window).await;
        }
        let campaigns: i64 =
            sqlx::query_scalar("SELECT count(*) FROM campaigns WHERE profile_hash = $1")
                .bind(&profile_hash)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(campaigns, 2, "the second window did not get its own campaign");

        let n: i64 = sqlx::query_scalar("SELECT n FROM campaign_path_stats WHERE profile_hash = $1")
            .bind(&profile_hash)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(n, 2, "the threshold state did not accumulate across windows");
    }

    /// Deleting an event -- which the retention sweep does daily -- must not
    /// leave a link pointing at nothing.
    #[tokio::test]
    async fn retention_deleting_an_event_takes_its_links_with_it() {
        let Some(db) = pool().await else { return };
        let (ua, at) = (unique_ua(), Utc::now());
        let mut ids = Vec::new();
        for _ in 0..MIN_EVENTS {
            ids.push(ingest(&db, &ua, 64500, at).await);
        }
        let (campaign_id, _, _) = campaign_of(&db, &ua, 64500).await.unwrap();

        sqlx::query("DELETE FROM events WHERE id = $1").bind(ids[0]).execute(&db).await.unwrap();
        let linked: i64 =
            sqlx::query_scalar("SELECT count(*) FROM campaign_events WHERE campaign_id = $1")
                .bind(campaign_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(linked, MIN_EVENTS - 1, "campaign_events did not cascade");
    }
}
