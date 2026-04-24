-- ============================================================
--  Migration: campaign detection
--  Run once against your existing D1 database:
--    wrangler d1 execute <your-db-name> --file=migrate_campaigns.sql
--
--  What this does:
--    1. Splits events.path into path (pathname only) + query (search string)
--    2. Adds campaign_id FK on events
--    3. Creates campaigns and campaign_events tables
--    4. Creates campaign_path_stats for adaptive z-score baseline
-- ============================================================

-- ── 1. Extend events ────────────────────────────────────────

-- Separate query string from pathname. Existing rows keep the
-- full original value in path; query stays NULL (acceptable —
-- we only need clean separation for future events).
ALTER TABLE events ADD COLUMN query       TEXT    NULL;
ALTER TABLE events ADD COLUMN campaign_id INTEGER NULL REFERENCES campaigns(id);

CREATE INDEX IF NOT EXISTS idx_events_campaign_id ON events(campaign_id);

-- ── 2. Campaigns ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS campaigns (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  -- SHA-256 prefix of the ordered path sequence (8 paths, pathnames only)
  path_seq_hash    TEXT    NOT NULL,
  first_seen_at    TEXT    NOT NULL,
  last_seen_at     TEXT    NOT NULL,
  -- Distinct IPs and ASNs observed in this campaign (JSON arrays)
  ip_set           TEXT    NOT NULL DEFAULT '[]',
  asn_set          TEXT    NOT NULL DEFAULT '[]',
  event_count      INTEGER NOT NULL DEFAULT 0,
  -- Cross-ASN flag: true when asn_set contains more than one distinct ASN
  is_coordinated   INTEGER NOT NULL DEFAULT 0  -- BOOLEAN (0/1)
);

CREATE INDEX IF NOT EXISTS idx_campaigns_hash        ON campaigns(path_seq_hash);
CREATE INDEX IF NOT EXISTS idx_campaigns_last_seen   ON campaigns(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_campaigns_coordinated ON campaigns(is_coordinated);

-- ── 3. Campaign <-> Event join ───────────────────────────────

CREATE TABLE IF NOT EXISTS campaign_events (
  campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
  event_id    INTEGER NOT NULL REFERENCES events(id),
  PRIMARY KEY (campaign_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_ce_event_id ON campaign_events(event_id);

-- ── 4. Adaptive threshold baseline ──────────────────────────
-- Rolling stats per path_seq_hash, updated on each campaign match.
-- Stores Welford online mean/variance for z-score computation
-- without retaining the full history.

CREATE TABLE IF NOT EXISTS campaign_path_stats (
  path_seq_hash TEXT    PRIMARY KEY,
  n             INTEGER NOT NULL DEFAULT 0,   -- sample count
  mean          REAL    NOT NULL DEFAULT 0.0, -- Welford running mean
  m2            REAL    NOT NULL DEFAULT 0.0  -- Welford running sum of squared diffs
);
