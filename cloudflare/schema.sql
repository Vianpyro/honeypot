-- ============================================================
--  Honeypot D1 Schema
--  Run once to initialize the database:
--    wrangler d1 execute <your-db-name> --file=cloudflare/schema.sql
--
--  Or paste directly into the Cloudflare D1 Console.
-- ============================================================

CREATE TABLE IF NOT EXISTS events (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  ip              TEXT    NOT NULL,
  country         TEXT,               -- 2-letter ISO country code (from Cloudflare cf object)
  asn             INTEGER,            -- Autonomous System Number
  ua              TEXT,               -- User-Agent header
  method          TEXT,               -- HTTP method (GET, POST, ...)
  path            TEXT,               -- Request pathname only (no query string)
  query           TEXT,               -- Query string (e.g. ?foo=bar), NULL when absent
  body            TEXT,               -- Raw request body (POST/PUT/PATCH), truncated at 2000 chars
  username        TEXT,               -- Extracted from form or JSON body when present
  password        TEXT,               -- Extracted from form or JSON body when present
  host            TEXT,               -- HTTP Host header (which subdomain was targeted)
  service         TEXT,               -- Matched simulator label (wordpress, api, sensitive, ...)
  created_at      TEXT    NOT NULL,   -- ISO 8601 timestamp
  exported_at     TEXT    NULL,       -- Set when row is included in an R2 archive
  tls_version     TEXT,               -- e.g. TLSv1.3
  http_protocol   TEXT,               -- e.g. HTTP/2, HTTP/3
  as_organization TEXT,               -- ASN org name (complements asn number)
  client_tcp_rtt  INTEGER,            -- TCP round-trip time in ms (bot framework fingerprint)
  campaign_id     INTEGER NULL REFERENCES campaigns(id)
);

CREATE INDEX IF NOT EXISTS idx_events_ip              ON events(ip);
CREATE INDEX IF NOT EXISTS idx_events_service         ON events(service);
CREATE INDEX IF NOT EXISTS idx_events_created_at      ON events(created_at);
CREATE INDEX IF NOT EXISTS idx_events_username        ON events(username);
CREATE INDEX IF NOT EXISTS idx_events_host            ON events(host);
CREATE INDEX IF NOT EXISTS idx_events_as_organization ON events(as_organization);
CREATE INDEX IF NOT EXISTS idx_events_tls_version     ON events(tls_version);
CREATE INDEX IF NOT EXISTS idx_events_campaign_id     ON events(campaign_id);

-- ── Campaigns ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS campaigns (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  -- SHA-256 prefix of the ordered path sequence (SEQ_LEN paths, pathnames only)
  path_seq_hash  TEXT    NOT NULL,
  first_seen_at  TEXT    NOT NULL,
  last_seen_at   TEXT    NOT NULL,
  -- Distinct IPs and ASNs observed in this campaign (JSON arrays)
  ip_set         TEXT    NOT NULL DEFAULT '[]',
  asn_set        TEXT    NOT NULL DEFAULT '[]',
  event_count    INTEGER NOT NULL DEFAULT 0,
  -- 1 when asn_set contains more than one distinct ASN
  is_coordinated INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_campaigns_hash        ON campaigns(path_seq_hash);
CREATE INDEX IF NOT EXISTS idx_campaigns_last_seen   ON campaigns(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_campaigns_coordinated ON campaigns(is_coordinated);

-- ── Campaign <-> Event join ───────────────────────────────────

CREATE TABLE IF NOT EXISTS campaign_events (
  campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
  event_id    INTEGER NOT NULL REFERENCES events(id),
  PRIMARY KEY (campaign_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_ce_event_id ON campaign_events(event_id);

-- ── Adaptive threshold baseline ──────────────────────────────
-- Welford online mean/variance per path_seq_hash.
-- Updated on each campaign match; never stores raw history.

CREATE TABLE IF NOT EXISTS campaign_path_stats (
  path_seq_hash TEXT PRIMARY KEY,
  n             INTEGER NOT NULL DEFAULT 0,
  mean          REAL    NOT NULL DEFAULT 0.0,
  m2            REAL    NOT NULL DEFAULT 0.0  -- running sum of squared diffs
);

-- -- Pending campaigns -----------------------------------------
-- Fingerprints that have not yet crossed the confirmation threshold.
-- Rows are promoted into `campaigns` (and deleted here) once
-- event_count >= threshold OR asn_set.size > 1.

CREATE TABLE IF NOT EXISTS pending_campaigns (
  path_seq_hash TEXT    PRIMARY KEY,
  first_seen_at TEXT    NOT NULL,
  last_seen_at  TEXT    NOT NULL,
  ip_set        TEXT    NOT NULL DEFAULT '[]',
  asn_set       TEXT    NOT NULL DEFAULT '[]',
  event_ids     TEXT    NOT NULL DEFAULT '[]',
  event_count   INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_pending_last_seen ON pending_campaigns(last_seen_at);

-- -- Daily rollups -------------------------------------------
-- Pre-aggregated counts per (day, dimension, key). Written by
-- the 4am cron for the previous day; backfilled one-shot from
-- historical events. All public stats queries read from here.

CREATE TABLE IF NOT EXISTS stats_daily (
  day   TEXT    NOT NULL,   -- YYYY-MM-DD UTC
  dim   TEXT    NOT NULL,   -- volume|country|service|path|asn|username|tls|protocol|campaign_volume
  key   TEXT    NOT NULL,   -- dimension value; '' for volume/campaign_volume
  extra TEXT,               -- side-channel (asn -> as_organization)
  count INTEGER NOT NULL,
  PRIMARY KEY (day, dim, key)
);

CREATE INDEX IF NOT EXISTS idx_stats_daily_dim_day ON stats_daily(dim, day);

CREATE TABLE IF NOT EXISTS abuseipdb_submissions (
  ip           TEXT    NOT NULL,
  submitted_on TEXT    NOT NULL,   -- YYYY-MM-DD UTC
  event_count  INTEGER NOT NULL,
  categories   TEXT    NOT NULL,   -- comma-separated AbuseIPDB category codes
  PRIMARY KEY (ip, submitted_on)
);

CREATE INDEX IF NOT EXISTS idx_abuseipdb_submitted_on ON abuseipdb_submissions(submitted_on);
