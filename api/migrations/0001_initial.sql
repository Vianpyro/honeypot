-- HoneyLab PostgreSQL schema.
--
-- This migration is intentionally self-contained and safe to run more than
-- once on an empty or partially initialised database.  Production execution
-- will be tracked by SQLx's migration table once the Rust API is added.

CREATE TABLE IF NOT EXISTS campaigns (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  profile_hash TEXT NOT NULL CHECK (length(profile_hash) = 64),
  bucket_start TIMESTAMPTZ NOT NULL,
  first_seen_at TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL,
  event_count INTEGER NOT NULL CHECK (event_count > 0),
  is_coordinated BOOLEAN NOT NULL DEFAULT FALSE,
  CONSTRAINT campaigns_profile_bucket_key UNIQUE (profile_hash, bucket_start),
  CONSTRAINT campaigns_time_order CHECK (last_seen_at >= first_seen_at)
);

CREATE TABLE IF NOT EXISTS events (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ingest_id UUID NOT NULL UNIQUE,
  observed_at TIMESTAMPTZ NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ip INET NOT NULL,
  country CHAR(2),
  asn BIGINT CHECK (asn >= 0),
  as_organization TEXT,
  ua TEXT,
  method TEXT NOT NULL CHECK (method ~ '^[A-Z]+$'),
  path TEXT NOT NULL CHECK (left(path, 1) = '/'),
  query TEXT,
  body TEXT CHECK (char_length(body) <= 2000),
  username TEXT,
  password TEXT,
  host TEXT,
  service TEXT NOT NULL,
  tls_version TEXT,
  http_protocol TEXT,
  client_tcp_rtt INTEGER CHECK (client_tcp_rtt >= 0),
  campaign_id BIGINT REFERENCES campaigns(id) ON DELETE SET NULL,
  CONSTRAINT events_country_format CHECK (country IS NULL OR country ~ '^[A-Z]{2}$')
);

-- One lock row per campaign identity serialises promotion and Welford updates.
CREATE TABLE IF NOT EXISTS campaign_locks (
  profile_hash TEXT NOT NULL CHECK (length(profile_hash) = 64),
  bucket_start TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (profile_hash, bucket_start)
);

CREATE TABLE IF NOT EXISTS pending_campaigns (
  profile_hash TEXT NOT NULL CHECK (length(profile_hash) = 64),
  bucket_start TIMESTAMPTZ NOT NULL,
  first_seen_at TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL,
  event_count INTEGER NOT NULL CHECK (event_count > 0),
  distinct_asn_count INTEGER NOT NULL DEFAULT 0 CHECK (distinct_asn_count >= 0),
  PRIMARY KEY (profile_hash, bucket_start),
  CONSTRAINT pending_campaigns_time_order CHECK (last_seen_at >= first_seen_at)
);

CREATE TABLE IF NOT EXISTS campaign_events (
  campaign_id BIGINT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
  event_id BIGINT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  PRIMARY KEY (campaign_id, event_id),
  CONSTRAINT campaign_events_one_campaign_per_event UNIQUE (event_id)
);

CREATE TABLE IF NOT EXISTS pending_campaign_events (
  profile_hash TEXT NOT NULL,
  bucket_start TIMESTAMPTZ NOT NULL,
  event_id BIGINT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  PRIMARY KEY (profile_hash, bucket_start, event_id),
  CONSTRAINT pending_campaign_events_pending_fk
    FOREIGN KEY (profile_hash, bucket_start)
    REFERENCES pending_campaigns(profile_hash, bucket_start) ON DELETE CASCADE,
  CONSTRAINT pending_campaign_events_one_pending_campaign_per_event UNIQUE (event_id)
);

CREATE TABLE IF NOT EXISTS campaign_path_stats (
  profile_hash TEXT PRIMARY KEY CHECK (length(profile_hash) = 64),
  n BIGINT NOT NULL DEFAULT 0 CHECK (n >= 0),
  mean DOUBLE PRECISION NOT NULL DEFAULT 0 CHECK (mean >= 0),
  m2 DOUBLE PRECISION NOT NULL DEFAULT 0 CHECK (m2 >= 0)
);

CREATE TABLE IF NOT EXISTS stats_daily (
  day DATE NOT NULL,
  dim TEXT NOT NULL CHECK (dim IN (
    'volume', 'country', 'service', 'path', 'asn', 'username', 'tls',
    'protocol', 'campaign_volume'
  )),
  key TEXT NOT NULL,
  extra TEXT,
  count BIGINT NOT NULL CHECK (count >= 0),
  PRIMARY KEY (day, dim, key)
);

CREATE TABLE IF NOT EXISTS abuseipdb_submissions (
  ip INET NOT NULL,
  submitted_on DATE NOT NULL,
  event_count INTEGER NOT NULL CHECK (event_count > 0),
  categories TEXT NOT NULL,
  PRIMARY KEY (ip, submitted_on)
);

CREATE TABLE IF NOT EXISTS job_runs (
  job_name TEXT NOT NULL,
  job_key DATE NOT NULL,
  completed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (job_name, job_key)
);

-- Public and private dashboard queries are time-scoped.  Do not index every
-- captured attribute: daily rollups avoid those broad scans.
CREATE INDEX IF NOT EXISTS idx_events_observed_at_desc
  ON events (observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_ip_observed_at_desc
  ON events (ip, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_service_observed_at_desc
  ON events (service, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_campaign_id
  ON events (campaign_id);
CREATE INDEX IF NOT EXISTS idx_campaigns_last_seen_at_desc
  ON campaigns (last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_stats_daily_dim_day
  ON stats_daily (dim, day);
CREATE INDEX IF NOT EXISTS idx_abuseipdb_submissions_submitted_on
  ON abuseipdb_submissions (submitted_on);
