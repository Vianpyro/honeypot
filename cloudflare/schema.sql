-- ============================================================
--  Honeypot D1 Schema
--  Run once to initialize the database:
--    wrangler d1 execute <your-db-name> --file=cloudflare/schema.sql
--
--  Or paste directly into the Cloudflare D1 Console.
-- ============================================================
 
CREATE TABLE IF NOT EXISTS events (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ip         TEXT    NOT NULL,
  country    TEXT,               -- 2-letter ISO country code (from Cloudflare cf object)
  asn        INTEGER,            -- Autonomous System Number
  ua         TEXT,               -- User-Agent header
  method     TEXT,               -- HTTP method (GET, POST, ...)
  path       TEXT,               -- Request path + query string
  body       TEXT,               -- Raw request body (POST/PUT/PATCH), truncated at 2000 chars
  username   TEXT,               -- Extracted from form or JSON body when present
  password   TEXT,               -- Extracted from form or JSON body when present
  host       TEXT,               -- HTTP Host header (which subdomain was targeted)
  service    TEXT,               -- Matched simulator label (wordpress, api, sensitive, ...)
  created_at TEXT    NOT NULL    -- ISO 8601 timestamp
);
 
-- Indexes for common query patterns in /hp-stats
CREATE INDEX IF NOT EXISTS idx_events_ip         ON events(ip);
CREATE INDEX IF NOT EXISTS idx_events_service    ON events(service);
CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);
CREATE INDEX IF NOT EXISTS idx_events_username   ON events(username);
CREATE INDEX IF NOT EXISTS idx_events_host       ON events(host);
