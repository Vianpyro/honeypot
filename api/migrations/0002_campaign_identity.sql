-- Campaign identity, made explicit.
--
-- 0001 described the shape but not what goes in it, and the Worker's D1 version
-- that this replaces had two features that could never fire:
--
--   1. `is_coordinated` was computed from a set of ASNs collected under a
--      fingerprint that ALREADY CONTAINED THE ASN. Every event under one
--      fingerprint therefore shared one ASN, the set never grew past a single
--      element, and cross-ASN coordination -- the interesting signal -- was
--      dead by construction.
--
--   2. The adaptive Welford threshold was keyed on a hash that CONTAINED THE
--      TIME BUCKET. Every ten minutes produced a new key, so `n` never left
--      zero and `mean + 2*stddev` was always 0. The threshold was permanently
--      MIN_EVENTS, and had been since it was written.
--
-- Both are fixed by separating three things the fingerprint had fused:
--
--   profile_hash  sha256(ua_prefix|asn)  -- the scanner identity, NO bucket,
--                                           so Welford stats accumulate across
--                                           windows and the threshold adapts
--   bucket_start  its own column         -- already unique with profile_hash
--   ua_hash       sha256(ua_prefix)      -- the identity WITHOUT the ASN, which
--                                           is what makes coordination visible

-- The ASN stays part of the campaign identity, so one very common User-Agent
-- cannot merge unrelated scanners into a single campaign. Coordination is
-- detected separately, over `ua_hash`, which is why that column exists.
ALTER TABLE campaigns
  ADD COLUMN IF NOT EXISTS ua_hash TEXT,
  ADD COLUMN IF NOT EXISTS asn BIGINT;

-- Backfill is a no-op: nothing has ever written to this table. The columns are
-- left nullable rather than NOT NULL for exactly that reason -- a constraint
-- that has never been tested against real rows is a deployment hazard, and the
-- writer sets them unconditionally.
CREATE INDEX IF NOT EXISTS idx_campaigns_ua_hash_bucket
  ON campaigns (ua_hash, bucket_start);

-- `distinct_asn_count` is dropped, not kept and ignored. With the ASN inside
-- the identity it can only ever be 1, and a column that structurally cannot
-- vary is a lie that the next reader has to disprove for themselves.
ALTER TABLE pending_campaigns DROP COLUMN IF EXISTS distinct_asn_count;

-- Promotion reads the pending row, writes a campaign, moves the links and
-- deletes the pending row. Two concurrent ingests for one identity would
-- otherwise both promote, producing two campaigns for the same
-- (profile_hash, bucket_start) -- or one failing on the unique constraint and
-- losing its event's link.
--
-- 0001 created `campaign_locks` for this and said so; this is the comment that
-- says how it is used. A row per identity is inserted on first sight and then
-- taken FOR UPDATE, so the whole detect-and-promote sequence is serialised per
-- scanner and per window, and not globally.
COMMENT ON TABLE campaign_locks IS
  'One row per (profile_hash, bucket_start). Taken FOR UPDATE to serialise '
  'campaign promotion and the Welford update against concurrent ingests.';
