// ============================================================
//  campaigns.js — Real-time campaign detection
//
//  A "campaign" is a burst of probes sharing the same scanner
//  identity: (ua_prefix, asn, 10-minute time bucket).
//
//  Detection pipeline (called from logEvent):
//    1. Derive a fingerprint from UA prefix + ASN + time bucket.
//    2. Look for an active campaign with that fingerprint.
//    3. If found: update ip_set/asn_set, increment count, link event.
//    4. If not found and event count >= threshold: create campaign.
//    5. Update the Welford baseline for adaptive thresholding.
//
//  Adaptive threshold:
//    Welford online algorithm maintains running mean + variance per
//    fingerprint without storing history. Threshold = mean + 2*stddev,
//    with a hard floor of MIN_EVENTS. Stabilises after ~14 days.
//
//  Cross-ASN coordination:
//    Detected when a campaign's asn_set grows beyond 1 — i.e. the
//    same UA fingerprint appears from multiple ASNs (e.g. LeakIX
//    distributing scans across DigitalOcean nodes).
// ============================================================

// Time bucket size in ms. Two events in the same bucket with the
// same fingerprint are considered part of the same campaign wave.
const BUCKET_MS = 10 * 60 * 1000; // 10 minutes

// UA prefix length for fingerprinting. Captures scanner identity
// (e.g. "Mozilla/5.0 (l9scan/2.0") without per-request variance.
const UA_PREFIX_LEN = 40;

// z-score multiplier for adaptive threshold.
const Z_THRESHOLD = 2.0;

// Hard floor: never confirm a campaign below this event count.
const MIN_EVENTS = 5;

// ── Helpers ──────────────────────────────────────────────────

// Stable fingerprint: UA prefix + ASN + 10-min bucket index.
// Bucket index ensures campaigns don't bleed across time windows.
function buildFingerprint(meta) {
    const uaPrefix = (meta.ua ?? '').slice(0, UA_PREFIX_LEN).trim();
    const asn = meta.asn ?? 0;
    const bucket = Math.floor(Date.now() / BUCKET_MS);
    return `${uaPrefix}|${asn}|${bucket}`;
}

// SHA-256 of the fingerprint string -> 16-char hex prefix.
async function hashFingerprint(fingerprint) {
    const buf = await crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode(fingerprint)
    );
    return Array.from(new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
        .slice(0, 16);
}

// Welford online update -> { n, mean, m2 }.
// Invariant: m2 / (n-1) = sample variance for n >= 2.
function welfordUpdate({ n, mean, m2 }, value) {
    const newN = n + 1;
    const delta = value - mean;
    const newMean = mean + delta / newN;
    const newM2 = m2 + delta * (value - newMean);
    return { n: newN, mean: newMean, m2: newM2 };
}

function stddev({ n, m2 }) {
    return n < 2 ? 0 : Math.sqrt(m2 / (n - 1));
}

// ── Core detection ───────────────────────────────────────────

export async function detectCampaign(meta, eventId, env) {
    try {
        const fingerprint = buildFingerprint(meta);
        const hash = await hashFingerprint(fingerprint);

        const statsRow = await env.DB.prepare(
            `SELECT n, mean, m2 FROM campaign_path_stats WHERE path_seq_hash = ?`
        ).bind(hash).first();

        const stats = statsRow ?? { n: 0, mean: 0, m2: 0 };
        const sd = stddev(stats);
        const threshold = Math.max(MIN_EVENTS, stats.mean + Z_THRESHOLD * sd);

        const existing = await env.DB.prepare(
            `SELECT id, ip_set, asn_set, event_count, is_coordinated
             FROM campaigns WHERE path_seq_hash = ?
             ORDER BY last_seen_at DESC LIMIT 1`
        ).bind(hash).first();

        if (existing) {
            const ipSet = new Set(JSON.parse(existing.ip_set));
            const asnSet = new Set(JSON.parse(existing.asn_set));
            ipSet.add(meta.ip);
            if (meta.asn) asnSet.add(String(meta.asn));

            const newCount = existing.event_count + 1;
            const isCoordinated = asnSet.size > 1 ? 1 : 0;

            const belowThreshold = newCount < threshold;
            const notCoordinated = !existing.is_coordinated && !isCoordinated;
            if (belowThreshold && notCoordinated) {
                await updateStats(hash, newCount, stats, env);
                return;
            }

            await env.DB.prepare(
                `UPDATE campaigns
                 SET last_seen_at = ?, ip_set = ?, asn_set = ?,
                     event_count = ?, is_coordinated = ?
                 WHERE id = ?`
            ).bind(
                meta.created_at,
                JSON.stringify([...ipSet]),
                JSON.stringify([...asnSet]),
                newCount, isCoordinated,
                existing.id
            ).run();

            await linkEvent(existing.id, eventId, env);
            await tagEvent(eventId, existing.id, env);
            await updateStats(hash, newCount, stats, env);

        } else {
            const isCoordinated = 0;

            const result = await env.DB.prepare(
                `INSERT INTO campaigns
                   (path_seq_hash, first_seen_at, last_seen_at,
                    ip_set, asn_set, event_count, is_coordinated)
                 VALUES (?, ?, ?, ?, ?, 1, ?)`
            ).bind(
                hash, meta.created_at, meta.created_at,
                JSON.stringify([meta.ip]),
                JSON.stringify(meta.asn ? [String(meta.asn)] : []),
                isCoordinated
            ).run();

            const campaignId = result.meta?.last_row_id ?? result.meta?.lastRowId;
            if (!campaignId) {
                console.error('[campaign] INSERT returned no last_row_id');
                return;
            }

            await linkEvent(campaignId, eventId, env);
            await tagEvent(eventId, campaignId, env);
            await updateStats(hash, 1, stats, env);
        }
    } catch (e) {
        console.error('[campaign] detection failed:', e.message);
    }
}

async function linkEvent(campaignId, eventId, env) {
    await env.DB.prepare(
        `INSERT OR IGNORE INTO campaign_events (campaign_id, event_id) VALUES (?, ?)`
    ).bind(campaignId, eventId).run();
}

async function tagEvent(eventId, campaignId, env) {
    await env.DB.prepare(
        `UPDATE events SET campaign_id = ? WHERE id = ?`
    ).bind(campaignId, eventId).run();
}

async function updateStats(hash, newValue, current, env) {
    const updated = welfordUpdate(current, newValue);
    await env.DB.prepare(
        `INSERT INTO campaign_path_stats (path_seq_hash, n, mean, m2)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(path_seq_hash) DO UPDATE SET
           n    = excluded.n,
           mean = excluded.mean,
           m2   = excluded.m2`
    ).bind(hash, updated.n, updated.mean, updated.m2).run();
}
