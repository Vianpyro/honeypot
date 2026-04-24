// ============================================================
//  campaigns.js — Real-time campaign detection
//
//  A "campaign" is a burst of probes sharing the same scanner
//  identity: (ua_prefix, asn, 10-minute time bucket).
//
//  Detection pipeline (called from logEvent):
//    1. Derive a fingerprint from UA prefix + ASN + time bucket.
//    2. If a confirmed campaign exists for the fingerprint:
//         increment counts, link event, done.
//    3. Otherwise accumulate into `pending_campaigns`.
//    4. Promote pending -> confirmed when either:
//         - event_count >= adaptive threshold, or
//         - asn_set grows beyond 1 (cross-ASN coordination).
//       On promotion, all pending event_ids are linked/tagged in
//       a single batch and the pending row is removed.
//    5. Welford stats are updated only on promotion, so mean/m2
//       reflect confirmed wave sizes, not running partial counts.
//
//  Adaptive threshold:
//    Welford online mean + variance per fingerprint hash.
//    Threshold = max(MIN_EVENTS, mean + Z_THRESHOLD * stddev).
// ============================================================

const BUCKET_MS = 10 * 60 * 1000;
const UA_PREFIX_LEN = 40;
const Z_THRESHOLD = 2.0;
const MIN_EVENTS = 5;

// Stable fingerprint: UA prefix + ASN + 10-min bucket index.
// Bucket index ensures campaigns don't bleed across time windows.
function buildFingerprint(meta) {
    const uaPrefix = (meta.ua ?? '').slice(0, UA_PREFIX_LEN).trim();
    const asn = meta.asn ?? 0;
    const bucket = Math.floor(Date.now() / BUCKET_MS);
    return `${uaPrefix}|${asn}|${bucket}`;
}

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

        const existing = await env.DB.prepare(
            `SELECT id, ip_set, asn_set, event_count, is_coordinated
             FROM campaigns WHERE path_seq_hash = ?
             ORDER BY last_seen_at DESC LIMIT 1`
        ).bind(hash).first();

        if (existing) {
            return updateConfirmed(existing, meta, eventId, env);
        }

        return accumulatePending(hash, meta, eventId, env);
    } catch (e) {
        console.error('[campaign] detection failed:', e.message);
    }
}

async function updateConfirmed(existing, meta, eventId, env) {
    const ipSet = new Set(JSON.parse(existing.ip_set));
    const asnSet = new Set(JSON.parse(existing.asn_set));
    ipSet.add(meta.ip);
    if (meta.asn) asnSet.add(String(meta.asn));

    const newCount = existing.event_count + 1;
    const isCoordinated = asnSet.size > 1 ? 1 : 0;

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

    await linkAndTag(existing.id, eventId, env);
}

async function accumulatePending(hash, meta, eventId, env) {
    const pending = await env.DB.prepare(
        `SELECT first_seen_at, ip_set, asn_set, event_ids, event_count
         FROM pending_campaigns WHERE path_seq_hash = ?`
    ).bind(hash).first();

    const ipSet = new Set(pending ? JSON.parse(pending.ip_set) : []);
    const asnSet = new Set(pending ? JSON.parse(pending.asn_set) : []);
    const eventIds = pending ? JSON.parse(pending.event_ids) : [];
    ipSet.add(meta.ip);
    if (meta.asn) asnSet.add(String(meta.asn));
    eventIds.push(eventId);

    const newCount = (pending?.event_count ?? 0) + 1;
    const isCoordinated = asnSet.size > 1;
    const firstSeenAt = pending?.first_seen_at ?? meta.created_at;

    const statsRow = await env.DB.prepare(
        `SELECT n, mean, m2 FROM campaign_path_stats WHERE path_seq_hash = ?`
    ).bind(hash).first();
    const stats = statsRow ?? { n: 0, mean: 0, m2: 0 };
    const threshold = Math.max(MIN_EVENTS, stats.mean + Z_THRESHOLD * stddev(stats));

    if (newCount >= threshold || isCoordinated) {
        await promote(hash, {
            firstSeenAt, lastSeenAt: meta.created_at,
            ipSet, asnSet, eventIds,
            eventCount: newCount, isCoordinated: isCoordinated ? 1 : 0,
        }, env);
        await updateStats(hash, newCount, stats, env);
        return;
    }

    await env.DB.prepare(
        `INSERT INTO pending_campaigns
           (path_seq_hash, first_seen_at, last_seen_at,
            ip_set, asn_set, event_ids, event_count)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(path_seq_hash) DO UPDATE SET
           last_seen_at = excluded.last_seen_at,
           ip_set       = excluded.ip_set,
           asn_set      = excluded.asn_set,
           event_ids    = excluded.event_ids,
           event_count  = excluded.event_count`
    ).bind(
        hash, firstSeenAt, meta.created_at,
        JSON.stringify([...ipSet]),
        JSON.stringify([...asnSet]),
        JSON.stringify(eventIds),
        newCount
    ).run();
}

// Promotion is not transactional across the INSERT and the batch:
// if the Worker dies between them, the campaign exists without its
// back-links and the pending row survives. The cron cleanup reaps
// orphaned pending rows; subsequent events take the fast path.
async function promote(hash, data, env) {
    const insert = await env.DB.prepare(
        `INSERT INTO campaigns
           (path_seq_hash, first_seen_at, last_seen_at,
            ip_set, asn_set, event_count, is_coordinated)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(
        hash, data.firstSeenAt, data.lastSeenAt,
        JSON.stringify([...data.ipSet]),
        JSON.stringify([...data.asnSet]),
        data.eventCount, data.isCoordinated
    ).run();

    const campaignId = insert.meta?.last_row_id ?? insert.meta?.lastRowId;
    if (!campaignId) {
        console.error('[campaign] promotion INSERT returned no last_row_id');
        return;
    }

    const stmts = [];
    for (const eid of data.eventIds) {
        stmts.push(env.DB.prepare(
            `INSERT OR IGNORE INTO campaign_events (campaign_id, event_id) VALUES (?, ?)`
        ).bind(campaignId, eid));
        stmts.push(env.DB.prepare(
            `UPDATE events SET campaign_id = ? WHERE id = ?`
        ).bind(campaignId, eid));
    }
    stmts.push(env.DB.prepare(
        `DELETE FROM pending_campaigns WHERE path_seq_hash = ?`
    ).bind(hash));

    await env.DB.batch(stmts);
}

async function linkAndTag(campaignId, eventId, env) {
    await env.DB.batch([
        env.DB.prepare(
            `INSERT OR IGNORE INTO campaign_events (campaign_id, event_id) VALUES (?, ?)`
        ).bind(campaignId, eventId),
        env.DB.prepare(
            `UPDATE events SET campaign_id = ? WHERE id = ?`
        ).bind(campaignId, eventId),
    ]);
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
