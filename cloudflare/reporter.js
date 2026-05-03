// ============================================================
//  reporter.js — Nightly AbuseIPDB submission
//
//  Runs at midnight UTC, before the 4am aggregation cron.
//  Reports on events from the previous 24h window.
//  Groups events from the past 24h by IP, skips IPs already
//  reported today, and submits one report per novel IP.
//
//  AbuseIPDB Webmaster tier: 500 reports/day, 1 report/IP/15 min.
//  D1 tracks submissions so re-runs are safe (idempotent).
//
//  Required secrets: ABUSEIPDB_KEY
//  Required binding: DB (D1, shared with honeypot worker)
// ============================================================

const ABUSEIPDB_REPORT_URL = 'https://api.abuseipdb.com/api/v2/report';

// AbuseIPDB category codes
const CAT_BRUTE_FORCE = 18;
const CAT_WEB_APP_ATTACK = 21;
const CAT_PORT_SCAN = 14;

const DAILY_REPORT_CAP = 500;

// IPs that should never be submitted (legitimate scanners, monitoring)
const ALLOWLIST_ASNS = new Set([
    // LeakIX
    14061,
    // Shodan
    20473,
]);

// ── Category selection ───────────────────────────────────────

// Invariant: every service maps to at least one category.
function categoriesFor(services) {
    const cats = new Set();
    for (const svc of services) {
        if (['login', 'wordpress', 'phpmyadmin', 'admin', 'vpn', 'mail'].includes(svc)) {
            cats.add(CAT_BRUTE_FORCE);
        }
        cats.add(CAT_WEB_APP_ATTACK);
        if (['catch-all', 'sensitive', 'infra'].includes(svc)) {
            cats.add(CAT_PORT_SCAN);
        }
    }
    return [...cats];
}

function buildComment(row) {
    const services = row.services.split(',').map(s => s.trim());
    const parts = [
        `Honeypot hit: ${row.event_count} request(s) over ${row.duration_minutes} min.`,
        `Services probed: ${services.join(', ')}.`,
        `ASN: ${row.asn} (${row.as_organization ?? 'unknown'}).`,
    ];
    if (row.submitted_creds) {
        parts.push('Submitted credentials (credential stuffing).');
    }
    if (row.used_encoding) {
        parts.push('Used URL-encoding evasion variants.');
    }
    parts.push('Source: automated honeypot (thevhome.com).');
    return parts.join(' ');
}

// ── Submission ───────────────────────────────────────────────

async function submitIP(ip, categories, comment, apiKey) {
    const body = new URLSearchParams({
        ip,
        categories: categories.join(','),
        comment: comment.slice(0, 1024),
    });
    const res = await fetch(ABUSEIPDB_REPORT_URL, {
        method: 'POST',
        headers: {
            Key: apiKey,
            Accept: 'application/json',
        },
        body,
    });

    if (!res.ok) {
        const text = await res.text();
        throw new Error(`AbuseIPDB ${res.status}: ${text.slice(0, 200)}`);
    }
    return res.json();
}

// ── Main export ──────────────────────────────────────────────

export async function reportToAbuseIPDB(env) {
    if (!env.ABUSEIPDB_KEY) {
        console.warn('[reporter] ABUSEIPDB_KEY not set, skipping');
        return;
    }

    // Aggregate past 24h: one row per IP with attack profile
    const { results: candidates } = await env.DB.prepare(`
        SELECT
            e.ip,
            e.asn,
            e.as_organization,
            COUNT(*)                                    AS event_count,
            GROUP_CONCAT(DISTINCT e.service)            AS services,
            CAST(
              (julianday(MAX(e.created_at)) - julianday(MIN(e.created_at)))
              * 1440 AS INTEGER
            )                                           AS duration_minutes,
            MAX(CASE WHEN e.username IS NOT NULL THEN 1 ELSE 0 END) AS submitted_creds,
            MAX(CASE WHEN e.path LIKE '%25%' OR e.path LIKE '%2e%' OR e.path LIKE '%2f%'
                     THEN 1 ELSE 0 END)                AS used_encoding
        FROM events e
        WHERE e.created_at >= datetime('now', '-1 day')
          AND e.ip != 'unknown'
        GROUP BY e.ip, e.asn, e.as_organization
        HAVING COUNT(*) >= 5
    `).all();

    if (!candidates.length) {
        console.log('[reporter] no candidates for submission');
        return;
    }

    // Filter IPs already submitted today to stay idempotent
    const today = new Date().toISOString().slice(0, 10);
    const { results: alreadyDone } = await env.DB.prepare(`
        SELECT ip FROM abuseipdb_submissions
        WHERE submitted_on = ?
    `).bind(today).all();
    const done = new Set(alreadyDone.map(r => r.ip));

    let submitted = 0;
    let skipped = 0;
    let errors = 0;

    for (const row of candidates) {
        if (submitted >= DAILY_REPORT_CAP) {
            console.warn('[reporter] daily cap reached, stopping');
            break;
        }
        if (done.has(row.ip) || ALLOWLIST_ASNS.has(row.asn)) {
            skipped++;
            continue;
        }

        const services = row.services.split(',').map(s => s.trim());
        const categories = categoriesFor(services);
        const comment = buildComment(row);

        try {
            await submitIP(row.ip, categories, comment, env.ABUSEIPDB_KEY);
            await env.DB.prepare(`
                INSERT OR IGNORE INTO abuseipdb_submissions (ip, submitted_on, event_count, categories)
                VALUES (?, ?, ?, ?)
            `).bind(row.ip, today, row.event_count, categories.join(',')).run();
            submitted++;
        } catch (e) {
            console.error(`[reporter] failed for ${row.ip}:`, e.message);
            errors++;
        }
    }

    console.log(`[reporter] submitted=${submitted} skipped=${skipped} errors=${errors}`);
}
