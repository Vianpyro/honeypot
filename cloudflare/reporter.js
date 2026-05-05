// ============================================================
//  reporter.js — Nightly AbuseIPDB bulk submission
//
//  Runs at midnight UTC (before the 4am aggregation cron).
//  Aggregates events from the past 48h into a single CSV and
//  submits via /api/v2/bulk-report (1 call, up to 10 000 IPs).
//
//  AbuseIPDB Webmaster tier: 10 bulk-report calls/day (10k IPs each).
//  D1 tracks submissions per IP per day -- re-runs are idempotent.
//
//  Required secrets: ABUSEIPDB_KEY
//  Required binding: DB (D1, shared with honeypot worker)
// ============================================================

const ABUSEIPDB_BULK_URL = 'https://api.abuseipdb.com/api/v2/bulk-report';

const CAT_BAD_WEB_BOT = 19;
const CAT_BRUTE_FORCE = 18;
const CAT_HACKING = 15;
const CAT_PORT_SCAN = 14;
const CAT_WEB_APP_ATTACK = 21;

// Legitimate scanners -- never submitted.
const ALLOWLIST_ASNS = new Set([
    13335,  // Cloudflare
    132892, // Cloudflare
    14061,  // DigitalOcean / LeakIX
    20473,  // Shodan (Vultr)
    398705, // Censys
    // 396982, // Google Cloud (GCP) -- includes some noisy IPs, but also some legit ones, so left out for now
    15169,  // Google
]);

// -- Helpers --------------------------------------------------

function categoriesFor(servicesStr) {
    const cats = new Set([CAT_WEB_APP_ATTACK, CAT_BAD_WEB_BOT]);
    for (const svc of servicesStr.split(',')) {
        if (['login', 'wordpress', 'phpmyadmin', 'admin', 'vpn', 'mail'].includes(svc.trim())) {
            cats.add(CAT_BRUTE_FORCE);
        }
        if (['catch-all', 'sensitive', 'infra'].includes(svc.trim())) {
            cats.add(CAT_PORT_SCAN);
        }
        if (['sensitive', 'infra', 'graphql', 'springboot', 'api'].includes(svc.trim())) {
            cats.add(CAT_HACKING);
        }
    }
    return [...cats];
}

function buildComment(row) {
    const parts = [
        `Honeypot: ${row.event_count} request(s) in ${row.duration_minutes ?? 0} min.`,
        `Paths: ${row.paths?.split(',').slice(0, 5).join(', ')}.`,
        `Method(s): ${row.methods}.`,
        row.ua ? `UA: ${row.ua.slice(0, 80)}.` : null,
        `ASN: ${row.asn} (${row.as_organization ?? 'unknown'}).`,
    ];
    if (row.submitted_creds) parts.push('Credential stuffing observed.');
    if (row.used_encoding) parts.push('URL-encoding WAF evasion detected.');
    return parts.filter(Boolean).join(' ').slice(0, 1024);
}

// Quotes the field if it contains a comma or double-quote.
function csvField(value) {
    const str = String(value ?? '');
    return str.includes(',') || str.includes('"')
        ? `"${str.replace(/"/g, '""')}"`
        : str;
}

// -- CSV builder ----------------------------------------------

// Returns { csv: string, rows: Array<{ip, categories, event_count}> }.
// Invariant: one row per IP, deduplicated against `alreadyDone`.
function buildCSV(candidates, alreadyDone) {
    const rows = [];
    const lines = ['IP,Categories,ReportDate,Comment'];

    for (const row of candidates) {
        if (alreadyDone.has(row.ip) || ALLOWLIST_ASNS.has(row.asn)) continue;

        const cats = categoriesFor(row.services);
        lines.push([
            csvField(row.ip),
            csvField(cats.join(',')),
            csvField(row.first_seen_at),
            csvField(buildComment(row)),
        ].join(','));

        rows.push({ ip: row.ip, categories: cats.join(','), event_count: row.event_count });
    }

    return { csv: lines.join('\n'), rows };
}

// -- Submission -----------------------------------------------

async function submitBulk(csvContent, apiKey) {
    const form = new FormData();
    form.append('csv', new Blob([csvContent], { type: 'text/csv' }), 'report.csv');

    const res = await fetch(ABUSEIPDB_BULK_URL, {
        method: 'POST',
        headers: {
            Key: apiKey,
            Accept: 'application/json',
        },
        body: form,
    });

    if (!res.ok) {
        const text = await res.text();
        throw new Error(`AbuseIPDB ${res.status}: ${text.slice(0, 200)}`);
    }
    return res.json();
}

async function recordSubmissions(env, rows, today) {
    if (!rows.length) return;
    await env.DB.batch(rows.map(r =>
        env.DB.prepare(
            `INSERT OR IGNORE INTO abuseipdb_submissions (ip, submitted_on, event_count, categories)
             VALUES (?, ?, ?, ?)`
        ).bind(r.ip, today, r.event_count, r.categories)
    ));
}

// -- Main export ----------------------------------------------

export async function reportToAbuseIPDB(env) {
    if (!env.ABUSEIPDB_KEY) {
        console.warn('[reporter] ABUSEIPDB_KEY not set, skipping');
        return;
    }

    const { results: candidates } = await env.DB.prepare(`
        SELECT
            e.ip,
            e.asn,
            e.as_organization,
            COUNT(*)                                    AS event_count,
            GROUP_CONCAT(DISTINCT e.service)            AS services,
            MIN(e.created_at)                           AS first_seen_at,
            GROUP_CONCAT(DISTINCT e.path)               AS paths,
            MAX(e.ua)                                   AS ua,
            GROUP_CONCAT(DISTINCT e.method)             AS methods,
            CAST(
                (julianday(MAX(e.created_at)) - julianday(MIN(e.created_at)))
                * 1440 AS INTEGER
            )                                           AS duration_minutes,
            MAX(CASE WHEN e.username IS NOT NULL THEN 1 ELSE 0 END) AS submitted_creds,
            MAX(CASE WHEN e.path LIKE '%25%' OR e.path LIKE '%2e%' OR e.path LIKE '%2f%'
                     THEN 1 ELSE 0 END)                AS used_encoding
        FROM events e
        WHERE e.created_at >= datetime('now', '-2 days')
          AND e.ip != 'unknown'
        GROUP BY e.ip, e.asn, e.as_organization
        HAVING COUNT(*) >= 5
    `).all();

    if (!candidates.length) {
        console.log('[reporter] no candidates');
        return;
    }

    const today = new Date().toISOString().slice(0, 10);
    const { results: done } = await env.DB.prepare(
        `SELECT ip FROM abuseipdb_submissions WHERE submitted_on = ?`
    ).bind(today).all();
    const alreadyDone = new Set(done.map(r => r.ip));

    const { csv, rows } = buildCSV(candidates, alreadyDone);
    if (!rows.length) {
        console.log('[reporter] all candidates already submitted today');
        return;
    }

    try {
        const result = await submitBulk(csv, env.ABUSEIPDB_KEY);
        const saved = result?.data?.savedReports ?? 0;
        const invalid = result?.data?.invalidReports ?? [];
        console.log(`[reporter] saved=${saved} invalid=${invalid.length} total=${rows.length}`);
        if (invalid.length) {
            console.warn('[reporter] invalid reports:', JSON.stringify(invalid));
        }
        await recordSubmissions(env, rows, today);
    } catch (e) {
        console.error('[reporter] bulk submission failed:', e.message);
    }
}
