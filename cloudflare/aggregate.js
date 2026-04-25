// ============================================================
//  aggregate.js -- Daily rollup into stats_daily
//
//  Called by the 4am cron for the previous UTC day.
//  Idempotent: DELETE + INSERT lets the same day be re-run
//  (cron retry, manual replay) without duplicating counts.
// ============================================================

export function yesterdayUTC() {
    return new Date(Date.now() - 86400_000).toISOString().slice(0, 10);
}

export async function aggregateDay(day, env) {
    try {
        await env.DB.batch([
            env.DB.prepare(`DELETE FROM stats_daily WHERE day = ?`).bind(day),

            env.DB.prepare(
                `INSERT INTO stats_daily (day, dim, key, count)
                 SELECT ?, 'volume', '', COUNT(*)
                 FROM events WHERE date(created_at) = ?`
            ).bind(day, day),

            env.DB.prepare(
                `INSERT INTO stats_daily (day, dim, key, count)
                 SELECT ?, 'country', country, COUNT(*)
                 FROM events
                 WHERE date(created_at) = ? AND country IS NOT NULL
                 GROUP BY country`
            ).bind(day, day),

            env.DB.prepare(
                `INSERT INTO stats_daily (day, dim, key, count)
                 SELECT ?, 'service', service, COUNT(*)
                 FROM events
                 WHERE date(created_at) = ?
                 GROUP BY service`
            ).bind(day, day),

            env.DB.prepare(
                `INSERT INTO stats_daily (day, dim, key, count)
                 SELECT ?, 'path', path, COUNT(*)
                 FROM events
                 WHERE date(created_at) = ?
                 GROUP BY path`
            ).bind(day, day),

            env.DB.prepare(
                `INSERT INTO stats_daily (day, dim, key, extra, count)
                 SELECT ?, 'asn', CAST(asn AS TEXT), MAX(as_organization), COUNT(*)
                 FROM events
                 WHERE date(created_at) = ? AND asn IS NOT NULL
                 GROUP BY asn`
            ).bind(day, day),

            env.DB.prepare(
                `INSERT INTO stats_daily (day, dim, key, count)
                 SELECT ?, 'username', username, COUNT(*)
                 FROM events
                 WHERE date(created_at) = ? AND username IS NOT NULL
                 GROUP BY username`
            ).bind(day, day),

            env.DB.prepare(
                `INSERT INTO stats_daily (day, dim, key, count)
                 SELECT ?, 'tls', tls_version, COUNT(*)
                 FROM events
                 WHERE date(created_at) = ? AND tls_version IS NOT NULL
                 GROUP BY tls_version`
            ).bind(day, day),

            env.DB.prepare(
                `INSERT INTO stats_daily (day, dim, key, count)
                 SELECT ?, 'protocol', http_protocol, COUNT(*)
                 FROM events
                 WHERE date(created_at) = ? AND http_protocol IS NOT NULL
                 GROUP BY http_protocol`
            ).bind(day, day),

            env.DB.prepare(
                `INSERT INTO stats_daily (day, dim, key, count)
                 SELECT ?, 'campaign_volume', '', COUNT(*)
                 FROM campaigns WHERE date(first_seen_at) = ?`
            ).bind(day, day),
        ]);
        console.log(`[aggregate] day=${day} rolled up`);
    } catch (e) {
        console.error(`[aggregate] day=${day} failed:`, e.message);
    }
}
