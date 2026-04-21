// ============================================================
//  logger.js — Async D1 event logger
//  Public — safe to publish
// ============================================================

export async function logEvent(meta, env) {
    try {
        await env.DB.prepare(`
      INSERT INTO events (ip, country, asn, ua, method, path, body, username, password, host, service, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
            meta.ip, meta.country, meta.asn, meta.ua,
            meta.method, meta.path, meta.body ?? null,
            meta.username ?? null, meta.password ?? null,
            meta.host ?? null,
            meta.service, meta.created_at,
        ).run();
    } catch (e) {
        console.error('[honeypot] DB write failed:', e.message);
    }
}
