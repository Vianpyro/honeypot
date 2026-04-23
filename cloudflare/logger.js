// ============================================================
//  logger.js — Async D1 event logger
// ============================================================

export async function logEvent(meta, env) {
    try {
        await env.DB.prepare(`
      INSERT INTO events (ip, country, asn, ua, method, path, body, username, password, host, service, created_at, as_organization, tls_version, http_protocol, client_tcp_rtt)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
            meta.ip, meta.country, meta.asn, meta.ua,
            meta.method, meta.path, meta.body ?? null,
            meta.username ?? null, meta.password ?? null,
            meta.host ?? null,
            meta.service, meta.created_at,
            meta.as_organization ?? null,
            meta.tls_version ?? null,
            meta.http_protocol ?? null,
            meta.client_tcp_rtt ?? null
        ).run();
    } catch (e) {
        console.error('[honeypot] DB write failed:', e.message);
    }
}
