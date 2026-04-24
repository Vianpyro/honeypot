// ============================================================
//  logger.js — Async D1 event logger
// ============================================================

import { detectCampaign } from './campaigns.js';

export async function logEvent(meta, env) {
    try {
        const result = await env.DB.prepare(`
            INSERT INTO events (ip, country, asn, ua, method, path, query, body, username, password, host, service, created_at, as_organization, tls_version, http_protocol, client_tcp_rtt)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
            meta.ip, meta.country, meta.asn, meta.ua,
            meta.method, meta.path, meta.query ?? null, meta.body ?? null,
            meta.username ?? null, meta.password ?? null,
            meta.host ?? null,
            meta.service, meta.created_at,
            meta.as_organization ?? null,
            meta.tls_version ?? null,
            meta.http_protocol ?? null,
            meta.client_tcp_rtt ?? null
        ).run();

        const eventId = result.meta?.last_row_id ?? result.meta?.lastRowId;
        if (!eventId) {
            console.error('[honeypot] INSERT returned no last_row_id');
            return;
        }
        await detectCampaign(meta, eventId, env);
    } catch (e) {
        console.error('[honeypot] DB write failed:', e.message);
    }
}
