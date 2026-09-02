// ============================================================
//  logger.js — Async D1 event logger
// ============================================================

import { detectCampaign } from './campaigns.js';
import { sendEvent } from './ingest.js';

export async function logEvent(meta, env) {
    // DUAL WRITE, D1 FIRST AND FOREMOST.
    //
    // Started here and awaited at the bottom, so the request to the PostgreSQL
    // API overlaps the D1 round-trips instead of following them: the whole of
    // logEvent still costs about what it did. `sendEvent` never throws and
    // never rejects, so nothing below has to guard against it, and it cannot
    // become an unhandled rejection in a request already being served.
    //
    // It is inert until the Worker has the VPC binding and the signing secret
    // (see ingest.js), so deploying this changes nothing on its own.
    //
    // WHY BOTH, FOR NOW: D1 stays the source of truth while the new path proves
    // itself against real traffic. Workers VPC is Beta and the tunnel is new;
    // neither is something to put an irreplaceable dataset behind on day one.
    // The statuses this returns are the failure rate that decides the cutover.
    const forwarded = sendEvent(meta, env);

    await writeToD1(meta, env);

    // Awaited, not abandoned: `waitUntil` ends when this function returns, and
    // a fetch still in flight at that moment is a lost event.
    await forwarded;
}

async function writeToD1(meta, env) {
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
            // Local to writeToD1 now, so it no longer skips the await on the
            // PostgreSQL delivery in the caller.
            console.error('[honeypot] INSERT returned no last_row_id');
            return;
        }
        await detectCampaign(meta, eventId, env);
    } catch (e) {
        console.error('[honeypot] DB write failed:', e.message);
    }
}
