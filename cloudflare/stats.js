// ============================================================
//  stats.js — /stats/api, proxied to the PostgreSQL API
// ============================================================
//
// This file used to hold ~200 lines of SQL against D1. All of it now lives in
// the API (api/src/stats.rs), reached through the Workers VPC binding, and what
// is left here is what genuinely belongs at the edge: CORS, the admin-token
// check, and the response cache.
//
// THE TOKEN CHECK STAYS IN THE WORKER. It is where ADMIN_SECRET already is, and
// where the public/private decision has always been made. The API is told the
// answer with a token of its own -- not with a query parameter, so that a
// future caller who is not this Worker cannot simply ask for the private scope.

import { json } from './helpers.js';

const CORS_ORIGINS = new Set([
    'https://vianpyro.github.io',
]);

const DEFAULT_DAYS = 30;
const MAX_DAYS = 100;

function corsHeaders(origin, isPrivate) {
    if (!isPrivate) {
        return {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, OPTIONS',
        };
    }
    const allowed = CORS_ORIGINS.has(origin) ? origin : null;
    if (!allowed) return {};
    return {
        'Access-Control-Allow-Origin': allowed,
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'X-Admin-Secret',
        'Vary': 'Origin',
    };
}

export async function statsApiHandler(request, env, isPrivate) {
    const origin = request.headers.get('Origin') ?? '';
    const cors = corsHeaders(origin, isPrivate);

    if (request.method === 'OPTIONS') {
        return new Response(null, { status: 204, headers: cors });
    }

    const url = new URL(request.url);
    const days = Math.min(parseInt(url.searchParams.get('days') ?? String(DEFAULT_DAYS)), MAX_DAYS);
    const limit = Math.min(parseInt(url.searchParams.get('limit') ?? '100'), 1000);

    // Unchanged from the D1 version: a 6-hour bucket in the key, so the cached
    // entry rolls over on its own rather than relying on TTL alone.
    const bucket = Math.floor(Date.now() / 21_600_000);
    const cacheKey = `stats-${isPrivate ? 'priv' : 'pub'}-${days}-${bucket}`;
    const cache = caches.default;
    const cacheUrl = new URL(`https://cache.internal/${cacheKey}`);

    const cached = await cache.match(cacheUrl);
    if (cached) {
        return json(await cached.json(), 200, cors);
    }

    if (!env.HONEYPOT_API) {
        console.error('[stats] HONEYPOT_API binding is missing');
        return json({ error: 'stats unavailable' }, 503, cors);
    }

    // The private scope is requested with a header the API compares in constant
    // time, NOT with a query parameter: a parameter would make the private data
    // one URL away for anything that could reach the service.
    const headers = {};
    if (isPrivate) {
        if (!env.HONEYPOT_STATS_TOKEN) {
            console.error('[stats] HONEYPOT_STATS_TOKEN is missing, serving public data');
        } else {
            headers['X-Honeypot-Stats-Token'] = env.HONEYPOT_STATS_TOKEN;
        }
    }

    let payload;
    try {
        // The hostname is ignored by the VPC binding, which routes to the
        // service's configured host and port; the path is not.
        const response = await env.HONEYPOT_API.fetch(
            `http://honeypot-api/v1/stats?days=${days}&limit=${limit}`,
            { headers },
        );
        if (!response.ok) {
            console.error(`[stats] API returned ${response.status}`);
            return json({ error: 'stats unavailable' }, 503, cors);
        }
        payload = await response.json();
    } catch (e) {
        console.error('[stats] API unreachable:', e.message);
        return json({ error: 'stats unavailable' }, 503, cors);
    }

    const ttl = isPrivate ? 120 : 21600;
    await cache.put(
        cacheUrl,
        new Response(JSON.stringify(payload), {
            headers: { 'Content-Type': 'application/json', 'Cache-Control': `s-maxage=${ttl}` },
        }),
    );

    return json(payload, 200, cors);
}
