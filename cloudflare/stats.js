// ============================================================
//  stats.js — /hp-stats (private) + /stats/api (public + private)
// ============================================================

import { json } from './helpers.js';

const CORS_ORIGINS = new Set([
    'https://vianpyro.github.io',
]);

const DEFAULT_DAYS = 90;
const MAX_DAYS = 365;

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

// ── Legacy private endpoint (kept for backward compat) ──────
export async function statsHandler(env, url) {
    const limit = Math.min(parseInt(url.searchParams.get('limit') ?? '50'), 500);

    const [recent, topIPs, topServices, topPaths, topCreds, topHosts] = await Promise.all([
        env.DB.prepare('SELECT ip, country, host, asn, method, path, service, username, password, ua, created_at FROM events ORDER BY created_at DESC LIMIT ?').bind(limit).all(),
        env.DB.prepare('SELECT ip, country, COUNT(*) c FROM events GROUP BY ip ORDER BY c DESC LIMIT 20').all(),
        env.DB.prepare('SELECT service, COUNT(*) c FROM events GROUP BY service ORDER BY c DESC').all(),
        env.DB.prepare('SELECT path, COUNT(*) c FROM events GROUP BY path ORDER BY c DESC LIMIT 20').all(),
        env.DB.prepare("SELECT username, password, COUNT(*) c FROM events WHERE username IS NOT NULL GROUP BY username, password ORDER BY c DESC LIMIT 50").all(),
        env.DB.prepare('SELECT host, COUNT(*) c FROM events GROUP BY host ORDER BY c DESC').all(),
    ]);

    return json({
        recent: recent.results,
        top_ips: topIPs.results,
        top_services: topServices.results,
        top_paths: topPaths.results,
        top_creds: topCreds.results,
        top_hosts: topHosts.results,
    });
}

// ── Public/private stats API with caching ───────────────────
export async function statsApiHandler(request, env, isPrivate) {
    const origin = request.headers.get('Origin') ?? '';
    const cors = corsHeaders(origin, isPrivate);

    if (request.method === 'OPTIONS') {
        return new Response(null, { status: 204, headers: cors });
    }

    const url = new URL(request.url);
    const days = Math.min(parseInt(url.searchParams.get('days') ?? String(DEFAULT_DAYS)), MAX_DAYS);
    const cacheKey = `stats-${isPrivate ? 'priv' : 'pub'}-${days}`;

    // Cache API — TTL 10 min for public, 2 min for private
    const cache = caches.default;
    const cacheUrl = new URL(`https://cache.internal/${cacheKey}`);
    const cached = await cache.match(cacheUrl);
    if (cached) {
        const body = await cached.json();
        return json(body, 200, cors);
    }

    const interval = `-${days} days`;

    const publicQueries = [
        // Daily volume
        env.DB.prepare(
            `SELECT date(created_at) d, COUNT(*) c FROM events WHERE created_at >= datetime('now', ?) AND created_at < date('now') GROUP BY d ORDER BY d ASC`
        ).bind(interval).all(),
        // Top countries
        env.DB.prepare(
            `SELECT country, COUNT(*) c FROM events WHERE created_at >= datetime('now', ?) AND created_at < date('now') GROUP BY country ORDER BY c DESC LIMIT 10`
        ).bind(interval).all(),
        // Top services
        env.DB.prepare(
            `SELECT service, COUNT(*) c FROM events WHERE created_at >= datetime('now', ?) AND created_at < date('now') GROUP BY service ORDER BY c DESC LIMIT 10`
        ).bind(interval).all(),
        // Top paths
        env.DB.prepare(
            `SELECT path, COUNT(*) c FROM events WHERE created_at >= datetime('now', ?) AND created_at < date('now') GROUP BY path ORDER BY c DESC LIMIT 10`
        ).bind(interval).all(),
        // Top ASNs
        env.DB.prepare(
            `SELECT asn, COUNT(*) c FROM events WHERE created_at >= datetime('now', ?) AND created_at < date('now') AND asn IS NOT NULL GROUP BY asn ORDER BY c DESC LIMIT 10`
        ).bind(interval).all(),
        // Top usernames (no passwords)
        env.DB.prepare(
            `SELECT username, COUNT(*) c FROM events WHERE created_at >= datetime('now', ?) AND created_at < date('now') AND username IS NOT NULL GROUP BY username ORDER BY c DESC LIMIT 10`
        ).bind(interval).all(),
        // Total count
        env.DB.prepare(
            `SELECT COUNT(*) total FROM events WHERE created_at >= datetime('now', ?) AND created_at < date('now')`
        ).bind(interval).first(),
    ];

    const [volume, topCountries, topServices, topPaths, topAsns, topUsernames, total] =
        await Promise.all(publicQueries);

    const payload = {
        meta: { days, total: total?.total ?? 0, generated_at: new Date().toISOString() },
        volume: volume.results,
        top_countries: topCountries.results,
        top_services: topServices.results,
        top_paths: topPaths.results,
        top_asns: topAsns.results,
        top_usernames: topUsernames.results,
    };

    if (isPrivate) {
        const limit = Math.min(parseInt(url.searchParams.get('limit') ?? '100'), 1000);
        const [recent, topIPs, topCreds, topHosts] = await Promise.all([
            env.DB.prepare(
                `SELECT ip, country, host, asn, method, path, service, username, password, ua, created_at FROM events WHERE created_at >= datetime('now', ?) ORDER BY created_at DESC LIMIT ?`
            ).bind(interval, limit).all(),
            env.DB.prepare(
                `SELECT ip, country, asn, COUNT(*) c FROM events WHERE created_at >= datetime('now', ?) GROUP BY ip ORDER BY c DESC LIMIT 20`
            ).bind(interval).all(),
            env.DB.prepare(
                `SELECT username, password, COUNT(*) c FROM events WHERE created_at >= datetime('now', ?) AND username IS NOT NULL GROUP BY username, password ORDER BY c DESC LIMIT 50`
            ).bind(interval).all(),
            env.DB.prepare(
                `SELECT host, COUNT(*) c FROM events WHERE created_at >= datetime('now', ?) GROUP BY host ORDER BY c DESC`
            ).bind(interval).all(),
        ]);
        payload.recent = recent.results;
        payload.top_ips = topIPs.results;
        payload.top_creds = topCreds.results;
        payload.top_hosts = topHosts.results;
    }

    const ttl = isPrivate ? 120 : 600;
    const cacheResponse = new Response(JSON.stringify(payload), {
        headers: { 'Content-Type': 'application/json', 'Cache-Control': `s-maxage=${ttl}` },
    });
    await cache.put(cacheUrl, cacheResponse);

    return json(payload, 200, cors);
}
