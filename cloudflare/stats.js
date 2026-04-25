// ============================================================
//  stats.js — /hp-stats (private) + /stats/api (public + private)
// ============================================================

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
    const bucket = Math.floor(Date.now() / 21_600_000); // ~6 hours
    const cacheKey = `stats-${isPrivate ? 'priv' : 'pub'}-${days}-${bucket}`;

    // Cache API — TTL 15 min for public, 2 min for private
    const cache = caches.default;
    const cacheUrl = new URL(`https://cache.internal/${cacheKey}`);
    const cached = await cache.match(cacheUrl);
    if (cached) {
        const body = await cached.json();
        return json(body, 200, cors);
    }

    const interval = `-${days} days`;
    const fromDay = `-${days} days`;

    const publicQueries = [
        // Daily volume
        env.DB.prepare(
            `SELECT day d, count c FROM stats_daily
             WHERE dim = 'volume' AND day >= date('now', ?) AND day < date('now')
             ORDER BY day ASC`
        ).bind(fromDay).all(),
        // Top countries
        env.DB.prepare(
            `SELECT key country, SUM(count) c FROM stats_daily
             WHERE dim = 'country' AND day >= date('now', ?) AND day < date('now')
             GROUP BY key ORDER BY c DESC LIMIT 10`
        ).bind(fromDay).all(),
        // Top services
        env.DB.prepare(
            `SELECT key service, SUM(count) c FROM stats_daily
             WHERE dim = 'service' AND day >= date('now', ?) AND day < date('now')
             GROUP BY key ORDER BY c DESC LIMIT 10`
        ).bind(fromDay).all(),
        // Top paths
        env.DB.prepare(
            `SELECT key path, SUM(count) c FROM stats_daily
             WHERE dim = 'path' AND day >= date('now', ?) AND day < date('now')
             GROUP BY key ORDER BY c DESC LIMIT 10`
        ).bind(fromDay).all(),
        // Top ASNs
        env.DB.prepare(
            `SELECT CAST(key AS INTEGER) asn, MAX(extra) as_organization, SUM(count) c
             FROM stats_daily
             WHERE dim = 'asn' AND day >= date('now', ?) AND day < date('now')
             GROUP BY key ORDER BY c DESC LIMIT 10`
        ).bind(fromDay).all(),
        // Top usernames
        env.DB.prepare(
            `SELECT key username, SUM(count) c FROM stats_daily
             WHERE dim = 'username' AND day >= date('now', ?) AND day < date('now')
             GROUP BY key ORDER BY c DESC LIMIT 10`
        ).bind(fromDay).all(),
        // Top TLS
        env.DB.prepare(
            `SELECT key tls_version, SUM(count) c FROM stats_daily
             WHERE dim = 'tls' AND day >= date('now', ?) AND day < date('now')
             GROUP BY key ORDER BY c DESC LIMIT 6`
        ).bind(fromDay).all(),
        // Top protocols
        env.DB.prepare(
            `SELECT key http_protocol, SUM(count) c FROM stats_daily
             WHERE dim = 'protocol' AND day >= date('now', ?) AND day < date('now')
             GROUP BY key ORDER BY c DESC LIMIT 6`
        ).bind(fromDay).all(),
        // Distinct country count
        env.DB.prepare(
            `SELECT COUNT(DISTINCT key) total FROM stats_daily
             WHERE dim = 'country' AND day >= date('now', ?) AND day < date('now')`
        ).bind(fromDay).first(),
        // Distinct service count
        env.DB.prepare(
            `SELECT COUNT(DISTINCT key) total FROM stats_daily
             WHERE dim = 'service' AND day >= date('now', ?) AND day < date('now')`
        ).bind(fromDay).first(),
        // Distinct username count
        env.DB.prepare(
            `SELECT COUNT(DISTINCT key) total FROM stats_daily
             WHERE dim = 'username' AND day >= date('now', ?) AND day < date('now')`
        ).bind(fromDay).first(),
        // Total events
        env.DB.prepare(
            `SELECT SUM(count) total FROM stats_daily
             WHERE dim = 'volume' AND day >= date('now', ?) AND day < date('now')`
        ).bind(fromDay).first(),
        // Daily campaign count
        env.DB.prepare(
            `SELECT day d, count c FROM stats_daily
             WHERE dim = 'campaign_volume' AND day >= date('now', ?) AND day < date('now')
             ORDER BY day ASC`
        ).bind(fromDay).all(),
    ];

    const [volume, topCountries, topServices, topPaths, topAsns, topUsernames, topTls, topProtocols, totalCountries, totalServices, totalUsernames, total, campaignVolume] =
        await Promise.all(publicQueries);

    const payload = {
        meta: {
            days,
            total: total?.total ?? 0,
            total_countries: totalCountries?.total ?? 0,
            total_services: totalServices?.total ?? 0,
            total_usernames: totalUsernames?.total ?? 0,
            generated_at: new Date().toISOString()
        },
        volume: volume.results,
        top_countries: topCountries.results,
        top_services: topServices.results,
        top_paths: topPaths.results,
        top_asns: topAsns.results,
        top_usernames: topUsernames.results,
        top_tls: topTls.results,
        top_protocols: topProtocols.results,
        campaign_volume: campaignVolume.results,
    };

    if (isPrivate) {
        const limit = Math.min(parseInt(url.searchParams.get('limit') ?? '100'), 1000);
        const [recent, topIPs, topCreds, topHosts] = await Promise.all([
            env.DB.prepare(
                `SELECT ip, country, host, asn, method, path, service, username, password, ua, created_at FROM events WHERE created_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?) ORDER BY created_at DESC LIMIT ?`
            ).bind(interval, limit).all(),
            env.DB.prepare(
                `SELECT ip, country, asn, COUNT(*) c FROM events WHERE created_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?) GROUP BY ip ORDER BY c DESC LIMIT 20`
            ).bind(interval).all(),
            env.DB.prepare(
                `SELECT username, password, COUNT(*) c FROM events WHERE created_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?) AND username IS NOT NULL GROUP BY username, password ORDER BY c DESC LIMIT 50`
            ).bind(interval).all(),
            env.DB.prepare(
                `SELECT host, COUNT(*) c FROM events WHERE created_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?) GROUP BY host ORDER BY c DESC`
            ).bind(interval).all(),
        ]);
        payload.recent = recent.results;
        payload.top_ips = topIPs.results;
        payload.top_creds = topCreds.results;
        payload.top_hosts = topHosts.results;
    }

    const ttl = isPrivate ? 120 : 21600; // 2 min for private, 6 hours for public (bucketed)
    const cacheResponse = new Response(JSON.stringify(payload), {
        headers: { 'Content-Type': 'application/json', 'Cache-Control': `s-maxage=${ttl}` },
    });
    await cache.put(cacheUrl, cacheResponse);

    return json(payload, 200, cors);
}
