// ============================================================
//  stats.js — Protected /hp-stats endpoint
// ============================================================

import { json } from './helpers.js';

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
