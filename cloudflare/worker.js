// ============================================================
//  worker.js — Honeypot entrypoint
//  Bindings required: HONEYPOT_API (Workers VPC), ADMIN_SECRET,
//                     HONEYPOT_HMAC_KEY, HONEYPOT_KEY_ID,
//                     HONEYPOT_STATS_TOKEN, NGINX_ORIGIN, ABUSEIPDB_KEY
//
//  D1 IS GONE. Events, campaigns, the daily rollups, retention and the
//  AbuseIPDB submissions all live in PostgreSQL, reached through the
//  Cloudflare Tunnel. This Worker no longer owns any state.
// ============================================================

import { notFound } from './helpers.js';
import { logEvent } from './logger.js';
import { statsApiHandler } from './stats.js';
import { simulators } from './simulators.js';
import { ABUSEIPDB_VERIFICATION_TOKEN, HONEYPOT_HOSTS, isMonitoring } from './config.js';
import { shouldLogEvent } from './logging.js';

// Any non-honeypot host, from a caller on one of these ASNs, also gets trapped
const DATACENTER_ASNS = new Set([
    14061, 16509, 14618, 396982, 24940, 20473, 13335,
    8758, 210558, 7029, 51396, 40676, 48090,
]);

// Self-announcing monitoring bots. They run on datacenter ASNs, so without this
// they get honeypotted, logged, and reported to AbuseIPDB as attackers.
// ponytail: UA match, spoofable — a spoofer just reaches nginx like any normal
// visitor, and honeypot-only hosts are checked first. Tighten to published IP
// ranges if that ever matters.
const MONITOR_UA = /UptimeRobot/i;

const SIMULATORS = [
    { label: 'wordpress', pattern: /^\/{1,2}(?:[\w-]+\/)?(wp-admin|wp-login\.php|xmlrpc\.php|wp-json|wp-content|wp-includes)/ },
    { label: 'phpmyadmin', pattern: /^\/(phpmyadmin|pma|phpMyAdmin)/ },
    { label: 'sensitive', pattern: /^\/(\.env|api\/\.env|env$|\.git\/config|config\.php|\.htpasswd|web\.config|\.DS_Store|src\/\.env|config\.env|config\.json|\.env\.(local|production|prod|dev|staging|development|backup)|@vite\/env|\.vscode\/sftp\.json|js\/config\.js)/ },
    { label: 'login', pattern: /^\/(login|signin|sign-in|log-in|logon|login\.action)(\/|$|\?)/ },
    { label: 'springboot', pattern: /^\/(actuator|v2\/api-docs|v3\/api-docs|webjars\/swagger-ui|swagger-ui\.html|api-docs|swagger\/v[0-9]+\/swagger\.json)/ },
    { label: 'skimmer', pattern: /\/(twint|lkk|qr_modal|bot-connect|support_parent|sys_files|protect)(\.js|\.css)?$/ },
    { label: 'infra', pattern: /^\/(terraform\.|docker-compose|\.aws\/|\.docker\/|id_rsa|export\.sql|sftp-config|opencode|service-account|google-credentials|google-services|firebase-adminsdk|app\/config\/parameters|v2\/_catalog|db\.sql|dump\.sql|db_backup\.sql|database\.sql|backup\.sql|mysql\.sql|sql\/|backup\/.*\.sql|\.runtimeconfig\.json)/ },
    { label: 'php', pattern: /^\/(info\.php|phpinfo\.php|pinfo\.php|test\.php|php\.php|i\.php)(\/|$|\?)/ },
    { label: 'mail', pattern: /^\/(webmail|roundcube|squirrelmail|horde|rainloop|mail|owa|exchange|autodiscover|remote)(\/|$)/ },
    { label: 'vpn', pattern: /^\/(vpn|remote|sslvpn|citrix|pulse|fortivpn|globalprotect|dana-na|\+CSCOE\+|remote\/login)(\/|$)/ },
    { label: 'cdn', pattern: /^\/(cdn|assets|static|files|uploads|media|storage|s3)(\/|$)/ },
    { label: 'graphql', pattern: /^\/(graphql|api\/graphql|api\/gql|gql)(\/|$|\?)/ },
    { label: 'api', pattern: /^\/api\/v[0-9]+\// },
    { label: 'admin', pattern: /^\/(admin|administrator|manager\/html|console|panel|dashboard)/ },
    { label: 'cgi', pattern: /^\/(cgi-bin|cgi)/ },
    { label: 'apache_status', pattern: /^\/(server-status|server-info|server|about|version)(\/|$|\?)/ },
    { label: 'laravel', pattern: /^\/(telescope|horizon|debugbar)(\/|$)/ },
    { label: 'aspnet', pattern: /^\/(trace\.axd|elmah\.axd|WebResource\.axd)(\/|$|\?)/ },
    { label: 'yii', pattern: /^\/debug\/default\// },
    { label: 'root', pattern: /^\/$/ },
];

// Paths that generate no useful threat intelligence — skip logging
const IGNORE_PATHS = [
    '/favicon.ico',
    '/robots.txt',
    '/sitemap.xml',
    '/.well-known/security.txt',
    '/.well-known/security.json',
    '/.well-known/dmarc-policy',
    '/apple-touch-icon.png',
    '/android-chrome-icon.png',
    '/abuseipdb-verification.html',
];

// RETENTION AND THE CRON JOBS THAT ENFORCED IT ARE GONE. Both now run in the
// API's own daily task, where they can also catch up after downtime -- see
// api/src/aggregate.rs and the retention sweep in api/src/main.rs. The Worker
// kept no state, so it has nothing left to prune.

async function safeCompare(a, b) {
    if (!a || !b) return false;
    const enc = new TextEncoder();
    const ta = enc.encode(a);
    const tb = enc.encode(b);
    const [ha, hb] = await Promise.all([
        crypto.subtle.digest('SHA-256', ta),
        crypto.subtle.digest('SHA-256', tb),
    ]);
    return crypto.subtle.timingSafeEqual(ha, hb);
}

function passthrough(request, env) {
    return fetch(request, {
        cf: { resolveOverride: new URL(env.NGINX_ORIGIN).hostname },
    });
}

export default {

    // NO `scheduled` HANDLER. Its two crons rolled up yesterday and pruned D1;
    // both moved into the API, which does them on its own daily tick and can
    // fill in days it missed. DELETE THE CRON TRIGGERS in the dashboard too --
    // a trigger firing into a Worker with no handler is a scheduled error
    // nobody reads.

    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        if (url.pathname === '/abuseipdb-verification.html') {
            return new Response(ABUSEIPDB_VERIFICATION_TOKEN, {
                headers: { 'Content-Type': 'text/html' },
            });
        }

        if (isMonitoring(url.hostname, url.pathname, env)) {
            return passthrough(request, env);
        }

        // Honeypot-only hosts always get trapped. On real hosts, let through both
        // announced monitoring bots and anyone not calling from a datacenter.
        if (!HONEYPOT_HOSTS.has(url.hostname)) {
            const isMonitorBot = MONITOR_UA.test(request.headers.get('User-Agent') ?? '');
            if (isMonitorBot || !DATACENTER_ASNS.has(request.cf?.asn)) {
                return passthrough(request, env);
            }
        }

        // `/hp-stats` IS GONE, and was deliberately not ported. It was marked
        // legacy, the dashboard does not call it, and its queries had no time
        // filter at all -- `GROUP BY ip ORDER BY count DESC` over the entire
        // table, which was survivable on a small D1 and is not something to
        // carry into a hundred days of PostgreSQL. `/stats/api?token=...`
        // returns a superset of it, bounded by a window.

        // ── Public/private stats API ──────────────────────────────
        // GET /stats/api              → public (aggregated, no IPs)
        // GET /stats/api?token=xxx    → private (full data, IPs, payloads)
        if (url.pathname === '/stats/api') {
            if (request.method === 'OPTIONS') {
                return statsApiHandler(request, env, false);
            }
            const token = url.searchParams.get('token');
            const isPrivate = token ? await safeCompare(token, env.ADMIN_SECRET) : false;
            return statsApiHandler(request, env, isPrivate);
        }

        // ── Collect attacker metadata ─────────────────────────────
        const meta = {
            ip: request.headers.get('CF-Connecting-IP') ?? 'unknown',
            country: request.cf?.country ?? 'XX',
            asn: request.cf?.asn ?? 0,
            as_organization: request.cf?.asOrganization ?? null,
            tls_version: request.cf?.tlsVersion ?? null,
            http_protocol: request.cf?.httpProtocol ?? null,
            client_tcp_rtt: request.cf?.clientTcpRtt ?? null,
            ua: request.headers.get('User-Agent') ?? '',
            method: request.method,
            path: url.pathname,
            query: url.search || null,
            host: request.headers.get('host') ?? '',
            body: null,
            username: null,
            password: null,
            service: 'catch-all',
            created_at: new Date().toISOString(),
        };

        if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
            try {
                const cl = parseInt(request.headers.get('content-length') ?? '0');
                if (cl < 100_000) {
                    meta.body = (await request.text()).slice(0, 2000);
                }

                const ct = request.headers.get('content-type') ?? '';

                // HTML form submissions
                if (meta.body && ct.includes('application/x-www-form-urlencoded')) {
                    const p = new URLSearchParams(meta.body);
                    meta.username = p.get('log')
                        ?? p.get('username')
                        ?? p.get('pma_username')
                        ?? p.get('user')
                        ?? p.get('_user')
                        ?? p.get('usr')
                        ?? p.get('email')
                        ?? null;
                    meta.password = p.get('pwd')
                        ?? p.get('password')
                        ?? p.get('pma_password')
                        ?? p.get('pass')
                        ?? p.get('_pass')
                        ?? p.get('credential')
                        ?? null;
                }

                if (meta.body && ct.includes('application/json')) {
                    try {
                        const j = JSON.parse(meta.body);
                        meta.username = j.username
                            ?? j.user
                            ?? j.email
                            ?? j.login
                            ?? j._user
                            ?? j.usr
                            ?? null;
                        meta.password = j.password
                            ?? j.pass
                            ?? j.secret
                            ?? j._pass
                            ?? j.passwd
                            ?? j.credential
                            ?? null;
                    } catch { }
                }
            } catch { }
        }

        // ── Route to simulator ────────────────────────────────────
        let response;
        for (const { label, pattern } of SIMULATORS) {
            if (pattern.test(url.pathname)) {
                meta.service = label;
                response = simulators[label](request, url);
                break;
            }
        }
        response ??= simulators['catch-all'](request, url);

        // ── Log to D1 asynchronously (non-blocking) ───────────────
        const isTest = await safeCompare(request.headers.get('X-Honeypot-Test'), env.ADMIN_SECRET);

        // `isMonitoring()` above already bypasses the known, deployment-specific
        // monitoring paths.  Keep this check limited to Cloudflare's verified
        // bots; the former MONITORING_PATHS map was never defined or imported.
        const isVerifiedMonitor = request.cf?.botManagement?.verifiedBot === true;

        // Exactly one asynchronous delivery attempt per eligible request.
        // Calling waitUntil twice here created two independent event inserts.
        if (shouldLogEvent(url.pathname, isTest, isVerifiedMonitor)) {
            ctx.waitUntil(logEvent(meta, env));
        }

        return response;
    },
};
