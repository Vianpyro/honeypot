// ============================================================
//  worker.js — Honeypot entrypoint
//  Bindings required: DB (D1), ADMIN_SECRET (env var)
// ============================================================

import { notFound } from './helpers.js';
import { logEvent } from './logger.js';
import { statsHandler, statsApiHandler } from './stats.js';
import { simulators } from './simulators.js';
import { aggregateDay, yesterdayUTC } from './aggregate.js';
import { reportToAbuseIPDB } from './reporter.js';
import { ABUSEIPDB_VERIFICATION_TOKEN, HONEYPOT_HOSTS, isMonitoring } from './config.js';

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

// Retention: 100 days — well within D1 free tier (~730 MB/year at 1000 req/day, 5 GB limit)
const RETENTION_DAYS = 100;
// Pending rows whose 10-min bucket has long since closed are dead weight.
// 1 bucket + 50 min buffer absorbs cron latency.
const PENDING_STALE_HOURS = 1;

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

async function handleCron(cron, env) {
    switch (cron) {
        case '0 0 * * *':
            await aggregateDay(yesterdayUTC(), env);
            return cleanupOldEntries(env);
        case '0 1 * * *':
            return reportToAbuseIPDB(env);
        default:
            console.warn(`[cron] unhandled expression: ${cron}`);
            return;
    }
}

async function cleanupOldEntries(env) {
    // Order matters: prune parents first so orphan sweeps find them gone.
    // D1 batch is transactional; each stmt sees prior stmts' changes.
    try {
        const results = await env.DB.batch([
            env.DB.prepare(
                `DELETE FROM events WHERE created_at < datetime('now', ?)`
            ).bind(`-${RETENTION_DAYS} days`),

            env.DB.prepare(
                `DELETE FROM campaigns WHERE last_seen_at < datetime('now', ?)`
            ).bind(`-${RETENTION_DAYS} days`),

            env.DB.prepare(
                `DELETE FROM pending_campaigns WHERE last_seen_at < datetime('now', ?)`
            ).bind(`-${PENDING_STALE_HOURS} hours`),

            env.DB.prepare(
                `DELETE FROM campaign_events WHERE event_id    NOT IN (SELECT id FROM events) OR campaign_id NOT IN (SELECT id FROM campaigns)`
            ),
            // Welford rows are orphaned once no campaign or pending references
            // their hash. Safe to drop; future events recreate on demand.
            env.DB.prepare(
                `DELETE FROM campaign_path_stats WHERE path_seq_hash NOT IN (SELECT path_seq_hash FROM campaigns) AND path_seq_hash NOT IN (SELECT path_seq_hash FROM pending_campaigns)`
            ),
        ]);
        const c = results.map(r => r.meta?.changes ?? 0);
        console.log(
            `[retention] events=${c[0]} campaigns=${c[1]} ` +
            `pending=${c[2]} orphan_joins=${c[3]} stats=${c[4]}`
        );
    } catch (e) {
        console.error('[retention] cleanup failed:', e.message);
    }
}

function passthrough(request, env) {
    return fetch(request, {
        cf: { resolveOverride: new URL(env.NGINX_ORIGIN).hostname },
    });
}

export default {

    async scheduled(event, env, ctx) {
        ctx.waitUntil(handleCron(event.cron, env));
    },

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

        // ── Legacy private stats endpoint ─────────────────────────
        if (url.pathname.startsWith('/hp-stats')) {
            if (!await safeCompare(request.headers.get('X-Admin-Secret'), env.ADMIN_SECRET)) {
                return notFound();
            }
            return statsHandler(env, url);
        }

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

        const isVerifiedMonitor =
            request.cf?.botManagement?.verifiedBot === true ||
            MONITORING_PATHS.get(url.hostname)?.test(url.pathname);

        if (!IGNORE_PATHS.includes(url.pathname) && !isTest && !isVerifiedMonitor) {
            ctx.waitUntil(logEvent(meta, env));
        }

        if (!IGNORE_PATHS.includes(url.pathname) && !isTest) {
            ctx.waitUntil(logEvent(meta, env));
        }

        return response;
    },
};
