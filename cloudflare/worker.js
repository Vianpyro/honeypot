// ============================================================
//  worker.js — Honeypot entrypoint
//  Bindings required: DB (D1), ADMIN_SECRET (env var)
//  Public — safe to publish
// ============================================================

import { notFound } from './helpers.js';
import { logEvent } from './logger.js';
import { statsHandler, statsApiHandler } from './stats.js';
import { simulators } from './simulators.js';

const SIMULATORS = [
    { label: 'wordpress', pattern: /^\/{1,2}(wp-admin|wp-login\.php|xmlrpc\.php|wp-json|wp-content|wp-includes)/ },
    { label: 'phpmyadmin', pattern: /^\/(phpmyadmin|pma|phpMyAdmin)/ },
    { label: 'sensitive', pattern: /^\/(\.env|api\/\.env|env$|\.git\/config|config\.php|\.htpasswd|web\.config|\.DS_Store|src\/\.env|config\.env|config\.json|\.env\.(local|production|prod|dev|staging|development|backup)|@vite\/env|\.vscode\/sftp\.json|js\/config\.js)/ },
    { label: 'login', pattern: /^\/(login|signin|sign-in|log-in|logon)(\/|$|\?)/ },
    { label: 'springboot', pattern: /^\/(actuator|v2\/api-docs|v3\/api-docs|webjars\/swagger-ui|swagger-ui\.html|api-docs)/ },
    { label: 'skimmer', pattern: /\/(twint|lkk|qr_modal|bot-connect|support_parent|sys_files|protect)/ },
    { label: 'infra', pattern: /^\/(terraform\.|docker-compose|\.aws\/|\.docker\/|id_rsa|export\.sql|sftp-config|opencode|service-account|google-credentials|google-services|firebase-adminsdk|app\/config\/parameters|v2\/_catalog)/ },
    { label: 'php', pattern: /^\/(info\.php|phpinfo\.php|pinfo\.php|test\.php|php\.php|i\.php)(\/|$|\?)/ },
    { label: 'mail', pattern: /^\/(webmail|roundcube|squirrelmail|horde|rainloop|mail|owa|exchange|autodiscover|remote)(\/|$)/ },
    { label: 'vpn', pattern: /^\/(vpn|remote|sslvpn|citrix|pulse|fortivpn|globalprotect|dana-na|\+CSCOE\+|remote\/login)(\/|$)/ },
    { label: 'cdn', pattern: /^\/(cdn|assets|static|files|uploads|media|storage|s3)(\/|$)/ },
    { label: 'graphql', pattern: /^\/(graphql|api\/graphql|api\/gql|gql)(\/|$|\?)/ },
    { label: 'api', pattern: /^\/api\/v[0-9]+\// },
    { label: 'admin', pattern: /^\/(admin|administrator|manager\/html|console|panel|dashboard)/ },
    { label: 'cgi', pattern: /^\/(cgi-bin|cgi)/ },
];

// Paths that generate no useful threat intelligence — skip logging
const IGNORE_PATHS = ['/favicon.ico', '/robots.txt', '/sitemap.xml'];

// Retention: 366 days — well within D1 free tier (~730 MB/year at 1000 req/day, 5 GB limit)
const RETENTION_DAYS = 366;

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
            return cleanupOldEntries(env);
        default:
            console.warn(`[cron] unhandled expression: ${cron}`);
            return;
    }
}

async function cleanupOldEntries(env) {
    try {
        const result = await env.DB.prepare(
            `DELETE FROM events WHERE created_at < datetime('now', ?)`
        ).bind(`-${RETENTION_DAYS} days`).run();
        console.log(`[retention] ${result.meta.changes} rows deleted`);
        return result;
    } catch (e) {
        console.error('[retention] cleanup failed:', e.message);
    }
}

export default {

    async scheduled(event, env, ctx) {
        ctx.waitUntil(handleCron(event.cron, env));
    },

    async fetch(request, env, ctx) {
        const url = new URL(request.url);

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
            ua: request.headers.get('User-Agent') ?? '',
            method: request.method,
            path: url.pathname + url.search,
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
                        ?? null;
                    meta.password = p.get('pwd')
                        ?? p.get('password')
                        ?? p.get('pma_password')
                        ?? p.get('pass')
                        ?? null;
                }

                if (meta.body && ct.includes('application/json')) {
                    try {
                        const j = JSON.parse(meta.body);
                        meta.username = j.username ?? j.user ?? j.email ?? j.login ?? null;
                        meta.password = j.password ?? j.pass ?? j.secret ?? null;
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
        if (!IGNORE_PATHS.includes(url.pathname) && !isTest) {
            ctx.waitUntil(logEvent(meta, env));
        }

        return response;
    },
};
