// ============================================================
//  worker.js — Honeypot entrypoint
//  Bindings required: DB (D1), ADMIN_SECRET (env var)
//  Public — safe to publish
// ============================================================

import { notFound } from './helpers.js';
import { logEvent } from './logger.js';
import { statsHandler } from './stats.js';
import { simulators } from './simulators.js';

const SIMULATORS = [
    // {1,2} allows double-slash paths like //sito/wp-includes/wlwmanifest.xml
    { label: 'wordpress', pattern: /^\/{1,2}(wp-admin|wp-login\.php|xmlrpc\.php|wp-json|wp-content|wp-includes)/ },
    { label: 'phpmyadmin', pattern: /^\/(phpmyadmin|pma|phpMyAdmin)/ },
    { label: 'sensitive', pattern: /^\/(\.env|\.git\/config|config\.php|\.htpasswd|web\.config|\.DS_Store|src\/\.env|config\.env|config\.json|\.env\.(local|production|prod|dev|staging))/ },
    { label: 'login', pattern: /^\/(login|signin|sign-in|log-in|logon)(\/|$|\?)/ },
    { label: 'springboot', pattern: /^\/(actuator|v2\/api-docs|v3\/api-docs|webjars\/swagger-ui|swagger-ui\.html|api-docs)/ },
    { label: 'skimmer', pattern: /\/(twint|lkk|qr_modal|bot-connect|support_parent|sys_files|protect)/ },
    { label: 'infra', pattern: /^\/(terraform\.|docker-compose|\.aws\/|\.docker\/|id_rsa|export\.sql|sftp-config|opencode|service-account|google-credentials|google-services|firebase-adminsdk|app\/config\/parameters)/ },
    { label: 'mail', pattern: /^\/(webmail|roundcube|squirrelmail|horde|rainloop|mail|owa|exchange|autodiscover|remote)(\/|$)/ },
    { label: 'vpn', pattern: /^\/(vpn|remote|sslvpn|citrix|pulse|fortivpn|globalprotect|dana-na|\+CSCOE\+|remote\/login)(\/|$)/ },
    { label: 'cdn', pattern: /^\/(cdn|assets|static|files|uploads|media|storage|s3)(\/|$)/ },
    { label: 'api', pattern: /^\/api\/v[0-9]+\// },
    { label: 'admin', pattern: /^\/(admin|administrator|manager\/html|console|panel|dashboard)/ },
    { label: 'cgi', pattern: /^\/(cgi-bin|cgi)/ },
];

// Paths that generate no useful threat intelligence — skip logging
const IGNORE_PATHS = ['/favicon.ico', '/robots.txt', '/sitemap.xml'];

export default {

    // ── Scheduled cleanup (nightly Cron Trigger) ───────────────
    async scheduled(_event, env, _ctx) {
        // Remove events older than 30 days
        await env.DB.prepare(
            "DELETE FROM events WHERE created_at < datetime('now', '-30 days')"
        ).run();

        // Hard cap at 50,000 rows to stay within D1 free tier limits
        await env.DB.prepare(`
      DELETE FROM events WHERE id IN (
        SELECT id FROM events ORDER BY created_at ASC
        LIMIT MAX(0, (SELECT COUNT(*) FROM events) - 50000)
      )
    `).run();
    },

    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        // ── Protected stats endpoint ──────────────────────────────
        // GET /hp-stats  +  header X-Admin-Secret: <your secret>
        if (url.pathname.startsWith('/hp-stats')) {
            if (request.headers.get('X-Admin-Secret') !== env.ADMIN_SECRET) {
                return notFound();
            }
            return statsHandler(env, url);
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
                meta.body = (await request.text()).slice(0, 2000);

                const ct = request.headers.get('content-type') ?? '';

                // HTML form submissions
                if (ct.includes('application/x-www-form-urlencoded') && meta.body) {
                    const p = new URLSearchParams(meta.body);
                    meta.username = p.get('log')          // WordPress
                        ?? p.get('username')      // generic
                        ?? p.get('pma_username')  // phpMyAdmin
                        ?? p.get('user')
                        ?? null;
                    meta.password = p.get('pwd')           // WordPress
                        ?? p.get('password')      // generic
                        ?? p.get('pma_password')  // phpMyAdmin
                        ?? p.get('pass')
                        ?? null;
                }

                // JSON body
                if (ct.includes('application/json') && meta.body) {
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
        if (!IGNORE_PATHS.includes(url.pathname)) {
            ctx.waitUntil(logEvent(meta, env));
        }

        return response;
    },
};
