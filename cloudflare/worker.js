// ============================================================
//  Cloudflare Worker Honeypot
//  Required bindings:
//    - DB           : D1 database (see schema.sql)
//    - ADMIN_SECRET : Secret string (set via: wrangler secret put ADMIN_SECRET)
// ============================================================

const SIMULATORS = [
  { label: 'wordpress',  pattern: /^\/(wp-admin|wp-login\.php|xmlrpc\.php|wp-json|wp-content)/ },
  { label: 'phpmyadmin', pattern: /^\/(phpmyadmin|pma|phpMyAdmin)/ },
  // Matches common sensitive file paths attackers probe for
  { label: 'sensitive',  pattern: /^\/(\.env|\.git\/config|config\.php|\.htpasswd|web\.config|\.DS_Store|src\/\.env|config\.env|\.env\.(local|production|prod|dev|staging))/ },
  { label: 'api',        pattern: /^\/api\/v[0-9]+\// },
  { label: 'admin',      pattern: /^\/(admin|administrator|manager\/html|console|panel|dashboard)/ },
  { label: 'cgi',        pattern: /^\/(cgi-bin|cgi)/ },
];

// Paths that generate no useful threat intelligence: skip logging
const IGNORE_PATHS = ['/favicon.ico', '/robots.txt', '/sitemap.xml', '/favicon.png'];

export default {

  // ── Scheduled cleanup (run nightly via Cron Trigger) ───────
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
    // Access via: GET /hp-stats  with header  X-Admin-Secret: <your secret>
    // Optional query param: ?limit=100 (max 500)
    if (url.pathname.startsWith('/hp-stats')) {
      if (request.headers.get('X-Admin-Secret') !== env.ADMIN_SECRET) {
        return notFound();
      }
      return statsHandler(env, url);
    }

    // ── Collect attacker metadata ─────────────────────────────
    const meta = {
      ip:         request.headers.get('CF-Connecting-IP') ?? 'unknown',
      country:    request.cf?.country ?? 'XX',
      asn:        request.cf?.asn ?? 0,
      ua:         request.headers.get('User-Agent') ?? '',
      method:     request.method,
      path:       url.pathname + url.search,
      host:       request.headers.get('host') ?? '',
      body:       null,
      username:   null,  // Extracted from POST body when available
      password:   null,  // Extracted from POST body when available
      service:    'catch-all',
      created_at: new Date().toISOString(),
    };

    // Extract credentials from request body (form-encoded and JSON)
    if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
      try {
        meta.body = (await request.text()).slice(0, 2000);

        const ct = request.headers.get('content-type') ?? '';

        // HTML form submissions (wp-login, phpmyadmin, generic admin panels)
        if (ct.includes('application/x-www-form-urlencoded') && meta.body) {
          const p = new URLSearchParams(meta.body);
          meta.username = p.get('log')           // WordPress username field
                       ?? p.get('username')      // Generic
                       ?? p.get('pma_username')  // phpMyAdmin
                       ?? p.get('user')
                       ?? null;
          meta.password = p.get('pwd')           // WordPress password field
                       ?? p.get('password')      // Generic
                       ?? p.get('pma_password')  // phpMyAdmin
                       ?? p.get('pass')
                       ?? null;
        }

        // REST API / JSON body
        if (ct.includes('application/json') && meta.body) {
          try {
            const j = JSON.parse(meta.body);
            meta.username = j.username ?? j.user ?? j.email ?? j.login ?? null;
            meta.password = j.password ?? j.pass ?? j.secret ?? null;
          } catch {}
        }
      } catch {}
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
    // ctx.waitUntil ensures the DB write completes after the response is sent
    if (!IGNORE_PATHS.includes(url.pathname)) {
      ctx.waitUntil(logEvent(meta, env));
    }

    return response;
  },
};

// ============================================================
//  Simulators: each returns a realistic-looking fake response
// ============================================================

const simulators = {

  wordpress(request, url) {
    if (url.pathname.includes('wp-login') || url.pathname.includes('wp-admin')) {
      if (request.method === 'POST') {
        // Return a fake failed login to encourage repeated credential attempts
        return html(wpLoginPage('Incorrect username or password.'), 200, phpHeaders());
      }
      return html(wpLoginPage(), 200, phpHeaders());
    }
    return json(
      { code: 'rest_no_route', message: 'No route was found matching the URL and request method.', data: { status: 404 } },
      404
    );
  },

  phpmyadmin(_request, _url) {
    return html(`<!DOCTYPE html><html lang="en"><head><title>phpMyAdmin</title></head><body>
<div id="pma_navigation"><h1>phpMyAdmin</h1></div>
<form method="post" action="/phpmyadmin/index.php">
  <table><tbody>
    <tr><td>Server:</td><td><input name="pma_servername" value="localhost"/></td></tr>
    <tr><td>Username:</td><td><input name="pma_username"/></td></tr>
    <tr><td>Password:</td><td><input type="password" name="pma_password"/></td></tr>
    <tr><td colspan="2"><input type="submit" value="Go"/></td></tr>
  </tbody></table>
</form></body></html>`, 200, phpHeaders());
  },

  sensitive(_request, url) {
    const p = url.pathname;

    if (p.includes('.env')) {
      // Returns a fake .env file with plausible-looking credentials
      // !! CUSTOMISE fakeEnvFile() below before deploying !!
      return plain(fakeEnvFile(), 200);
    }
    if (p.includes('.git/config')) {
      // Fake git remote pointing to a fictitious private repo
      // !! REPLACE the github.com URL with a fictional one !!
      return plain(
        `[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n` +
        `[remote "origin"]\n\turl = git@github.com:example-org/prod-app.git\n` +
        `\tfetch = +refs/heads/*:refs/remotes/origin/*\n` +
        `[branch "main"]\n\tremote = origin\n\tmerge = refs/heads/main\n`,
        200
      );
    }
    if (p.includes('config.php')) {
      return html(
        `<?php\n/* Database */\ndefine('DB_NAME', 'prod_db');\ndefine('DB_USER', 'wp_user');\n` +
        // !! REPLACE with fictional credentials !!
        `define('DB_PASSWORD', 'FAKE_DB_PASSWORD_HERE');\ndefine('DB_HOST', 'localhost');\n?>`,
        200, phpHeaders()
      );
    }
    return plain('', 403);
  },

  api(request, url) {
    // Generic API responses
    if (request.method === 'POST' && url.pathname.match(/\/(login|auth|token)/)) {
      return json({ success: false, error: 'Invalid credentials', code: 401 }, 401);
    }
    if (request.method === 'GET') {
      return json(
        { error: 'Unauthorized', message: 'A valid bearer token is required.', code: 'AUTH_REQUIRED' },
        401,
        { 'WWW-Authenticate': 'Bearer realm="api"' }
      );
    }
    return json({ error: 'Not found' }, 404);
  },

  admin(_request, _url) {
    return html(`<!DOCTYPE html><html><head><title>Admin Panel</title></head><body>
<h2>Admin Login</h2>
<form method="post">
  <label>Username: <input type="text" name="username" autocomplete="off"/></label><br><br>
  <label>Password: <input type="password" name="password"/></label><br><br>
  <input type="submit" value="Sign In"/>
</form></body></html>`, 200, { Server: 'Apache/2.4.41 (Ubuntu)' });
  },

  cgi(_request, _url) {
    return plain(
      'CGI Error: malformed header from script. Bad header=Content-type: text/html\n',
      500,
      { Server: 'Apache/2.2.34 (Unix)' }
    );
  },

  'catch-all'(_request, _url) {
    return html(`<!DOCTYPE html><html><head><title>404 Not Found</title></head>
<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p>
<hr><address>Apache/2.4.41 (Ubuntu) Server at Port 443</address></body></html>`,
      404,
      { Server: 'Apache/2.4.41 (Ubuntu)' }
    );
  },
};

// ============================================================
//  Stats endpoint : returns JSON with aggregated threat data
// ============================================================

async function statsHandler(env, url) {
  const limit = Math.min(parseInt(url.searchParams.get('limit') ?? '50'), 500);

  const [recent, topIPs, topServices, topPaths, topCreds, topHosts] = await Promise.all([
    env.DB.prepare(
      'SELECT ip, country, host, asn, method, path, service, username, password, ua, created_at FROM events ORDER BY created_at DESC LIMIT ?'
    ).bind(limit).all(),
    env.DB.prepare('SELECT ip, country, COUNT(*) c FROM events GROUP BY ip ORDER BY c DESC LIMIT 20').all(),
    env.DB.prepare('SELECT service, COUNT(*) c FROM events GROUP BY service ORDER BY c DESC').all(),
    env.DB.prepare('SELECT path, COUNT(*) c FROM events GROUP BY path ORDER BY c DESC LIMIT 20').all(),
    env.DB.prepare(
      'SELECT username, password, COUNT(*) c FROM events WHERE username IS NOT NULL GROUP BY username, password ORDER BY c DESC LIMIT 50'
    ).all(),
    env.DB.prepare('SELECT host, COUNT(*) c FROM events GROUP BY host ORDER BY c DESC').all(),
  ]);

  return json({
    recent:       recent.results,
    top_ips:      topIPs.results,
    top_services: topServices.results,
    top_paths:    topPaths.results,
    top_creds:    topCreds.results,
    top_hosts:    topHosts.results,
  });
}

// ============================================================
//  Logger : async D1 write
// ============================================================

async function logEvent(meta, env) {
  try {
    await env.DB.prepare(`
      INSERT INTO events (ip, country, asn, ua, method, path, body, username, password, host, service, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      meta.ip, meta.country, meta.asn, meta.ua,
      meta.method, meta.path, meta.body ?? null,
      meta.username ?? null, meta.password ?? null,
      meta.host ?? null,
      meta.service, meta.created_at,
    ).run();
  } catch (e) {
    console.error('[honeypot] DB write failed:', e.message);
  }
}

// ============================================================
//  Fake content generators
//  !! Customise these before deploying : use fictional values !!
// ============================================================

function wpLoginPage(error = '') {
  return `<!DOCTYPE html><html lang="en"><head><title>Log In &lsaquo; WordPress</title>
<style>body{font:13px/1.4 sans-serif;background:#f1f1f1;}.login-form{background:#fff;padding:26px;width:320px;margin:60px auto;}</style>
</head><body>
<div class="login-form">
  <h1 style="text-align:center">WordPress</h1>
  ${error ? `<div style="color:red;margin-bottom:12px">${error}</div>` : ''}
  <form method="post" action="/wp-login.php">
    <p><label>Username or Email<br><input type="text" name="log" size="20" style="width:100%"/></label></p>
    <p><label>Password<br><input type="password" name="pwd" size="20" style="width:100%"/></label></p>
    <p><input type="submit" name="wp-submit" value="Log In" style="width:100%"/></p>
    <input type="hidden" name="redirect_to" value="/wp-admin/"/>
    <input type="hidden" name="testcookie" value="1"/>
  </form>
</div></body></html>`;
}

function fakeEnvFile() {
  // All values below are fictional and for honeypot purposes only.
  // !! REPLACE all values with your own fictional credentials before deploying !!
  // The SECRET_HINT is the base64-encoded path to the CTF step 2 endpoint.
  // !! REMOVE or CHANGE the SECRET_HINT if not running a CTF !!
  return `APP_NAME=MyApplication
APP_ENV=production
APP_KEY=base64:FAKE_APP_KEY_HERE
APP_DEBUG=false
APP_URL=https://example.com

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=app_prod
DB_USERNAME=app_user
DB_PASSWORD=FAKE_DB_PASSWORD_HERE

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=null
REDIS_PORT=6379

MAIL_MAILER=smtp
MAIL_HOST=smtp.mailgun.org
MAIL_PORT=587
MAIL_USERNAME=postmaster@mg.example.com
MAIL_PASSWORD=FAKE_MAIL_PASSWORD_HERE

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=FAKE_AWS_SECRET_HERE
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=my-app-prod-bucket

STRIPE_KEY=sk_live_FAKE_STRIPE_KEY_HERE
STRIPE_SECRET=sk_live_FAKE_STRIPE_SECRET_HERE

JWT_SECRET=FAKE_JWT_SECRET_HERE
`;
}

// ============================================================
//  Response helpers
// ============================================================

function html(body, status = 200, extra = {}) {
  return new Response(body, { status, headers: { 'Content-Type': 'text/html;charset=UTF-8', ...extra } });
}

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', ...extra } });
}

function plain(body, status = 200, extra = {}) {
  return new Response(body, { status, headers: { 'Content-Type': 'text/plain', ...extra } });
}

function phpHeaders() {
  return { 'X-Powered-By': 'PHP/8.1.2', Server: 'Apache/2.4.52 (Ubuntu)' };
}

function notFound() {
  return new Response('Not found', { status: 404 });
}
