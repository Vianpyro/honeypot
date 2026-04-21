// ============================================================
//  simulators.js — Service simulators
//  Public — safe to publish (fake content imported from content.js)
// ============================================================

import { html, json, plain, phpHeaders } from './helpers.js';
import { wpLoginPage, fakeEnvFile, fakeConfigJson, CTF_FLAG, GUEST_JWT, FAKE_GIT_REMOTE, FAKE_PHP_DB_PASSWORD } from './content.js';

export const simulators = {

    wordpress(request, url) {
        if (url.pathname.includes('wp-login') || url.pathname.includes('wp-admin')) {
            if (request.method === 'POST') {
                return html(wpLoginPage('Incorrect username or password.'), 200, phpHeaders());
            }
            return html(wpLoginPage(), 200, phpHeaders());
        }
        // wlwmanifest.xml, xmlrpc, wp-json, wp-includes
        return json({ code: 'rest_no_route', message: 'No route was found matching the URL and request method.', data: { status: 404 } }, 404);
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
            return plain(fakeEnvFile(), 200);
        }
        if (p.includes('.git/config')) {
            return plain(
                `[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n` +
                `[remote "origin"]\n\turl = ${FAKE_GIT_REMOTE}\n` +
                `\tfetch = +refs/heads/*:refs/remotes/origin/*\n` +
                `[branch "main"]\n\tremote = origin\n\tmerge = refs/heads/main\n`,
                200
            );
        }
        if (p.includes('config.php')) {
            return html(
                `<?php\n/* Database */\ndefine('DB_NAME', 'prod_db');\ndefine('DB_USER', 'wp_user');\n` +
                `define('DB_PASSWORD', '${FAKE_PHP_DB_PASSWORD}');\ndefine('DB_HOST', 'localhost');\n?>`,
                200, phpHeaders()
            );
        }
        if (p.includes('config.json')) {
            return json(fakeConfigJson());
        }
        return plain('', 403);
    },

    // Generic login page — catches /login, /signin, /sign-in, /log-in, /logon
    // Also handles query params like /login?login_only=1 (seen in Finnish bot attacks)
    login(request, _url) {
        if (request.method === 'POST') {
            return json({ success: false, error: 'Invalid username or password.' }, 401);
        }
        return html(`<!DOCTYPE html><html><head><title>Login</title></head><body>
<h2>Login</h2>
<form method="post">
  <label>Username or Email<br><input type="text" name="username" autocomplete="off" style="width:260px"/></label><br><br>
  <label>Password<br><input type="password" name="password" style="width:260px"/></label><br><br>
  <input type="submit" value="Login"/>
</form></body></html>`, 200, { Server: 'nginx/1.18.0' });
    },

    // Simulates a Spring Boot app with Swagger UI and Actuator endpoints
    springboot(_request, url) {
        if (url.pathname.includes('swagger-ui')) {
            return html(`<!DOCTYPE html><html><head><title>Swagger UI</title></head><body>
<h2>Swagger UI</h2><div id="swagger-ui"></div>
<script>const defined_spec = "/v3/api-docs";</script>
</body></html>`, 200, { Server: 'Apache-Coyote/1.1' });
        }
        if (url.pathname.includes('actuator/env')) {
            // Redacted passwords are realistic — real Spring Boot actuator behaviour
            return json({
                activeProfiles: ['prod'],
                propertySources: [{
                    name: 'applicationConfig', properties: {
                        'spring.datasource.url': { value: 'jdbc:mysql://localhost:3306/prod_db' },
                        'spring.datasource.username': { value: 'app_user' },
                        'spring.datasource.password': { value: '****************' },
                        'server.port': { value: '8080' },
                        'jwt.secret': { value: '****************' },
                    }
                }],
            });
        }
        if (url.pathname.includes('v2/api-docs') || url.pathname.includes('v3/api-docs')) {
            return json({
                openapi: '3.0.1',
                info: { title: 'Application API', version: 'v1' },
                servers: [{ url: 'https://api.example.com' }],
                paths: {
                    '/api/v1/users': { get: { summary: 'List users', security: [{ bearerAuth: [] }] } },
                    '/api/v1/login': { post: { summary: 'Authenticate' } },
                    '/api/v1/admin': { get: { summary: 'Admin panel', security: [{ bearerAuth: [] }] } },
                },
            });
        }
        return json({ status: 'UP' });
    },

    // Simulates a payment skimmer target — returns convincing fake JS
    // to keep the scanner engaged and log all follow-up requests
    skimmer(_request, url) {
        const filename = url.pathname.split('/').pop();
        return plain(
            `/* ${filename} */\n(function(){\n  var _c={};\n  function init(){_c.ready=true;}\n  document.addEventListener('DOMContentLoaded',init);\n})();`,
            200,
            { 'Content-Type': 'application/javascript', Server: 'nginx/1.18.0' }
        );
    },

    api(request, url) {
        // CTF Step 2 — reached by decoding SECRET_HINT from the .env file (base64)
        if (url.pathname === '/api/v1/internal/health') {
            return json({ status: 'ok', token: GUEST_JWT });
        }

        // CTF Step 3 — signature is never verified, only decoded payload role is checked
        // Vulnerability: forge a JWT with {"role":"admin"} and any/no signature
        if (url.pathname === '/api/v1/internal/admin') {
            const auth = request.headers.get('Authorization') ?? '';
            const token = auth.replace('Bearer ', '');
            if (token) {
                try {
                    const payload = JSON.parse(atob(token.split('.')[1]));
                    if (payload.role === 'admin') {
                        return json({ flag: CTF_FLAG, message: 'Welcome, admin.' });
                    }
                } catch { }
            }
            return json({ error: 'Forbidden', message: 'Admin role required.' }, 403);
        }

        if (request.method === 'POST' && url.pathname.match(/\/(login|auth|token)/)) {
            return json({ success: false, error: 'Invalid credentials', code: 401 }, 401);
        }
        if (request.method === 'GET') {
            return json({ error: 'Unauthorized', message: 'A valid bearer token is required.', code: 'AUTH_REQUIRED' }, 401, {
                'WWW-Authenticate': 'Bearer realm="api"',
            });
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
        return plain('CGI Error: malformed header from script. Bad header=Content-type: text/html\n', 500, {
            Server: 'Apache/2.2.34 (Unix)',
        });
    },

    'catch-all'(_request, _url) {
        return html(`<!DOCTYPE html><html><head><title>404 Not Found</title></head>
<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p>
<hr><address>Apache/2.4.41 (Ubuntu) Server at Port 443</address></body></html>`, 404, {
            Server: 'Apache/2.4.41 (Ubuntu)',
        });
    },
};
