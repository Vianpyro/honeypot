// ============================================================
//  simulators.js — Service simulators
// ============================================================

import { html, json, plain, phpHeaders } from './helpers.js';
import {
    wpLoginPage, fakeEnvFile, fakeConfigJson, CTF_FLAG, GUEST_JWT, FAKE_GIT_REMOTE, FAKE_PHP_DB_PASSWORD,
    fakeTerraformState, fakeTerraformVars, fakeDockerCompose, fakeAwsCredentials, fakeGcpServiceAccount,
    fakeSshKey, fakeSymfonyParameters, FAKE_PHP_ENV_ROWS, fakeJsConfig
} from './content.js';

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
        if (p.includes('.env') || p === '/env') {
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
        if (p.includes('js/config.js')) {
            return plain(fakeJsConfig(), 200, { 'Content-Type': 'application/javascript' });
        }
        if (p.includes('@vite/env')) {
            // Vite exposes this endpoint in dev mode — bots look for leaked env vars
            return json({
                DEV: false, PROD: true, MODE: 'production',
                VITE_API_URL: 'https://api.example.com',
                VITE_API_KEY: 'vk_live_fAk3V1t3K3y1234567890abcdef',
                VITE_STRIPE_KEY: 'pk_live_FaKeStRiPePublicKey1234567890',
                VITE_SENTRY_DSN: 'https://fakekey@o123456.ingest.sentry.io/789012',
                VITE_SUPABASE_URL: 'https://fakeproject.supabase.co',
                VITE_SUPABASE_ANON: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake',
            });
        }
        if (p.includes('.vscode/sftp.json')) {
            return json({
                name: 'Production', host: '54.210.167.33', port: 22,
                protocol: 'sftp', username: 'deploy',
                privateKeyPath: '/home/deploy/.ssh/id_rsa',
                remotePath: '/var/www/app', uploadOnSave: true,
            });
        }
        return plain('', 403);
    },

    // Simulates PHP info pages — a classic fingerprinting target
    php(_request, _url) {
        return html(`<!DOCTYPE html><html><head><title>phpinfo()</title>
<style>body{background:#fff;font-family:sans-serif}
table{border-collapse:collapse;width:100%}
td{border:1px solid #888;padding:3px 10px;font-size:12px}
.h{background:#9999cc;color:#fff;font-weight:700}
.v{background:#ccccff}.v2{background:#ddddf7}</style></head><body>
<table>
<tr class="h"><td colspan="2">PHP Version 8.1.2</td></tr>
<tr><td class="v">System</td><td class="v2">Linux prod-server 5.15.0-1034-aws #38-Ubuntu SMP</td></tr>
<tr><td class="v">Server API</td><td class="v2">Apache 2.0 Handler</td></tr>
<tr><td class="v">Configuration File</td><td class="v2">/etc/php/8.1/apache2/php.ini</td></tr>
<tr><td class="v">Loaded Extensions</td><td class="v2">mysqli, pdo_mysql, openssl, curl, json, mbstring</td></tr>
<tr class="h"><td colspan="2">Environment</td></tr>
${FAKE_PHP_ENV_ROWS}
</table></body></html>`, 200, phpHeaders());
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

    // Simulates exposed infrastructure-as-code and cloud credential files
    infra(_request, url) {
        const p = url.pathname;

        if (p.includes('terraform.tfstate')) {
            return json(fakeTerraformState());
        }
        if (p.includes('terraform.tfvars')) {
            return plain(fakeTerraformVars(), 200);
        }
        if (p.includes('docker-compose')) {
            return plain(fakeDockerCompose(), 200, { 'Content-Type': 'text/yaml' });
        }
        if (p.includes('.aws/credentials')) {
            return plain(fakeAwsCredentials(), 200);
        }
        if (p.includes('service-account') || p.includes('google-credentials') ||
            p.includes('google-services') || p.includes('firebase-adminsdk')) {
            return json(fakeGcpServiceAccount());
        }
        if (p.includes('id_rsa')) {
            return plain(fakeSshKey(), 200);
        }
        if (p.includes('export.sql')) {
            return plain(
                `-- MySQL dump 8.0.35\n-- Host: localhost\n-- Database: app_prod\n` +
                `CREATE TABLE users (id INT, email VARCHAR(255), password_hash VARCHAR(255));\n` +
                `INSERT INTO users VALUES (1,'admin@example.com','$2y$10$fakehashedpassword');\n`,
                200, { 'Content-Type': 'text/plain' }
            );
        }
        if (p.includes('sftp-config') || p.includes('opencode')) {
            return json({
                type: 'sftp', host: '54.210.167.33', port: 22,
                user: 'deploy', password: 'dep10yP@ss!', remotePath: '/var/www/app',
            });
        }
        // Symfony parameters.yml
        if (p.includes('parameters.yml')) {
            return plain(fakeSymfonyParameters(), 200, { 'Content-Type': 'text/yaml' });
        }
        return plain('', 403);
    },

    // Simulates a GraphQL endpoint — responds to introspection and common queries
    graphql(request, _url) {
        // Introspection query — bots use this to map the schema
        if (request.method === 'POST') {
            return json({
                data: {
                    __schema: {
                        queryType: { name: 'Query' },
                        mutationType: { name: 'Mutation' },
                        types: [
                            {
                                name: 'Query', fields: [
                                    { name: 'user', args: [{ name: 'id', type: { name: 'ID' } }] },
                                    { name: 'users', args: [] },
                                    { name: 'me', args: [] },
                                    { name: 'token', args: [{ name: 'username', type: { name: 'String' } }, { name: 'password', type: { name: 'String' } }] },
                                ]
                            },
                            {
                                name: 'Mutation', fields: [
                                    { name: 'login', args: [{ name: 'username', type: { name: 'String' } }, { name: 'password', type: { name: 'String' } }] },
                                    { name: 'createUser', args: [{ name: 'input', type: { name: 'UserInput' } }] },
                                    { name: 'deleteUser', args: [{ name: 'id', type: { name: 'ID' } }] },
                                ]
                            },
                            {
                                name: 'User', fields: [
                                    { name: 'id' }, { name: 'email' }, { name: 'role' },
                                    { name: 'passwordHash' }, { name: 'apiKey' },
                                ]
                            },
                        ],
                    },
                },
            });
        }
        // GET — return GraphQL playground UI (common on misconfigured servers)
        return html(`<!DOCTYPE html><html><head><title>GraphQL Playground</title></head><body>
<div id="root"><p>Loading GraphQL Playground...</p></div>
<script>window.GRAPHQL_ENDPOINT = '/graphql';</script>
</body></html>`, 200, { Server: 'nginx/1.18.0' });
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

    // Simulates a webmail server — Roundcube is the most common target
    mail(request, url) {
        const p = url.pathname;
        if (p.includes('roundcube') || p === '/webmail' || p === '/mail' || p === '/') {
            if (request.method === 'POST') {
                return json({ status: 'error', message: 'Login failed. Invalid username or password.' }, 401);
            }
            return html(`<!DOCTYPE html><html><head><title>Roundcube Webmail</title></head><body>
<div style="max-width:340px;margin:60px auto;font-family:sans-serif">
  <h2 style="color:#333">Roundcube Webmail</h2>
  <form method="post">
    <p><label>Username<br><input type="text" name="_user" style="width:100%;padding:.4rem"/></label></p>
    <p><label>Password<br><input type="password" name="_pass" style="width:100%;padding:.4rem"/></label></p>
    <p><input type="submit" value="Login" style="background:#005b99;color:#fff;border:none;padding:.5rem 1.5rem;cursor:pointer"/></p>
  </form>
</div></body></html>`, 200, { Server: 'Apache/2.4.41 (Ubuntu)', 'X-Powered-By': 'PHP/8.1.2' });
        }
        if (p.includes('autodiscover') || p.includes('owa') || p.includes('exchange')) {
            return html(`<!DOCTYPE html><html><head><title>Outlook Web Access</title></head><body>
<div style="max-width:340px;margin:60px auto;font-family:sans-serif">
  <h2>Outlook Web Access</h2>
  <form method="post">
    <p><label>Domain\\Username<br><input type="text" name="username" style="width:100%;padding:.4rem"/></label></p>
    <p><label>Password<br><input type="password" name="password" style="width:100%;padding:.4rem"/></label></p>
    <p><input type="submit" value="Sign in" style="background:#0078d4;color:#fff;border:none;padding:.5rem 1.5rem;cursor:pointer"/></p>
  </form>
</div></body></html>`, 200, { Server: 'Microsoft-IIS/10.0', 'X-Powered-By': 'ASP.NET' });
        }
        return plain('', 404);
    },

    // Simulates a VPN login portal — covers Cisco, Fortinet, Palo Alto, Citrix
    vpn(request, url) {
        const p = url.pathname;
        if (request.method === 'POST') {
            return json({ status: 'failed', message: 'Authentication failed. Invalid credentials.' }, 401);
        }
        if (p.includes('fortivpn') || p.includes('remote')) {
            return html(`<!DOCTYPE html><html><head><title>FortiGate SSL VPN</title></head><body>
<div style="max-width:340px;margin:60px auto;font-family:sans-serif">
  <h2 style="color:#c0392b">FortiGate SSL VPN</h2>
  <form method="post">
    <p><label>Username<br><input type="text" name="username" style="width:100%;padding:.4rem"/></label></p>
    <p><label>Password<br><input type="password" name="credential" style="width:100%;padding:.4rem"/></label></p>
    <p><input type="submit" value="Sign In" style="background:#c0392b;color:#fff;border:none;padding:.5rem 1.5rem;cursor:pointer"/></p>
  </form>
</div></body></html>`, 200, { Server: 'xxxxxxxx-xxxxx', 'X-Frame-Options': 'SAMEORIGIN' });
        }
        // Default: Cisco AnyConnect
        return html(`<!DOCTYPE html><html><head><title>Cisco AnyConnect</title></head><body>
<div style="max-width:340px;margin:60px auto;font-family:sans-serif">
  <h2 style="color:#049fd9">Cisco AnyConnect Secure Mobility</h2>
  <form method="post" action="/+webvpn+/index.html">
    <p><label>Username<br><input type="text" name="username" style="width:100%;padding:.4rem"/></label></p>
    <p><label>Password<br><input type="password" name="password" style="width:100%;padding:.4rem"/></label></p>
    <p><input type="submit" value="Login" style="background:#049fd9;color:#fff;border:none;padding:.5rem 1.5rem;cursor:pointer"/></p>
  </form>
</div></body></html>`, 200, { Server: 'Cisco HTTP Server' });
    },

    // Simulates a CDN / object storage endpoint — returns plausible-looking asset listings
    cdn(_request, url) {
        const p = url.pathname;
        // Simulate an open S3-style bucket listing
        if (p === '/files' || p === '/storage' || p === '/s3' || p === '/') {
            return plain(
                `<?xml version="1.0" encoding="UTF-8"?>\n` +
                `<ListBucketResult>\n  <Name>my-app-prod-bucket</Name>\n  <Prefix></Prefix>\n` +
                `  <Contents><Key>uploads/avatar_1.jpg</Key><Size>24601</Size></Contents>\n` +
                `  <Contents><Key>uploads/backup_2024.sql.gz</Key><Size>1048576</Size></Contents>\n` +
                `  <Contents><Key>private/config.env</Key><Size>512</Size></Contents>\n` +
                `  <Contents><Key>private/id_rsa</Key><Size>3247</Size></Contents>\n` +
                `</ListBucketResult>`,
                200, { 'Content-Type': 'application/xml', Server: 'AmazonS3' }
            );
        }
        // Simulate a 403 for direct asset access — realistic CDN behaviour
        return plain('Access Denied', 403, { Server: 'AmazonS3' });
    },

    'catch-all'(_request, _url) {
        return html(`<!DOCTYPE html><html><head><title>404 Not Found</title></head>
<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p>
<hr><address>Apache/2.4.41 (Ubuntu) Server at Port 443</address></body></html>`, 404, {
            Server: 'Apache/2.4.41 (Ubuntu)',
        });
    },
};
