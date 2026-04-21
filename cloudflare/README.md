# Cloudflare Worker Honeypot

A lightweight HTTP honeypot running entirely on Cloudflare's free tier, no VPS required.
It simulates common attack surfaces (WordPress, phpMyAdmin, exposed `.env` files, admin panels, REST APIs, Spring Boot, payment skimmers) and logs every probe to a D1 SQL database.

## Features

- Simulates WordPress, phpMyAdmin, sensitive files (`.env`, `.git/config`, `config.json`, ...), login pages, admin panels, REST APIs, Spring Boot/Swagger, payment skimmer targets, and CGI endpoints
- Extracts and logs credentials submitted via POST (form-encoded and JSON)
- Logs attacker IP, country, ASN, User-Agent, host, path, and timestamp
- Protected stats endpoint (`/hp-stats`) returning aggregated threat intelligence
- Automatic nightly cleanup via Cron Trigger (30-day retention, 50k row cap)
- Modular file structure -- easy to extend with new simulators
- Runs entirely on Cloudflare's free tier (Workers + D1)

## File structure

```
cloudflare/
  worker.js       <- Entrypoint (fetch, scheduled) -- public
  simulators.js   <- All service simulators        -- public
  helpers.js      <- Response helper functions     -- public
  stats.js        <- /hp-stats endpoint            -- public
  logger.js       <- Async D1 event logger         -- public
  schema.sql      <- D1 database schema            -- public
  content.js      <- Fake credentials, CTF flag    -- KEEP PRIVATE
```

`content.js` is the only file that should not be published. It contains all
deployment-specific content: fictional credentials, CTF flags, and any other
values unique to your honeypot instance.

## Simulated services

| Path pattern                                 | Simulator       | Notes                            |
| -------------------------------------------- | --------------- | -------------------------------- |
| `/wp-*`, `//wp-*`                            | WordPress       | Login page, xmlrpc, wlwmanifest  |
| `/phpmyadmin`                                | phpMyAdmin      | Login form                       |
| `/.env`, `/.git/config`, `/config.json`, ... | Sensitive files | Fake credentials                 |
| `/login`, `/signin`, `/logon`                | Login page      | Catches credential stuffing      |
| `/actuator`, `/v3/api-docs`, `/swagger-ui`   | Spring Boot     | Actuator + Swagger UI            |
| `/js/twint_ch.js`, `/bot-connect.js`, ...    | Skimmer         | Fake JS to engage scanners       |
| `/api/v*/`                                   | REST API        | Generic + optional CTF challenge |
| `/admin`, `/dashboard`, `/console`           | Admin panel     | Generic login form               |
| `/cgi-bin`                                   | CGI             | Error response                   |
| `*`                                          | Catch-all       | 404 Apache                       |

## Architecture

```
Internet / attacker
        | HTTPS
        v
Cloudflare Worker (worker.js)
        |
        +-- Path router
        |     +-- /wp-*           -> WordPress simulator
        |     +-- /phpmyadmin     -> phpMyAdmin simulator
        |     +-- /.env / .git    -> Sensitive files simulator
        |     +-- /login          -> Login simulator
        |     +-- /actuator       -> Spring Boot simulator
        |     +-- skimmer paths   -> Skimmer simulator
        |     +-- /api/v*/        -> REST API simulator
        |     +-- /admin/*        -> Admin panel simulator
        |     +-- /cgi-bin/*      -> CGI simulator
        |     +-- *               -> Catch-all (404)
        |
        +-- Logger (async, non-blocking)
        |     +-- D1 SQL database
        |
        +-- /hp-stats             -> Protected stats endpoint
```

## Deployment

### Prerequisites

- A Cloudflare account with a domain
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/) -- recommended, but not required (see Option B below)

---

### Option A -- Wrangler CLI (recommended)

#### 1. Create the D1 database

```bash
wrangler d1 create <your-db-name>
# Copy the database_id from the output into wrangler.toml
```

#### 2. Initialize the schema

```bash
wrangler d1 execute <your-db-name> --file=cloudflare/schema.sql
```

#### 3. Configure `wrangler.toml`

```toml
name = "honeypot"
main = "cloudflare/worker.js"
compatibility_date = "2026-01-01"

[[d1_databases]]
binding = "DB"
database_name = "<your-db-name>"
database_id = "<your-database-id>"
```

#### 4. Set the admin secret

```bash
wrangler secret put ADMIN_SECRET
# Enter a strong secret string when prompted
```

#### 5. Deploy

```bash
wrangler deploy
```

---

### Option B -- Cloudflare Dashboard (no local install required)

1. **Create the Worker**: Workers & Pages -> Create -> Worker -> name it -> Deploy
2. **Paste the code**: click **Edit code** -> create each `.js` file from the `cloudflare/` folder -> set `worker.js` as the entrypoint -> Save & Deploy
3. **Create the D1 database**: Storage & databases -> D1 -> Create database -> name it
4. **Initialize the schema**: open your database -> Console tab -> paste the contents of `cloudflare/schema.sql` -> Execute
5. **Bind D1 to the Worker**: Workers & Pages -> your worker -> Bindings -> Add -> D1 Database -> variable name `DB` -> select your database -> Save
6. **Set the admin secret**: Settings -> Variables and Secrets -> Add -> name `ADMIN_SECRET` -> enter your secret -> check Encrypt -> Save

### Attach custom domains (optional but recommended)

In the Cloudflare dashboard: **Workers & Pages -> your worker -> Settings -> Domains & Routes -> Add custom domain**

Suggested subdomains to attract scanners:

```
api.yourdomain.org
dev.yourdomain.org
git.yourdomain.org
staging.yourdomain.org
```

### Set up the nightly cleanup cron

**Workers & Pages -> your worker -> Settings -> Trigger Events -> Add Cron Trigger**

```
0 4 * * *
```

## Customisation

Before deploying, edit `cloudflare/content.js` and replace all placeholder values
with your own fictional credentials. Every value in that file should be unique to
your deployment -- do not reuse values from this repository.

## Querying your data

Access the stats endpoint:

```bash
curl https://your-worker.workers.dev/hp-stats \
  -H 'X-Admin-Secret: your-secret'
```

Returns JSON with: `recent`, `top_ips`, `top_services`, `top_paths`, `top_creds`, `top_hosts`.

Or query D1 directly in the Cloudflare dashboard console:

```sql
-- Most recent hits with credentials
SELECT created_at, host, country, path, username, password
FROM events
WHERE username IS NOT NULL
ORDER BY created_at DESC
LIMIT 50;

-- Top attacked paths
SELECT path, COUNT(*) c
FROM events
GROUP BY path
ORDER BY c DESC
LIMIT 20;

-- Most active attackers
SELECT ip, country, asn, COUNT(*) c
FROM events
GROUP BY ip
ORDER BY c DESC
LIMIT 20;
```

## Adding a new simulator

1. Create a new function in `simulators.js` following the existing pattern
2. Add a matching entry to the `SIMULATORS` array in `worker.js`
3. If the simulator uses fake credentials or sensitive content, add them to `content.js` and import them

## Legal notice

This honeypot is intended to be deployed on infrastructure you own or control.
Deploying it on systems you do not own, or using it to collect data without
authorisation, may violate applicable laws including the Computer Fraud and Abuse
Act (US) or equivalent legislation in your jurisdiction.

The fake credentials included in the simulators are entirely fictional. Any
resemblance to real credentials is coincidental.

---

_By Vianpyro_
