# HoneyLab

A personal honeypot lab built to learn how the internet actually behaves — who scans it, what they look for, and how attack campaigns are structured.

Currently captures ~1 000–12 000 events/day across 45+ countries with zero infrastructure cost, and automatically reports malicious IPs to AbuseIPDB.

<a href="https://www.abuseipdb.com/user/298048" title="AbuseIPDB is an IP address blacklist for webmasters and sysadmins to report IP addresses engaging in abusive behavior on their networks">
  <img src="https://www.abuseipdb.com/contributor/298048.svg" alt="AbuseIPDB Contributor Badge" style="width: 401px;background: #35c246 linear-gradient(rgba(255,255,255,0), rgba(255,255,255,.3) 50%, rgba(0,0,0,.2) 51%, rgba(0,0,0,0)); padding: 5px;">
</a>

**[Live dashboard](https://vianpyro.github.io/honeypot)** — public, updated every 6-24 hours.

---

## Honeypots

| Directory | Platform | Status | What it catches |
|-----------|----------|--------|-----------------|
| [`cloudflare/`](cloudflare/) | Cloudflare Workers + D1 | Live | HTTP scanners, credential stuffers, vulnerability probers |
| `ssh/` | Oracle Cloud Free Tier | Planned | SSH brute force, key spray campaigns |
| `tcp/` | Oracle Cloud Free Tier | Planned | Port scanners, protocol fingerprinting |

---

## Cloudflare HTTP Honeypot

Runs entirely on Cloudflare's free tier — no VPS, no fixed cost.
Simulates common attack surfaces and logs every probe to a D1 SQLite database.

### Simulated services

| Path pattern | Simulated service |
|---|---|
| `/wp-*` | WordPress login, xmlrpc, REST API |
| `/phpmyadmin` | phpMyAdmin login |
| `/.env`, `/.git/config`, `/config.json`, ... | Exposed secrets & credentials |
| `/login`, `/signin`, `/logon` | Generic login (credential stuffing target) |
| `/actuator`, `/v3/api-docs`, `/swagger-ui` | Spring Boot + Swagger |
| `/graphql` | GraphQL introspection |
| `/api/v*/` | REST API + CTF challenge |
| `/admin`, `/dashboard`, `/console` | Admin panel |
| `/telescope`, `/horizon` | Laravel debug panels |
| `/trace.axd` | ASP.NET trace |
| `/debug/default/` | Yii2 debug toolbar |
| `/server-status`, `/server-info` | Apache status |
| `/webmail`, `/roundcube`, `/owa` | Webmail + Exchange |
| `/vpn`, `/fortivpn`, `/+CSCOE\+/` | VPN portals |
| `*` | Catch-all 404 (Apache) |

### Architecture

```
Attacker
   |
   | HTTPS
   v
Cloudflare Router Worker          <- routes by hostname/ASN
   |
   +-- Honeypot Worker (worker.js)
   |      |
   |      +-- Path router -> simulator (simulators.js)
   |      +-- Logger      -> D1 (logger.js)
   |      +-- Campaign detector (campaigns.js)
   |      +-- /stats/api  -> public dashboard
   |
   +-- Nginx (personal services, same domain)
```

### Features

- Extracts and logs credentials submitted via POST (form-encoded and JSON)
- Real-time campaign detection with adaptive Welford threshold
- Pre-aggregated daily rollups — public stats never touch raw event data
- Nightly AbuseIPDB reporting — automatically contributes malicious IPs
- 100-day retention with nightly cleanup cron
- 6-hour public dashboard cache with rolling window

### Deployment

See [`cloudflare/README.md`](cloudflare/README.md) for full setup instructions.

Quick start:

```bash
wrangler d1 create <your-db-name>
wrangler d1 execute <your-db-name> --file=cloudflare/schema.sql
wrangler secret put ADMIN_SECRET
wrangler secret put ABUSEIPDB_KEY
wrangler deploy
```

---

## What I've learned so far

- AS48090 (TECHOFF SRV LIMITED) accounts for the majority of HTTP scanning volume, operating in coordinated bursts of ~150 req/min with URL-encoding WAF evasion.
- Credential stuffers actively recycle credentials extracted from `.env` honeypot responses — within seconds of receiving a fake secret, they replay it on login endpoints.
- ~98% of traffic is automated; the rare human attacker is identifiable by irregular timing, exploratory path sequences, and tool-specific request signatures.
- LeakIX, Shodan, and Palo Alto Cortex Xpanse account for a measurable share of "attacks" and should be allowlisted in any reporting pipeline.

---

## File structure

```
honeypot/
  cloudflare/
    worker.js       <- Entrypoint (fetch, scheduled)
    simulators.js   <- Service simulators
    helpers.js      <- Response helpers
    stats.js        <- Public + private stats API
    logger.js       <- Async D1 event logger
    campaigns.js    <- Real-time campaign detection
    aggregate.js    <- Daily rollup cron
    reporter.js     <- Nightly AbuseIPDB submission
    schema.sql      <- D1 schema
    content.js      <- Fake credentials (KEEP PRIVATE, not in this repo)
  ssh/              <- Coming soon
  tcp/              <- Coming soon
```

> `content.js` is excluded from this repository. It contains fictional credentials unique to this deployment.
> Create your own before deploying — see [`cloudflare/README.md`](cloudflare/README.md).

---

## Legal notice

This project is deployed on infrastructure I own and control.
All captured data is used solely for personal security research and threat intelligence contribution.
Fake credentials are entirely fictional.

---

*By [Vianpyro](https://github.com/Vianpyro) — a cybersecurity student learning by doing.*
