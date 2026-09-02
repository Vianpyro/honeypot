# honeypot-api

The ingest service between the Cloudflare Worker and PostgreSQL. One endpoint
that matters, `POST /v1/events`, plus `GET /healthz` for the container probe.

## Request contract

```
POST /v1/events
Content-Type: application/json
X-Honeypot-Key-Id: v1
X-Honeypot-Timestamp: 2026-09-02T18:04:11.412Z
X-Honeypot-Signature: <base64url, unpadded, no '=' >
```

The signature is `HMAC-SHA256` over a canonical string, NOT over the raw
request:

```
METHOD \n PATH \n TIMESTAMP \n hex(sha256(BODY))
```

`TIMESTAMP` is the `X-Honeypot-Timestamp` header **byte for byte**, so any
RFC3339 spelling the client prefers works and there is no formatting agreement
to get wrong. `PATH` is `/v1/events`. Both are in the string, so a signature
minted for one endpoint cannot be replayed against another.

The timestamp must be within ±60 s of the server's clock.

### Responses

| Status | Meaning |
|-------:|---------|
| `201` | stored |
| `200` | already stored — same `event_id`, idempotent no-op |
| `400` | malformed JSON, unknown field, missing field |
| `401` | missing/unparseable auth header, or timestamp outside the window |
| `403` | unknown key id, or a signature that does not verify |
| `413` | body over 8 KiB |
| `422` | parsed, but a field is out of range |
| `503` | PostgreSQL unavailable, or the 5 s request deadline blown — retry |

Error bodies are `{"error": "<fixed string>"}`. Nothing derived from the
request, from PostgreSQL or from the key material is ever returned or logged.

### Idempotence

`event_id` becomes `events.ingest_id`, which is `UNIQUE`. The write is a single
`INSERT ... ON CONFLICT (ingest_id) DO NOTHING RETURNING id` — never a `SELECT`
then an `INSERT`, which would leave exactly the window it is meant to close.
The Worker uses `ctx.waitUntil()` and may retry after a timeout that PostgreSQL
already committed; that retry must produce one row and a `200`.

## Configuration

All of it through the environment (see `../.env.example`):

| Variable | Default | |
|---|---|---|
| `DATABASE_URL` | — | required |
| `HONEYPOT_HMAC_KEYS` | — | required, `key-id:base64url-secret[,…]`, ≥ 32-byte secrets |
| `HONEYPOT_BIND` | `0.0.0.0:8080` | |
| `HONEYPOT_RETENTION_DAYS` | `100` | `≤ 0` disables the sweep |
| `HONEYPOT_DB_MAX_CONNECTIONS` | `16` | |
| `RUST_LOG` | `honeypot_api=info,tower_http=warn` | |

## Migrations

`migrations/` is embedded at compile time and applied by the process itself at
startup, under SQLx's advisory lock. **The build needs no database**: every
statement goes through `sqlx::query`, never `sqlx::query!`, so nothing is
checked against a live server at compile time and CI stays reproducible.

Schema changes go in a NEW numbered file. SQLx records a checksum per migration
and refuses one that changed after it was applied.

## Tests

```sh
cargo test                       # auth + validation, no database needed
```

The database tests skip — loudly — without `TEST_DATABASE_URL`. To run the
whole suite against a throwaway PostgreSQL:

```sh
docker run -d --rm --name honeypot-test-pg \
    -e POSTGRES_PASSWORD=test -e POSTGRES_DB=honeypot -p 55432:5432 postgres:18
TEST_DATABASE_URL='postgres://postgres:test@127.0.0.1:55432/honeypot' cargo test
docker stop honeypot-test-pg
```

They run in parallel against one database and do not truncate anything: each
test mints its own `event_id` and asserts only on rows carrying it. Running
`cargo test` twice in a row against the same database must stay green — that is
also the "migrations are repeatable" check.
