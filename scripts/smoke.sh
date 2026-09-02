#!/bin/sh
# End-to-end check of the deployed stack: signs a real event, posts it from the
# `edge` network the way cloudflared will, and verifies it landed in PostgreSQL
# exactly once.
#
# It also asserts the two properties that are easy to lose in a hurried edit and
# invisible until someone scans the host: NOTHING is published on the host, and
# the database container has no route to the internet.
#
# Run it from the project directory (the one holding compose.yml and .env),
# after `docker compose up -d`:
#
#     sh scripts/smoke.sh
#
# The HTTP contract itself -- every status code, the replay window, the field
# limits -- is covered by `cargo test` in api/. This proves the WIRING.

set -eu

PROJECT=honeypot
CURL_IMAGE=curlimages/curl:8.11.1

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok   $*"; }

# --- The two structural properties -------------------------------------------

for container in "${PROJECT}-postgres" "${PROJECT}-api" ; do
    published=$(docker port "$container" 2>/dev/null || true)
    [ -z "$published" ] || fail "$container publishes a host port: $published"
done
pass "no host port is published"

# `internal: true` means no default route at all. Read from /proc, NOT with
# `ip route`: neither image ships iproute2, so `ip route show default` prints
# nothing and an empty-output check passes whatever the network actually is --
# a test that cannot fail. /proc/net/route always exists; a default route is a
# line whose Destination column is 00000000.
for container in "${PROJECT}-postgres" "${PROJECT}-api" ; do
    defaults=$(docker exec "$container" \
        awk 'NR>1 && $2=="00000000" {n++} END {print n+0}' /proc/net/route)
    [ "$defaults" = "0" ] || fail "$container has $defaults default route(s); its networks are not internal"
done
pass "neither postgres nor the API has a route off the host"

# --- Liveness ----------------------------------------------------------------

edge_curl() {
    docker run --rm --network "${PROJECT}_edge" "$CURL_IMAGE" "$@"
}

code=$(edge_curl --silent --output /dev/null --write-out '%{http_code}' \
        http://api:8080/healthz)
[ "$code" = "204" ] || fail "/healthz returned $code, expected 204"
pass "/healthz answers on the edge network"

# --- A real signed event, end to end -----------------------------------------

# The first key id:secret pair from .env, which is what the Worker would use.
[ -f .env ] || fail ".env not found -- run this from the project directory"
keys=$(grep '^HONEYPOT_HMAC_KEYS=' .env | cut -d= -f2-)
key_id=${keys%%:*}
secret=${keys#*:}
secret=${secret%%,*}

# base64url, unpadded -> hex, for `openssl -macopt hexkey:`.
#
# KNOWN, ACCEPTED: `openssl dgst -macopt hexkey:...` puts the signing key on a
# command line, where anything able to read /proc on this host sees it for the
# length of one exec. That is not a leak the API has -- it is this operator
# script's. The hosts it runs on have one administrator, and the alternative
# (openssl cannot read a MAC key from a file) is to ship a signing helper, which
# is more code than the exposure is worth. Do not lift this pattern into
# anything that runs unattended or on a shared machine.
b64url_to_hex() {
    v=$(printf '%s' "$1" | tr '_-' '/+')
    # Re-pad: `openssl base64 -d` needs the '=' the unpadded form drops.
    case $(( ${#v} % 4 )) in
        2) v="${v}==" ;;
        3) v="${v}=" ;;
    esac
    printf '%s' "$v" | openssl base64 -d -A | od -An -tx1 -v | tr -d ' \n'
}

event_id=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n' | sed \
    -E 's/^(.{8})(.{4})(.{3})(.{3})(.{12}).*/\1-\2-7\3-8\4-\5/')
timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
body='{"event_id":"'"$event_id"'","observed_at":"'"$timestamp"'","ip":"203.0.113.9",'
body="$body"'"country":"CA","asn":13335,"as_organization":"CLOUDFLARENET",'
body="$body"'"tls_version":"TLSv1.3","http_protocol":"HTTP/2","client_tcp_rtt":12,'
body="$body"'"ua":"smoke/1.0","method":"GET","path":"/wp-login.php","query":null,'
body="$body"'"host":"honeypot.example","service":"wordpress","body":null,'
body="$body"'"username":null,"password":null}'

body_hash=$(printf '%s' "$body" | openssl dgst -sha256 -hex | sed 's/^.*= *//')
canonical=$(printf 'POST\n/v1/events\n%s\n%s' "$timestamp" "$body_hash")
signature=$(printf '%s' "$canonical" \
    | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$(b64url_to_hex "$secret")" -binary \
    | openssl base64 -A | tr '+/' '-_' | tr -d '=')

post() {
    edge_curl --silent --output /dev/null --write-out '%{http_code}' \
        --request POST http://api:8080/v1/events \
        --header 'Content-Type: application/json' \
        --header "X-Honeypot-Key-Id: $key_id" \
        --header "X-Honeypot-Timestamp: $timestamp" \
        --header "X-Honeypot-Signature: $signature" \
        --data "$body"
}

code=$(post)
[ "$code" = "201" ] || fail "first POST returned $code, expected 201"
pass "a signed event is accepted (201)"

# The Worker's retry after a waitUntil timeout: same event_id, same signature.
code=$(post)
[ "$code" = "200" ] || fail "replayed POST returned $code, expected 200 (duplicate)"
pass "the same event replays as a duplicate (200)"

# An unsigned request must not reach the database at all.
code=$(edge_curl --silent --output /dev/null --write-out '%{http_code}' \
        --request POST http://api:8080/v1/events \
        --header 'Content-Type: application/json' --data "$body")
[ "$code" = "401" ] || fail "unsigned POST returned $code, expected 401"
pass "an unsigned event is refused (401)"

# --- The row, read from PostgreSQL itself ------------------------------------

user=$(grep '^POSTGRES_USER=' .env | cut -d= -f2- || true)
db=$(grep '^POSTGRES_DB=' .env | cut -d= -f2- || true)
rows=$(docker exec "${PROJECT}-postgres" psql -U "${user:-honeypot}" -d "${db:-honeypot}" \
    -tAc "SELECT count(*) FROM events WHERE ingest_id = '${event_id}'")
[ "$rows" = "1" ] || fail "expected exactly 1 row for $event_id, found $rows"
pass "exactly one row in PostgreSQL for the event (idempotent)"

echo "smoke: all checks passed"
