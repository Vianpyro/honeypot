import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
    LIMITS,
    base64urlDecode,
    base64urlEncode,
    buildPayload,
    canonicalRequest,
    clamp,
    resetDisabledWarning,
    sendEvent,
    signRequest,
} from '../cloudflare/ingest.js';

// The same key and body as api/src/auth.rs's own tests, so the two suites are
// talking about the same thing.
const KEY = 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY';
const TIMESTAMP = '2026-09-01T12:00:00.000Z';
const BODY = new TextEncoder().encode('{"event_id":"01991f0b-5d00-7000-8000-000000000000"}');

// THE CONTRACT TEST. This exact value is asserted by
// api/src/auth.rs::tests::matches_the_worker_reference_vector, so the JavaScript
// signer and the Rust verifier cannot drift apart without one of the two
// suites going red. If you change the canonical string, both fail -- which is
// the point, because the alternative is discovering it as a 403 in production.
const REFERENCE_SIGNATURE = '3T6XgvahXPscTT2Qo0cCwRE2Deo1DDdZwm-U0_r1GUE';

const meta = {
    ip: '203.0.113.7',
    country: 'CA',
    asn: 13335,
    as_organization: 'CLOUDFLARENET',
    tls_version: 'TLSv1.3',
    http_protocol: 'HTTP/2',
    client_tcp_rtt: 42,
    ua: 'curl/8.5.0',
    method: 'POST',
    path: '/wp-login.php',
    query: '?redirect_to=%2Fwp-admin',
    host: 'honeypot.example',
    body: 'log=admin&pwd=hunter2',
    username: 'admin',
    password: 'hunter2',
    service: 'wordpress',
    created_at: '2026-09-01T12:00:00.000Z',
};

test('base64url round-trips without padding', () => {
    const bytes = new Uint8Array([0, 1, 250, 251, 252, 253, 254, 255]);
    const encoded = base64urlEncode(bytes);
    assert.equal(encoded.includes('='), false);
    assert.equal(encoded.includes('+'), false);
    assert.equal(encoded.includes('/'), false);
    assert.deepEqual([...base64urlDecode(encoded)], [...bytes]);
});

test('the canonical string is METHOD, PATH, TIMESTAMP, body hash', () => {
    assert.equal(
        canonicalRequest('POST', '/v1/events', TIMESTAMP, 'abc123'),
        `POST\n/v1/events\n${TIMESTAMP}\nabc123`,
    );
});

test('the signature matches the vector the Rust verifier asserts', async () => {
    const signature = await signRequest(KEY, 'POST', '/v1/events', TIMESTAMP, BODY);
    assert.equal(signature, REFERENCE_SIGNATURE);
});

test('the signature covers the body, the path and the timestamp', async () => {
    const base = await signRequest(KEY, 'POST', '/v1/events', TIMESTAMP, BODY);
    const otherBody = await signRequest(KEY, 'POST', '/v1/events', TIMESTAMP, new TextEncoder().encode('{}'));
    const otherPath = await signRequest(KEY, 'POST', '/v1/other', TIMESTAMP, BODY);
    const otherTime = await signRequest(KEY, 'POST', '/v1/events', '2026-09-01T12:00:01.000Z', BODY);
    assert.notEqual(base, otherBody);
    assert.notEqual(base, otherPath);
    assert.notEqual(base, otherTime);
});

test('the payload carries every field the server declares, and no others', () => {
    const payload = buildPayload(meta, '01991f0b-5d00-7000-8000-000000000000');
    assert.deepEqual(Object.keys(payload).sort(), [
        'as_organization', 'asn', 'body', 'client_tcp_rtt', 'country', 'event_id',
        'host', 'http_protocol', 'ip', 'method', 'observed_at', 'password', 'path',
        'query', 'service', 'tls_version', 'ua', 'username',
    ]);
    assert.equal(payload.observed_at, meta.created_at);
    assert.equal(payload.ip, '203.0.113.7');
});

test('an event with no usable IP is dropped before it costs a subrequest', () => {
    // worker.js falls back to the literal 'unknown' when CF-Connecting-IP is
    // absent, and PostgreSQL's INET cannot hold it.
    assert.equal(buildPayload({ ...meta, ip: 'unknown' }, 'x'), null);
    assert.equal(buildPayload({ ...meta, ip: '' }, 'x'), null);
    assert.equal(buildPayload({ ...meta, method: 'get' }, 'x'), null);
});

test('hostile field lengths are clamped rather than dropped', () => {
    const payload = buildPayload(
        { ...meta, ua: 'A'.repeat(9000), path: `/${'b'.repeat(9000)}`, host: 'h'.repeat(400) },
        'x',
    );
    assert.equal(payload.ua.length, LIMITS.ua);
    assert.equal(payload.path.length, LIMITS.path);
    assert.equal(payload.host.length, LIMITS.host);
    assert.equal(payload.path.startsWith('/'), true);
});

test('clamp removes NUL and never leaves a lone surrogate behind', () => {
    assert.equal(clamp('ad\0min', 100), 'admin');
    // Truncating mid-emoji would otherwise emit an unpaired \uD8xx escape,
    // which serde_json rejects outright.
    const truncated = clamp(`${'a'.repeat(9)}\u{1F600}`, 10);
    assert.equal(truncated, 'a'.repeat(9));
    assert.equal(JSON.parse(JSON.stringify(truncated)), truncated);
});

test('the payload survives JSON round-tripping with hostile input', () => {
    const payload = buildPayload(
        { ...meta, username: `admin\0\u{1F600}`, body: `${'x'.repeat(1999)}\u{1F600}` },
        'x',
    );
    const reparsed = JSON.parse(JSON.stringify(payload));
    assert.equal(reparsed.username.includes('\0'), false);
    assert.ok(reparsed.body.length <= LIMITS.body);
});

test('delivery is inert until the binding and the secret both exist', async () => {
    resetDisabledWarning();
    assert.equal(await sendEvent(meta, {}), 'disabled');
    assert.equal(await sendEvent(meta, { HONEYPOT_API: { fetch: () => {} } }), 'disabled');
    assert.equal(await sendEvent(meta, { HONEYPOT_HMAC_KEY: KEY }), 'disabled');
});

// Success is silent, so "no output" must not be able to mean two things.
test('being switched off says so exactly once per isolate', async () => {
    resetDisabledWarning();
    const said = [];
    const warn = console.warn;
    console.warn = (line) => said.push(line);
    try {
        await sendEvent(meta, {});
        await sendEvent(meta, {});
        await sendEvent(meta, { HONEYPOT_HMAC_KEY: KEY });
    } finally {
        console.warn = warn;
    }
    assert.equal(said.length, 1, 'the warning repeated, or never fired');
    assert.match(said[0], /delivery is OFF/);
    assert.match(said[0], /binding MISSING/);
});

test('a configured delivery signs the exact bytes it sends', async () => {
    let seen;
    const env = {
        HONEYPOT_HMAC_KEY: KEY,
        HONEYPOT_KEY_ID: 'v1',
        HONEYPOT_API: {
            fetch: async (url, init) => {
                seen = { url, init };
                return { status: 201 };
            },
        },
    };
    const status = await sendEvent(meta, env, '01991f0b-5d00-7000-8000-000000000000');
    assert.equal(status, 'created');
    assert.equal(seen.url.endsWith('/v1/events'), true);
    assert.equal(seen.init.headers['X-Honeypot-Key-Id'], 'v1');

    // Re-sign the body that was actually transmitted, with the timestamp that
    // was actually sent. Anything that mutated the payload between signing and
    // sending shows up here.
    const expected = await signRequest(
        KEY, 'POST', '/v1/events',
        seen.init.headers['X-Honeypot-Timestamp'],
        seen.init.body,
    );
    assert.equal(seen.init.headers['X-Honeypot-Signature'], expected);
});

test('a rejection from the API never throws into the D1 path', async () => {
    const env = {
        HONEYPOT_HMAC_KEY: KEY,
        HONEYPOT_API: { fetch: async () => { throw new Error('tunnel down'); } },
    };
    assert.equal(await sendEvent(meta, env), 'unreachable');
    const refusing = {
        HONEYPOT_HMAC_KEY: KEY,
        HONEYPOT_API: { fetch: async () => ({ status: 403 }) },
    };
    assert.equal(await sendEvent(meta, refusing), 'http_403');
});

// The payload's field NAMES are a contract with a struct in another language
// that uses `deny_unknown_fields`: rename one on either side and every event is
// a 400, while both suites stay green. So the struct is read here rather than
// duplicated as a list somebody has to remember to update.
test('the payload fields are exactly the ones the Rust struct declares', async () => {
    const source = await readFile(new URL('../api/src/main.rs', import.meta.url), 'utf8');
    const struct = source.match(/struct EventPayload \{([\s\S]*?)\n\}/);
    assert.ok(struct, 'EventPayload not found in api/src/main.rs');
    const declared = [...struct[1].matchAll(/^\s{4}(\w+):/gm)].map((m) => m[1]).sort();
    const sent = Object.keys(buildPayload(meta, 'x')).sort();
    assert.deepEqual(sent, declared);
});
