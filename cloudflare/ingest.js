// ============================================================
//  ingest.js — HMAC-signed delivery to the PostgreSQL API
// ============================================================
//
// The second half of a DUAL WRITE. D1 remains the source of truth; this sends
// the same event through the Cloudflare Tunnel to honeypot-api, which writes it
// to PostgreSQL. Nothing here may delay or fail the D1 path -- see logger.js.
//
// It is OFF unless configured. No boolean flag: the presence of the VPC binding
// and the signing secret IS the flag, so a Worker deployed without them behaves
// exactly as it did before.
//
// WIRING (Cloudflare dashboard, not in this repository):
//   - a Workers VPC service binding named HONEYPOT_API, pointing at the
//     `honeypot` VPC service (HTTP, host `api`, port 8080);
//   - a secret HONEYPOT_HMAC_KEY -- the base64url secret HALF of one
//     `key-id:secret` pair from the server's HONEYPOT_HMAC_KEYS;
//   - a plain variable HONEYPOT_KEY_ID matching that pair's id (default 'v1').

const PATH = '/v1/events';

// Mirror of the server's own validation (api/src/main.rs). Values are clamped
// to these lengths BEFORE sending, because the honeypot is fed hostile input by
// design: a scanner with a 9 KB User-Agent would otherwise produce a 422, the
// event would be missing from PostgreSQL while D1 kept it, and the divergence
// would be silent. Clamping loses the tail of one field; dropping loses the
// event. D1 still holds the untruncated value.
export const LIMITS = {
    as_organization: 512,
    ua: 2048,
    path: 2048,
    query: 2048,
    host: 253,
    body: 2000,
    username: 2000,
    password: 2000,
    service: 64,
};

const encoder = new TextEncoder();

export function base64urlEncode(bytes) {
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64urlDecode(value) {
    const padded = value.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

function hex(bytes) {
    return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

// Clamp to a length the server accepts, and remove the two things that are
// legal in JSON and impossible downstream:
//
//   - NUL, which PostgreSQL cannot store in a TEXT column at all;
//   - a lone high surrogate left behind by truncating mid-emoji, which
//     JSON.stringify would emit as an unpaired \uD8xx escape and serde_json
//     would reject -- turning a long User-Agent into a 400.
export function clamp(value, limit) {
    if (value === null || value === undefined) return null;
    let text = String(value).replace(/\0/g, '');
    if (text.length > limit) {
        text = text.slice(0, limit);
        const last = text.charCodeAt(text.length - 1);
        if (last >= 0xd800 && last <= 0xdbff) text = text.slice(0, -1);
    }
    return text;
}

// The canonical string the signature covers. It MUST match
// api/src/auth.rs::canonical_request byte for byte:
//
//     METHOD \n PATH \n TIMESTAMP \n hex(sha256(BODY))
//
// TIMESTAMP is the X-Honeypot-Timestamp header exactly as sent -- the server
// signs the bytes it received rather than re-serialising the parsed value, so
// there is no formatting convention for the two sides to disagree about.
export function canonicalRequest(method, path, timestamp, bodyHashHex) {
    return `${method}\n${path}\n${timestamp}\n${bodyHashHex}`;
}

export async function signRequest(secretBase64url, method, path, timestamp, bodyBytes) {
    const digest = await crypto.subtle.digest('SHA-256', bodyBytes);
    const canonical = canonicalRequest(method, path, timestamp, hex(new Uint8Array(digest)));
    const key = await crypto.subtle.importKey(
        'raw',
        base64urlDecode(secretBase64url),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign'],
    );
    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(canonical));
    return base64urlEncode(new Uint8Array(signature));
}

// Every field the server's `deny_unknown_fields` payload declares, always
// present, `null` where absent. Returns null when the event cannot be
// represented at all, so the caller skips a request it knows will be refused.
export function buildPayload(meta, eventId) {
    // `meta.ip` falls back to the literal 'unknown' when CF-Connecting-IP is
    // missing (worker.js). PostgreSQL's INET has no room for that, so the event
    // is dropped here rather than spending a subrequest on a guaranteed 400.
    // D1 keeps it, which is the whole point of dual-writing.
    if (!meta.ip || !/^[0-9a-fA-F:.]+$/.test(meta.ip)) return null;
    // Cloudflare always gives a standard method, but the column is
    // `CHECK (method ~ '^[A-Z]{1,16}$')` and this is cheaper than a 422.
    if (!/^[A-Z]{1,16}$/.test(meta.method ?? '')) return null;

    return {
        event_id: eventId,
        observed_at: meta.created_at,
        ip: meta.ip,
        // 'XX' is worker.js's fallback and satisfies the server's ^[A-Z]{2}$,
        // so it travels as-is: an unknown country is data, not an error.
        country: clamp(meta.country, 2),
        asn: meta.asn ?? null,
        as_organization: clamp(meta.as_organization, LIMITS.as_organization),
        tls_version: clamp(meta.tls_version, 32),
        http_protocol: clamp(meta.http_protocol, 32),
        client_tcp_rtt: meta.client_tcp_rtt ?? null,
        ua: clamp(meta.ua, LIMITS.ua),
        method: meta.method,
        path: clamp(meta.path, LIMITS.path),
        query: clamp(meta.query, LIMITS.query),
        host: clamp(meta.host, LIMITS.host),
        service: clamp(meta.service, LIMITS.service),
        body: clamp(meta.body, LIMITS.body),
        username: clamp(meta.username, LIMITS.username),
        password: clamp(meta.password, LIMITS.password),
    };
}

// Delivers one event. NEVER THROWS and never rejects: the caller starts it
// concurrently with the D1 write and awaits it afterwards, so a rejection that
// escaped would surface as an unhandled rejection in a request the visitor is
// already being served.
//
// Returns a short status string, which is what makes the dual-write period
// measurable in Workers Logs: 'created' and 'duplicate' are successes,
// anything else is the failure rate we need before cutting over.
//
// `eventId` is a parameter, not a local: it is the server's idempotency key, so
// a retry MUST reuse it. There is deliberately no retry yet -- one attempt,
// and the failure rate this reports is what decides whether one is worth a
// second subrequest.
export async function sendEvent(meta, env, eventId = crypto.randomUUID()) {
    const binding = env.HONEYPOT_API;
    const secret = env.HONEYPOT_HMAC_KEY;
    if (!binding || !secret) return 'disabled';

    try {
        const payload = buildPayload(meta, eventId);
        if (!payload) return 'unrepresentable';

        // Serialised ONCE. The signature covers these exact bytes, and sending
        // a second stringify would be a different body if key order ever moved.
        const bodyBytes = encoder.encode(JSON.stringify(payload));
        const timestamp = new Date().toISOString();
        const signature = await signRequest(secret, 'POST', PATH, timestamp, bodyBytes);

        // The hostname is ignored by the VPC binding, which routes to the
        // service's configured host and port. The PATH is not: it is in the
        // canonical string above and the server checks it.
        const response = await binding.fetch(`http://honeypot-api${PATH}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Honeypot-Key-Id': env.HONEYPOT_KEY_ID ?? 'v1',
                'X-Honeypot-Timestamp': timestamp,
                'X-Honeypot-Signature': signature,
            },
            body: bodyBytes,
        });

        if (response.status === 201) return 'created';
        if (response.status === 200) return 'duplicate';
        // The status only. The body is a fixed server-side string, and logging
        // anything derived from the event would put captured credentials into
        // Workers Logs.
        console.error(`[honeypot] ingest API returned ${response.status}`);
        return `http_${response.status}`;
    } catch (error) {
        console.error('[honeypot] ingest API unreachable:', error.message);
        return 'unreachable';
    }
}
