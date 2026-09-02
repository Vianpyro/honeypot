//! Request authentication for `POST /v1/events`.
//!
//! The Worker signs a CANONICAL STRING rather than the raw request, so proxies
//! that rewrite headers or re-chunk the body cannot invalidate a signature that
//! still covers everything that matters:
//!
//!     METHOD \n PATH \n TIMESTAMP \n hex(sha256(BODY))
//!
//! TIMESTAMP IS THE HEADER'S BYTES, VERBATIM -- not a re-serialisation of the
//! parsed value. An earlier version signed
//! `parsed.to_rfc3339_opts(Millis, true)`, which silently required the client
//! to emit exactly three fractional digits and a `Z`: a Worker sending
//! `2026-09-01T12:00:00Z` or `...12:00:00.123456Z` produced a valid timestamp,
//! a valid signature, and a 403. Signing the bytes that were sent removes the
//! agreement-on-formatting problem entirely; the parse is used only for the
//! replay window.
//!
//! The secret never leaves this module and is never formatted into an error.

use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

/// Replay window. A Worker retry after `waitUntil()` timed out happens within
/// seconds; a minute each way covers clock skew between Cloudflare's edge and
/// this host without leaving a captured request usable for long.
pub const MAX_TIMESTAMP_SKEW: Duration = Duration::seconds(60);

/// Bounds the base64 decode and the RFC3339 parse before either runs. Both are
/// linear in their input, and hyper's own per-header limit is far larger than
/// either of these fields can legitimately be.
const MAX_AUTH_HEADER_BYTES: usize = 128;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug)]
pub struct AuthKeys {
    keys: HashMap<String, Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    /// The timestamp header is oversized or not RFC3339.
    MalformedTimestamp,
    /// Parsed, but outside the replay window in either direction.
    Expired,
    /// The signature header is oversized or not base64url.
    MalformedSignature,
    /// No such key id.
    UnknownKey,
    /// Correct shape, wrong MAC.
    InvalidSignature,
}

impl AuthKeys {
    /// `HONEYPOT_HMAC_KEYS` is a comma-separated `key-id:base64url-secret` map.
    /// Several entries are accepted at once so a secret rotation has an overlap
    /// window: the Worker switches `X-Honeypot-Key-Id`, and the old key is
    /// dropped from the environment on the next deploy.
    pub fn from_env(value: &str) -> Result<Self, String> {
        let mut keys = HashMap::new();
        for entry in value.split(',').map(str::trim).filter(|entry| !entry.is_empty()) {
            let (key_id, encoded_key) = entry.split_once(':').ok_or_else(|| {
                "HONEYPOT_HMAC_KEYS must contain key-id:base64url-secret pairs".to_owned()
            })?;
            if key_id.is_empty()
                || !key_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err("HMAC key IDs must be non-empty ASCII identifiers".to_owned());
            }
            let key = URL_SAFE_NO_PAD
                .decode(encoded_key)
                .map_err(|_| "HMAC key is not valid base64url (unpadded)".to_owned())?;
            if key.len() < 32 {
                return Err("HMAC keys must be at least 32 bytes".to_owned());
            }
            if keys.insert(key_id.to_owned(), key).is_some() {
                return Err("HMAC key IDs must be unique".to_owned());
            }
        }
        if keys.is_empty() {
            return Err("HONEYPOT_HMAC_KEYS must contain at least one key".to_owned());
        }
        Ok(Self { keys })
    }

    pub fn verify(
        &self,
        key_id: &str,
        timestamp: &str,
        signature: &str,
        method: &str,
        path: &str,
        body: &[u8],
        now: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        if timestamp.len() > MAX_AUTH_HEADER_BYTES {
            return Err(AuthError::MalformedTimestamp);
        }
        if signature.len() > MAX_AUTH_HEADER_BYTES {
            return Err(AuthError::MalformedSignature);
        }

        let parsed = DateTime::parse_from_rfc3339(timestamp)
            .map_err(|_| AuthError::MalformedTimestamp)?
            .with_timezone(&Utc);
        // Symmetric: a timestamp far in the FUTURE is rejected too. Otherwise a
        // captured request stays replayable until its stated time arrives.
        if (now - parsed).num_seconds().unsigned_abs() > MAX_TIMESTAMP_SKEW.num_seconds() as u64 {
            return Err(AuthError::Expired);
        }

        let key = self.keys.get(key_id).ok_or(AuthError::UnknownKey)?;
        let supplied = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| AuthError::MalformedSignature)?;

        let mut mac = HmacSha256::new_from_slice(key)
            .expect("HMAC takes a key of any length; from_env already enforced >= 32 bytes");
        mac.update(canonical_request(method, path, timestamp, body).as_bytes());
        // `verify_slice` IS the constant-time comparison. Never compare the two
        // tags with `==`: that returns on the first differing byte and leaks the
        // correct prefix one request at a time.
        mac.verify_slice(&supplied).map_err(|_| AuthError::InvalidSignature)
    }
}

pub fn canonical_request(method: &str, path: &str, timestamp: &str, body: &[u8]) -> String {
    let body_hash = hex::encode(Sha256::digest(body));
    format!("{method}\n{path}\n{timestamp}\n{body_hash}")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test-only secrets: 32 ASCII bytes each, base64url unpadded.
    const KEY: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY";
    const OTHER_KEY: &str = "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA";
    const TS: &str = "2026-09-01T12:00:00.000Z";
    const BODY: &[u8] = br#"{"event_id":"01991f0b-5d00-7000-8000-000000000000"}"#;

    fn keys() -> AuthKeys {
        AuthKeys::from_env(&format!("active:{KEY},retired:{OTHER_KEY}")).unwrap()
    }

    fn sign_with(secret: &str, timestamp: &str, body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(&URL_SAFE_NO_PAD.decode(secret).unwrap()).unwrap();
        mac.update(canonical_request("POST", "/v1/events", timestamp, body).as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    fn sign(timestamp: &str, body: &[u8]) -> String {
        sign_with(KEY, timestamp, body)
    }

    fn at(timestamp: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(timestamp).unwrap().with_timezone(&Utc)
    }

    fn verify_at(sig: &str, now: &str) -> Result<(), AuthError> {
        keys().verify("active", TS, sig, "POST", "/v1/events", BODY, at(now))
    }

    #[test]
    fn accepts_a_valid_signature() {
        assert_eq!(verify_at(&sign(TS, BODY), TS), Ok(()));
    }

    /// THE CROSS-LANGUAGE CONTRACT, and the reason this constant is written out
    /// rather than computed on both sides.
    ///
    /// The signer lives in the Worker (cloudflare/ingest.js) and the verifier
    /// lives here. Two implementations of one canonical string drift silently:
    /// a change to the separator, the hash encoding or the timestamp handling
    /// leaves both suites green and produces a 403 in production, on the path
    /// that carries the events.
    ///
    /// test/ingest.test.js asserts this exact string for the same key, body and
    /// timestamp. Changing the canonical format now turns BOTH suites red,
    /// which is the only place that failure is cheap.
    #[test]
    fn matches_the_worker_reference_vector() {
        const REFERENCE: &str = "3T6XgvahXPscTT2Qo0cCwRE2Deo1DDdZwm-U0_r1GUE";
        assert_eq!(sign_with(KEY, TS, BODY), REFERENCE, "the Rust signer moved away from the vector");
        assert_eq!(
            keys().verify("active", TS, REFERENCE, "POST", "/v1/events", BODY, at(TS)),
            Ok(()),
            "the Rust verifier rejects a signature the Worker would send"
        );
    }

    #[test]
    fn accepts_every_configured_key_id() {
        let sig = sign_with(OTHER_KEY, TS, BODY);
        assert_eq!(keys().verify("retired", TS, &sig, "POST", "/v1/events", BODY, at(TS)), Ok(()));
    }

    #[test]
    fn rejects_a_signature_made_with_the_wrong_secret() {
        let sig = sign_with(OTHER_KEY, TS, BODY);
        assert_eq!(verify_at(&sig, TS), Err(AuthError::InvalidSignature));
    }

    #[test]
    fn rejects_an_unknown_key_id() {
        let sig = sign(TS, BODY);
        assert_eq!(
            keys().verify("nope", TS, &sig, "POST", "/v1/events", BODY, at(TS)),
            Err(AuthError::UnknownKey)
        );
    }

    #[test]
    fn rejects_a_malformed_signature() {
        assert_eq!(verify_at("not base64!!", TS), Err(AuthError::MalformedSignature));
        assert_eq!(
            verify_at(&"A".repeat(MAX_AUTH_HEADER_BYTES + 1), TS),
            Err(AuthError::MalformedSignature)
        );
    }

    #[test]
    fn rejects_a_truncated_signature_rather_than_matching_its_prefix() {
        // A well-formed base64url encoding of the CORRECT tag with its last
        // byte removed. `verify_slice` must reject on length rather than
        // conclude that a matching 31-byte prefix is good enough.
        let full = URL_SAFE_NO_PAD.decode(sign(TS, BODY)).unwrap();
        let short = URL_SAFE_NO_PAD.encode(&full[..full.len() - 1]);
        assert_eq!(verify_at(&short, TS), Err(AuthError::InvalidSignature));
    }

    #[test]
    fn rejects_an_expired_timestamp() {
        assert_eq!(verify_at(&sign(TS, BODY), "2026-09-01T12:01:01Z"), Err(AuthError::Expired));
    }

    #[test]
    fn rejects_a_timestamp_too_far_in_the_future() {
        assert_eq!(verify_at(&sign(TS, BODY), "2026-09-01T11:58:59Z"), Err(AuthError::Expired));
    }

    #[test]
    fn accepts_a_timestamp_inside_the_window() {
        assert_eq!(verify_at(&sign(TS, BODY), "2026-09-01T12:00:59Z"), Ok(()));
        assert_eq!(verify_at(&sign(TS, BODY), "2026-09-01T11:59:01Z"), Ok(()));
    }

    #[test]
    fn rejects_a_malformed_timestamp() {
        let sig = sign("yesterday", BODY);
        assert_eq!(
            keys().verify("active", "yesterday", &sig, "POST", "/v1/events", BODY, at(TS)),
            Err(AuthError::MalformedTimestamp)
        );
    }

    /// The signature covers the body hash, so anything appended, removed or
    /// changed after signing fails -- which is what stops anyone on the path
    /// from editing a captured credential into the record.
    #[test]
    fn rejects_a_body_modified_after_signing() {
        let sig = sign(TS, BODY);
        let tampered = br#"{"event_id":"01991f0b-5d00-7000-8000-000000000001"}"#;
        assert_eq!(
            keys().verify("active", TS, &sig, "POST", "/v1/events", tampered, at(TS)),
            Err(AuthError::InvalidSignature)
        );
    }

    /// METHOD and PATH are in the canonical string, so a signature minted for
    /// one endpoint cannot be replayed against another.
    #[test]
    fn rejects_a_signature_bound_to_another_method_or_path() {
        let sig = sign(TS, BODY);
        assert_eq!(
            keys().verify("active", TS, &sig, "GET", "/v1/events", BODY, at(TS)),
            Err(AuthError::InvalidSignature)
        );
        assert_eq!(
            keys().verify("active", TS, &sig, "POST", "/v1/other", BODY, at(TS)),
            Err(AuthError::InvalidSignature)
        );
    }

    /// The canonical string carries the header byte for byte, so any RFC3339
    /// spelling the client chooses works. This is the regression test for the
    /// re-serialisation bug described at the top of this file.
    #[test]
    fn accepts_any_rfc3339_spelling_of_the_same_instant() {
        for spelling in
            ["2026-09-01T12:00:00Z", "2026-09-01T12:00:00.123456Z", "2026-09-01T08:00:00-04:00"]
        {
            let sig = sign_with(KEY, spelling, BODY);
            assert_eq!(
                keys().verify("active", spelling, &sig, "POST", "/v1/events", BODY, at(TS)),
                Ok(()),
                "{spelling}"
            );
        }
    }

    #[test]
    fn rejects_a_key_shorter_than_the_hmac_block() {
        assert!(AuthKeys::from_env("active:c2hvcnQ").is_err());
    }

    #[test]
    fn rejects_an_empty_or_malformed_key_environment() {
        assert!(AuthKeys::from_env("").is_err());
        assert!(AuthKeys::from_env("no-colon-here").is_err());
        assert!(AuthKeys::from_env(&format!("dup:{KEY},dup:{OTHER_KEY}")).is_err());
        assert!(AuthKeys::from_env(&format!("bad id:{KEY}")).is_err());
    }
}
