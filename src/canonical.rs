//! Canonical-JSON SHA-256 — byte-identical to BaseOracle's `canonicalHash`.
//!
//! The proof-of-context wire format commits to JSON payloads by their
//! canonical-JSON SHA-256 digest. "Canonical" means: object keys sorted,
//! no insignificant whitespace, arrays left in order — the construction in
//! `BaseOracle/src/utils/poc.js` (`sortKeys` + `JSON.stringify` + SHA-256).
//! This module reproduces it in Rust so a Rust verifier computes the *same*
//! 32-byte digest the JavaScript implementations do.
//!
//! The cross-language test vectors at
//! `github.com/asastuai/proof-of-context/test-vectors/v0.1.json` (mirrored in
//! BaseOracle's `test/cross-language-vectors.test.js`) are the source of
//! truth; the unit tests below pin those exact hashes.
//!
//! Key ordering note: JavaScript's `Array.prototype.sort` orders strings by
//! UTF-16 code unit, while Rust's `str` ordering is by Unicode scalar value.
//! These agree for all Basic Multilingual Plane keys (every key in the v0.1
//! wire format is ASCII), so the constructions match. A future revision that
//! admits non-BMP keys would need to revisit this.

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::context::Hash32;

/// Serialize a JSON value to its canonical string form: object keys sorted
/// recursively, arrays kept in order, scalars rendered by `serde_json` (which
/// matches `JSON.stringify` for the number and string shapes in the wire
/// format), with no insignificant whitespace.
///
/// Implemented with explicit recursive key sorting rather than relying on
/// `serde_json::Map`'s default ordering, so the result is correct even if the
/// `preserve_order` feature is enabled somewhere in the dependency graph.
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

/// SHA-256 of the [`canonical_json`] of `value`, as a 32-byte digest.
pub fn canonical_hash(value: &Value) -> Hash32 {
    let json = canonical_json(value);
    Sha256::digest(json.as_bytes()).into()
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                // serde_json renders a string with JSON escaping + quotes,
                // matching JSON.stringify for object keys.
                out.push_str(&Value::String((*k).clone()).to_string());
                out.push(':');
                write_canonical(&map[*k], out);
            }
            out.push('}');
        }
        Value::Array(arr) => {
            out.push('[');
            for (i, v) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(v, out);
            }
            out.push(']');
        }
        // Scalars (string / number / bool / null): serde_json's compact form.
        scalar => out.push_str(&scalar.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three cross-language vectors from the v0.1 wire format. If these
    /// drift, the Rust canonical-hash has diverged from BaseOracle/TrustLayer/
    /// Vigil/PayClaw and cross-implementation verification breaks.
    #[test]
    fn cross_language_vectors() {
        let cases = [
            (
                serde_json::json!({ "token": "ETH", "price_usd": 2500 }),
                "{\"price_usd\":2500,\"token\":\"ETH\"}",
                "5525810608ca0d5ec814d45159e4f11e09a533061f04f4193850b3ca2fc5c453",
            ),
            (
                serde_json::json!({
                    "feed": "ETH/USD",
                    "status": "healthy",
                    "metrics": { "staleness_seconds": 12, "deviation_pct": 0.014 },
                    "sources": ["chainlink", "pyth"]
                }),
                "{\"feed\":\"ETH/USD\",\"metrics\":{\"deviation_pct\":0.014,\"staleness_seconds\":12},\"sources\":[\"chainlink\",\"pyth\"],\"status\":\"healthy\"}",
                "e37d05d4f5f4f3b18ecea8d7e0253aca799ad7e06d3f2c20b6b5cab39769443d",
            ),
            (
                serde_json::json!({}),
                "{}",
                "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            ),
        ];
        for (payload, expected_json, expected_hex) in cases {
            assert_eq!(canonical_json(&payload), expected_json, "canonical JSON drift");
            assert_eq!(hex::encode(canonical_hash(&payload)), expected_hex, "sha256 drift");
        }
    }
}
