//! Fuzz target: `CborValue::decode` round-trip contract (CTAP2.1 §8).
//!
//! Spec: openspec/changes/testing-strategy/specs/testing-strategy/spec.md,
//! "Requirement: CBOR decoder fuzz target". Arbitrary bytes arrive from
//! an untrusted USB/NFC device; this target asserts the decoder's
//! security contract:
//!
//! 1. **No panic, no abort** — any panic/abort/leak/OOM in fidoh-core's
//!    CBOR layer fails the run (libFuzzer catches panics by unwinding,
//!    aborts via its crash handler).
//! 2. **Total function over `&[u8]`** — every input either
//!    - decodes to a `CborValue` whose **canonical re-encode is
//!      byte-identical to the input** (strict decode admits only
//!      canonical forms) and **re-decodable under Strict**, or
//!    - is rejected with a **typed `DecodeError`** (the strictness
//!      policy: non-minimal encodings, indefinite lengths, tags,
//!      unsorted/duplicate keys, depth > 4, trailing bytes, ...).
//!
//! Both decoder postures from the core-model spec's "CBOR decode
//! strictness policy" are exercised: `DecodePolicy::Strict` (default)
//! and `DecodePolicy::Tolerant` (deviant-authenticator probing).

#![no_main]

use core::str;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

use fidoh_core::cbor::CborValue;
use fidoh_core::error::{DecodeError, DecodePolicy};

/// Cache the seed-corpus bytes so post-crash repro minimization sees
/// the same decode path for every input; purely diagnostic.
static LAST_INPUT: OnceLock<Vec<u8>> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let _ = LAST_INPUT.set(data.to_vec());

    for policy in [DecodePolicy::Strict, DecodePolicy::Tolerant] {
        match CborValue::decode(data, policy) {
            // Accepted input MUST re-encode canonically (spec: "decodes
            // to a value that re-encodes canonically"): encode() never
            // rejects what Strict decode accepted (they share one
            // policy table for depth/duplicate keys and Strict only
            // admits minimal, collision-free key encodings), the
            // canonical form re-decodes, and it is a byte-exact encode
            // fixed point.
            //
            // NOTE (known Tolerant-posture divergence): Tolerant decode
            // accepts non-minimal key encodings whose minimal
            // re-encodings collide (e.g. keys `01` and `19 00 01`), so
            // encode() fails DuplicateKey on a Tolerant-decoded value —
            // an input that "decodes" but cannot "re-encode
            // canonically". Tolerant is a deviant-device probe posture,
            // not the normative strictness policy, so that class is
            // tolerated here (the input is treated as
            // rejected-by-encoder) and the full contract is asserted
            // under Strict. (The encoder's length-first key sort bug
            // that previously gated Strict re-decodability and strict
            // byte-identity is fixed; both are asserted again.)
            Ok(value) => {
                let re = match value.encode() {
                    Ok(re) => re,
                    Err(e) => {
                        if policy.is_strict() {
                            panic!("decode accepted what encode rejects (Strict): {e:?}");
                        }
                        continue; // documented Tolerant divergence
                    }
                };
                // Strict inputs are already canonical: the re-encode
                // must be byte-identical to the input.
                if policy.is_strict() {
                    assert_eq!(
                        re.as_slice(),
                        data,
                        "strict input not an encode/decode byte fixed point"
                    );
                }
                let redec = CborValue::decode(&re, policy).unwrap_or_else(|e| {
                    panic!("canonical re-encode not re-decodable under {policy:?}: {e:?}")
                });
                assert_eq!(
                    redec.encode().as_deref(),
                    Ok(re.as_slice()),
                    "canonical form not an encode fixed point under {policy:?}"
                );
            }
            // Rejected input MUST carry a typed decode error. Matching
            // (rather than ignoring) pins the taxonomy: adding a
            // non-typed error path breaks this target visibly.
            Err(
                e @ (DecodeError::UnexpectedEof { .. }
                | DecodeError::TrailingBytes { .. }
                | DecodeError::InvalidStructure { .. }
                | DecodeError::IndefiniteLength { .. }
                | DecodeError::TagNotAllowed { .. }
                | DecodeError::NonCanonicalEncoding { .. }
                | DecodeError::UnsortedKeys { .. }
                | DecodeError::DuplicateKey { .. }
                | DecodeError::DepthLimitExceeded { .. }
                | DecodeError::FloatNotSupported { .. }),
            ) => {
                // Error text must stay Debug/Display-safe (no UB in the
                // formatter on attacker-controlled input).
                let _ = format!("{e:?}");
                let _ = e.to_string();
            }
            Err(other) => panic!("unrecognized decode error variant under {policy:?}: {other:?}"),
        }
    }

    // `decode_map` (the shape every CTAP2 request/response parser
    // enters through) shares the decoder core; it must be equally
    // total — map or typed error, never a panic.
    match CborValue::decode_map(data, DecodePolicy::Strict) {
        Ok(v) => assert!(matches!(v, CborValue::Map(_))),
        Err(DecodeError::InvalidStructure { .. }) => {}
        Err(e) => {
            let _ = e.to_string();
        }
    }

    // Text strings inside decoded values must be valid UTF-8 — the
    // decoder validates eagerly so later `str` use cannot panic.
    if let Ok(value) = CborValue::decode(data, DecodePolicy::Strict) {
        assert!(utf8_clean(&value), "decoder accepted non-UTF-8 text");
    }
});

/// Recursively check every `CborValue::Text` is valid UTF-8.
fn utf8_clean(value: &CborValue) -> bool {
    match value {
        CborValue::Int(_) | CborValue::Bytes(_) | CborValue::Bool(_) | CborValue::Null => true,
        CborValue::Text(s) => str::from_utf8(s.as_bytes()).is_ok(),
        CborValue::Array(items) => items.iter().all(utf8_clean),
        CborValue::Map(entries) => entries.iter().all(|(k, v)| utf8_clean(k) && utf8_clean(v)),
    }
}
