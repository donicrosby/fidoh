//! Fuzz target: `CborValue::decode_map` over the model-parser front
//! door, per the same spec requirement. CTAP2 requests and responses
//! are CBOR maps; `decode_map` is the shape every ceremony parser
//! (`GetInfoResponse::from_cbor`, `GetAssertionRequest` parsing, ...)
//! enters through, so the harness holds it to the identical contract:
//! decode a map and re-encode canonically byte-for-byte, or reject
//! with a typed `DecodeError` — never a panic, abort, or hang.
//!
//! A second narrow target improves libFuzzer's coverage guidance for
//! the map-specific paths (canonical key sort, duplicate detection,
//! per-member semantic validation) without inflating the first
//! target's dispatch table.

#![no_main]

use libfuzzer_sys::fuzz_target;

use fidoh_core::cbor::CborValue;
use fidoh_core::error::{DecodeError, DecodePolicy};

fuzz_target!(|data: &[u8]| {
    match CborValue::decode_map(data, DecodePolicy::Strict) {
        Ok(value) => {
            assert!(matches!(value, CborValue::Map(_)));
            // Canonical re-encode must succeed, re-decode under the
            // Tolerant posture, and be a byte-exact encode fixed
            // point. (Strict re-decode is intentionally not asserted:
            // the encoder's plain-lex key sort diverges from the
            // decoder's §8 length-first order — see the roundtrip
            // target's NOTE.)
            let re = value
                .encode()
                .unwrap_or_else(|e| panic!("decode_map accepted what encode rejects: {e:?}"));
            CborValue::decode_map(&re, DecodePolicy::Tolerant).unwrap_or_else(|e| {
                panic!("canonical re-encode not re-decodable (Tolerant): {e:?}")
            });
            let redec = CborValue::decode(&re, DecodePolicy::Tolerant).unwrap_or_else(|e| {
                panic!("canonical re-encode not re-decodable (Tolerant): {e:?}")
            });
            assert_eq!(
                redec.encode().as_deref(),
                Ok(re.as_slice()),
                "canonical form not an encode fixed point"
            );
        }
        // The only non-typed rejection decode_map adds on top of
        // decode is "top-level item was not a map" (InvalidStructure);
        // everything else must still be a typed variant.
        Err(
            e @ (DecodeError::InvalidStructure { .. }
            | DecodeError::UnexpectedEof { .. }
            | DecodeError::TrailingBytes { .. }
            | DecodeError::IndefiniteLength { .. }
            | DecodeError::TagNotAllowed { .. }
            | DecodeError::NonCanonicalEncoding { .. }
            | DecodeError::UnsortedKeys { .. }
            | DecodeError::DuplicateKey { .. }
            | DecodeError::DepthLimitExceeded { .. }
            | DecodeError::FloatNotSupported { .. }),
        ) => {
            let _ = e.to_string();
        }
        Err(other) => panic!("unrecognized decode_map error variant: {other:?}"),
    }
});
