//! Canonical CBOR model, encoder, and strict/tolerant decoder.
//!
//! Implements CTAP2.1 §8 ("CBOR encoding and decoding"):
//!
//! - **Integer/length minimality** — every integer and every length in
//!   major types 2–5 is encoded in the smallest permitted form
//!   (§8, "Integer representation" and length rule).
//! - **Definite length only** — no indefinite-length items are emitted;
//!   they are rejected on decode in *both* postures (§8: indefinite
//!   items MUST be made definite).
//! - **No tags** — major type 6 is never emitted and always rejected on
//!   decode (§8: tags "MUST NOT be present").
//! - **Sorted map keys** — keys sort lowest-to-highest by
//!   (major type, encoded length, byte-wise lexical order) of their
//!   canonical encodings (§8 map-key ordering rule).
//! - **No duplicate map keys** — never emitted; rejected on decode in
//!   both postures (§8 SHOULD-reject; duplicate keys are a semantic
//!   ambiguity, not an encoding-form deviation).
//! - **Nesting depth ≤ 4** — enforced on encode before serialization
//!   and on decode in both postures (§8 nesting limit).
//!
//! ## Why a hand-rolled canonical layer instead of serde_cbor
//!
//! The manifest ships serde_cbor, but it cannot enforce several §8
//! rules natively, and serde_cbor 0.11's built-in no_std support is
//! limited (its `alloc` feature arrived in serde_cbor 2.x). Concretely:
//!
//! - serde_cbor's serializer always packs integers minimally, but map
//!   ordering depends on the serialized data structure — BTreeMap
//!   ordering does NOT match the CTAP2 canonical key order
//!   (length-first byte-wise lexical), so sorted-key emission needs a
//!   dedicated canonicalization pass.
//! - serde_cbor's deserializer happily accepts indefinite-length items
//!   and non-minimal arguments; strict rejection of those (and of tags,
//!   unsorted keys, and depth > 4) is not configurable.
//!
//! Per the task allowance ("implement a small canonical layer on top"),
//! encoding and decoding are therefore implemented directly against the
//! CTAP2.1 §8 rules, citing the requirement each check enforces.

use alloc::borrow::ToOwned;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{DecodeError, DecodePolicy, EncodeError};

/// Maximum nesting of CBOR maps/arrays (CTAP2.1 §8).
pub const MAX_DEPTH: u32 = 4;

/// A CBOR data item, restricted to the subset CTAP2.1 §8 messages use.
///
/// Negative integers are represented as a single `i128` plane so that
/// the canonical key sort (which operates on encodings) never has to
/// reason about two's complement. No tags (§8) and no floats — no
/// v1-scope message uses floats (design Q1); a float on the wire is a
/// typed decode error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CborValue {
    /// Unsigned (>= 0) or negative (< 0) integer.
    Int(i128),
    /// Byte string (major type 2).
    Bytes(Vec<u8>),
    /// Text string (major type 3).
    Text(String),
    /// Array (major type 4).
    Array(Vec<CborValue>),
    /// Map (major type 5). Iteration order is irrelevant; encoding
    /// always applies the canonical key sort.
    Map(Vec<(CborValue, CborValue)>),
    /// `false` / `true` (major type 7, simple values 20/21).
    Bool(bool),
    /// `null` (major type 7, simple value 22).
    Null,
}

impl CborValue {
    /// The CBOR major type (0–7) of this value's top-level item.
    pub fn major_type(&self) -> u8 {
        match self {
            Self::Int(n) if *n >= 0 => 0,
            Self::Int(_) => 1,
            Self::Bytes(_) => 2,
            Self::Text(_) => 3,
            Self::Array(_) => 4,
            Self::Map(_) => 5,
            Self::Bool(_) | Self::Null => 7,
        }
    }

    /// Encode this value in the CTAP2 canonical CBOR encoding form
    /// (CTAP2.1 §8). Returns an error if the structure nests deeper
    /// than 4 levels or a map contains duplicate keys — both rejected
    /// *before* serialization, per the spec scenarios.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::new();
        encode_value(self, 0, &mut out)?;
        Ok(out)
    }

    /// Decode a single top-level item from `bytes` under `policy`.
    /// Trailing bytes after the item are an error (CTAP2 messages carry
    /// exactly one top-level item per message, §8).
    pub fn decode(bytes: &[u8], policy: DecodePolicy) -> Result<Self, DecodeError> {
        let mut dec = Decoder::new(bytes, policy);
        let value = dec.value(0)?;
        if dec.pos != bytes.len() {
            return Err(DecodeError::TrailingBytes { offset: dec.pos });
        }
        Ok(value)
    }

    /// Decode a top-level CBOR **map** under `policy`. Any other
    /// top-level type is a structure error.
    pub fn decode_map(bytes: &[u8], policy: DecodePolicy) -> Result<Self, DecodeError> {
        match Self::decode(bytes, policy)? {
            map @ Self::Map(_) => Ok(map),
            other => Err(DecodeError::InvalidStructure {
                offset: 0,
                detail: match other.major_type() {
                    0 | 1 => "expected a CBOR map, found an integer",
                    2 => "expected a CBOR map, found a byte string",
                    3 => "expected a CBOR map, found a text string",
                    4 => "expected a CBOR map, found an array",
                    _ => "expected a CBOR map, found a simple value",
                },
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Append the minimal-length argument encoding for `arg` under major
/// type `major` (CTAP2.1 §8 integer/length minimality).
fn write_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let mt = major << 5;
    if arg < 24 {
        out.push(mt | arg as u8);
    } else if arg <= 0xFF {
        out.push(mt | 24);
        out.push(arg as u8);
    } else if arg <= 0xFFFF {
        out.push(mt | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= 0xFFFF_FFFF {
        out.push(mt | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

fn encode_value(value: &CborValue, depth: u32, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    // CTAP2.1 §8: no more than 4 levels of nested maps/arrays. The
    // top-level container sits at depth 0; children at depth+1. A
    // container opened at depth == MAX_DEPTH would be level 5.
    if depth >= MAX_DEPTH && matches!(value, CborValue::Array(_) | CborValue::Map(_)) {
        return Err(EncodeError::DepthLimitExceeded);
    }
    match value {
        CborValue::Int(n) if *n >= 0 => write_head(out, 0, *n as u64),
        CborValue::Int(n) => {
            // n is negative; the argument is -1 - n (RFC 8949 §3.1).
            write_head(out, 1, (-1 - *n) as u64)
        }
        CborValue::Bytes(b) => {
            write_head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        CborValue::Text(s) => {
            write_head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        CborValue::Array(items) => {
            write_head(out, 4, items.len() as u64);
            for item in items {
                encode_value(item, depth + 1, out)?;
            }
        }
        CborValue::Map(entries) => {
            write_head(out, 5, entries.len() as u64);
            let mut keys: Vec<(Vec<u8>, &CborValue)> = Vec::with_capacity(entries.len());
            for (k, v) in entries {
                keys.push((encode_value_vec(k, depth + 1)?, v));
            }
            // Encoders MUST NOT emit duplicate map keys (CTAP2.1 §8).
            keys.sort_by(|a, b| a.0.cmp(&b.0));
            for pair in keys.windows(2) {
                if pair[0].0 == pair[1].0 {
                    return Err(EncodeError::DuplicateKey);
                }
            }
            for (key_bytes, v) in keys {
                out.extend_from_slice(&key_bytes);
                encode_value(v, depth + 1, out)?;
            }
        }
        CborValue::Bool(false) => out.push(0xF4),
        CborValue::Bool(true) => out.push(0xF5),
        CborValue::Null => out.push(0xF6),
    }
    Ok(())
}

fn encode_value_vec(value: &CborValue, depth: u32) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    encode_value(value, depth, &mut out)?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Canonical ordering of two already-encoded keys per CTAP2.1 §8:
/// shorter encoded key first, then byte-wise lexical order. (Major
/// type precedes length implicitly: a higher major type always encodes
/// to a higher leading byte for equal lengths, and shorter sorts first.)
pub(crate) fn canonical_key_cmp(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
    policy: DecodePolicy,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8], policy: DecodePolicy) -> Self {
        Self {
            bytes,
            pos: 0,
            policy,
        }
    }

    fn value(&mut self, depth: u32) -> Result<CborValue, DecodeError> {
        let offset = self.pos;
        let initial = *self
            .bytes
            .get(self.pos)
            .ok_or(DecodeError::UnexpectedEof { offset })?;
        self.pos += 1;
        let major = initial >> 5;
        let info = initial & 0x1F;

        match major {
            0 | 1 => {
                let arg = self.argument(info, offset)?;
                let n = i128::from(arg);
                Ok(CborValue::Int(if major == 0 { n } else { -1 - n }))
            }
            2 | 3 => {
                let len = self.length_argument(info, offset)?;
                let end = self
                    .pos
                    .checked_add(len)
                    .ok_or(DecodeError::InvalidStructure {
                        offset,
                        detail: "length overflows address space",
                    })?;
                if end > self.bytes.len() {
                    return Err(DecodeError::UnexpectedEof { offset: self.pos });
                }
                let raw = &self.bytes[self.pos..end];
                self.pos = end;
                if major == 2 {
                    Ok(CborValue::Bytes(raw.to_vec()))
                } else {
                    let text =
                        core::str::from_utf8(raw).map_err(|_| DecodeError::InvalidStructure {
                            offset,
                            detail: "text string is not valid UTF-8",
                        })?;
                    Ok(CborValue::Text(text.to_owned()))
                }
            }
            4 => {
                // CTAP2.1 §8 nesting limit (both postures).
                if depth >= MAX_DEPTH {
                    return Err(DecodeError::DepthLimitExceeded { offset });
                }
                let len = self.length_argument(info, offset)?;
                let mut items = Vec::with_capacity(len.min(1024));
                for _ in 0..len {
                    items.push(self.value(depth + 1)?);
                }
                Ok(CborValue::Array(items))
            }
            5 => {
                if depth >= MAX_DEPTH {
                    return Err(DecodeError::DepthLimitExceeded { offset });
                }
                let len = self.length_argument(info, offset)?;
                let mut entries: Vec<(CborValue, CborValue)> = Vec::with_capacity(len.min(1024));
                let mut seen: BTreeMap<Vec<u8>, ()> = BTreeMap::new();
                let mut prev_key: Option<Vec<u8>> = None;
                for _ in 0..len {
                    let key_offset = self.pos;
                    let key = self.value(depth + 1)?;
                    let key_bytes = self.bytes[key_offset..self.pos].to_vec();
                    // Duplicate keys are a semantic ambiguity: rejected in
                    // both postures (CTAP2.1 §8 duplicate-key SHOULD-reject).
                    if seen.insert(key_bytes.clone(), ()).is_some() {
                        return Err(DecodeError::DuplicateKey { offset });
                    }
                    // Sorted map keys: strict decode enforces the §8
                    // canonical order; tolerant decode accepts any order.
                    if self.policy.is_strict() {
                        if let Some(prev) = &prev_key {
                            if canonical_key_cmp(prev, &key_bytes) != core::cmp::Ordering::Less {
                                return Err(DecodeError::UnsortedKeys { offset: key_offset });
                            }
                        }
                    }
                    prev_key = Some(key_bytes);
                    let val = self.value(depth + 1)?;
                    entries.push((key, val));
                }
                Ok(CborValue::Map(entries))
            }
            6 => {
                // CTAP2.1 §8: tags MUST NOT be present. Rejected in both
                // postures — a tag cannot be resolved to definite form.
                let tag = self.argument_lenient(info, offset)?;
                Err(DecodeError::TagNotAllowed { offset, tag })
            }
            _ => self.simple(info, offset),
        }
    }

    /// Read the argument of an integer (major 0/1), enforcing minimality
    /// under strict decode (CTAP2.1 §8 integer minimality).
    fn argument(&mut self, info: u8, offset: usize) -> Result<u64, DecodeError> {
        self.argument_impl(info, offset, self.policy.is_strict())
    }

    /// Read a length argument for major types 2–5. Indefinite-length
    /// items (info 31) are rejected in both postures (CTAP2.1 §8:
    /// definite-length only).
    fn length_argument(&mut self, info: u8, offset: usize) -> Result<usize, DecodeError> {
        if info == 31 {
            return Err(DecodeError::IndefiniteLength { offset });
        }
        let arg = self.argument_impl(info, offset, self.policy.is_strict())?;
        usize::try_from(arg).map_err(|_| DecodeError::InvalidStructure {
            offset,
            detail: "length does not fit in usize",
        })
    }

    /// Argument read without the minimality check (used only to surface
    /// the tag number in a `TagNotAllowed` error).
    fn argument_lenient(&mut self, info: u8, offset: usize) -> Result<u64, DecodeError> {
        self.argument_impl(info, offset, false)
    }

    fn argument_impl(&mut self, info: u8, offset: usize, strict: bool) -> Result<u64, DecodeError> {
        match info {
            0..=23 => Ok(u64::from(info)),
            24 => {
                let v = self.take::<1>(offset)?[0];
                if strict && v < 24 {
                    return Err(DecodeError::NonCanonicalEncoding { offset });
                }
                Ok(u64::from(v))
            }
            25 => {
                let v = u16::from_be_bytes(self.take::<2>(offset)?);
                if strict && v <= 0xFF {
                    return Err(DecodeError::NonCanonicalEncoding { offset });
                }
                Ok(u64::from(v))
            }
            26 => {
                let v = u32::from_be_bytes(self.take::<4>(offset)?);
                if strict && v <= 0xFFFF {
                    return Err(DecodeError::NonCanonicalEncoding { offset });
                }
                Ok(u64::from(v))
            }
            27 => {
                let v = u64::from_be_bytes(self.take::<8>(offset)?);
                if strict && v <= 0xFFFF_FFFF {
                    return Err(DecodeError::NonCanonicalEncoding { offset });
                }
                Ok(v)
            }
            // 28, 29, 30 are reserved (RFC 8949 §3.1); 31 is the
            // indefinite-length marker handled by `length_argument` —
            // for integers it is structurally invalid.
            _ => Err(DecodeError::InvalidStructure {
                offset,
                detail: "reserved or indefinite additional information",
            }),
        }
    }

    fn simple(&mut self, info: u8, offset: usize) -> Result<CborValue, DecodeError> {
        match info {
            20 => Ok(CborValue::Bool(false)),
            21 => Ok(CborValue::Bool(true)),
            22 => Ok(CborValue::Null),
            // 23 = undefined and the one-byte simple-value forms are not
            // used by any v1-scope CTAP2 message (design Q3/Q1 scope).
            // 25/26/27 = f16/f32/f64: no v1-scope message uses floats.
            25..=27 => Err(DecodeError::FloatNotSupported { offset }),
            _ => Err(DecodeError::InvalidStructure {
                offset,
                detail: "unsupported simple value",
            }),
        }
    }

    fn take<const N: usize>(&mut self, offset: usize) -> Result<[u8; N], DecodeError> {
        if self.pos + N > self.bytes.len() {
            return Err(DecodeError::UnexpectedEof { offset });
        }
        let mut buf = [0u8; N];
        buf.copy_from_slice(&self.bytes[self.pos..self.pos + N]);
        self.pos += N;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DecodePolicy;
    use alloc::string::String;
    use alloc::vec;

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    // ------------------------------------------------------------------
    // Scenario: Encoding a getInfo request map with multiple keys
    // ------------------------------------------------------------------
    // WHEN a CBOR map contains an unsigned-integer key and a text-string
    // key THEN the unsigned-integer key sorts first (major type 0
    // precedes major type 3), every integer/length is minimal, and the
    // output has no tags, indefinite items, or duplicate keys.
    #[test]
    fn getinfo_request_map_sorts_int_key_before_text_key() {
        let value = CborValue::Map(vec![
            (
                CborValue::Text(alloc::string::String::from("relyingPartyId")),
                CborValue::Text(alloc::string::String::from("example.com")),
            ),
            (CborValue::Int(1), CborValue::Int(2)),
        ]);
        let bytes = value.encode().unwrap();
        // CONSTRUCTED vector per CTAP2.1 §8 sorted-map-keys rule.
        // map(2) | 1: 2 | text "relyingPartyId": "example.com"
        assert_eq!(
            bytes,
            hex(concat!(
                "a2",
                "0102",
                "6e72656c79696e6750617274794964",
                "6b6578616d706c652e636f6d"
            ))
        );
        // No indefinite-length break byte (0xFF) and no tag initial
        // bytes (major type 6 => 0xC0..=0xDF) anywhere in the output.
        assert!(!bytes.contains(&0xFF));
        assert!(bytes.iter().all(|b| (b & 0xE0) != 0xC0));
    }

    // ------------------------------------------------------------------
    // Scenario: Encoding a nested structure at the depth limit
    // ------------------------------------------------------------------
    #[test]
    fn nested_structure_at_depth_limit_encodes_and_fifth_level_is_rejected() {
        // Four nested container levels: map > array > map > array.
        let level4 = CborValue::Array(vec![CborValue::Int(1)]);
        let level3 = CborValue::Map(vec![(CborValue::Int(1), level4)]);
        let level2 = CborValue::Array(vec![level3]);
        let level1 = CborValue::Map(vec![(CborValue::Int(1), level2)]);
        assert!(level1.encode().is_ok());

        // A fifth container level is rejected with a typed encoding
        // error BEFORE serialization (CTAP2.1 §8 nesting limit).
        let level5 = CborValue::Map(vec![(CborValue::Int(1), level1)]);
        assert_eq!(
            level5.encode().unwrap_err(),
            EncodeError::DepthLimitExceeded
        );
    }

    // ------------------------------------------------------------------
    // Scenario: Strict decode rejects a non-canonical response
    // ------------------------------------------------------------------
    #[test]
    fn strict_rejects_nonminimal_int_and_tolerant_yields_same_value() {
        // 200 encoded with a uint16 argument (non-minimal, CTAP2.1 §8).
        let bytes = hex("1900c8");
        assert_eq!(
            CborValue::decode(&bytes, DecodePolicy::Strict).unwrap_err(),
            DecodeError::NonCanonicalEncoding { offset: 0 }
        );
        assert_eq!(
            CborValue::decode(&bytes, DecodePolicy::Tolerant).unwrap(),
            CborValue::Int(200)
        );
    }

    // ------------------------------------------------------------------
    // Scenario: Strict decode rejects duplicate map keys
    // ------------------------------------------------------------------
    #[test]
    fn duplicate_map_keys_rejected_in_both_postures() {
        // map {1: 1, 1: 2}
        let bytes = hex("a201010102");
        for policy in [DecodePolicy::Strict, DecodePolicy::Tolerant] {
            assert_eq!(
                CborValue::decode(&bytes, policy).unwrap_err(),
                DecodeError::DuplicateKey { offset: 0 },
                "policy: {policy:?}"
            );
        }
    }

    // ------------------------------------------------------------------
    // Scenario: CBOR nesting beyond the limit is rejected
    // ------------------------------------------------------------------
    #[test]
    fn decode_nesting_beyond_four_levels_rejected_in_both_postures() {
        // Five nested containers: map > array > map > array > map.
        // The error fires at the offset of the fifth container (the
        // innermost map), byte 6.
        let bytes = hex("a10181a10181a101");
        for policy in [DecodePolicy::Strict, DecodePolicy::Tolerant] {
            assert_eq!(
                CborValue::decode(&bytes, policy).unwrap_err(),
                DecodeError::DepthLimitExceeded { offset: 6 },
                "policy: {policy:?}"
            );
        }
        // The same structure trimmed to four levels decodes in both.
        let four = hex("a10181a10101");
        for policy in [DecodePolicy::Strict, DecodePolicy::Tolerant] {
            assert!(CborValue::decode(&four, policy).is_ok(), "{policy:?}");
        }
    }

    #[test]
    fn indefinite_length_items_rejected_in_both_postures() {
        // Indefinite byte string h'61' followed by a break.
        let bstr = hex("5f4161ff");
        // Indefinite array [1].
        let arr = hex("9f01ff");
        // Bare indefinite map (break immediately).
        let map = hex("bfff");
        for bytes in [&bstr, &arr, &map] {
            for policy in [DecodePolicy::Strict, DecodePolicy::Tolerant] {
                assert_eq!(
                    CborValue::decode(bytes, policy).unwrap_err(),
                    DecodeError::IndefiniteLength { offset: 0 },
                    "bytes {:02x?}, policy {policy:?}",
                    bytes
                );
            }
        }
    }

    #[test]
    fn cbor_tags_rejected_in_both_postures() {
        // Tag 1 wrapping integer 1 (RFC 8949 §2.4 tag).
        let bytes = hex("c101");
        for policy in [DecodePolicy::Strict, DecodePolicy::Tolerant] {
            assert_eq!(
                CborValue::decode(&bytes, policy).unwrap_err(),
                DecodeError::TagNotAllowed { offset: 0, tag: 1 },
                "policy: {policy:?}"
            );
        }
        // Even a non-minimally encoded tag is rejected as a tag: the
        // tag rule fires before any minimality check.
        let nonminimal = hex("d90001");
        assert_eq!(
            CborValue::decode(&nonminimal, DecodePolicy::Tolerant).unwrap_err(),
            DecodeError::TagNotAllowed { offset: 0, tag: 1 }
        );
    }

    #[test]
    fn unsorted_map_keys_rejected_strict_accepted_tolerant() {
        // map {"b": 1, "a": 2} — keys out of canonical order.
        let bytes = hex("a2616201616102");
        assert_eq!(
            CborValue::decode(&bytes, DecodePolicy::Strict).unwrap_err(),
            DecodeError::UnsortedKeys { offset: 4 }
        );
        let value = CborValue::decode(&bytes, DecodePolicy::Tolerant).unwrap();
        assert_eq!(
            value,
            CborValue::Map(vec![
                (
                    CborValue::Text(alloc::string::String::from("b")),
                    CborValue::Int(1)
                ),
                (
                    CborValue::Text(alloc::string::String::from("a")),
                    CborValue::Int(2)
                ),
            ])
        );
    }

    // ------------------------------------------------------------------
    // Round trips and canonical-form determinism
    // ------------------------------------------------------------------
    fn roundtrip_cases() -> Vec<CborValue> {
        vec![
            CborValue::Int(0),
            CborValue::Int(23),
            CborValue::Int(24),
            CborValue::Int(255),
            CborValue::Int(256),
            CborValue::Int(65535),
            CborValue::Int(65536),
            CborValue::Int(4294967295),
            CborValue::Int(4294967296),
            CborValue::Int(-1),
            CborValue::Int(-24),
            CborValue::Int(-25),
            CborValue::Int(-256),
            CborValue::Int(-257),
            CborValue::Int(-65536),
            CborValue::Int(-65537),
            CborValue::Bytes(vec![]),
            CborValue::Bytes((0..=255).collect()),
            CborValue::Text(alloc::string::String::from("hello")),
            CborValue::Text(alloc::string::String::new()),
            CborValue::Array(vec![]),
            CborValue::Array(vec![
                CborValue::Int(1),
                CborValue::Text(alloc::string::String::from("a")),
            ]),
            CborValue::Map(vec![]),
            CborValue::Map(vec![
                (CborValue::Int(1), CborValue::Bool(true)),
                (CborValue::Int(-3), CborValue::Bytes(vec![0xAA, 0xBB])),
                (CborValue::Text(String::from("k")), CborValue::Null),
            ]),
        ]
    }

    #[test]
    fn encode_decode_round_trip_is_identity_and_canonical_is_stable() {
        for value in roundtrip_cases() {
            let bytes = value.encode().unwrap();
            let decoded = CborValue::decode(&bytes, DecodePolicy::Strict).unwrap();
            assert_eq!(decoded, value, "bytes {bytes:02x?}");
            // Canonical-form stability: strict-decoded value re-encodes
            // to the identical bytes (the encoding form is unique).
            let reencoded = decoded.encode().unwrap();
            assert_eq!(reencoded, bytes, "value {value:?}");
        }
    }

    // Integer minimality (CTAP2.1 §8): every integer uses the smallest
    // permitted encoding, at every argument-width boundary.
    #[test]
    fn integers_use_minimal_length_encoding() {
        let cases: &[(i128, &str)] = &[
            (23, "17"),
            (24, "1818"),
            (255, "18ff"),
            (256, "190100"),
            (65535, "19ffff"),
            (65536, "1a00010000"),
            (4294967295, "1affffffff"),
            (4294967296, "1b0000000100000000"),
            (-1, "20"),
            (-24, "37"),
            (-25, "3818"),
            (-256, "38ff"),
            (-257, "390100"),
            (-65536, "39ffff"),
            (-65537, "3a00010000"),
        ];
        for (n, expected) in cases.iter().copied() {
            let bytes = CborValue::Int(n).encode().unwrap();
            assert_eq!(bytes, hex(expected), "Int({n})");
            assert_eq!(
                CborValue::decode(&bytes, DecodePolicy::Strict).unwrap(),
                CborValue::Int(n)
            );
        }
    }

    #[test]
    fn simple_values_encode_decode() {
        assert_eq!(CborValue::Bool(false).encode().unwrap(), hex("f4"));
        assert_eq!(CborValue::Bool(true).encode().unwrap(), hex("f5"));
        assert_eq!(CborValue::Null.encode().unwrap(), hex("f6"));
        assert_eq!(
            CborValue::decode(&hex("f4"), DecodePolicy::Strict).unwrap(),
            CborValue::Bool(false)
        );
        assert_eq!(
            CborValue::decode(&hex("f6"), DecodePolicy::Strict).unwrap(),
            CborValue::Null
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        assert_eq!(
            CborValue::decode(&hex("0001"), DecodePolicy::Strict).unwrap_err(),
            DecodeError::TrailingBytes { offset: 1 }
        );
    }

    #[test]
    fn truncated_input_reports_unexpected_eof() {
        // u64 argument cut short.
        assert_eq!(
            CborValue::decode(&hex("1b00000000"), DecodePolicy::Strict).unwrap_err(),
            DecodeError::UnexpectedEof { offset: 0 }
        );
    }

    #[test]
    fn reserved_additional_info_is_a_structure_error() {
        // Additional info 28 is reserved (RFC 8949 §3.1).
        assert!(matches!(
            CborValue::decode(&hex("1c"), DecodePolicy::Strict),
            Err(DecodeError::InvalidStructure { .. })
        ));
    }

    #[test]
    fn nonminimal_lengths_rejected_strict_accepted_tolerant() {
        // One-item array declared with a one-byte length argument
        // (minimal form is 0x81).
        let bytes = hex("980101");
        assert_eq!(
            CborValue::decode(&bytes, DecodePolicy::Strict).unwrap_err(),
            DecodeError::NonCanonicalEncoding { offset: 0 }
        );
        assert_eq!(
            CborValue::decode(&bytes, DecodePolicy::Tolerant).unwrap(),
            CborValue::Array(vec![CborValue::Int(1)])
        );
    }

    #[test]
    fn floats_are_typed_decode_errors_in_both_postures() {
        // f64 1.0 (major 7, additional info 27).
        let bytes = hex("fb3ff0000000000000");
        for policy in [DecodePolicy::Strict, DecodePolicy::Tolerant] {
            assert_eq!(
                CborValue::decode(&bytes, policy).unwrap_err(),
                DecodeError::FloatNotSupported { offset: 0 },
                "policy: {policy:?}"
            );
        }
    }

    // CONSTRUCTED vector modeled on the authenticatorGetInfo example
    // response of CTAP2.1 §6.4.1: five members (01, 02, 03, 05, 06).
    // The exact byte string is independently derived from the §6.4
    // member table and asserted against the §8 canonical encoding.
    #[test]
    fn constructed_getinfo_example_round_trips_through_canonical_bytes() {
        let value = CborValue::Map(vec![
            (
                CborValue::Int(0x01),
                CborValue::Array(vec![
                    CborValue::Text(alloc::string::String::from("FIDO_2_0")),
                    CborValue::Text(alloc::string::String::from("FIDO_2_1_PRE")),
                    CborValue::Text(alloc::string::String::from("U2F_V2")),
                ]),
            ),
            (
                CborValue::Int(0x02),
                CborValue::Array(vec![CborValue::Text(alloc::string::String::from(
                    "hmac-secret",
                ))]),
            ),
            (CborValue::Int(0x03), CborValue::Bytes(vec![0u8; 16])),
            (
                CborValue::Int(0x05),
                CborValue::Map(vec![
                    (
                        CborValue::Text(alloc::string::String::from("rk")),
                        CborValue::Bool(true),
                    ),
                    (
                        CborValue::Text(alloc::string::String::from("up")),
                        CborValue::Bool(true),
                    ),
                ]),
            ),
            (
                CborValue::Int(0x06),
                CborValue::Array(vec![CborValue::Int(2)]),
            ),
        ]);
        let bytes = value.encode().unwrap();
        assert_eq!(
            bytes,
            hex(concat!(
                "a5",
                "0183684649444f5f325f306c4649444f5f325f315f505245665532465f5632",
                "02816b686d61632d736563726574",
                "035000000000000000000000000000000000",
                "05a262726bf5627570f5",
                "068102",
            )),
            "canonical bytes of the constructed getInfo example"
        );
        assert_eq!(
            CborValue::decode(&bytes, DecodePolicy::Strict).unwrap(),
            value
        );
    }
}
