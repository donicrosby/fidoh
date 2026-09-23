//! COSE_Key representation for ES256 as used by CTAP2 (design D6).
//!
//! Parameter labels and values per RFC 9053 §7 and §7.1.1:
//!
//! | Name | Label | CBOR type | Value for ES256 |
//! |---|---|---|---|
//! | kty | 1 | int | 2 (EC2) |
//! | alg | 3 | int | −7 (ES256) |
//! | crv | −1 | int | 1 (P-256) |
//! | x | −2 | bstr | x-coordinate (leading zeros preserved) |
//! | y | −3 | bstr | y-coordinate (leading zeros preserved) |
//!
//! For public keys `crv`, `x`, and `y` are REQUIRED (RFC 9053 §7.1.1).
//! RFC 9053 §7.1: "Applications MUST check that the curve and the key
//! type are consistent and reject a key if they are not."

use alloc::vec;
use alloc::vec::Vec;

use crate::cbor::CborValue;
use crate::error::{DecodeError, EncodeError};

/// COSE label for `kty` (RFC 9053 §7, Table 3).
const LABEL_KTY: i128 = 1;
/// COSE label for `alg` (RFC 9053 §7, Table 3).
const LABEL_ALG: i128 = 3;
/// COSE label for `crv` (RFC 9053 §7.1, Table 18 context).
const LABEL_CRV: i128 = -1;
/// COSE label for `x` (RFC 9053 §7.1.1).
const LABEL_X: i128 = -2;
/// COSE label for `y` (RFC 9053 §7.1.1).
const LABEL_Y: i128 = -3;

/// COSE key type EC2 (RFC 9053 §7, Table 17).
pub const KTY_EC2: i128 = 2;
/// COSE algorithm ES256 — ECDSA with SHA-256 (RFC 9053 §2/§3 registry).
pub const ALG_ES256: i128 = -7;
/// COSE elliptic curve P-256 / secp256r1 (RFC 9053 §7.1, Table 18).
pub const CRV_P256: i128 = 1;

/// A COSE_Key for an ES256 (ECDSA w/ SHA-256 over P-256) public key
/// (RFC 9053 §7.1.1, design D6).
///
/// `x` and `y` carry the raw coordinate octets; leading-zero octets
/// are preserved verbatim (RFC 9053 §7.1.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoseEs256Key {
    /// x-coordinate of the public key point.
    pub x: Vec<u8>,
    /// y-coordinate of the public key point.
    pub y: Vec<u8>,
}

impl CoseEs256Key {
    /// Encode as a canonical CBOR map with labels {1: 2, 3: −7,
    /// −1: 1, −2: x, −3: y} (RFC 9053 §7.1.1, CTAP2.1 §8).
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        self.to_cbor().encode()
    }

    /// The intermediate CBOR map representation.
    pub fn to_cbor(&self) -> CborValue {
        CborValue::Map(vec![
            (CborValue::Int(LABEL_KTY), CborValue::Int(KTY_EC2)),
            (CborValue::Int(LABEL_ALG), CborValue::Int(ALG_ES256)),
            (CborValue::Int(LABEL_CRV), CborValue::Int(CRV_P256)),
            (CborValue::Int(LABEL_X), CborValue::Bytes(self.x.clone())),
            (CborValue::Int(LABEL_Y), CborValue::Bytes(self.y.clone())),
        ])
    }

    /// Decode from a CBOR map, enforcing the RFC 9053 §7.1 consistency
    /// rule: an EC2 key whose curve is not an EC2 curve (e.g. crv=6,
    /// Ed25519 — an OKP curve) is rejected as inconsistent.
    ///
    /// `alg` (label 3) is optional on the wire here — CTAP2 credential
    /// public keys may omit it — but if present it MUST be ES256 (−7)
    /// for this typed representation.
    pub fn from_cbor(value: &CborValue) -> Result<Self, DecodeError> {
        let entries = match value {
            CborValue::Map(entries) => entries,
            _ => {
                return Err(DecodeError::TypeMismatch {
                    member: "coseKey",
                    expected: "map",
                })
            }
        };

        let mut kty: Option<i128> = None;
        let mut alg: Option<i128> = None;
        let mut crv: Option<i128> = None;
        let mut x: Option<Vec<u8>> = None;
        let mut y: Option<Vec<u8>> = None;

        for (key, val) in entries {
            // Unknown labels are ignored per CTAP2.1 §8's
            // unknown-map-key MUST-ignore rule.
            let label = match key {
                CborValue::Int(n) => *n,
                _ => continue,
            };
            match label {
                LABEL_KTY => {
                    kty = Some(int_member(val, "kty")?);
                }
                LABEL_ALG => {
                    alg = Some(int_member(val, "alg")?);
                }
                LABEL_CRV => {
                    crv = Some(int_member(val, "crv")?);
                }
                LABEL_X => {
                    x = Some(bytes_member(val, "x")?);
                }
                LABEL_Y => {
                    y = Some(bytes_member(val, "y")?);
                }
                _ => {}
            }
        }

        let kty = kty.ok_or(DecodeError::MissingMember { member: "kty" })?;
        if kty != KTY_EC2 {
            return Err(DecodeError::InvalidValue {
                member: "kty",
                detail: alloc::format!("expected EC2 ({KTY_EC2}) for ES256, got {kty}"),
            });
        }
        if let Some(alg) = alg {
            if alg != ALG_ES256 {
                return Err(DecodeError::InvalidValue {
                    member: "alg",
                    detail: alloc::format!("expected ES256 ({ALG_ES256}), got {alg}"),
                });
            }
        }
        // crv, x, y are REQUIRED for public keys (RFC 9053 §7.1.1).
        let crv = crv.ok_or(DecodeError::MissingMember { member: "crv" })?;
        // RFC 9053 §7.1: curve and key type MUST be consistent.
        // EC2 curves per RFC 9053 §7.1 Table 18 are P-256 (1), P-384
        // (2), P-521 (3); anything else (e.g. 6, Ed25519, an OKP curve)
        // is inconsistent with kty=EC2.
        if !matches!(crv, 1..=3) {
            return Err(DecodeError::InvalidValue {
                member: "crv",
                detail: alloc::format!(
                    "curve {crv} is inconsistent with key type EC2 (RFC 9053 §7.1)"
                ),
            });
        }
        if crv != CRV_P256 {
            return Err(DecodeError::InvalidValue {
                member: "crv",
                detail: alloc::format!("expected P-256 ({CRV_P256}) for ES256, got {crv}"),
            });
        }
        let x = x.ok_or(DecodeError::MissingMember { member: "x" })?;
        let y = y.ok_or(DecodeError::MissingMember { member: "y" })?;
        Ok(Self { x, y })
    }
}

pub(crate) fn int_member(value: &CborValue, member: &'static str) -> Result<i128, DecodeError> {
    match value {
        CborValue::Int(n) => Ok(*n),
        _ => Err(DecodeError::TypeMismatch {
            member,
            expected: "integer",
        }),
    }
}

pub(crate) fn bytes_member(
    value: &CborValue,
    member: &'static str,
) -> Result<Vec<u8>, DecodeError> {
    match value {
        CborValue::Bytes(b) => Ok(b.clone()),
        _ => Err(DecodeError::TypeMismatch {
            member,
            expected: "byte string",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DecodePolicy;
    use alloc::vec;

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    // CONSTRUCTED vector per RFC 9053 §7.1.1 and CTAP2.1 §6.4.1's
    // clientPIN `keyAgreement` shape. Canonical key order: 01, 03,
    // 20 (-1), 21 (-2), 22 (-3); each 32-byte coordinate rides in a
    // definite-length bstr (0x58 0x20).
    #[test]
    fn well_formed_es256_public_key_round_trips_through_canonical_bytes() {
        let x = [0x11u8; 32];
        let y = [0x22u8; 32];
        let key = CoseEs256Key {
            x: x.to_vec(),
            y: y.to_vec(),
        };
        let bytes = key.encode().unwrap();
        let mut want = hex("a5010203262001215820");
        want.extend_from_slice(&x);
        want.extend_from_slice(&hex("225820"));
        want.extend_from_slice(&y);
        assert_eq!(bytes, want);
        assert_eq!(
            CoseEs256Key::from_cbor(&CborValue::decode(&bytes, DecodePolicy::Strict).unwrap())
                .unwrap(),
            key
        );
        // Leading-zero octets are preserved on the wire (RFC 9053
        // §7.1.1) - a key whose x starts with 0x00 round-trips byte
        // for byte.
        let mut leading_x = vec![0x00u8, 0xAB];
        leading_x.extend(core::iter::repeat(0x7Fu8).take(30));
        let leading_zero = CoseEs256Key {
            x: leading_x,
            y: y.to_vec(),
        };
        let zb = leading_zero.encode().unwrap();
        assert_eq!(zb[10], 0x00); // first x octet on the wire
        assert_eq!(
            CoseEs256Key::from_cbor(&CborValue::decode(&zb, DecodePolicy::Strict).unwrap())
                .unwrap(),
            leading_zero
        );
    }

    // ------------------------------------------------------------------
    // Scenario: Well-formed ES256 public key decodes
    // ------------------------------------------------------------------
    #[test]
    fn well_formed_es256_public_key_decodes() {
        // map {1: 2, 3: -7, -1: 1, -2: h'00..1f', -3: h'00..1f'}
        let mut bytes = hex("a5010203262001215820");
        bytes.extend(0u8..32);
        bytes.extend_from_slice(&hex("225820"));
        bytes.extend(0u8..32);
        let key =
            CoseEs256Key::from_cbor(&CborValue::decode(&bytes, DecodePolicy::Strict).unwrap())
                .unwrap();
        assert_eq!(key.x, (0u8..32).collect::<Vec<_>>());
        assert_eq!(key.y, (0u8..32).collect::<Vec<_>>());
    }

    // ------------------------------------------------------------------
    // Scenario: Inconsistent curve and key type rejected
    // ------------------------------------------------------------------
    #[test]
    fn inconsistent_curve_and_key_type_rejected() {
        // kty=2 (EC2) with crv=6 (Ed25519, an OKP curve) violates the
        // RFC 9053 §7.1 MUST-check rule.
        let mut bytes = hex("a401022006215820");
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.extend_from_slice(&hex("225820"));
        bytes.extend_from_slice(&[0u8; 32]);
        let err =
            CoseEs256Key::from_cbor(&CborValue::decode(&bytes, DecodePolicy::Strict).unwrap())
                .unwrap_err();
        assert_eq!(
            err,
            DecodeError::InvalidValue {
                member: "crv",
                detail: alloc::string::String::from(
                    "curve 6 is inconsistent with key type EC2 (RFC 9053 §7.1)",
                ),
            }
        );
    }

    // ------------------------------------------------------------------
    // Scenario: Missing y coordinate on a public key rejected
    // ------------------------------------------------------------------
    #[test]
    fn missing_y_coordinate_on_public_key_rejected() {
        // map {1: 2, 3: -7, -1: 1, -2: h'..'} - no -3 member.
        let mut bytes = hex("a4010203262001215820");
        bytes.extend_from_slice(&[0u8; 32]);
        let err =
            CoseEs256Key::from_cbor(&CborValue::decode(&bytes, DecodePolicy::Strict).unwrap())
                .unwrap_err();
        assert_eq!(err, DecodeError::MissingMember { member: "y" });
    }

    #[test]
    fn missing_required_members_and_wrong_types_are_typed_errors() {
        // kty itself missing: {3: -7, -1: 1, -2: x, -3: y}
        let mut bytes = hex("a403262001215820");
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.extend_from_slice(&hex("225820"));
        bytes.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            CoseEs256Key::from_cbor(&CborValue::decode(&bytes, DecodePolicy::Strict).unwrap())
                .unwrap_err(),
            DecodeError::MissingMember { member: "kty" }
        );
        // Wrong kty value (OKP = 1): typed invalid-value error.
        let mut bytes = hex("a5010103262001215820");
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.extend_from_slice(&hex("225820"));
        bytes.extend_from_slice(&[0u8; 32]);
        assert!(matches!(
            CoseEs256Key::from_cbor(&CborValue::decode(&bytes, DecodePolicy::Strict).unwrap()),
            Err(DecodeError::InvalidValue { member: "kty", .. })
        ));
        // x present but as a text string: typed type mismatch.
        // map {1: 2, 3: -7, -1: 1, -2: "xyzzy"} — complete in itself;
        // decoded tolerantly because the text x-key sorts after the
        // integer keys (a wire order strict mode would reject).
        let bytes = hex("a4010203262001216578797a7a79");
        let raw = CborValue::decode(&bytes, DecodePolicy::Tolerant).expect("tolerant decode");
        assert!(matches!(
            CoseEs256Key::from_cbor(&raw),
            Err(DecodeError::TypeMismatch { member: "x", .. })
        ));
        // alg present with a non-ES256 value (-6) is rejected.
        let mut bytes = hex("a5010203252001215820");
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.extend_from_slice(&hex("225820"));
        bytes.extend_from_slice(&[0u8; 32]);
        assert!(matches!(
            CoseEs256Key::from_cbor(&CborValue::decode(&bytes, DecodePolicy::Strict).unwrap()),
            Err(DecodeError::InvalidValue { member: "alg", .. })
        ));
    }

    // Unknown labels inside a COSE_Key map MUST be ignored
    // (CTAP2.1 §8), including integer labels beyond the five known
    // ones and text-string labels.
    #[test]
    fn unknown_labels_are_ignored() {
        // Canonical key order: 01, 03, 20 (-1), 21 (-2), 22 (-3),
        // 1863 (label 99, two bytes long), 627a7a ("zz", three bytes).
        let mut map = hex("a7010203262001215820");
        map.extend_from_slice(&[0u8; 32]); // x
        map.extend_from_slice(&hex("225820"));
        map.extend_from_slice(&[0x77u8; 32]); // y
        map.extend_from_slice(&hex("1863182a")); // 99: 42 - unknown
        map.extend_from_slice(&hex("627a7af4")); // "zz": false - unknown
        let key = CoseEs256Key::from_cbor(&CborValue::decode(&map, DecodePolicy::Strict).unwrap())
            .unwrap();
        assert_eq!(key.x, vec![0u8; 32]);
        assert_eq!(key.y, vec![0x77u8; 32]);
    }
}
