//! PIN/UV auth parameter shapes (design D5).
//!
//! Types only, per CTAP2.1 §6.2 and §6.5.5: the clientPIN protocol
//! itself (key agreement, shared-secret derivation, pinUvAuthToken
//! lifecycle, retries) is a named v1 non-goal (openspec/config.yaml).
//!
//! - `pinUvAuthProtocol`: value 1 = PIN/UV Auth Protocol One
//!   (CTAP2.1 §6.5.6); value 2 = PIN/UV Auth Protocol Two
//!   (CTAP2.1 §6.5.7). The selected value MUST be one the
//!   authenticator supports, as reported by getInfo
//!   `pinUvAuthProtocols` (0x06) (CTAP2.1 §6.5.5).
//! - `pinUvAuthParam`: byte string carrying the output of the abstract
//!   `authenticate(key, message)` operation (CTAP2.1 §6.5.4); in
//!   authenticatorGetAssertion it is
//!   `authenticate(pinUvAuthToken, clientDataHash)` (CTAP2.1 §6.2).

use crate::error::DecodeError;

/// PIN/UV auth protocol selector (CTAP2.1 §6.5.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PinUvAuthProtocol {
    /// PIN/UV Auth Protocol One (CTAP2.1 §6.5.6).
    One,
    /// PIN/UV Auth Protocol Two (CTAP2.1 §6.5.7).
    Two,
    /// A protocol version outside the two specified values, preserved
    /// for future CTAP versions (never rejected by the model).
    Other(u32),
}

impl PinUvAuthProtocol {
    /// Map the raw `pinUvAuthProtocols` unsigned integer to its typed
    /// selector.
    pub fn from_u32(value: u32) -> Self {
        match value {
            1 => Self::One,
            2 => Self::Two,
            other => Self::Other(other),
        }
    }

    /// The raw unsigned-integer value for this selector.
    pub fn to_u32(self) -> u32 {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Other(v) => v,
        }
    }

    /// Whether this protocol version appears in a getInfo
    /// `pinUvAuthProtocols` (0x06) list — the CTAP2.1 §6.5.5 rule that
    /// the selected value MUST be authenticator-supported. The model
    /// records the answer; the ceremony layer turns a `false` into its
    /// typed failure (core-model spec scenario "pinUvAuthProtocol
    /// present without authenticator support is rejected at the
    /// ceremony layer").
    pub fn is_supported_by(self, supported: &[PinUvAuthProtocol]) -> bool {
        supported.contains(&self)
    }
}

impl From<u32> for PinUvAuthProtocol {
    fn from(value: u32) -> Self {
        Self::from_u32(value)
    }
}

/// `pinUvAuthParam` (getInfo/getAssertion key 0x06): the wire shape of
/// the abstract `authenticate(key, message)` output
/// (CTAP2.1 §6.5.4, §6.2). A plain newtype over the byte string; the
/// bytes are opaque to the model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinUvAuthParam {
    /// The authenticate() output bytes.
    pub bytes: alloc::vec::Vec<u8>,
}

impl PinUvAuthParam {
    /// Wrap raw authenticate() output bytes.
    pub fn new(bytes: alloc::vec::Vec<u8>) -> Self {
        Self { bytes }
    }

    /// The parameter's CBOR encoding: a byte string (CTAP2.1 §6.2,
    /// key 0x06).
    pub fn to_cbor(&self) -> crate::cbor::CborValue {
        crate::cbor::CborValue::Bytes(self.bytes.clone())
    }

    /// Extract from a CBOR byte-string member.
    pub fn from_cbor(value: &crate::cbor::CborValue) -> Result<Self, DecodeError> {
        Ok(Self {
            bytes: crate::cose::bytes_member(value, "pinUvAuthParam")?,
        })
    }
}
