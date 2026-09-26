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

// ---------------------------------------------------------------------------
// PIN-provider seam (add-client-pin, design D3).
//
// The caller owns PIN collection: fidoh-core NEVER reads stdin, never
// spawns UI, never retains PIN bytes beyond the single acquisition
// transaction (error-diagnostics no-secrets rule). The seam is the
// ONLY path by which PIN bytes enter the library.
// ---------------------------------------------------------------------------

/// Caller-typed failure of the PIN provider (e.g. the user cancelled
/// the prompt). The ceremony maps this onto
/// [`CeremonyError::PinProviderFailed`](crate::error::CeremonyError)
/// without any authenticator round-trip.
#[derive(Debug)]
pub struct PinSourceError {
    /// Opaque caller context. Never printed by fidoh (no-secrets
    /// rule): only its presence is surfaced.
    pub _context: (),
}

/// The PIN-provider seam (add-client-pin spec, "PIN-provider callback
/// seam"): one `provide_pin` call per acquisition, invoked after the
/// shared secret is established and before the token request
/// (CTAP2.1 §6.5.5.7.2 step 1: collect before use).
pub trait PinProvider {
    /// Return the PIN as UTF-8 bytes, or a caller-typed failure. The
    /// returned buffer is zeroized by the library after use.
    fn provide_pin(&mut self) -> Result<alloc::vec::Vec<u8>, PinSourceError>;
}

/// A boxed, sendable provider handle for ceremony inputs.
pub struct PinProviderHandle {
    inner: alloc::boxed::Box<dyn FnMut() -> Result<alloc::vec::Vec<u8>, PinSourceError> + Send>,
}

impl core::fmt::Debug for PinProviderHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // No-secrets rule: never print anything the closure captured.
        f.write_str("PinProviderHandle(..)")
    }
}

impl PinProviderHandle {
    /// Build a handle from a closure (the common shape: an app wraps
    /// its own prompt/keystore).
    pub fn from_closure(
        f: impl FnMut() -> Result<alloc::vec::Vec<u8>, PinSourceError> + Send + 'static,
    ) -> Self {
        Self {
            inner: alloc::boxed::Box::new(f),
        }
    }
}

impl PinProvider for PinProviderHandle {
    fn provide_pin(&mut self) -> Result<alloc::vec::Vec<u8>, PinSourceError> {
        (self.inner)()
    }
}

/// CTAP2.1 §6.5.5 maximum PIN byte length (63 UTF-8 bytes; the 64th
/// byte is always padding).
pub const MAX_PIN_BYTES: usize = 63;

/// authenticatorClientPIN subCommands (CTAP2.1 §6.5.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientPinSubCommand {
    /// getPINRetries (0x01).
    GetPinRetries,
    /// getKeyAgreement (0x02).
    GetKeyAgreement,
    /// getPinToken (0x05) — CTAP2.0-token fallback, default mc+ga
    /// permissions (§6.5.5.7.1).
    GetPinToken,
    /// getPinUvAuthTokenUsingPinWithPermissions (0x09) (§6.5.5.7.2).
    GetPinUvAuthTokenUsingPinWithPermissions,
}

impl ClientPinSubCommand {
    /// The subCommand byte.
    pub fn to_u8(self) -> u8 {
        match self {
            Self::GetPinRetries => 0x01,
            Self::GetKeyAgreement => 0x02,
            Self::GetPinToken => 0x05,
            Self::GetPinUvAuthTokenUsingPinWithPermissions => 0x09,
        }
    }
}

/// pinUvAuthToken permissions bitfield (CTAP2.1 §6.5.5.7).
pub mod permissions {
    /// makeCredential permission (0x01).
    pub const MC: u32 = 0x01;
    /// getAssertion permission (0x02).
    pub const GA: u32 = 0x02;
}

/// The authenticatorClientPIN (0x06) request model (CTAP2.1 §6.5.5):
/// the members the v2 acquisition flow sends. Encoded through the
/// canonical CBOR layer (sorted keys, minimal lengths).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientPinRequest {
    /// pinUvAuthProtocol (0x01).
    pub protocol: PinUvAuthProtocol,
    /// subCommand (0x02).
    pub sub_command: ClientPinSubCommand,
    /// keyAgreement (0x03): the platform's COSE_Key (getKeyAgreement,
    /// and every PIN-bearing subcommand per §6.5.5.7.2).
    pub key_agreement: Option<crate::cbor::CborValue>,
    /// pinUvAuthParam (0x04) (unused by the acquisition subcommands in
    /// v2 scope; carried for wire completeness).
    pub pin_uv_auth_param: Option<PinUvAuthParam>,
    /// pinHashEnc (0x06): encrypt(sharedSecret, LEFT(SHA-256(PIN),16)).
    pub pin_hash_enc: Option<alloc::vec::Vec<u8>>,
    /// permissions (0x09): bitfield, MUST NOT be 0 when present.
    pub permissions: Option<u32>,
    /// rpId (0x0A): the permissions RP ID.
    pub rp_id: Option<alloc::string::String>,
}

impl ClientPinRequest {
    /// The canonical CBOR encoding (CTAP2.1 §6.5.5 request map; keys
    /// 0x01, 0x02, 0x03, 0x04, 0x06, 0x09, 0x0A).
    pub fn encode(&self) -> Result<alloc::vec::Vec<u8>, crate::error::EncodeError> {
        use crate::cbor::CborValue;
        let mut entries: alloc::vec::Vec<(CborValue, CborValue)> = alloc::vec::Vec::new();
        entries.push((
            CborValue::Int(0x01),
            CborValue::Int(i128::from(self.protocol.to_u32())),
        ));
        entries.push((
            CborValue::Int(0x02),
            CborValue::Int(i128::from(self.sub_command.to_u8())),
        ));
        if let Some(ka) = &self.key_agreement {
            entries.push((CborValue::Int(0x03), ka.clone()));
        }
        if let Some(param) = &self.pin_uv_auth_param {
            entries.push((CborValue::Int(0x04), param.to_cbor()));
        }
        if let Some(hash_enc) = &self.pin_hash_enc {
            entries.push((CborValue::Int(0x06), CborValue::Bytes(hash_enc.clone())));
        }
        if let Some(perms) = self.permissions {
            if perms == 0 {
                return Err(crate::error::EncodeError::InvalidRequest(
                    crate::error::InvalidRequest::EmptyPermissions,
                ));
            }
            entries.push((CborValue::Int(0x09), CborValue::Int(i128::from(perms))));
        }
        if let Some(rp) = &self.rp_id {
            entries.push((CborValue::Int(0x0A), CborValue::Text(rp.clone())));
        }
        CborValue::Map(entries).encode()
    }
}

/// The authenticatorClientPIN response members the acquisition flow
/// consumes (CTAP2.1 §6.5.5 response table).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientPinResponse {
    /// keyAgreement (0x01).
    pub key_agreement: Option<crate::cbor::CborValue>,
    /// pinUvAuthToken (0x02): encrypt(sharedSecret, token).
    pub pin_uv_auth_token: Option<alloc::vec::Vec<u8>>,
    /// pinRetries (0x03).
    pub pin_retries: Option<u8>,
    /// uvRetries (0x05).
    pub uv_retries: Option<u8>,
}

impl ClientPinResponse {
    /// Decode from a CBOR map (strict posture; unknown keys ignored
    /// per CTAP2.1 §8).
    pub fn from_cbor(value: &crate::cbor::CborValue) -> Result<Self, DecodeError> {
        use crate::cbor::CborValue;
        let entries = match value {
            CborValue::Map(entries) => entries,
            _ => {
                return Err(DecodeError::TypeMismatch {
                    member: "clientPinResponse",
                    expected: "map",
                })
            }
        };
        let mut out = Self::default();
        for (k, v) in entries {
            let key = match k {
                CborValue::Int(n) if *n >= 0 => u128::try_from(*n).unwrap_or(u128::MAX),
                _ => continue,
            };
            match key {
                0x01 => out.key_agreement = Some(v.clone()),
                0x02 => {
                    out.pin_uv_auth_token = Some(crate::cose::bytes_member(v, "pinUvAuthToken")?)
                }
                0x03 => {
                    out.pin_retries = Some(
                        u8::try_from(crate::get_info::uint_member(v, "pinRetries")?).map_err(
                            |_| DecodeError::InvalidValue {
                                member: "pinRetries",
                                detail: alloc::string::String::from("exceeds u8"),
                            },
                        )?,
                    )
                }
                0x05 => {
                    out.uv_retries = Some(
                        u8::try_from(crate::get_info::uint_member(v, "uvRetries")?).map_err(
                            |_| DecodeError::InvalidValue {
                                member: "uvRetries",
                                detail: alloc::string::String::from("exceeds u8"),
                            },
                        )?,
                    )
                }
                _ => {}
            }
        }
        Ok(out)
    }
}
