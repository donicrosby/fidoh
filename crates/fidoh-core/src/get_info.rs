//! authenticatorGetInfo response model (CTAP2.1 §6.4).
//!
//! Members 0x01–0x15 with optionality exactly as the spec table states
//! (design D3): `versions` and `aaguid` are Required; all other
//! members are Optional, including members v1 never sends or consumes.
//! Unknown map keys are ignored (CTAP2.1 §8 MUST-ignore); unknown
//! option-ID strings likewise.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::cbor::CborValue;
use crate::cose::int_member;
use crate::error::DecodeError;

/// `versions` member (0x01): array of text strings, Required
/// (CTAP2.1 §6.4). Semantically required — decoded via the model's
/// post-parse validation.
const KEY_VERSIONS: u128 = 0x01;
/// `extensions` member (0x02).
const KEY_EXTENSIONS: u128 = 0x02;
/// `aaguid` member (0x03): byte string of exactly 16 bytes, Required.
const KEY_AAGUID: u128 = 0x03;
/// `options` member (0x04): map of option-ID string → bool.
const KEY_OPTIONS: u128 = 0x04;
/// `maxMsgSize` member (0x05).
const KEY_MAX_MSG_SIZE: u128 = 0x05;
/// `pinUvAuthProtocols` member (0x06): decreasing preference, no
/// duplicates, non-empty if present.
const KEY_PIN_UV_AUTH_PROTOCOLS: u128 = 0x06;
/// `maxCredentialCountInList` member (0x07): > 0 if present.
const KEY_MAX_CREDENTIAL_COUNT_IN_LIST: u128 = 0x07;
/// `maxCredentialIdLength` member (0x08): > 0 if present.
const KEY_MAX_CREDENTIAL_ID_LENGTH: u128 = 0x08;
/// `transports` member (0x09): no duplicates, non-empty if present,
/// unknown values tolerated.
const KEY_TRANSPORTS: u128 = 0x09;
/// `algorithms` member (0x0A): ordered most- to least-preferred, no
/// duplicates, non-empty if present.
const KEY_ALGORITHMS: u128 = 0x0A;
/// `maxSerializedLargeBlobArray` member (0x0B): ≥ 1024 if present.
const KEY_MAX_SERIALIZED_LARGE_BLOB_ARRAY: u128 = 0x0B;
/// `forcePINChange` member (0x0C).
const KEY_FORCE_PIN_CHANGE: u128 = 0x0C;
/// `minPINLength` member (0x0D).
const KEY_MIN_PIN_LENGTH: u128 = 0x0D;
/// `firmwareVersion` member (0x0E).
const KEY_FIRMWARE_VERSION: u128 = 0x0E;
/// `maxCredBlobLength` member (0x0F): ≥ 32 if present.
const KEY_MAX_CRED_BLOB_LENGTH: u128 = 0x0F;
/// `maxRPIDsForSetMinPINLength` member (0x10).
const KEY_MAX_RPIDS_FOR_SET_MIN_PIN_LENGTH: u128 = 0x10;
/// `preferredPlatformUvAttempts` member (0x11): > 0.
const KEY_PREFERRED_PLATFORM_UV_ATTEMPTS: u128 = 0x11;
/// `uvModality` member (0x12).
const KEY_UV_MODALITY: u128 = 0x12;
/// `certifications` member (0x13): map; value shape uninterpreted
/// (design Q3).
const KEY_CERTIFICATIONS: u128 = 0x13;
/// `remainingDiscoverableCredentials` member (0x14).
const KEY_REMAINING_DISCOVERABLE_CREDENTIALS: u128 = 0x14;
/// `vendorPrototypeConfigCommands` member (0x15): may be empty.
const KEY_VENDOR_PROTOTYPE_CONFIG_COMMANDS: u128 = 0x15;

/// authenticatorGetInfo response (CTAP2.1 §6.4).
///
/// Absent optional members are reported as `None` — absence, not a
/// spec default (core-model scenario "Minimal getInfo response
/// decodes"). Defaults exist only for the `options` map entries (see
/// [`AuthenticatorOptions`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GetInfoResponse {
    /// 0x01 — Required. e.g. "FIDO_2_1", "FIDO_2_0", "FIDO_2_1_PRE",
    /// "U2F_V2".
    pub versions: Vec<String>,
    /// 0x02 — Optional. Supported extensions.
    pub extensions: Option<Vec<String>>,
    /// 0x03 — Required. Exactly 16 bytes (CTAP2.1 §6.4).
    pub aaguid: [u8; 16],
    /// 0x04 — Optional. Option IDs per CTAP2.1 §6.4; unknown IDs are
    /// preserved here and ignored by the accessor.
    pub options: Option<AuthenticatorOptions>,
    /// 0x05 — Optional. Max message size.
    pub max_msg_size: Option<u64>,
    /// 0x06 — Optional. Decreasing authenticator preference; no
    /// duplicates; non-empty if present.
    pub pin_uv_auth_protocols: Option<Vec<crate::pin::PinUvAuthProtocol>>,
    /// 0x07 — Optional. > 0 if present.
    pub max_credential_count_in_list: Option<u64>,
    /// 0x08 — Optional. > 0 if present.
    pub max_credential_id_length: Option<u64>,
    /// 0x09 — Optional. WebAuthn AuthenticatorTransport values; no
    /// duplicates; non-empty if present; unknown values tolerated.
    pub transports: Option<Vec<String>>,
    /// 0x0A — Optional. PublicKeyCredentialParameters, ordered most- to
    /// least-preferred; no duplicates; non-empty if present.
    pub algorithms: Option<Vec<PublicKeyCredentialParameter>>,
    /// 0x0B — Optional. ≥ 1024 if present.
    pub max_serialized_large_blob_array: Option<u64>,
    /// 0x0C — Optional.
    pub force_pin_change: Option<bool>,
    /// 0x0D — Optional. Present iff clientPIN supported.
    pub min_pin_length: Option<u64>,
    /// 0x0E — Optional.
    pub firmware_version: Option<u64>,
    /// 0x0F — Optional. ≥ 32 if present.
    pub max_cred_blob_length: Option<u64>,
    /// 0x10 — Optional. Only if setMinPINLength supported.
    pub max_rpids_for_set_min_pin_length: Option<u64>,
    /// 0x11 — Optional. > 0. Unsigned integer (major type 0).
    pub preferred_platform_uv_attempts: Option<u64>,
    /// 0x12 — Optional. FIDORegistry §3.1 user verification methods.
    pub uv_modality: Option<u64>,
    /// 0x13 — Optional. Values uninterpreted (design Q3).
    pub certifications: Option<CborValue>,
    /// 0x14 — Optional.
    pub remaining_discoverable_credentials: Option<u64>,
    /// 0x15 — Optional. May be empty.
    pub vendor_prototype_config_commands: Option<Vec<u64>>,
}

/// One `PublicKeyCredentialParameters` entry of the `algorithms`
/// (0x0A) array (CTAP2.1 §6.4): `{"type": "public-key", "alg": int}`
/// (WebAuthn §5.8.3 parameter shape).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyCredentialParameter {
    /// COSE algorithm identifier, e.g. −7 (ES256), −8 (EdDSA),
    /// −257 (RS256).
    pub alg: i64,
}

/// authenticatorGetInfo `options` (0x04): map from option-ID string to
/// bool (CTAP2.1 §6.4).
///
/// Unknown option-ID strings are ignored per the unknown-map-key rule
/// (CTAP2.1 §8); absent IDs are reported with their specification
/// defaults via the typed accessors. Recognized IDs not listed by the
/// caller are also preserved verbatim in [`Self::entries`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthenticatorOptions {
    /// Raw decoded entries, including any unknown option IDs (kept for
    /// diagnostics; accessors ignore them).
    pub entries: BTreeMap<String, bool>,
}

/// Typed option IDs recognized by CTAP2.1 §6.4.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OptionId {
    /// `plat` — default false.
    Plat,
    /// `rk` — default false.
    Rk,
    /// `clientPin` — default: not supported (false).
    ClientPin,
    /// `up` — default true.
    Up,
    /// `uv` — default: not supported (false).
    Uv,
    /// `pinUvAuthToken` — default: not supported (false).
    PinUvAuthToken,
    /// `noMcGaPermissionsWithClientPin` — default false.
    NoMcGaPermissionsWithClientPin,
    /// `largeBlobs` — default: not supported (false).
    LargeBlobs,
    /// `ep` — default: not supported (false).
    Ep,
    /// `bioEnroll` — default: not supported (false).
    BioEnroll,
    /// `userVerificationMgmtPreview` — default: not supported (false).
    UserVerificationMgmtPreview,
    /// `uvBioEnroll` — default: not supported (false).
    UvBioEnroll,
    /// `authnrCfg` — default: not supported (false).
    AuthnrCfg,
    /// `uvAcfg` — default: not supported (false).
    UvAcfg,
    /// `credMgmt` — default: not supported (false).
    CredMgmt,
    /// `credentialMgmtPreview` — default: not supported (false).
    CredentialMgmtPreview,
    /// `setMinPINLength` — default: not supported (false).
    SetMinPinLength,
    /// `makeCredUvNotRqd` — default false.
    MakeCredUvNotRqd,
    /// `alwaysUv` — default: not supported (false).
    AlwaysUv,
}

impl OptionId {
    /// The option-ID string as it appears on the wire
    /// (CTAP2.1 §6.4).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plat => "plat",
            Self::Rk => "rk",
            Self::ClientPin => "clientPin",
            Self::Up => "up",
            Self::Uv => "uv",
            Self::PinUvAuthToken => "pinUvAuthToken",
            Self::NoMcGaPermissionsWithClientPin => "noMcGaPermissionsWithClientPin",
            Self::LargeBlobs => "largeBlobs",
            Self::Ep => "ep",
            Self::BioEnroll => "bioEnroll",
            Self::UserVerificationMgmtPreview => "userVerificationMgmtPreview",
            Self::UvBioEnroll => "uvBioEnroll",
            Self::AuthnrCfg => "authnrCfg",
            Self::UvAcfg => "uvAcfg",
            Self::CredMgmt => "credMgmt",
            Self::CredentialMgmtPreview => "credentialMgmtPreview",
            Self::SetMinPinLength => "setMinPINLength",
            Self::MakeCredUvNotRqd => "makeCredUvNotRqd",
            Self::AlwaysUv => "alwaysUv",
        }
    }

    /// The specification default when the option ID is absent from the
    /// `options` map (CTAP2.1 §6.4 option defaults).
    ///
    /// "Not supported" options default to false; `up` defaults to true
    /// because user presence is always performed unless stated
    /// otherwise.
    pub fn default_value(self) -> bool {
        matches!(self, Self::Up)
    }
}

impl AuthenticatorOptions {
    /// Decode an `options` CBOR map (string → bool). Values of the
    /// wrong CBOR type are a typed type-mismatch error; unknown
    /// option-ID strings are preserved in `entries` and ignored by
    /// [`Self::get`].
    pub fn from_cbor(value: &CborValue) -> Result<Self, DecodeError> {
        let map = match value {
            CborValue::Map(entries) => entries,
            _ => {
                return Err(DecodeError::TypeMismatch {
                    member: "options",
                    expected: "map",
                })
            }
        };
        let mut entries = BTreeMap::new();
        for (key, val) in map {
            let id = match key {
                CborValue::Text(s) => s.clone(),
                _ => {
                    return Err(DecodeError::TypeMismatch {
                        member: "options",
                        expected: "string keys",
                    })
                }
            };
            let enabled = match val {
                CborValue::Bool(b) => *b,
                _ => {
                    return Err(DecodeError::TypeMismatch {
                        member: "options",
                        expected: "boolean values",
                    })
                }
            };
            entries.insert(id, enabled);
        }
        Ok(Self { entries })
    }

    /// The value of a recognized option ID, falling back to its
    /// specification default when absent (CTAP2.1 §6.4).
    pub fn get(&self, id: OptionId) -> bool {
        self.entries
            .get(id.as_str())
            .copied()
            .unwrap_or_else(|| id.default_value())
    }
}

impl GetInfoResponse {
    /// Decode a `getInfo` response CBOR map (post-status-byte CBOR
    /// portion, CTAP2.1 §6.4.1 step 5). Unknown map keys are ignored
    /// (CTAP2.1 §8); required members and member types are validated
    /// identically in strict and tolerant postures.
    pub fn from_cbor(value: &CborValue) -> Result<Self, DecodeError> {
        let map = match value {
            CborValue::Map(entries) => entries,
            _ => {
                return Err(DecodeError::TypeMismatch {
                    member: "getInfoResponse",
                    expected: "map",
                })
            }
        };

        // All members decode from their wire representation first; the
        // required-member and per-member semantic checks then run in
        // `validate`.
        let mut versions: Option<Vec<String>> = None;
        let mut extensions: Option<Vec<String>> = None;
        let mut aaguid: Option<Vec<u8>> = None;
        let mut options: Option<AuthenticatorOptions> = None;
        let mut max_msg_size: Option<u64> = None;
        let mut pin_uv_auth_protocols: Option<Vec<crate::pin::PinUvAuthProtocol>> = None;
        let mut max_credential_count_in_list: Option<u64> = None;
        let mut max_credential_id_length: Option<u64> = None;
        let mut transports: Option<Vec<String>> = None;
        let mut algorithms: Option<Vec<PublicKeyCredentialParameter>> = None;
        let mut max_serialized_large_blob_array: Option<u64> = None;
        let mut force_pin_change: Option<bool> = None;
        let mut min_pin_length: Option<u64> = None;
        let mut firmware_version: Option<u64> = None;
        let mut max_cred_blob_length: Option<u64> = None;
        let mut max_rpids_for_set_min_pin_length: Option<u64> = None;
        let mut preferred_platform_uv_attempts: Option<u64> = None;
        let mut uv_modality: Option<u64> = None;
        let mut certifications: Option<CborValue> = None;
        let mut remaining_discoverable_credentials: Option<u64> = None;
        let mut vendor_prototype_config_commands: Option<Vec<u64>> = None;

        for (key, val) in map {
            // Keys are unsigned integers per the CTAP2.1 §6.4 table;
            // decode through u128 so a malicious u64::MAX+1 argument
            // cannot wrap.
            let key = match key {
                CborValue::Int(n) if *n >= 0 => {
                    u128::try_from(*n).map_err(|_| DecodeError::InvalidValue {
                        member: "getInfoResponse",
                        detail: format!("map key {} exceeds u64", *n),
                    })?
                }
                CborValue::Int(_) => continue, // negative key: unknown
                _ => continue,                 // non-integer key: unknown
            };
            match key {
                KEY_VERSIONS => versions = Some(text_array(val, "versions")?),
                KEY_EXTENSIONS => extensions = Some(text_array(val, "extensions")?),
                KEY_AAGUID => aaguid = Some(crate::cose::bytes_member(val, "aaguid")?),
                KEY_OPTIONS => options = Some(AuthenticatorOptions::from_cbor(val)?),
                KEY_MAX_MSG_SIZE => max_msg_size = Some(uint_member(val, "maxMsgSize")?),
                KEY_PIN_UV_AUTH_PROTOCOLS => {
                    let raw = uint_array(val, "pinUvAuthProtocols")?;
                    let mut list = Vec::with_capacity(raw.len());
                    for n in raw {
                        list.push(crate::pin::PinUvAuthProtocol::from_u32(
                            u32::try_from(n).map_err(|_| DecodeError::InvalidValue {
                                member: "pinUvAuthProtocols",
                                detail: format!("protocol value {n} exceeds u32"),
                            })?,
                        ));
                    }
                    pin_uv_auth_protocols = Some(list);
                }
                KEY_MAX_CREDENTIAL_COUNT_IN_LIST => {
                    max_credential_count_in_list =
                        Some(uint_member(val, "maxCredentialCountInList")?)
                }
                KEY_MAX_CREDENTIAL_ID_LENGTH => {
                    max_credential_id_length = Some(uint_member(val, "maxCredentialIdLength")?)
                }
                KEY_TRANSPORTS => transports = Some(text_array(val, "transports")?),
                KEY_ALGORITHMS => algorithms = Some(algorithms_member(val)?),
                KEY_MAX_SERIALIZED_LARGE_BLOB_ARRAY => {
                    max_serialized_large_blob_array =
                        Some(uint_member(val, "maxSerializedLargeBlobArray")?)
                }
                KEY_FORCE_PIN_CHANGE => {
                    force_pin_change = Some(bool_member(val, "forcePINChange")?)
                }
                KEY_MIN_PIN_LENGTH => min_pin_length = Some(uint_member(val, "minPINLength")?),
                KEY_FIRMWARE_VERSION => {
                    firmware_version = Some(uint_member(val, "firmwareVersion")?)
                }
                KEY_MAX_CRED_BLOB_LENGTH => {
                    max_cred_blob_length = Some(uint_member(val, "maxCredBlobLength")?)
                }
                KEY_MAX_RPIDS_FOR_SET_MIN_PIN_LENGTH => {
                    max_rpids_for_set_min_pin_length =
                        Some(uint_member(val, "maxRPIDsForSetMinPINLength")?)
                }
                KEY_PREFERRED_PLATFORM_UV_ATTEMPTS => {
                    preferred_platform_uv_attempts =
                        Some(uint_member(val, "preferredPlatformUvAttempts")?)
                }
                KEY_UV_MODALITY => uv_modality = Some(uint_member(val, "uvModality")?),
                KEY_CERTIFICATIONS => {
                    let inner = match val {
                        CborValue::Map(_) => val.clone(),
                        _ => {
                            return Err(DecodeError::TypeMismatch {
                                member: "certifications",
                                expected: "map",
                            })
                        }
                    };
                    certifications = Some(inner);
                }
                KEY_REMAINING_DISCOVERABLE_CREDENTIALS => {
                    remaining_discoverable_credentials =
                        Some(uint_member(val, "remainingDiscoverableCredentials")?)
                }
                KEY_VENDOR_PROTOTYPE_CONFIG_COMMANDS => {
                    vendor_prototype_config_commands =
                        Some(uint_array(val, "vendorPrototypeConfigCommands")?)
                }
                // Unknown member keys MUST be ignored (CTAP2.1 §8).
                _ => {}
            }
        }

        Self::validate(
            versions,
            extensions,
            aaguid,
            options,
            max_msg_size,
            pin_uv_auth_protocols,
            max_credential_count_in_list,
            max_credential_id_length,
            transports,
            algorithms,
            max_serialized_large_blob_array,
            force_pin_change,
            min_pin_length,
            firmware_version,
            max_cred_blob_length,
            max_rpids_for_set_min_pin_length,
            preferred_platform_uv_attempts,
            uv_modality,
            certifications,
            remaining_discoverable_credentials,
            vendor_prototype_config_commands,
        )
    }

    /// Required-member and per-member semantic validation
    /// (CTAP2.1 §6.4 table).
    #[allow(clippy::too_many_arguments)]
    fn validate(
        versions: Option<Vec<String>>,
        extensions: Option<Vec<String>>,
        aaguid: Option<Vec<u8>>,
        options: Option<AuthenticatorOptions>,
        max_msg_size: Option<u64>,
        pin_uv_auth_protocols: Option<Vec<crate::pin::PinUvAuthProtocol>>,
        max_credential_count_in_list: Option<u64>,
        max_credential_id_length: Option<u64>,
        transports: Option<Vec<String>>,
        algorithms: Option<Vec<PublicKeyCredentialParameter>>,
        max_serialized_large_blob_array: Option<u64>,
        force_pin_change: Option<bool>,
        min_pin_length: Option<u64>,
        firmware_version: Option<u64>,
        max_cred_blob_length: Option<u64>,
        max_rpids_for_set_min_pin_length: Option<u64>,
        preferred_platform_uv_attempts: Option<u64>,
        uv_modality: Option<u64>,
        certifications: Option<CborValue>,
        remaining_discoverable_credentials: Option<u64>,
        vendor_prototype_config_commands: Option<Vec<u64>>,
    ) -> Result<Self, DecodeError> {
        // Required members (CTAP2.1 §6.4): versions, aaguid.
        let versions = versions.ok_or(DecodeError::MissingMember { member: "versions" })?;
        let aaguid = aaguid.ok_or(DecodeError::MissingMember { member: "aaguid" })?;
        let aaguid: [u8; 16] =
            aaguid
                .try_into()
                .map_err(|raw: Vec<u8>| DecodeError::InvalidValue {
                    member: "aaguid",
                    detail: format!("expected exactly 16 bytes, got {}", raw.len()),
                })?;

        // Non-empty if present (CTAP2.1 §6.4 table).
        let pin_uv_auth_protocols = non_empty(pin_uv_auth_protocols, "pinUvAuthProtocols")?;
        if let Some(list) = &pin_uv_auth_protocols {
            // Decreasing authenticator preference with no duplicates.
            let mut sorted: Vec<_> = list.iter().map(|p| p.to_u32()).collect();
            sorted.sort_unstable();
            if sorted.len() > 1 && sorted.windows(2).any(|w| w[0] == w[1]) {
                return Err(DecodeError::InvalidValue {
                    member: "pinUvAuthProtocols",
                    detail: "duplicate protocol values".into(),
                });
            }
        }
        let max_credential_count_in_list =
            positive(max_credential_count_in_list, "maxCredentialCountInList")?;
        let max_credential_id_length = positive(max_credential_id_length, "maxCredentialIdLength")?;
        let transports = non_empty(transports, "transports")?;
        if let Some(list) = &transports {
            // Unknown transport values tolerated; duplicates not.
            let mut sorted: Vec<&String> = list.iter().collect();
            sorted.sort();
            if sorted.len() > 1 && sorted.windows(2).any(|w| w[0] == w[1]) {
                return Err(DecodeError::InvalidValue {
                    member: "transports",
                    detail: "duplicate transport values".into(),
                });
            }
        }
        let algorithms = non_empty(algorithms, "algorithms")?;
        if let Some(list) = &algorithms {
            let mut algs: Vec<i64> = list.iter().map(|p| p.alg).collect();
            algs.sort_unstable();
            if algs.len() > 1 && algs.windows(2).any(|w| w[0] == w[1]) {
                return Err(DecodeError::InvalidValue {
                    member: "algorithms",
                    detail: "duplicate algorithm identifiers".into(),
                });
            }
        }
        if let Some(v) = max_serialized_large_blob_array {
            if v < 1024 {
                return Err(DecodeError::InvalidValue {
                    member: "maxSerializedLargeBlobArray",
                    detail: format!("value {v} is below the minimum 1024"),
                });
            }
        }
        if let Some(v) = max_cred_blob_length {
            if v < 32 {
                return Err(DecodeError::InvalidValue {
                    member: "maxCredBlobLength",
                    detail: format!("value {v} is below the minimum 32"),
                });
            }
        }
        if let Some(v) = preferred_platform_uv_attempts {
            if v == 0 {
                return Err(DecodeError::InvalidValue {
                    member: "preferredPlatformUvAttempts",
                    detail: "value must be greater than 0".into(),
                });
            }
        }

        Ok(Self {
            versions,
            extensions,
            aaguid,
            options,
            max_msg_size,
            pin_uv_auth_protocols,
            max_credential_count_in_list,
            max_credential_id_length,
            transports,
            algorithms,
            max_serialized_large_blob_array,
            force_pin_change,
            min_pin_length,
            firmware_version,
            max_cred_blob_length,
            max_rpids_for_set_min_pin_length,
            preferred_platform_uv_attempts,
            uv_modality,
            certifications,
            remaining_discoverable_credentials,
            vendor_prototype_config_commands,
        })
    }

    /// The typed value of a recognized option ID from the `options`
    /// (0x04) member, falling back to the specification default when
    /// the member or the ID is absent (CTAP2.1 §6.4).
    pub fn option(&self, id: crate::get_info::OptionId) -> bool {
        self.options
            .as_ref()
            .map(|o| o.get(id))
            .unwrap_or_else(|| id.default_value())
    }

    /// Re-serialize the present members as a canonical CBOR map
    /// (CTAP2.1 §6.4 member order). Encode→decode→encode is
    /// byte-identical: canonical form is unique.
    pub fn to_wire_cbor(&self) -> Result<Vec<u8>, crate::error::EncodeError> {
        let mut entries: Vec<(CborValue, CborValue)> = Vec::with_capacity(21);
        entries.push((
            CborValue::Int(KEY_VERSIONS as i128),
            CborValue::Array(
                self.versions
                    .iter()
                    .map(|v| CborValue::Text(v.clone()))
                    .collect(),
            ),
        ));
        if let Some(ext) = &self.extensions {
            entries.push((
                CborValue::Int(KEY_EXTENSIONS as i128),
                CborValue::Array(ext.iter().map(|v| CborValue::Text(v.clone())).collect()),
            ));
        }
        entries.push((
            CborValue::Int(KEY_AAGUID as i128),
            CborValue::Bytes(self.aaguid.to_vec()),
        ));
        if let Some(opts) = &self.options {
            entries.push((
                CborValue::Int(KEY_OPTIONS as i128),
                CborValue::Map(
                    opts.entries
                        .iter()
                        .map(|(k, v)| (CborValue::Text(k.clone()), CborValue::Bool(*v)))
                        .collect(),
                ),
            ));
        }
        let uints: [(u128, Option<u64>); 12] = [
            (KEY_MAX_MSG_SIZE, self.max_msg_size),
            (
                KEY_MAX_CREDENTIAL_COUNT_IN_LIST,
                self.max_credential_count_in_list,
            ),
            (KEY_MAX_CREDENTIAL_ID_LENGTH, self.max_credential_id_length),
            (
                KEY_MAX_SERIALIZED_LARGE_BLOB_ARRAY,
                self.max_serialized_large_blob_array,
            ),
            (KEY_MIN_PIN_LENGTH, self.min_pin_length),
            (KEY_FIRMWARE_VERSION, self.firmware_version),
            (KEY_MAX_CRED_BLOB_LENGTH, self.max_cred_blob_length),
            (
                KEY_MAX_RPIDS_FOR_SET_MIN_PIN_LENGTH,
                self.max_rpids_for_set_min_pin_length,
            ),
            (
                KEY_PREFERRED_PLATFORM_UV_ATTEMPTS,
                self.preferred_platform_uv_attempts,
            ),
            (KEY_UV_MODALITY, self.uv_modality),
            (
                KEY_REMAINING_DISCOVERABLE_CREDENTIALS,
                self.remaining_discoverable_credentials,
            ),
            // Placeholder slot keeps the array shape; value ignored.
            (0, None),
        ];
        for (key, value) in uints {
            if let Some(v) = value {
                entries.push((CborValue::Int(key as i128), CborValue::Int(i128::from(v))));
            }
        }
        if let Some(protocols) = &self.pin_uv_auth_protocols {
            entries.push((
                CborValue::Int(KEY_PIN_UV_AUTH_PROTOCOLS as i128),
                CborValue::Array(
                    protocols
                        .iter()
                        .map(|p| CborValue::Int(i128::from(p.to_u32())))
                        .collect(),
                ),
            ));
        }
        if let Some(transports) = &self.transports {
            entries.push((
                CborValue::Int(KEY_TRANSPORTS as i128),
                CborValue::Array(
                    transports
                        .iter()
                        .map(|t| CborValue::Text(t.clone()))
                        .collect(),
                ),
            ));
        }
        if let Some(algs) = &self.algorithms {
            entries.push((
                CborValue::Int(KEY_ALGORITHMS as i128),
                CborValue::Array(
                    algs.iter()
                        .map(|p| {
                            CborValue::Map(vec![
                                (
                                    CborValue::Text(alloc::string::String::from("type")),
                                    CborValue::Text(alloc::string::String::from("public-key")),
                                ),
                                (
                                    CborValue::Text(alloc::string::String::from("alg")),
                                    CborValue::Int(i128::from(p.alg)),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ));
        }
        if let Some(force) = self.force_pin_change {
            entries.push((
                CborValue::Int(KEY_FORCE_PIN_CHANGE as i128),
                CborValue::Bool(force),
            ));
        }
        if let Some(certs) = &self.certifications {
            entries.push((CborValue::Int(KEY_CERTIFICATIONS as i128), certs.clone()));
        }
        if let Some(cmds) = &self.vendor_prototype_config_commands {
            entries.push((
                CborValue::Int(KEY_VENDOR_PROTOTYPE_CONFIG_COMMANDS as i128),
                CborValue::Array(
                    cmds.iter()
                        .map(|c| CborValue::Int(i128::from(*c)))
                        .collect(),
                ),
            ));
        }
        CborValue::Map(entries).encode()
    }
}

fn non_empty<T>(
    value: Option<Vec<T>>,
    member: &'static str,
) -> Result<Option<Vec<T>>, DecodeError> {
    if value.as_ref().is_some_and(Vec::is_empty) {
        return Err(DecodeError::InvalidValue {
            member,
            detail: "present but empty".into(),
        });
    }
    Ok(value)
}

pub(crate) fn uint_member(value: &CborValue, member: &'static str) -> Result<u64, DecodeError> {
    match value {
        CborValue::Int(n) if *n >= 0 => u64::try_from(*n).map_err(|_| DecodeError::InvalidValue {
            member,
            detail: alloc::format!("integer {n} exceeds u64"),
        }),
        _ => Err(DecodeError::TypeMismatch {
            member,
            expected: "unsigned integer",
        }),
    }
}

fn bool_member(value: &CborValue, member: &'static str) -> Result<bool, DecodeError> {
    match value {
        CborValue::Bool(b) => Ok(*b),
        _ => Err(DecodeError::TypeMismatch {
            member,
            expected: "boolean",
        }),
    }
}

pub(crate) fn text_array(
    value: &CborValue,
    member: &'static str,
) -> Result<Vec<String>, DecodeError> {
    match value {
        CborValue::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    CborValue::Text(s) => out.push(s.clone()),
                    _ => {
                        return Err(DecodeError::TypeMismatch {
                            member,
                            expected: "array of text strings",
                        })
                    }
                }
            }
            Ok(out)
        }
        _ => Err(DecodeError::TypeMismatch {
            member,
            expected: "array",
        }),
    }
}

fn uint_array(value: &CborValue, member: &'static str) -> Result<Vec<u64>, DecodeError> {
    match value {
        CborValue::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(uint_member(item, member)?);
            }
            Ok(out)
        }
        _ => Err(DecodeError::TypeMismatch {
            member,
            expected: "array of unsigned integers",
        }),
    }
}

/// `algorithms` (0x0A): array of `PublicKeyCredentialParameters`
/// (WebAuthn §5.8.3: `{"type": "public-key", "alg": int}`).
fn algorithms_member(value: &CborValue) -> Result<Vec<PublicKeyCredentialParameter>, DecodeError> {
    match value {
        CborValue::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let entries = match item {
                    CborValue::Map(entries) => entries,
                    _ => {
                        return Err(DecodeError::TypeMismatch {
                            member: "algorithms",
                            expected: "array of maps",
                        })
                    }
                };
                let mut alg: Option<i64> = None;
                let mut type_ok = false;
                for (key, val) in entries {
                    match key {
                        CborValue::Text(s) if s == "type" => match val {
                            CborValue::Text(t) if t == "public-key" => type_ok = true,
                            _ => {
                                return Err(DecodeError::TypeMismatch {
                                    member: "algorithms",
                                    expected: r#""type": "public-key""#,
                                })
                            }
                        },
                        CborValue::Text(s) if s == "alg" => {
                            alg = Some(i64::try_from(int_member(val, "algorithms")?).map_err(
                                |_| DecodeError::InvalidValue {
                                    member: "algorithms",
                                    detail: "alg value out of i64 range".into(),
                                },
                            )?)
                        }
                        // Unknown keys inside the parameter map: ignored
                        // (CTAP2.1 §8).
                        _ => {}
                    }
                }
                let alg = alg.ok_or(DecodeError::MissingMember {
                    member: "algorithms[alg]",
                })?;
                if !type_ok {
                    return Err(DecodeError::MissingMember {
                        member: "algorithms[type]",
                    });
                }
                out.push(PublicKeyCredentialParameter { alg });
            }
            Ok(out)
        }
        _ => Err(DecodeError::TypeMismatch {
            member: "algorithms",
            expected: "array",
        }),
    }
}

/// Positive integer constraint ("> 0 if present", CTAP2.1 §6.4 table).
fn positive(value: Option<u64>, member: &'static str) -> Result<Option<u64>, DecodeError> {
    if value == Some(0) {
        return Err(DecodeError::InvalidValue {
            member,
            detail: "value must be greater than 0".into(),
        });
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DecodePolicy;
    use crate::pin::PinUvAuthProtocol;
    use alloc::vec;

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    fn decode(bytes: &[u8]) -> Result<GetInfoResponse, DecodeError> {
        GetInfoResponse::from_cbor(&CborValue::decode_map(bytes, DecodePolicy::Strict)?)
    }

    // CONSTRUCTED vector per the CTAP2.1 §6.4.1 example response
    // (versions, extensions, aaguid, options, maxMsgSize,
    // pinUvAuthProtocols), verified against the encoder.
    #[test]
    fn full_getinfo_example_round_trips() {
        let response = GetInfoResponse {
            versions: vec![
                String::from("FIDO_2_1"),
                String::from("FIDO_2_0"),
                String::from("FIDO_2_1_PRE"),
                String::from("U2F_V2"),
            ],
            extensions: Some(vec![String::from("credProtect")]),
            aaguid: [0x2F; 16],
            options: Some(AuthenticatorOptions {
                entries: BTreeMap::from([(String::from("rk"), true), (String::from("up"), true)]),
            }),
            max_msg_size: Some(1200),
            pin_uv_auth_protocols: Some(vec![PinUvAuthProtocol::Two, PinUvAuthProtocol::One]),
            ..Default::default()
        };
        let map = CborValue::Map(vec![
            (
                CborValue::Int(0x01),
                CborValue::Array(vec![
                    CborValue::Text(String::from("FIDO_2_1")),
                    CborValue::Text(String::from("FIDO_2_0")),
                    CborValue::Text(String::from("FIDO_2_1_PRE")),
                    CborValue::Text(String::from("U2F_V2")),
                ]),
            ),
            (
                CborValue::Int(0x02),
                CborValue::Array(vec![CborValue::Text(String::from("credProtect"))]),
            ),
            (CborValue::Int(0x03), CborValue::Bytes(vec![0x2F; 16])),
            (
                CborValue::Int(0x04),
                CborValue::Map(vec![
                    (CborValue::Text(String::from("rk")), CborValue::Bool(true)),
                    (CborValue::Text(String::from("up")), CborValue::Bool(true)),
                ]),
            ),
            (CborValue::Int(0x05), CborValue::Int(1200)),
            (
                CborValue::Int(0x06),
                CborValue::Array(vec![CborValue::Int(2), CborValue::Int(1)]),
            ),
        ]);
        let bytes = map.encode().unwrap();
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded, response);
        // Round trip back through the wire form is byte-identical.
        assert_eq!(decoded.to_wire_cbor().unwrap(), bytes,);
    }

    // ------------------------------------------------------------------
    // Scenario: Minimal getInfo response decodes
    // ------------------------------------------------------------------
    #[test]
    fn minimal_getinfo_response_decodes_with_optionals_absent() {
        // map {1: ["FIDO_2_0"], 3: h'(16 zero bytes)'}
        let bytes = hex(concat!(
            "a2",
            "0181684649444f5f325f30",
            "035000000000000000000000000000000000"
        ));
        let response = decode(&bytes).unwrap();
        assert_eq!(response.versions, vec![String::from("FIDO_2_0")]);
        assert_eq!(response.aaguid, [0u8; 16]);
        // Optional members report absence, not defaults.
        assert!(response.extensions.is_none());
        assert!(response.options.is_none());
        assert!(response.max_msg_size.is_none());
        assert!(response.pin_uv_auth_protocols.is_none());
        assert!(response.max_credential_count_in_list.is_none());
        assert!(response.max_credential_id_length.is_none());
        assert!(response.transports.is_none());
        assert!(response.algorithms.is_none());
        assert!(response.max_serialized_large_blob_array.is_none());
        assert!(response.force_pin_change.is_none());
        assert!(response.min_pin_length.is_none());
        assert!(response.firmware_version.is_none());
        assert!(response.max_cred_blob_length.is_none());
        assert!(response.max_rpids_for_set_min_pin_length.is_none());
        assert!(response.preferred_platform_uv_attempts.is_none());
        assert!(response.uv_modality.is_none());
        assert!(response.certifications.is_none());
        assert!(response.remaining_discoverable_credentials.is_none());
        assert!(response.vendor_prototype_config_commands.is_none());
    }

    // ------------------------------------------------------------------
    // Scenario: getInfo response missing a required member
    // ------------------------------------------------------------------
    #[test]
    fn getinfo_response_missing_required_member_fails() {
        // map {1: ["FIDO_2_0"]} — aaguid (0x03) missing.
        let bytes = hex("a10181684649444f5f325f30");
        assert_eq!(
            decode(&bytes).unwrap_err(),
            DecodeError::MissingMember { member: "aaguid" }
        );
        // Missing versions instead.
        let bytes = hex("a1035000000000000000000000000000000000");
        assert_eq!(
            decode(&bytes).unwrap_err(),
            DecodeError::MissingMember { member: "versions" }
        );
    }

    // ------------------------------------------------------------------
    // Scenario: Absent option ID yields its specification default
    // ------------------------------------------------------------------
    #[test]
    fn absent_option_id_yields_specification_default() {
        // options map {"rk": true} with no "up" entry.
        let bytes = hex(concat!(
            "a3",
            "0181684649444f5f325f30",
            "035000000000000000000000000000000000",
            "04a162726bf5"
        ));
        let response = decode(&bytes).unwrap();
        assert!(response.option(OptionId::Rk));
        assert!(response.option(OptionId::Up));
        assert!(!(response.option(OptionId::Plat)));
        assert!(!(response.option(OptionId::ClientPin)));
        assert!(!(response.option(OptionId::AlwaysUv)));
        // Options member entirely absent: every ID reports its default.
        let bytes = hex(concat!(
            "a2",
            "0181684649444f5f325f30",
            "035000000000000000000000000000000000"
        ));
        let response = decode(&bytes).unwrap();
        assert!(response.option(OptionId::Up));
        assert!(!(response.option(OptionId::Rk)));
    }

    // ------------------------------------------------------------------
    // Scenario: Unknown option ID is ignored
    // ------------------------------------------------------------------
    #[test]
    fn unknown_option_id_is_ignored() {
        // options map {"rk": true, "fancyNewOption": false}.
        let bytes = hex(concat!(
            "a3",
            "0181684649444f5f325f30",
            "035000000000000000000000000000000000",
            "04a262726bf566756e65776964f4"
        ));
        let response = decode(&bytes).unwrap();
        assert!(response.option(OptionId::Rk));
        // The unknown ID neither rejects nor perturbs known defaults.
        assert!(response.option(OptionId::Up));
    }

    // ------------------------------------------------------------------
    // Scenario: getInfo response with a newer, unknown member
    // ------------------------------------------------------------------
    #[test]
    fn newer_unknown_member_is_ignored() {
        // Known members plus unknown keys 0x7F (int) with an arbitrary
        // value; decoding succeeds and known members survive.
        let bytes = hex(concat!(
            "a4",
            "0181684649444f5f325f30",
            "035000000000000000000000000000000000",
            "0b1904d2",     // 0x0B maxSerializedLargeBlobArray: 1234
            "187f6375666f"  // key 0x7F: "ufo" — from a later CTAP version
        ));
        let response = decode(&bytes).unwrap();
        assert_eq!(response.max_serialized_large_blob_array, Some(1234));
        assert_eq!(response.versions.len(), 1);
    }

    // ------------------------------------------------------------------
    // Scenario: Unknown key vs wrong type on a known key
    // ------------------------------------------------------------------
    #[test]
    fn unknown_key_tolerated_but_known_key_wrong_type_rejected() {
        // Unknown key with arbitrary (even nonsensical) value: OK.
        let bytes = hex(concat!(
            "a3",
            "0181684649444f5f325f30",
            "035000000000000000000000000000000000",
            "187e01" // key 0x7E: arbitrary value — ignored
        ));
        assert!(decode(&bytes).is_ok());
        // Known key with the wrong CBOR type (maxMsgSize as text).
        let bytes = hex(concat!(
            "a3",
            "0181684649444f5f325f30",
            "035000000000000000000000000000000000",
            "05646e6f7065" // 0x05: "nope"
        ));
        assert_eq!(
            decode(&bytes).unwrap_err(),
            DecodeError::TypeMismatch {
                member: "maxMsgSize",
                expected: "unsigned integer",
            }
        );
    }

    #[test]
    fn aaguid_wrong_length_is_a_typed_invalid_value() {
        // aaguid of 15 bytes.
        let bytes = hex(concat!(
            "a2",
            "0181684649444f5f325f30",
            "034f000000000000000000000000000000"
        ));
        assert!(matches!(
            decode(&bytes).unwrap_err(),
            DecodeError::InvalidValue {
                member: "aaguid",
                ..
            }
        ));
    }

    #[test]
    fn semantic_constraints_are_enforced() {
        // pinUvAuthProtocols present but empty.
        let bytes = hex(concat!(
            "a3",
            "0181684649444f5f325f30",
            "035000000000000000000000000000000000",
            "0680"
        ));
        assert!(matches!(
            decode(&bytes).unwrap_err(),
            DecodeError::InvalidValue {
                member: "pinUvAuthProtocols",
                ..
            }
        ));
        // pinUvAuthProtocols with duplicate values [2, 2].
        let bytes = hex(concat!(
            "a3",
            "0181684649444f5f325f30",
            "035000000000000000000000000000000000",
            "06820202"
        ));
        assert!(matches!(
            decode(&bytes).unwrap_err(),
            DecodeError::InvalidValue {
                member: "pinUvAuthProtocols",
                ..
            }
        ));
        // maxSerializedLargeBlobArray below 1024.
        let bytes = hex(concat!(
            "a3",
            "0181684649444f5f325f30",
            "035000000000000000000000000000000000",
            "0b1903e7"
        ));
        assert!(matches!(
            decode(&bytes).unwrap_err(),
            DecodeError::InvalidValue {
                member: "maxSerializedLargeBlobArray",
                ..
            }
        ));
        // maxCredentialCountInList of zero.
        let bytes = hex(concat!(
            "a3",
            "0181684649444f5f325f30",
            "035000000000000000000000000000000000",
            "0700"
        ));
        assert!(matches!(
            decode(&bytes).unwrap_err(),
            DecodeError::InvalidValue {
                member: "maxCredentialCountInList",
                ..
            }
        ));
        // transports present but empty.
        let bytes = hex(concat!(
            "a3",
            "0181684649444f5f325f30",
            "035000000000000000000000000000000000",
            "0980"
        ));
        assert!(matches!(
            decode(&bytes).unwrap_err(),
            DecodeError::InvalidValue {
                member: "transports",
                ..
            }
        ));
        // algorithms present but empty.
        let bytes = hex(concat!(
            "a3",
            "0181684649444f5f325f30",
            "035000000000000000000000000000000000",
            "0a80"
        ));
        assert!(matches!(
            decode(&bytes).unwrap_err(),
            DecodeError::InvalidValue {
                member: "algorithms",
                ..
            }
        ));
        // algorithms entry without "alg".
        let bytes = hex(concat!(
            "a3",
            "0181684649444f5f325f30",
            "035000000000000000000000000000000000",
            "0a81a1636b65796165" // [{"key": "e"}] — no type/alg
        ));
        assert!(matches!(
            decode(&bytes).unwrap_err(),
            DecodeError::MissingMember {
                member: "algorithms[alg]",
                ..
            }
        ));
    }

    #[test]
    fn algorithms_decode_with_type_and_alg() {
        // 0x0A member built through the typed encoder so the vector
        // cannot drift from the map shape.
        let algorithms = CborValue::Array(vec![CborValue::Map(vec![
            (
                CborValue::Text(String::from("type")),
                CborValue::Text(String::from("public-key")),
            ),
            (CborValue::Text(String::from("alg")), CborValue::Int(-7)),
        ])]);
        let map = CborValue::Map(vec![
            (
                CborValue::Int(0x01),
                CborValue::Array(vec![CborValue::Text(String::from("FIDO_2_0"))]),
            ),
            (CborValue::Int(0x03), CborValue::Bytes(vec![0u8; 16])),
            (CborValue::Int(0x0A), algorithms),
        ]);
        let response = GetInfoResponse::from_cbor(
            &CborValue::decode(&map.encode().unwrap(), DecodePolicy::Strict).unwrap(),
        )
        .unwrap();
        assert_eq!(
            response.algorithms,
            Some(vec![PublicKeyCredentialParameter { alg: -7 }])
        );
    }

    #[test]
    fn option_map_wrong_value_type_is_typed_error() {
        // options map with an integer value instead of bool.
        let bytes = hex(concat!(
            "a3",
            "0181684649444f5f325f30",
            "035000000000000000000000000000000000",
            "04a162726b01"
        ));
        assert!(matches!(
            decode(&bytes).unwrap_err(),
            DecodeError::TypeMismatch {
                member: "options",
                ..
            }
        ));
    }
}
