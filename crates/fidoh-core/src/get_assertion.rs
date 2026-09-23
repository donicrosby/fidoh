//! authenticatorGetAssertion request and response models
//! (CTAP2.1 §6.2).
//!
//! Request keys 0x01–0x07; response keys 0x01–0x07. Required members
//! are `rpId` and `clientDataHash` on the request, and `credential`,
//! `authData`, and `signature` on the response; all other members are
//! Optional. Wire
//! rules enforced here are that an empty `allowList` MUST NOT be sent
//! (§6.2), that `options.uv` and `pinUvAuthParam` are mutually
//! exclusive (§6.2), and that `userSelected` MUST NOT be present when
//! numberOfCredentials > 1 (§6.2).

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use crate::cbor::CborValue;
use crate::error::{DecodeError, EncodeError, InvalidRequest};
use crate::pin::{PinUvAuthParam, PinUvAuthProtocol};

const KEY_RP_ID: u128 = 0x01;
const KEY_CLIENT_DATA_HASH: u128 = 0x02;
const KEY_ALLOW_LIST: u128 = 0x03;
const KEY_EXTENSIONS: u128 = 0x04;
const KEY_OPTIONS: u128 = 0x05;
const KEY_PIN_UV_AUTH_PARAM: u128 = 0x06;
const KEY_PIN_UV_AUTH_PROTOCOL: u128 = 0x07;

const KEY_CREDENTIAL: u128 = 0x01;
const KEY_AUTH_DATA: u128 = 0x02;
const KEY_SIGNATURE: u128 = 0x03;
const KEY_USER: u128 = 0x04;
const KEY_NUMBER_OF_CREDENTIALS: u128 = 0x05;
const KEY_USER_SELECTED: u128 = 0x06;
const KEY_LARGE_BLOB_KEY: u128 = 0x07;

/// PublicKeyCredentialDescriptor (WebAuthn §5.8.4, CTAP2.1 §6.2
/// usage): the credential identifier plus its type string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyCredentialDescriptor {
    /// `type` member: always "public-key" for CTAP2 credentials.
    pub type_field: CredentialType,
    /// `id` member: the credential ID bytes.
    pub id: Vec<u8>,
    /// `transports` member: optional hint array; unknown values
    /// tolerated (CTAP2.1 §8 unknown-key/value tolerance).
    pub transports: Option<Vec<alloc::string::String>>,
}

/// The `type` member of a PublicKeyCredentialDescriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialType {
    /// "public-key" — the only type CTAP2 uses.
    PublicKey,
}

impl PublicKeyCredentialDescriptor {
    /// Decode from a CBOR map. Unknown keys are ignored; missing
    /// `type`/`id` or wrong types are typed errors.
    pub fn from_cbor(value: &CborValue) -> Result<Self, DecodeError> {
        let map = match value {
            CborValue::Map(entries) => entries,
            _ => {
                return Err(DecodeError::TypeMismatch {
                    member: "credentialDescriptor",
                    expected: "map",
                })
            }
        };
        let mut type_field: Option<CredentialType> = None;
        let mut id: Option<Vec<u8>> = None;
        let mut transports: Option<Vec<alloc::string::String>> = None;
        for (key, val) in map {
            match key {
                CborValue::Text(s) if s == "type" => {
                    type_field = Some(match val {
                        CborValue::Text(t) if t == "public-key" => CredentialType::PublicKey,
                        _ => {
                            return Err(DecodeError::TypeMismatch {
                                member: "credentialDescriptor[type]",
                                expected: "\"public-key\"",
                            })
                        }
                    });
                }
                CborValue::Text(s) if s == "id" => {
                    id = Some(crate::cose::bytes_member(val, "credentialDescriptor[id]")?)
                }
                CborValue::Text(s) if s == "transports" => {
                    transports = Some(crate::get_info::text_array(val, "transports")?)
                }
                // Unknown keys ignored (CTAP2.1 §8).
                _ => {}
            }
        }
        let type_field = type_field.ok_or(DecodeError::MissingMember {
            member: "credentialDescriptor[type]",
        })?;
        let id = id.ok_or(DecodeError::MissingMember {
            member: "credentialDescriptor[id]",
        })?;
        Ok(Self {
            type_field,
            id,
            transports,
        })
    }

    /// The descriptor's CBOR map representation.
    pub fn to_cbor(&self) -> CborValue {
        let mut entries = vec![
            (
                CborValue::Text(alloc::borrow::ToOwned::to_owned("type")),
                CborValue::Text(alloc::string::String::from("public-key")),
            ),
            (
                CborValue::Text(alloc::borrow::ToOwned::to_owned("id")),
                CborValue::Bytes(self.id.clone()),
            ),
        ];
        if let Some(transports) = &self.transports {
            entries.push((
                CborValue::Text(alloc::borrow::ToOwned::to_owned("transports")),
                CborValue::Array(
                    transports
                        .iter()
                        .map(|t| CborValue::Text(t.clone()))
                        .collect(),
                ),
            ));
        }
        CborValue::Map(entries)
    }
}

/// PublicKeyCredentialUserEntity (WebAuthn §5.8.3, CTAP2.1 §6.2
/// response member 0x04).
///
/// `id` is mandatory when this member is present for discoverable
/// credentials; identifiable info is absent if UV was not performed
/// (CTAP2.1 §6.2 response table).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyCredentialUserEntity {
    /// `id` member: user handle (mandatory when present for
    /// discoverable credentials).
    pub id: Vec<u8>,
    /// `name` member (optional).
    pub name: Option<alloc::string::String>,
    /// `displayName` member (optional).
    pub display_name: Option<alloc::string::String>,
}

impl PublicKeyCredentialUserEntity {
    /// Decode from a CBOR map. Unknown keys are ignored.
    pub fn from_cbor(value: &CborValue) -> Result<Self, DecodeError> {
        let map = match value {
            CborValue::Map(entries) => entries,
            _ => {
                return Err(DecodeError::TypeMismatch {
                    member: "user",
                    expected: "map",
                })
            }
        };
        let mut id: Option<Vec<u8>> = None;
        let mut name: Option<alloc::string::String> = None;
        let mut display_name: Option<alloc::string::String> = None;
        for (key, val) in map {
            match key {
                CborValue::Text(s) if s == "id" => {
                    id = Some(crate::cose::bytes_member(val, "user[id]")?)
                }
                CborValue::Text(s) if s == "name" => name = Some(text_member(val, "user[name]")?),
                CborValue::Text(s) if s == "displayName" => {
                    display_name = Some(text_member(val, "user[displayName]")?)
                }
                _ => {}
            }
        }
        let id = id.ok_or(DecodeError::MissingMember { member: "user[id]" })?;
        Ok(Self {
            id,
            name,
            display_name,
        })
    }

    /// The entity's CBOR map representation (id + present members).
    pub fn to_cbor(&self) -> CborValue {
        let mut entries = vec![(
            CborValue::Text(alloc::borrow::ToOwned::to_owned("id")),
            CborValue::Bytes(self.id.clone()),
        )];
        if let Some(name) = &self.name {
            entries.push((
                CborValue::Text(alloc::borrow::ToOwned::to_owned("name")),
                CborValue::Text(name.clone()),
            ));
        }
        if let Some(display_name) = &self.display_name {
            entries.push((
                CborValue::Text(alloc::borrow::ToOwned::to_owned("displayName")),
                CborValue::Text(display_name.clone()),
            ));
        }
        CborValue::Map(entries)
    }
}

/// authenticatorGetAssertion request (CTAP2.1 §6.2).
///
/// Construct via [`GetAssertionRequest::new`] (which applies the
/// empty-allowList rule) or struct literal; call
/// [`Self::encode`] to serialize. [`Self::validate`] enforces the
/// §6.2 wire rules before encoding.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GetAssertionRequest {
    /// 0x01 — Required. Relying party identifier (WebAuthn).
    pub rp_id: alloc::string::String,
    /// 0x02 — Required. Hash of serialized client data (WebAuthn).
    pub client_data_hash: Vec<u8>,
    /// 0x03 — Optional. An empty list MUST be `None` (§6.2: "A
    /// platform MUST NOT send an empty allowList"); `new` enforces
    /// this.
    pub allow_list: Option<Vec<PublicKeyCredentialDescriptor>>,
    /// 0x04 — Optional. CBOR map (extension ID → input).
    pub extensions: Option<CborValue>,
    /// 0x05 — Optional. Keys: `up` (default true), `uv` (default
    /// false, deprecated in CTAP2.1).
    pub options: Option<GetAssertionOptions>,
    /// 0x06 — Optional. `authenticate(pinUvAuthToken, clientDataHash)`
    /// (CTAP2.1 §6.2).
    pub pin_uv_auth_param: Option<PinUvAuthParam>,
    /// 0x07 — Optional. Selected PIN/UV protocol version.
    pub pin_uv_auth_protocol: Option<PinUvAuthProtocol>,
}

/// authenticatorGetAssertion `options` (0x05) (CTAP2.1 §6.2).
///
/// `rk` MUST NOT be included in a getAssertion request (§6.2); the
/// model has no `rk` field, so it can never be sent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GetAssertionOptions {
    /// `up` — default true.
    pub up: Option<bool>,
    /// `uv` — default false; deprecated in CTAP2.1. Mutually exclusive
    /// with `pinUvAuthParam` (§6.2).
    pub uv: Option<bool>,
}

impl GetAssertionRequest {
    /// Construct a request, applying the §6.2 empty-allowList rule:
    /// an empty list is stored as `None` (omitted on the wire).
    pub fn new(
        rp_id: alloc::string::String,
        client_data_hash: Vec<u8>,
    ) -> Result<Self, EncodeError> {
        Ok(Self {
            rp_id,
            client_data_hash,
            allow_list: None,
            extensions: None,
            options: None,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        })
    }

    /// Set the allow list; an empty list is converted to `None` per
    /// CTAP2.1 §6.2 ("MUST NOT send an empty allowList").
    pub fn with_allow_list(mut self, list: Vec<PublicKeyCredentialDescriptor>) -> Self {
        self.allow_list = if list.is_empty() { None } else { Some(list) };
        self
    }

    /// Enforce the CTAP2.1 §6.2 request wire rules:
    ///
    /// - `options.uv` and `pinUvAuthParam` MUST NOT both be present;
    /// - the request MUST NOT include the `rk` option key (structurally
    ///   impossible: the model carries no `rk` field).
    pub fn validate(&self) -> Result<(), EncodeError> {
        let uv_set = self.options.is_some_and(|o| o.uv.is_some());
        if uv_set && self.pin_uv_auth_param.is_some() {
            return Err(EncodeError::InvalidRequest(
                InvalidRequest::UvOptionWithPinUvAuthParam,
            ));
        }
        Ok(())
    }

    /// Encode the request as canonical CBOR (CTAP2.1 §6.2 request
    /// structure, §8 canonical form). Validation runs first.
    pub fn encode(&self) -> Result<alloc::vec::Vec<u8>, EncodeError> {
        self.validate()?;
        let mut entries: Vec<(CborValue, CborValue)> = Vec::with_capacity(7);
        entries.push((
            CborValue::Int(KEY_RP_ID as i128),
            CborValue::Text(self.rp_id.clone()),
        ));
        entries.push((
            CborValue::Int(KEY_CLIENT_DATA_HASH as i128),
            CborValue::Bytes(self.client_data_hash.clone()),
        ));
        if let Some(list) = &self.allow_list {
            if list.is_empty() {
                // Defensive: `new`/`with_allow_list` already normalize.
                return Err(EncodeError::InvalidRequest(InvalidRequest::EmptyAllowList));
            }
            entries.push((
                CborValue::Int(KEY_ALLOW_LIST as i128),
                CborValue::Array(list.iter().map(|d| d.to_cbor()).collect()),
            ));
        }
        if let Some(ext) = &self.extensions {
            entries.push((CborValue::Int(KEY_EXTENSIONS as i128), ext.clone()));
        }
        if let Some(opts) = &self.options {
            let mut opt_entries: Vec<(CborValue, CborValue)> = Vec::new();
            if let Some(up) = opts.up {
                opt_entries.push((
                    CborValue::Text(alloc::borrow::ToOwned::to_owned("up")),
                    CborValue::Bool(up),
                ));
            }
            if let Some(uv) = opts.uv {
                opt_entries.push((
                    CborValue::Text(alloc::borrow::ToOwned::to_owned("uv")),
                    CborValue::Bool(uv),
                ));
            }
            entries.push((
                CborValue::Int(KEY_OPTIONS as i128),
                CborValue::Map(opt_entries),
            ));
        }
        if let Some(param) = &self.pin_uv_auth_param {
            entries.push((
                CborValue::Int(KEY_PIN_UV_AUTH_PARAM as i128),
                param.to_cbor(),
            ));
        }
        if let Some(protocol) = &self.pin_uv_auth_protocol {
            entries.push((
                CborValue::Int(KEY_PIN_UV_AUTH_PROTOCOL as i128),
                CborValue::Int(i128::from(protocol.to_u32())),
            ));
        }
        CborValue::Map(entries).encode()
    }

    /// Decode a request from its CBOR map (soft-token harness /
    /// probing use).
    pub fn from_cbor(value: &CborValue) -> Result<Self, DecodeError> {
        let map = match value {
            CborValue::Map(entries) => entries,
            _ => {
                return Err(DecodeError::TypeMismatch {
                    member: "getAssertionRequest",
                    expected: "map",
                })
            }
        };
        let mut rp_id: Option<alloc::string::String> = None;
        let mut client_data_hash: Option<Vec<u8>> = None;
        let mut allow_list: Option<Vec<PublicKeyCredentialDescriptor>> = None;
        let mut extensions: Option<CborValue> = None;
        let mut options: Option<GetAssertionOptions> = None;
        let mut pin_uv_auth_param: Option<PinUvAuthParam> = None;
        let mut pin_uv_auth_protocol: Option<PinUvAuthProtocol> = None;
        for (key, val) in map {
            let key = match key {
                CborValue::Int(n) if *n >= 0 => u128::try_from(*n).unwrap_or(u128::MAX),
                _ => continue,
            };
            match key {
                KEY_RP_ID => rp_id = Some(text_member(val, "rpId")?),
                KEY_CLIENT_DATA_HASH => {
                    client_data_hash = Some(crate::cose::bytes_member(val, "clientDataHash")?)
                }
                KEY_ALLOW_LIST => {
                    allow_list = Some(descriptor_array(val)?);
                    // An empty allowList decoded from a request map is
                    // normalized to absent, matching the MUST-NOT-send
                    // rule symmetrically.
                    if allow_list.as_ref().is_some_and(Vec::is_empty) {
                        allow_list = None;
                        continue;
                    }
                }
                KEY_EXTENSIONS => extensions = Some(val.clone()),
                KEY_OPTIONS => {
                    let opt_map = match val {
                        CborValue::Map(opt_entries) => opt_entries,
                        _ => {
                            return Err(DecodeError::TypeMismatch {
                                member: "options",
                                expected: "map",
                            })
                        }
                    };
                    let mut opts = GetAssertionOptions::default();
                    for (k, v) in opt_map {
                        match k {
                            CborValue::Text(s) if s == "up" => {
                                opts.up = Some(bool_member(v, "options[up]")?)
                            }
                            CborValue::Text(s) if s == "uv" => {
                                opts.uv = Some(bool_member(v, "options[uv]")?)
                            }
                            // `rk` is not a getAssertion option key
                            // (§6.2); treat it as unknown and ignore.
                            _ => {}
                        }
                    }
                    options = Some(opts);
                }
                KEY_PIN_UV_AUTH_PARAM => pin_uv_auth_param = Some(PinUvAuthParam::from_cbor(val)?),
                KEY_PIN_UV_AUTH_PROTOCOL => {
                    let n = crate::get_info::uint_member(val, "pinUvAuthProtocol")?;
                    pin_uv_auth_protocol = Some(PinUvAuthProtocol::from_u32(
                        u32::try_from(n).map_err(|_| DecodeError::InvalidValue {
                            member: "pinUvAuthProtocol",
                            detail: format!("value {n} exceeds u32"),
                        })?,
                    ));
                }
                _ => {}
            }
        }
        let rp_id = rp_id.ok_or(DecodeError::MissingMember { member: "rpId" })?;
        let client_data_hash = client_data_hash.ok_or(DecodeError::MissingMember {
            member: "clientDataHash",
        })?;
        Ok(Self {
            rp_id,
            client_data_hash,
            allow_list,
            extensions,
            options,
            pin_uv_auth_param,
            pin_uv_auth_protocol,
        })
    }
}

/// authenticatorGetAssertion response (CTAP2.1 §6.2).
///
/// `credential`, `authData`, `signature` are Required; all other
/// members Optional. `numberOfCredentials` and `userSelected` carry
/// their spec defaults on the struct so a decoded absent member
/// reports the default (1 / false) exactly as the spec scenario
/// requires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetAssertionResponse {
    /// 0x01 — Required. Credential identifier used.
    pub credential: PublicKeyCredentialDescriptor,
    /// 0x02 — Required. Signed-over contextual bindings (WebAuthn).
    pub auth_data: Vec<u8>,
    /// 0x03 — Required. Assertion signature (WebAuthn).
    pub signature: Vec<u8>,
    /// 0x04 — Optional. Identifiable info absent if UV not performed;
    /// `id` mandatory for discoverable credentials when present.
    pub user: Option<PublicKeyCredentialUserEntity>,
    /// 0x05 — Optional. Defaults to 1 (CTAP2.1 §6.2).
    pub number_of_credentials: u64,
    /// 0x06 — Optional. Defaults to false; MUST NOT be present when
    /// allowList was given, when numberOfCredentials > 1, or in
    /// getNextAssertion responses (CTAP2.1 §6.2).
    pub user_selected: bool,
    /// 0x07 — Optional. Present only if the credential has an
    /// associated largeBlobKey.
    pub large_blob_key: Option<Vec<u8>>,
    /// True when member 0x05 was present on the wire.
    pub number_of_credentials_present: bool,
    /// True when member 0x06 was present on the wire.
    pub user_selected_present: bool,
}

impl GetAssertionResponse {
    /// Decode a getAssertion response CBOR map (post-status-byte
    /// portion, CTAP2.1 §6.2.1). Required members enforced; the
    /// userSelected/numberOfCredentials constraint is validated.
    pub fn from_cbor(value: &CborValue) -> Result<Self, DecodeError> {
        let map = match value {
            CborValue::Map(entries) => entries,
            _ => {
                return Err(DecodeError::TypeMismatch {
                    member: "getAssertionResponse",
                    expected: "map",
                })
            }
        };
        let mut credential: Option<PublicKeyCredentialDescriptor> = None;
        let mut auth_data: Option<Vec<u8>> = None;
        let mut signature: Option<Vec<u8>> = None;
        let mut user: Option<PublicKeyCredentialUserEntity> = None;
        let mut number_of_credentials: Option<u64> = None;
        let mut user_selected: Option<bool> = None;
        let mut large_blob_key: Option<Vec<u8>> = None;

        for (key, val) in map {
            let key = match key {
                CborValue::Int(n) if *n >= 0 => u128::try_from(*n).unwrap_or(u128::MAX),
                _ => continue,
            };
            match key {
                KEY_CREDENTIAL => credential = Some(PublicKeyCredentialDescriptor::from_cbor(val)?),
                KEY_AUTH_DATA => auth_data = Some(crate::cose::bytes_member(val, "authData")?),
                KEY_SIGNATURE => signature = Some(crate::cose::bytes_member(val, "signature")?),
                KEY_USER => user = Some(PublicKeyCredentialUserEntity::from_cbor(val)?),
                KEY_NUMBER_OF_CREDENTIALS => {
                    number_of_credentials =
                        Some(crate::get_info::uint_member(val, "numberOfCredentials")?)
                }
                KEY_USER_SELECTED => user_selected = Some(bool_member(val, "userSelected")?),
                KEY_LARGE_BLOB_KEY => {
                    large_blob_key = Some(crate::cose::bytes_member(val, "largeBlobKey")?)
                }
                _ => {}
            }
        }

        let credential = credential.ok_or(DecodeError::MissingMember {
            member: "credential",
        })?;
        let auth_data = auth_data.ok_or(DecodeError::MissingMember { member: "authData" })?;
        let signature = signature.ok_or(DecodeError::MissingMember {
            member: "signature",
        })?;

        // §6.2: userSelected MUST NOT be present when numberOfCredentials
        // > 1 (also when an allowList was given — a request-context rule
        // the caller layers on — and in getNextAssertion responses).
        if user_selected.is_some() && number_of_credentials.unwrap_or(1) > 1 {
            return Err(DecodeError::InvalidValue {
                member: "userSelected",
                detail: "MUST NOT be present when numberOfCredentials > 1 (CTAP2.1 §6.2)".into(),
            });
        }

        Ok(Self {
            credential,
            auth_data,
            signature,
            user,
            number_of_credentials: number_of_credentials.unwrap_or(1),
            user_selected: user_selected.unwrap_or(false),
            large_blob_key,
            number_of_credentials_present: number_of_credentials.is_some(),
            user_selected_present: user_selected.is_some(),
        })
    }

    /// Encode the response map (soft-token harness use). All members
    /// present on the struct are emitted.
    pub fn encode(&self) -> Result<alloc::vec::Vec<u8>, EncodeError> {
        let mut entries: Vec<(CborValue, CborValue)> = Vec::with_capacity(7);
        entries.push((
            CborValue::Int(KEY_CREDENTIAL as i128),
            self.credential.to_cbor(),
        ));
        entries.push((
            CborValue::Int(KEY_AUTH_DATA as i128),
            CborValue::Bytes(self.auth_data.clone()),
        ));
        entries.push((
            CborValue::Int(KEY_SIGNATURE as i128),
            CborValue::Bytes(self.signature.clone()),
        ));
        if let Some(user) = &self.user {
            entries.push((CborValue::Int(KEY_USER as i128), user.to_cbor()));
        }
        if self.number_of_credentials_present {
            entries.push((
                CborValue::Int(KEY_NUMBER_OF_CREDENTIALS as i128),
                CborValue::Int(i128::from(self.number_of_credentials)),
            ));
        }
        if self.user_selected_present {
            entries.push((
                CborValue::Int(KEY_USER_SELECTED as i128),
                CborValue::Bool(self.user_selected),
            ));
        }
        if let Some(key) = &self.large_blob_key {
            entries.push((
                CborValue::Int(KEY_LARGE_BLOB_KEY as i128),
                CborValue::Bytes(key.clone()),
            ));
        }
        CborValue::Map(entries).encode()
    }
}

fn text_member(
    value: &CborValue,
    member: &'static str,
) -> Result<alloc::string::String, DecodeError> {
    match value {
        CborValue::Text(s) => Ok(s.clone()),
        _ => Err(DecodeError::TypeMismatch {
            member,
            expected: "text string",
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

fn descriptor_array(value: &CborValue) -> Result<Vec<PublicKeyCredentialDescriptor>, DecodeError> {
    match value {
        CborValue::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(PublicKeyCredentialDescriptor::from_cbor(item)?);
            }
            Ok(out)
        }
        _ => Err(DecodeError::TypeMismatch {
            member: "allowList",
            expected: "array of PublicKeyCredentialDescriptor",
        }),
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

    fn decode_request(bytes: &[u8]) -> Result<GetAssertionRequest, DecodeError> {
        GetAssertionRequest::from_cbor(&CborValue::decode_map(bytes, DecodePolicy::Strict)?)
    }

    fn decode_response(bytes: &[u8]) -> Result<GetAssertionResponse, DecodeError> {
        GetAssertionResponse::from_cbor(&CborValue::decode_map(bytes, DecodePolicy::Strict)?)
    }

    fn sample_descriptor(id: u8) -> PublicKeyCredentialDescriptor {
        PublicKeyCredentialDescriptor {
            type_field: CredentialType::PublicKey,
            id: vec![id; 16],
            transports: None,
        }
    }

    // ------------------------------------------------------------------
    // Scenario: Minimal getAssertion request encodes
    // ------------------------------------------------------------------
    #[test]
    fn minimal_request_encodes_with_exactly_keys_01_and_02() {
        let request =
            GetAssertionRequest::new(String::from("example.com"), vec![0xAA; 32]).unwrap();
        let bytes = request.encode().unwrap();
        // map(2) | 1: "example.com" | 2: h'(32 x AA)'
        let mut expected = vec![0xA2u8, 0x01];
        expected.extend_from_slice(&hex("6b6578616d706c652e636f6d"));
        expected.push(0x02);
        expected.push(0x58);
        expected.push(0x20);
        expected.extend_from_slice(&[0xAA; 32]);
        assert_eq!(bytes, expected);
        // Decode side sees the same two members.
        let decoded = decode_request(&bytes).unwrap();
        assert_eq!(decoded.rp_id, "example.com");
        assert_eq!(decoded.client_data_hash, vec![0xAA; 32]);
        assert!(decoded.allow_list.is_none());
    }

    // ------------------------------------------------------------------
    // Scenario: Empty allowList is omitted, not sent
    // ------------------------------------------------------------------
    #[test]
    fn empty_allow_list_is_omitted_not_sent() {
        let request = GetAssertionRequest::new(String::from("example.com"), vec![0xAA; 32])
            .unwrap()
            .with_allow_list(vec![]);
        assert!(request.allow_list.is_none());
        let bytes = request.encode().unwrap();
        // Same bytes as the minimal request: key 0x03 absent.
        let minimal =
            GetAssertionRequest::new(String::from("example.com"), vec![0xAA; 32]).unwrap();
        assert_eq!(bytes, minimal.encode().unwrap());
    }

    // ------------------------------------------------------------------
    // Scenario: uv option and pinUvAuthParam are mutually exclusive
    // ------------------------------------------------------------------
    #[test]
    fn uv_option_and_pin_uv_auth_param_are_mutually_exclusive() {
        let mut request =
            GetAssertionRequest::new(String::from("example.com"), vec![0xAA; 32]).unwrap();
        request.options = Some(GetAssertionOptions {
            up: None,
            uv: Some(true),
        });
        request.pin_uv_auth_param = Some(PinUvAuthParam::new(vec![0x99; 32]));
        assert_eq!(
            request.encode().unwrap_err(),
            EncodeError::InvalidRequest(InvalidRequest::UvOptionWithPinUvAuthParam)
        );
        // uv alone (deprecated but legal) encodes fine.
        let mut uv_only =
            GetAssertionRequest::new(String::from("example.com"), vec![0xAA; 32]).unwrap();
        uv_only.options = Some(GetAssertionOptions {
            up: Some(true),
            uv: Some(true),
        });
        assert!(uv_only.encode().is_ok());
        // pinUvAuthParam alone encodes fine.
        let mut param_only =
            GetAssertionRequest::new(String::from("example.com"), vec![0xAA; 32]).unwrap();
        param_only.pin_uv_auth_param = Some(PinUvAuthParam::new(vec![0x99; 32]));
        param_only.pin_uv_auth_protocol = Some(PinUvAuthProtocol::Two);
        assert!(param_only.encode().is_ok());
    }

    // ------------------------------------------------------------------
    // Scenario: getAssertion request carries both PIN/UV parameters
    // ------------------------------------------------------------------
    #[test]
    fn request_with_both_pin_uv_parameters_is_typed() {
        // CONSTRUCTED full-request vector: rpId, clientDataHash,
        // allowList, options{up}, pinUvAuthParam, pinUvAuthProtocol=2.
        let mut request = GetAssertionRequest::new(String::from("example.com"), vec![0xAB; 32])
            .unwrap()
            .with_allow_list(vec![sample_descriptor(0x42)]);
        request.options = Some(GetAssertionOptions {
            up: Some(true),
            uv: None,
        });
        request.pin_uv_auth_param = Some(PinUvAuthParam::new(vec![0x77; 32]));
        request.pin_uv_auth_protocol = Some(PinUvAuthProtocol::Two);
        let bytes = request.encode().unwrap();
        // Canonical order: 01, 02, 03, 05, 06, 07 (04 absent).
        let mut expected = Vec::new();
        expected.push(0xA6);
        expected.push(0x01);
        expected.extend_from_slice(&hex("6b6578616d706c652e636f6d"));
        expected.push(0x02);
        expected.push(0x58);
        expected.push(0x20);
        expected.extend_from_slice(&[0xAB; 32]);
        expected.push(0x03);
        expected.push(0x81);
        expected.push(0xA2);
        expected.extend_from_slice(&hex("62696450")); // "id": h'(16 x 42)
        expected.extend_from_slice(&[0x42; 16]);
        expected.extend_from_slice(&hex("64747970656a7075626c69632d6b6579"));
        expected.push(0x05);
        expected.push(0xA1);
        expected.extend_from_slice(&hex("627570f5")); // "up": true
        expected.push(0x06);
        expected.push(0x58);
        expected.push(0x20);
        expected.extend_from_slice(&[0x77; 32]);
        expected.push(0x07);
        expected.push(0x02);
        assert_eq!(bytes, expected);
        // Round-trip identity through the decoder.
        let decoded = decode_request(&bytes).unwrap();
        assert_eq!(decoded.pin_uv_auth_protocol, Some(PinUvAuthProtocol::Two));
        assert_eq!(
            decoded.pin_uv_auth_param.as_ref().unwrap().bytes,
            vec![0x77; 32]
        );
        assert_eq!(decoded.allow_list.as_ref().unwrap().len(), 1);
    }

    // ------------------------------------------------------------------
    // Scenario: Minimal getAssertion response decodes
    // ------------------------------------------------------------------
    #[test]
    fn minimal_response_decodes_with_spec_defaults() {
        // map {1: {type, id}, 2: authData, 3: signature}
        let mut bytes =
            hex("a301a2626964501111111111111111111111111111111164747970656a7075626c69632d6b6579");
        bytes.push(0x02);
        bytes.push(0x43);
        bytes.extend_from_slice(&[0xDA, 0xD0, 0x0D]);
        bytes.push(0x03);
        bytes.push(0x43);
        bytes.extend_from_slice(&[0x5E, 0x5E, 0x5E]);
        let response = decode_response(&bytes).unwrap();
        assert_eq!(response.credential.id, vec![0x11; 16]);
        assert_eq!(response.auth_data, vec![0xDA, 0xD0, 0x0D]);
        assert_eq!(response.signature, vec![0x5E, 0x5E, 0x5E]);
        // Defaults reported as the spec says: 1 and false.
        assert_eq!(response.number_of_credentials, 1);
        assert!(!(response.user_selected));
        assert!(!response.number_of_credentials_present);
        assert!(!response.user_selected_present);
        assert!(response.user.is_none());
        assert!(response.large_blob_key.is_none());
    }

    // ------------------------------------------------------------------
    // Scenario: Response missing a required member fails
    // ------------------------------------------------------------------
    #[test]
    fn response_missing_required_member_fails() {
        // map {1: credential, 2: authData} — signature (0x03) missing.
        let mut bytes =
            hex("a201a2626964501111111111111111111111111111111164747970656a7075626c69632d6b6579");
        bytes.push(0x02);
        bytes.push(0x43);
        bytes.extend_from_slice(&[0xDA, 0xD0, 0x0D]);
        assert_eq!(
            decode_response(&bytes).unwrap_err(),
            DecodeError::MissingMember {
                member: "signature"
            }
        );
    }

    // ------------------------------------------------------------------
    // Scenario: userSelected constraints are validated
    // ------------------------------------------------------------------
    #[test]
    fn user_selected_with_multiple_credentials_is_rejected() {
        // map {1: credential, 2: authData, 3: signature, 5: 3, 6: true}
        let mut bytes =
            hex("a501a2626964501111111111111111111111111111111164747970656a7075626c69632d6b6579");
        bytes.push(0x02);
        bytes.push(0x43);
        bytes.extend_from_slice(&[0xDA, 0xD0, 0x0D]);
        bytes.push(0x03);
        bytes.push(0x43);
        bytes.extend_from_slice(&[0x5E, 0x5E, 0x5E]);
        bytes.push(0x05);
        bytes.push(0x03);
        bytes.push(0x06);
        bytes.push(0xF5);
        assert!(matches!(
            decode_response(&bytes).unwrap_err(),
            DecodeError::InvalidValue {
                member: "userSelected",
                ..
            }
        ));
        // userSelected with the default numberOfCredentials (absent,
        // i.e. 1) is fine.
        let mut bytes =
            hex("a401a2626964501111111111111111111111111111111164747970656a7075626c69632d6b6579");
        bytes.push(0x02);
        bytes.push(0x43);
        bytes.extend_from_slice(&[0xDA, 0xD0, 0x0D]);
        bytes.push(0x03);
        bytes.push(0x43);
        bytes.extend_from_slice(&[0x5E, 0x5E, 0x5E]);
        bytes.push(0x06);
        bytes.push(0xF5);
        let response = decode_response(&bytes).unwrap();
        assert!(response.user_selected_present);
        assert!(response.user_selected);
        assert_eq!(response.number_of_credentials, 1);
    }

    #[test]
    fn full_response_round_trips() {
        let response = GetAssertionResponse {
            credential: sample_descriptor(0x77),
            auth_data: vec![0x01; 37],
            signature: vec![0x02; 70],
            user: Some(PublicKeyCredentialUserEntity {
                id: vec![0x0A; 8],
                name: Some(String::from("fred")),
                display_name: None,
            }),
            number_of_credentials: 2,
            user_selected: false,
            large_blob_key: Some(vec![0x03; 32]),
            number_of_credentials_present: true,
            user_selected_present: false,
        };
        let bytes = response.encode().unwrap();
        assert_eq!(decode_response(&bytes).unwrap(), response);
    }

    #[test]
    fn request_missing_required_members_fail() {
        // Missing clientDataHash.
        let bytes = hex("a1016b6578616d706c652e636f6d");
        assert_eq!(
            decode_request(&bytes).unwrap_err(),
            DecodeError::MissingMember {
                member: "clientDataHash"
            }
        );
        // Missing rpId.
        let mut bytes = vec![0xA1u8, 0x02, 0x58, 0x20];
        bytes.extend_from_slice(&[0xAA; 32]);
        assert_eq!(
            decode_request(&bytes).unwrap_err(),
            DecodeError::MissingMember { member: "rpId" }
        );
    }

    // pinUvAuthProtocol support check against a getInfo list
    // (CTAP2.1 §6.5.5): the model records the verdict; the ceremony
    // layer turns it into its typed failure.
    #[test]
    fn pin_uv_auth_protocol_support_is_recorded() {
        let supported = vec![PinUvAuthProtocol::One, PinUvAuthProtocol::Two];
        assert!(PinUvAuthProtocol::One.is_supported_by(&supported));
        assert!(PinUvAuthProtocol::Two.is_supported_by(&supported));
        assert!(!PinUvAuthProtocol::from_u32(3).is_supported_by(&supported));
        assert_eq!(PinUvAuthProtocol::Two.to_u32(), 2);
        assert_eq!(PinUvAuthProtocol::One.to_u32(), 1);
        assert_eq!(PinUvAuthProtocol::from_u32(1), PinUvAuthProtocol::One);
        assert_eq!(PinUvAuthProtocol::from_u32(2), PinUvAuthProtocol::Two);
    }

    #[test]
    fn unknown_request_keys_are_ignored() {
        // Valid request members plus unknown keys 99 (18 63) and a
        // negative key -1 (20); both MUST be ignored (CTAP2.1 §8).
        let mut bytes = vec![0xA4u8, 0x01];
        bytes.extend_from_slice(&hex("6b6578616d706c652e636f6d"));
        bytes.push(0x02);
        bytes.push(0x58);
        bytes.push(0x20);
        bytes.extend_from_slice(&[0xAA; 32]);
        bytes.extend_from_slice(&hex("2000")); // -1: 0 — unknown
        bytes.extend_from_slice(&hex("1863f4")); // 99: false — unknown
        let decoded = decode_request(&bytes).unwrap();
        assert_eq!(decoded.rp_id, "example.com");
        assert_eq!(decoded.client_data_hash, vec![0xAA; 32]);
    }
}
