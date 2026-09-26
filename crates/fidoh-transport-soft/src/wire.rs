//! Wire encoders for the soft token's CTAP2 responses (transport-soft
//! spec: authenticatorData layout, COSE key encoding, getInfo shape).
//!
//! CBOR emission goes through [`CborValue`](fidoh_core::cbor::CborValue)
//! so the client stack's canonical-decode path is exercised unchanged.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use fidoh_core::cbor::CborValue;
use fidoh_core::cose::CoseEs256Key;
use fidoh_core::error::{EncodeError, Error};
use fidoh_core::get_assertion::{
    CredentialType, GetAssertionResponse, PublicKeyCredentialDescriptor,
    PublicKeyCredentialUserEntity,
};
use fidoh_core::get_info::{AuthenticatorOptions, GetInfoResponse};

use sha2::{Digest, Sha256};

use crate::auth::AAGUID;

/// SHA-256 of `data` (rpIdHash input per WebAuthn L2 §6.1).
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Flag bits per WebAuthn L2 §6.1.
pub(crate) const FLAG_UP: u8 = 1 << 0;
pub(crate) const FLAG_UV: u8 = 1 << 2;
pub(crate) const FLAG_AT: u8 = 1 << 6;

/// Build `authenticatorData` per WebAuthn L2 §6.1: 32-byte rpIdHash,
/// flags byte, 4-byte big-endian signCount, then attested credential
/// data when `attested` is `Some((credential_id, cose_key))` (AT set;
/// makeCredential responses only — the soft token emits no extensions,
/// so ED is always 0).
pub(crate) fn authenticator_data(
    rp_id: &str,
    up: bool,
    uv: bool,
    sign_count: u32,
    attested: Option<(&[u8], &CoseEs256Key)>,
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(37 + 16 + 2 + 64 + 77);
    out.extend_from_slice(&sha256(rp_id.as_bytes()));
    let mut flags = 0u8;
    if up {
        flags |= FLAG_UP;
    }
    if uv {
        flags |= FLAG_UV;
    }
    if attested.is_some() {
        flags |= FLAG_AT;
    }
    out.push(flags);
    out.extend_from_slice(&sign_count.to_be_bytes());
    if let Some((credential_id, cose_key)) = attested {
        out.extend_from_slice(&AAGUID);
        let len = u16::try_from(credential_id.len()).map_err(|_| {
            crate::rng::soft_err(alloc::format!(
                "credential ID length {} exceeds u16",
                credential_id.len()
            ))
        })?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(credential_id);
        out.extend_from_slice(
            &cose_key
                .encode()
                .map_err(|e| crate::rng::soft_err(e.to_string()))?,
        );
    }
    Ok(out)
}

/// The pinned-AAGUID getInfo response model (CTAP2.1 §6.4;
/// transport-soft spec "authenticatorGetInfo") — clientPIN-capable
/// variant (add-client-pin task 4.2): `uv_capable` reflects the
/// configured UV mode capability; `pin_feature` false keeps the v1
/// byte-shape exactly (no clientPin members, no protocols). When
/// armed, the harness-configured `protocols` list and the
/// `advertise_pin_uv_auth_token` switch shape the clientPIN feature
/// advertisement (false models the CTAP2.0 getPinToken-only token —
/// the platform then falls back to subcommand 0x05).
pub(crate) fn get_info_response_with_protocols(
    uv_capable: bool,
    pin_feature: bool,
    protocols: &[fidoh_core::pin::PinUvAuthProtocol],
    advertise_pin_uv_auth_token: bool,
) -> GetInfoResponse {
    let mut options = alloc::collections::BTreeMap::new();
    options.insert(String::from("rk"), true);
    options.insert(String::from("up"), true);
    options.insert(String::from("uv"), uv_capable);
    if pin_feature {
        options.insert(String::from("clientPin"), true);
        if advertise_pin_uv_auth_token {
            options.insert(String::from("pinUvAuthToken"), true);
        }
    }
    GetInfoResponse {
        versions: alloc::vec![String::from("FIDO_2_0"), String::from("FIDO_2_1")],
        extensions: None,
        aaguid: AAGUID,
        options: Some(AuthenticatorOptions { entries: options }),
        pin_uv_auth_protocols: pin_feature.then(|| protocols.to_vec()),
        ..Default::default()
    }
}

/// The parsed assertion parts the device shim hands to tests, built
/// from the wire response body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssertionParts {
    /// The credential descriptor echoed in the response (0x01).
    pub credential_id: Vec<u8>,
    /// authenticatorData (0x02).
    pub auth_data: Vec<u8>,
    /// DER-encoded ECDSA P-256 signature over
    /// `authData || clientDataHash` (0x03).
    pub signature: Vec<u8>,
    /// The user handle, present for discoverable credentials (0x04).
    pub user_handle: Option<Vec<u8>>,
    /// numberOfCredentials (0x05) when the response carried it.
    pub number_of_credentials: u64,
}

impl AssertionParts {
    /// Build the response body CBOR from the parts (CTAP2.1 §6.2
    /// response structure).
    pub(crate) fn encode_response(
        credential_id: &[u8],
        auth_data: &[u8],
        signature: &[u8],
        user_handle: Option<&[u8]>,
        number_of_credentials: Option<u64>,
    ) -> Result<Vec<u8>, EncodeError> {
        let response = GetAssertionResponse {
            credential: PublicKeyCredentialDescriptor {
                type_field: CredentialType::PublicKey,
                id: credential_id.to_vec(),
                transports: None,
            },
            auth_data: auth_data.to_vec(),
            signature: signature.to_vec(),
            user: user_handle.map(|handle| PublicKeyCredentialUserEntity {
                id: handle.to_vec(),
                name: None,
                display_name: None,
            }),
            number_of_credentials: number_of_credentials.unwrap_or(1),
            user_selected: false,
            large_blob_key: None,
            number_of_credentials_present: number_of_credentials.is_some(),
            user_selected_present: false,
        };
        response.encode()
    }

    /// Parse a getAssertion response body (test/harness use).
    pub fn decode_response(body: &[u8]) -> Result<Self, fidoh_core::DecodeError> {
        let value = CborValue::decode_map(body, fidoh_core::DecodePolicy::Strict)?;
        let response = GetAssertionResponse::from_cbor(&value)?;
        Ok(Self {
            credential_id: response.credential.id,
            auth_data: response.auth_data,
            signature: response.signature,
            user_handle: response.user.map(|u| u.id),
            number_of_credentials: response.number_of_credentials,
        })
    }
}
