//! Versioned credential-store snapshots (transport-soft spec
//! "Credential store": serde-serializable snapshot including private
//! keys; design OQ-3 resolved to JSON for readability of committed
//! fixtures).
//!
//! Snapshots are test-harness artifacts and are NOT part of the
//! client-facing API (feature-gated behind `snapshot`).

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::auth::SoftAuthenticator;

/// Snapshot format version. Bump on any incompatible change; import
/// rejects unknown versions with a typed error.
pub const SNAPSHOT_VERSION: u32 = 1;

/// A versioned, serde-serializable export of the full credential
/// store (including private keys — fixtures need real keys to verify
/// signatures, and these are test-only keys).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Snapshot {
    /// Format version ([`SNAPSHOT_VERSION`]).
    pub version: u32,
    /// The global signature counter value at export time.
    pub sign_count: u32,
    /// Every stored credential source record.
    pub credentials: Vec<SnapshotCredential>,
}

/// One credential source record in a snapshot. Byte fields are hex
/// strings so committed JSON fixtures stay human-reviewable.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotCredential {
    /// Credential ID, hex-encoded.
    pub id: String,
    /// The relying party ID.
    pub rp_id: String,
    /// User handle, hex-encoded.
    pub user_handle: String,
    /// P-256 private key scalar, hex-encoded (32 bytes).
    pub private_key: String,
    /// Whether the credential is discoverable (resident).
    pub resident: bool,
}

/// Snapshot import/export failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotError {
    /// The snapshot's version is not supported by this build.
    UnsupportedVersion(u32),
    /// A hex field was malformed or had the wrong length.
    MalformedHex(&'static str),
    /// A private key was not a valid P-256 scalar.
    InvalidPrivateKey,
    /// JSON serialization/deserialization failed.
    Json(String),
}

impl core::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => write!(
                f,
                "unsupported snapshot version {v} (this build supports {SNAPSHOT_VERSION})"
            ),
            Self::MalformedHex(field) => write!(f, "malformed hex in snapshot field '{field}'"),
            Self::InvalidPrivateKey => {
                f.write_str("snapshot private key is not a valid P-256 scalar")
            }
            Self::Json(e) => write!(f, "snapshot JSON error: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SnapshotError {}

/// Export the full store as a versioned snapshot.
pub fn export(auth: &SoftAuthenticator) -> Snapshot {
    let mut credentials = Vec::with_capacity(auth.credentials().len());
    for (i, record) in auth.credentials().iter().enumerate() {
        let key = auth.record_key_bytes(i).unwrap_or([0u8; 32]);
        credentials.push(SnapshotCredential {
            id: hex_encode(&record.id),
            rp_id: record.rp_id.clone(),
            user_handle: hex_encode(&record.user_handle),
            private_key: hex_encode(&key),
            resident: record.resident,
        });
    }
    Snapshot {
        version: SNAPSHOT_VERSION,
        sign_count: auth.sign_count(),
        credentials,
    }
}

/// Import a snapshot into a fresh authenticator.
pub fn import(auth: &mut SoftAuthenticator, snapshot: &Snapshot) -> Result<(), SnapshotError> {
    if snapshot.version != SNAPSHOT_VERSION {
        return Err(SnapshotError::UnsupportedVersion(snapshot.version));
    }
    for cred in &snapshot.credentials {
        let id = hex_decode(&cred.id, "id")?;
        let user_handle = hex_decode(&cred.user_handle, "user_handle")?;
        let key_bytes = hex_decode(&cred.private_key, "private_key")?;
        let key: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| SnapshotError::MalformedHex("private_key"))?;
        auth.push_record_bytes(id, cred.rp_id.clone(), user_handle, key, cred.resident)
            .map_err(|_| SnapshotError::InvalidPrivateKey)?;
    }
    auth.set_sign_count(snapshot.sign_count);
    Ok(())
}

/// Serialize a snapshot to JSON (design OQ-3: JSON over CBOR for
/// fixture readability).
pub fn to_json(snapshot: &Snapshot) -> Result<String, SnapshotError> {
    serde_json::to_string_pretty(snapshot).map_err(|e| SnapshotError::Json(alloc::format!("{e}")))
}

/// Deserialize a snapshot from JSON.
pub fn from_json(json: &str) -> Result<Snapshot, SnapshotError> {
    serde_json::from_str(json).map_err(|e| SnapshotError::Json(alloc::format!("{e}")))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(b & 0x0F), 16).unwrap_or('0'));
    }
    out
}

fn hex_decode(s: &str, field: &'static str) -> Result<Vec<u8>, SnapshotError> {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(SnapshotError::MalformedHex(field));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16);
        let lo = (pair[1] as char).to_digit(16);
        match (hi, lo) {
            (Some(hi), Some(lo)) => out.push(((hi << 4) | lo) as u8),
            _ => return Err(SnapshotError::MalformedHex(field)),
        }
    }
    Ok(out)
}
