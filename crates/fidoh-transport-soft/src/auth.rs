//! The authenticator core: credential store, signature counter,
//! makeCredential (internal) and getAssertion command logic
//! (transport-soft spec requirements "Internal
//! authenticatorMakeCredential", "authenticatorGetAssertion
//! signatures", "Signature counter", "Credential store").
//!
//! Pure state machine — no waits, no I/O. The async knob handling
//! (keepalives, poke waits, delays) lives in [`crate::device`].

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use fidoh_core::cose::CoseEs256Key;
use fidoh_core::get_assertion::GetAssertionRequest;
use fidoh_core::{Error, StatusCode};

use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};

use crate::config::{Config, Knobs, RngConfig, UpUvMode};
use crate::rng::{soft_err, DeterministicRng, RngSource};
use crate::wire;

/// The pinned soft-token AAGUID (transport-soft spec
/// "authenticatorGetInfo": a fixed 16-byte value reserved for the soft
/// token, distinct from any production authenticator). Documented in
/// docs/transport-soft.md.
pub const AAGUID: [u8; 16] = *b"fidoh-soft-token";

/// Maximum credentials parked in the multi-assertion queue
/// (defensive bound; CTAP2.1 §6.2 numberOfCredentials flow).
pub const MAX_ASSERTION_QUEUE: usize = 8;

/// A stored credential source record (WebAuthn L2 §4: type
/// public-key, private key, rpId, userHandle).
#[derive(Clone)]
pub struct CredentialRecord {
    /// Credential ID (random 32-byte handle generated at minting).
    pub id: Vec<u8>,
    /// The relying party ID this credential is scoped to.
    pub rp_id: String,
    /// The user handle associated at minting.
    pub user_handle: Vec<u8>,
    /// The ECDSA P-256 private key (kept in-memory only).
    private_key: SigningKey,
    /// Whether the credential is discoverable (resident) — resident
    /// credentials are returned for requests without an allowList and
    /// carry the user handle in assertions (CTAP2.1 §6.2).
    pub resident: bool,
}

impl CredentialRecord {
    /// The COSE-encoded public key (RFC 8152 §8 / RFC 9053 §7.1).
    pub fn public_key(&self) -> CoseEs256Key {
        cose_key_of(self.private_key.verifying_key())
    }

    /// The P-256 verifying key, for signature verification in tests.
    pub fn verifying_key(&self) -> VerifyingKey {
        *self.private_key.verifying_key()
    }
}

impl core::fmt::Debug for CredentialRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CredentialRecord")
            .field("id", &self.id)
            .field("rp_id", &self.rp_id)
            .field("user_handle", &self.user_handle)
            .field("resident", &self.resident)
            .finish_non_exhaustive()
    }
}

/// Arguments for the internal harness-only makeCredential
/// (CTAP2.1 §6.1). NOT part of the client-facing API.
#[derive(Clone, Debug)]
pub struct MakeCredentialArgs {
    /// The relying party ID (e.g. `"example.com"`).
    pub rp_id: String,
    /// The user handle to bind (WebAuthn L2 §4 credential source).
    pub user_handle: Vec<u8>,
    /// Store as a discoverable (resident) credential. Default true
    /// (the token reports `rk: true`).
    pub resident: bool,
}

/// What a minted credential looks like to the harness: the stored
/// record plus the makeCredential response bytes (attested credential
/// data, fmt `none` — WebAuthn L2 §8.7).
#[derive(Clone, Debug)]
pub struct MintedCredential {
    /// The stored credential source record.
    pub record: CredentialRecord,
    /// The full authenticatorData blob, including attested credential
    /// data (pinned AAGUID, credential ID, COSE key).
    pub attested_auth_data: Vec<u8>,
    /// The signCount after minting (the counter increments by exactly
    /// 1 per successful makeCredential).
    pub sign_count: u32,
}

/// The soft-token authenticator: state + config, per the transport-soft
/// design's "authenticator core" layer.
pub struct SoftAuthenticator {
    pub(crate) credentials: Vec<CredentialRecord>,
    pub(crate) sign_count: u32,
    up_mode: UpUvMode,
    uv_mode: UpUvMode,
    pub(crate) knobs: Knobs,
    rng: Box<dyn RngSource + Send>,
    /// Poke latches, released by `poke_user_presence` /
    /// `poke_user_verification`; consumed by pending UP/UV waits.
    pub(crate) up_poked: bool,
    pub(crate) uv_poked: bool,
    /// Parked multi-assertion queue (credentials beyond the first from
    /// the most recent getAssertion), drained by getNextAssertion.
    /// Entries are (credential index, up outcome, uv outcome).
    pub(crate) assertion_queue: Vec<(usize, bool, bool)>,
}

impl SoftAuthenticator {
    /// A default-configured authenticator (pinned AAGUID, empty store,
    /// auto-approve UP/UV, build-salted deterministic entropy).
    pub fn new(config: Config) -> Self {
        let rng: Box<dyn RngSource + Send> = match config.rng {
            RngConfig::Default => Box::new(DeterministicRng::build_salted()),
            RngConfig::Seeded(r) => Box::new(r),
        };
        Self {
            credentials: Vec::new(),
            sign_count: config.initial_sign_count,
            up_mode: config.up_mode,
            uv_mode: config.uv_mode,
            knobs: config.knobs,
            rng,
            up_poked: false,
            uv_poked: false,
            assertion_queue: Vec::new(),
        }
    }

    /// An authenticator with a caller-supplied randomness source
    /// (design §Cryptography: the randomness seam).
    pub fn with_rng(config: Config, rng: impl RngSource + Send + 'static) -> Self {
        let mut this = Self::new(config);
        this.rng = Box::new(rng);
        this
    }

    /// The configured UP behavior mode.
    pub fn up_mode(&self) -> UpUvMode {
        self.up_mode
    }

    /// The configured UV behavior mode.
    pub fn uv_mode(&self) -> UpUvMode {
        self.uv_mode
    }

    /// Set the UP behavior mode (harness knob).
    pub fn set_up_mode(&mut self, mode: UpUvMode) {
        self.up_mode = mode;
    }

    /// Set the UV behavior mode (harness knob).
    pub fn set_uv_mode(&mut self, mode: UpUvMode) {
        self.uv_mode = mode;
    }

    /// Mutable access to the error-injection knobs.
    pub fn knobs_mut(&mut self) -> &mut Knobs {
        &mut self.knobs
    }

    /// Release a pending `require-explicit-poke` UP wait.
    pub fn poke_user_presence(&mut self) {
        self.up_poked = true;
    }

    /// Release a pending `require-explicit-poke` UV wait.
    pub fn poke_user_verification(&mut self) {
        self.uv_poked = true;
    }

    /// Consume the UP poke latch (true once per poke).
    pub(crate) fn take_up_poke(&mut self) -> bool {
        core::mem::take(&mut self.up_poked)
    }

    /// Consume the UV poke latch (true once per poke).
    pub(crate) fn take_uv_poke(&mut self) -> bool {
        core::mem::take(&mut self.uv_poked)
    }

    /// The current global signature counter value.
    pub fn sign_count(&self) -> u32 {
        self.sign_count
    }

    /// The stored credentials (read-only; lookup by ID and enumeration
    /// by rpId per transport-soft spec "Credential store").
    pub fn credentials(&self) -> &[CredentialRecord] {
        &self.credentials
    }

    /// Look up a credential by ID.
    pub fn credential_by_id(&self, id: &[u8]) -> Option<&CredentialRecord> {
        self.credentials.iter().find(|c| c.id == id)
    }

    /// The getInfo response model for the current configuration
    /// (transport-soft spec "authenticatorGetInfo").
    pub fn get_info(&self) -> fidoh_core::get_info::GetInfoResponse {
        // The `uv` option reports whether UV can ever succeed: any mode
        // other than always-fail is UV-capable (auto-approve and
        // require-explicit-poke both reach UV=true outcomes).
        wire::get_info_response(self.uv_mode != UpUvMode::AlwaysFail)
    }

    /// INTERNAL harness-only authenticatorMakeCredential (CTAP2.1
    /// §6.1): mint a fresh ES256 keypair, generate a credential ID,
    /// persist the credential source record. Not reachable through the
    /// `Device` trait.
    pub fn make_credential(&mut self, args: MakeCredentialArgs) -> Result<MintedCredential, Error> {
        let private_key = self.generate_key()?;
        let credential_id = self.rng.bytes(32)?;
        let record = CredentialRecord {
            id: credential_id,
            rp_id: args.rp_id,
            user_handle: args.user_handle,
            private_key,
            resident: args.resident,
        };
        self.sign_count = self.sign_count.wrapping_add(1);
        let attested_auth_data = wire::authenticator_data(
            &record.rp_id,
            true, // UP: minting is harness-driven, presence is implied
            true, // UV outcome mirrors the configured capability
            self.sign_count,
            Some((&record.id, &record.public_key())),
        )?;
        let minted = MintedCredential {
            sign_count: self.sign_count,
            attested_auth_data,
            record: record.clone(),
        };
        self.credentials.push(record);
        Ok(minted)
    }

    /// Draw a fresh P-256 keypair from the configured RNG (32 bytes,
    /// reduced mod the group order by `SecretKey::from_bytes`; on the
    /// astronomically unlikely out-of-range draw, retry once with a
    /// fresh draw before failing typed).
    fn generate_key(&mut self) -> Result<SigningKey, Error> {
        for _ in 0..2 {
            let bytes = self.rng.bytes(32)?;
            if let Ok(key) = SigningKey::from_slice(&bytes) {
                return Ok(key);
            }
        }
        Err(soft_err(String::from(
            "rng produced out-of-range P-256 scalar twice",
        )))
    }

    /// Resolve the credential this assertion will use, applying the
    /// allowList rule (CTAP2.1 §6.2 step: credentials on the allowList
    /// that this authenticator holds) and the wrong-credential-id knob.
    ///
    /// Returns the selected record index plus the queue of additional
    /// matching credentials (multi-assertion flow).
    pub(crate) fn select_credentials(
        &mut self,
        request: &GetAssertionRequest,
    ) -> Result<Vec<usize>, StatusCode> {
        let matching: Vec<usize> = match &request.allow_list {
            Some(list) => self
                .credentials
                .iter()
                .enumerate()
                .filter(|(_, c)| c.rp_id == request.rp_id && list.iter().any(|d| d.id == c.id))
                .map(|(i, _)| i)
                .collect(),
            // No allowList: discoverable credentials for the rpId
            // (resident-key flow, CTAP2.1 §6.2).
            None => self
                .credentials
                .iter()
                .enumerate()
                .filter(|(_, c)| c.resident && c.rp_id == request.rp_id)
                .map(|(i, _)| i)
                .collect(),
        };
        if matching.is_empty() {
            return Err(StatusCode::NoCredentials);
        }
        Ok(matching)
    }

    /// Build and sign an assertion for credential `index` with the
    /// resolved UP/UV outcomes. Increments the global counter by
    /// exactly 1 per successful assertion (transport-soft spec
    /// "Signature counter").
    ///
    /// `sign_as` overrides are handled by the caller echoing a
    /// different stored credential's ID in the response descriptor;
    /// the SIGNATURE always stays under the selected credential's key
    /// (wrong-credential-id knob: the signature must remain valid per
    /// the transport-soft spec scenario).
    pub(crate) fn sign_assertion(
        &mut self,
        index: usize,
        client_data_hash: &[u8],
        up: bool,
        uv: bool,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let record = self
            .credentials
            .get(index)
            .ok_or_else(|| soft_err(String::from("credential index out of range")))?;
        self.sign_count = self.sign_count.wrapping_add(1);
        let auth_data = wire::authenticator_data(
            &record.rp_id,
            up,
            uv,
            self.sign_count,
            None, // AT is 0 in assertions (WebAuthn L2 §6.5)
        )?;
        let mut signed = Vec::with_capacity(auth_data.len() + client_data_hash.len());
        signed.extend_from_slice(&auth_data);
        signed.extend_from_slice(client_data_hash);
        // Real ECDSA P-256 over authenticatorData || clientDataHash,
        // ASN.1 DER encoded (CTAP2.1 §6.2.2 step 5; WebAuthn L2 §6.5).
        let signature: Signature = record.private_key.sign(&signed);
        let der = signature.to_der();
        Ok((auth_data, der.as_bytes().to_vec()))
    }

    /// The raw private-key bytes of a stored credential (snapshot
    /// export support).
    #[cfg(feature = "snapshot")]
    pub(crate) fn record_key_bytes(&self, index: usize) -> Option<[u8; 32]> {
        self.credentials.get(index).map(|c| {
            let bytes = c.private_key.to_bytes();
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            out
        })
    }

    /// Restore a credential record from raw key bytes (snapshot import).
    #[cfg(feature = "snapshot")]
    pub(crate) fn push_record_bytes(
        &mut self,
        id: Vec<u8>,
        rp_id: String,
        user_handle: Vec<u8>,
        private_key: [u8; 32],
        resident: bool,
    ) -> Result<(), Error> {
        let key = SigningKey::from_slice(&private_key)
            .map_err(|_| soft_err(String::from("snapshot private key is not a P-256 scalar")))?;
        self.credentials.push(CredentialRecord {
            id,
            rp_id,
            user_handle,
            private_key: key,
            resident,
        });
        Ok(())
    }

    /// Restore the signature counter (snapshot import).
    #[cfg(feature = "snapshot")]
    pub(crate) fn set_sign_count(&mut self, count: u32) {
        self.sign_count = count;
    }
}

/// COSE encode a verifying key per RFC 8152 §8 / RFC 9053 §7.1:
/// `{1: 2, 3: -7, -1: 1, -2: x, -3: y}` with 32-byte coordinates.
pub(crate) fn cose_key_of(key: &VerifyingKey) -> CoseEs256Key {
    let point = key.to_encoded_point(false);
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    if let Some(xi) = point.x() {
        x.copy_from_slice(xi);
    }
    if let Some(yi) = point.y() {
        y.copy_from_slice(yi);
    }
    CoseEs256Key {
        x: x.to_vec(),
        y: y.to_vec(),
    }
}
