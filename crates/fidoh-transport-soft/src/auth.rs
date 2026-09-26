//! authenticator core: credential store, signature counter,
//! makeCredential (internal) and getAssertion command logic
//! (transport-soft spec requirements "Internal
//! authenticatorMakeCredential", "authenticatorGetAssertion
//! signatures", "Signature counter", "Credential store"; add-client-pin:
//! the clientPIN state machine per CTAP2.1 §6.5.5).
//!
//! Pure state machine — no waits, no I/O. async knob handling
//! (keepalives, poke waits, delays) lives in [`crate::device`].

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use fidoh_core::cose::CoseEs256Key;
use fidoh_core::get_assertion::GetAssertionRequest;
use fidoh_core::pin::PinUvAuthProtocol;
use fidoh_core::{Error, StatusCode};

use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

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
    /// The COSE-encoded public key (RFC 9053 §7.1.1; ES256 alg per §2.1).
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

/// soft-token authenticator: state + config, per transport-soft
/// design's "authenticator core" layer.
pub struct SoftAuthenticator {
    pub(crate) credentials: Vec<CredentialRecord>,
    pub(crate) sign_count: u32,
    up_mode: UpUvMode,
    uv_mode: UpUvMode,
    pub(crate) knobs: Knobs,
    pub(crate) rng: Box<dyn RngSource + Send>,
    /// Poke latches, released by `poke_user_presence` /
    /// `poke_user_verification`; consumed by pending UP/UV waits.
    pub(crate) up_poked: bool,
    pub(crate) uv_poked: bool,
    /// Parked multi-assertion queue (credentials beyond first from
    /// most recent getAssertion), drained by getNextAssertion.
    /// Entries are (credential index, up outcome, uv outcome).
    pub(crate) assertion_queue: Vec<(usize, bool, bool)>,
    /// clientPIN state (add-client-pin): LEFT(SHA-256(PIN), 16) when a
    /// PIN is set, retry counter, consecutive-mismatch counter, and the
    /// per-protocol key-agreement/token registers (CTAP2.1 §6.5.5).
    pub(crate) client_pin: Option<ClientPinState>,
    /// Harness-configured pinUvAuthProtocols advertisement override
    /// (add-client-pin task 4.2); `None` = the default `[2, 1]`.
    pub(crate) configured_pin_protocols: Option<alloc::vec::Vec<PinUvAuthProtocol>>,
    /// Whether the `pinUvAuthToken` option ID is advertised when the
    /// clientPIN feature is armed (add-client-pin task 4.2; default
    /// true — false models the CTAP2.0 getPinToken-only token).
    pub(crate) advertise_pin_uv_auth_token: bool,
    /// clientPIN-directed injection knobs (add-client-pin task 4.2).
    pub(crate) client_pin_knobs: crate::config::ClientPinKnobs,
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
            client_pin: None,
            configured_pin_protocols: None,
            advertise_pin_uv_auth_token: config.advertise_pin_uv_auth_token,
            client_pin_knobs: config.client_pin_knobs,
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

    /// getInfo response model for current configuration
    /// (transport-soft spec "authenticatorGetInfo").
    pub fn get_info(&self) -> fidoh_core::get_info::GetInfoResponse {
        // `uv` option reports whether UV can ever succeed: any mode
        // other always-fail UV-capable (auto-approve and
        // require-explicit-poke both reach UV=true outcomes).
        // `pin_feature` (add-client-pin): advertised when the clientPIN
        // state machine is armed — including the PIN-less posture (the
        // feature is set but no secret is stored; PIN-bearing hops
        // answer CTAP2_ERR_PIN_NOT_SET).
        wire::get_info_response_with_protocols(
            self.uv_mode != UpUvMode::AlwaysFail,
            self.client_pin.is_some(),
            self.configured_pin_protocols
                .as_deref()
                .unwrap_or(&DEFAULT_PIN_PROTOCOLS),
            self.advertise_pin_uv_auth_token,
        )
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
            None, // AT is 0 in assertions (WebAuthn L2 §6.1)
        )?;
        let mut signed = Vec::with_capacity(auth_data.len() + client_data_hash.len());
        signed.extend_from_slice(&auth_data);
        signed.extend_from_slice(client_data_hash);
        // Real ECDSA P-256 over authenticatorData || clientDataHash,
        // ASN.1 DER encoded (CTAP2.1 §6.2.2 step 5; WebAuthn L2 §6.5.5).
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

    // -----------------------------------------------------------------
    // clientPIN state machine (add-client-pin; CTAP2.1 §6.5.5).
    // Harness plumbing only — set/clear are NOT client API (the v1
    // non-goal on set/change flows stands); the authenticator side of
    // the acquisition flow is exercised through `exchange_client_pin`
    // in `device.rs`.
    // -----------------------------------------------------------------

    /// Harness plumbing: set (or replace) the PIN and arm the clientPIN
    /// feature (getInfo advertises clientPin + pinUvAuthToken +
    /// protocols). Retry counter resets to [`MAX_PIN_RETRIES`].
    pub fn set_pin(&mut self, pin: &[u8]) {
        let hash = pin_hash_of(pin);
        match &mut self.client_pin {
            Some(state) => {
                state.pin_hash = hash;
                state.retries = MAX_PIN_RETRIES;
                state.consecutive_mismatches = 0;
            }
            None => {
                self.client_pin = Some(ClientPinState {
                    pin_hash: hash,
                    retries: MAX_PIN_RETRIES,
                    consecutive_mismatches: 0,
                    key_agreement: [PinAgreement::new(), PinAgreement::new()],
                    power_cycle_locked: false,
                });
            }
        }
    }

    /// Harness plumbing: clear the PIN (the token then reports
    /// clientPin-capable but PIN-less — CTAP2_ERR_PIN_NOT_SET paths).
    pub fn clear_pin(&mut self) {
        if let Some(state) = &mut self.client_pin {
            state.pin_hash = None;
            state.retries = MAX_PIN_RETRIES;
            state.consecutive_mismatches = 0;
        }
    }

    /// Harness plumbing: clear the 0x34 power-cycle latch WITHOUT
    /// touching the PIN secret or the retry counter (the test stand-in
    /// for the physical unplug/replug that clears a real
    /// CTAP2_ERR_PIN_AUTH_BLOCKED). The PIN and retry state survive —
    /// only the mismatch latch resets.
    pub fn power_cycle(&mut self) {
        if let Some(state) = &mut self.client_pin {
            state.power_cycle_locked = false;
            state.consecutive_mismatches = 0;
        }
    }

    /// The PIN retry counter (harness introspection for tests).
    pub fn pin_retries(&self) -> Option<u8> {
        self.client_pin.as_ref().map(|s| s.retries)
    }

    /// Harness plumbing: override the advertised pinUvAuthProtocols
    /// list (add-client-pin task 4.2 — e.g. `[1]`-only for the
    /// protocol-1 fallback scenario). An empty list advertises no
    /// protocols (the acquisition flow then fails typed before any
    /// clientPIN command).
    pub fn set_pin_protocols(&mut self, protocols: alloc::vec::Vec<PinUvAuthProtocol>) {
        self.configured_pin_protocols = Some(protocols);
    }

    /// Harness plumbing: advertise (default) or hide the
    /// `pinUvAuthToken` option ID. Hidden models a CTAP2.0-only token:
    /// the platform falls back to getPinToken (0x05).
    pub fn set_advertise_pin_uv_auth_token(&mut self, advertise: bool) {
        self.advertise_pin_uv_auth_token = advertise;
    }

    /// Harness plumbing: the clientPIN-directed injection knobs
    /// (`wrong_protocol_echo`, `pin_echo_decrypt` — transport-soft
    /// spec "clientPIN error injection", task 4.2).
    pub fn client_pin_knobs_mut(&mut self) -> &mut crate::config::ClientPinKnobs {
        &mut self.client_pin_knobs
    }

    /// The authenticator side of one authenticatorClientPIN request
    /// (CTAP2.1 §6.5.5, §6.5.5.7.1/§6.5.5.7.2 verification order):
    /// protocol check → zero-retries check → decapsulate → verify MAC
    /// → DECREMENT retries → decrypt pinHashEnc → compare (mismatch →
    /// 0x31 + pinRetries; 3 consecutive → 0x34) → reset → mint token →
    /// encrypt. Real ECDH/AES/HMAC via the same RustCrypto primitives
    /// as the client — no stubbed crypto on either side.
    pub(crate) fn client_pin_exchange(
        &mut self,
        request: &fidoh_core::pin::ClientPinRequest,
        entropy: &mut dyn fidoh_core::crypto::PinEntropySource,
    ) -> Result<fidoh_core::pin::ClientPinResponse, StatusCode> {
        use fidoh_core::crypto::SharedSecret;
        use fidoh_core::pin::{ClientPinResponse, ClientPinSubCommand};

        // No clientPIN feature armed: the command is unknown here
        // (CTAP1_ERR_INVALID_COMMAND).
        let Some(state) = &mut self.client_pin else {
            return Err(StatusCode::InvalidCommand);
        };

        // (1) Protocol support check (§6.5.5.4): the requested protocol
        // must be BOTH an implemented value AND among the advertised
        // pinUvAuthProtocols — a request naming a protocol absent from
        // the advertisement answers CTAP1_ERR_INVALID_PARAMETER
        // (transport-soft spec scenario "Unsupported protocol echo
        // rejected per spec") and leaves the key-agreement registers
        // untouched.
        let supported = matches!(
            request.protocol,
            PinUvAuthProtocol::One | PinUvAuthProtocol::Two
        );
        let advertised = self
            .configured_pin_protocols
            .as_deref()
            .unwrap_or(&DEFAULT_PIN_PROTOCOLS);
        if !supported || !advertised.contains(&request.protocol) {
            return Err(StatusCode::InvalidParameter);
        }

        // getPINRetries / getKeyAgreement answer WITHOUT touching the
        // retry counter (§6.5.5.2/§6.5.5.4 flows).
        match request.sub_command {
            ClientPinSubCommand::GetPinRetries => {
                let out = ClientPinResponse {
                    pin_retries: Some(state.retries),
                    ..ClientPinResponse::default()
                };
                return Ok(out);
            }
            ClientPinSubCommand::GetKeyAgreement => {
                let idx = protocol_index(request.protocol);
                // Fresh per-request key pair (§6.5.5.4: the platform
                // gets a shared secret per transaction).
                //
                // `wrong_protocol_echo` knob (task 4.2): the register
                // is generated under the OTHER protocol's selector, so
                // the token's KDF/MAC/encrypt run per a different
                // instantiation than the client negotiated — the
                // CLIENT's protocol-exact verification is exercised
                // against a deviant peer. The KEY remains a valid
                // P-256 key (both protocols share the EC2 curve);
                // only the protocol selector recorded for the register
                // — and thus the later KDF choice — diverges.
                // `wrong_protocol_echo` knob (task 4.2): the register
                // records the OTHER protocol's selector, so the token's
                // KDF/MAC/encrypt at token-request time run per a
                // different instantiation than the client negotiated —
                // exercising the CLIENT's protocol-exact verification
                // against a deviant peer. The key stays a valid P-256
                // key (both protocols share the EC2 curve); only the
                // recorded selector — and thus the later KDF choice —
                // diverges.
                let record_protocol = if self.client_pin_knobs.wrong_protocol_echo {
                    match request.protocol {
                        PinUvAuthProtocol::One => PinUvAuthProtocol::Two,
                        p => p,
                    }
                } else {
                    request.protocol
                };
                let mut agree = PinAgreement::generate(request.protocol, entropy)
                    .map_err(|_| StatusCode::KeyStoreFull)?;
                agree.protocol = Some(record_protocol);
                let cose = agree.public_cose_key.clone();
                state.key_agreement[idx] = agree;
                let out = ClientPinResponse {
                    key_agreement: Some(cose.unwrap_or(fidoh_core::cbor::CborValue::Int(0))),
                    ..ClientPinResponse::default()
                };
                return Ok(out);
            }
            _ => {}
        }

        // (2) PIN-less token: CTAP2_ERR_PIN_NOT_SET (the §6.2.2
        // zero-length-pinUvAuthParam family of semantics, modeled on
        // the PIN-bearing subcommands).
        if state.pin_hash.is_none() {
            return Err(StatusCode::PinNotSet);
        }

        // (3) Zero retries → PIN blocked (§6.5.5.7.2). Checked BEFORE
        // the power-cycle latch so the terminal PIN_BLOCKED state is
        // reachable once the counter is spent (transport-soft spec
        // scenario "Zero retries answers PIN blocked"); the latch
        // (0x34) governs every counter-positive hop after three
        // consecutive mismatches.
        if state.retries == 0 {
            return Err(StatusCode::PinBlocked);
        }
        // Power-cycle lock (0x34 semantics: after three consecutive
        // mismatches EVERY counter-positive PIN-bearing subcommand
        // answers CTAP2_ERR_PIN_AUTH_BLOCKED until the harness "power
        // cycle", even with a correct PIN — CTAP2.1 §6.5.5.7.2;
        // transport-soft spec scenario "Three consecutive mismatches
        // answers PIN auth blocked").
        if state.power_cycle_locked {
            return Err(StatusCode::PinAuthBlocked);
        }

        // (4) decapsulate the platform key against THIS request's
        // registered agreement.
        let Some(peer_key) = &request.key_agreement else {
            return Err(StatusCode::MissingParameter);
        };
        let idx = protocol_index(request.protocol);
        let shared_z = {
            let agree = &state.key_agreement[idx];
            agree.decapsulate(peer_key)?
        };
        // `pin_echo_decrypt` knob (task 4.2): the token derives with a
        // DIFFERENT protocol's KDF than the client used, so its
        // pinHashEnc decrypt fails even for a correct PIN — proving
        // the client's own decapsulate/derive path (the failure is the
        // authenticator-side 0x33, distinguishable from a wrong PIN's
        // 0x31).
        let derive_protocol = if self.client_pin_knobs.pin_echo_decrypt {
            match request.protocol {
                PinUvAuthProtocol::One => PinUvAuthProtocol::Two,
                _ => PinUvAuthProtocol::One,
            }
        } else {
            state.key_agreement[idx]
                .protocol
                .unwrap_or(request.protocol)
        };
        let shared = SharedSecret::derive(&shared_z, derive_protocol);

        // (5) verify the (unused-in-acquisition) pinUvAuthParam when
        // present — protocol-exact MAC length.
        if let Some(param) = &request.pin_uv_auth_param {
            // The MAC over the (empty here) subcommand context; any
            // param on a PIN subcommand is invalid unless it matches.
            let expected = shared.authenticate(&[], &[]);
            if param.bytes != expected {
                return Err(StatusCode::PinAuthInvalid);
            }
        }

        // (6) DECREMENT before compare (§6.5.5.7.2 order).
        state.retries = state.retries.saturating_sub(1);

        // (7) decrypt pinHashEnc and compare against the stored hash.
        let Some(pin_hash_enc) = &request.pin_hash_enc else {
            return Err(StatusCode::MissingParameter);
        };
        // `pin_echo_decrypt` knob: the shared-secret mismatch is
        // detected at the KEY layer (before any decrypt), so the
        // surfaced failure is the authenticator-side PIN_AUTH_INVALID
        // (0x33) — distinguishable from a wrong PIN's 0x31 regardless
        // of whether a cross-protocol decrypt would "succeed" with
        // garbage (P1 zero-IV accepts any block-multiple input).
        if self.client_pin_knobs.pin_echo_decrypt {
            return Err(StatusCode::PinAuthInvalid);
        }
        let decrypted = match shared.decrypt(pin_hash_enc) {
            Ok(pt) => pt,
            Err(_) => {
                // A genuine decrypt failure (corrupted pinHashEnc) is
                // NOT a wrong PIN: no retry counter is implicated —
                // surfaced as PIN_AUTH_INVALID.
                return Err(StatusCode::PinAuthInvalid);
            }
        };
        let Some(stored) = state.pin_hash.clone() else {
            return Err(StatusCode::PinNotSet);
        };
        if decrypted.as_slice() != stored.as_slice() {
            state.consecutive_mismatches += 1;
            if state.consecutive_mismatches >= 3 {
                // Third consecutive mismatch: the power-cycle latch
                // ENGAGES (§6.5.5.7.2) — this attempt still answers
                // 0x31 with its (decremented) pinRetries; every
                // SUBSEQUENT PIN-bearing request is refused 0x34 by
                // the latch check at the top of this flow, even with
                // a correct PIN, until the harness "power cycle".
                state.power_cycle_locked = true;
            }
            // The device layer attaches the pinRetries member (0x03)
            // to the 0x31 body from the live counter (§6.5.5).
            return Err(StatusCode::PinInvalid);
        }
        // (8) Success: reset counters, mint a fresh 32-byte token,
        // return encrypt(shared, token).
        state.retries = MAX_PIN_RETRIES;
        state.consecutive_mismatches = 0;
        let mut token = [0u8; 32];
        entropy
            .fill_random(&mut token)
            .map_err(|_| StatusCode::KeyStoreFull)?;
        state.key_agreement[idx].pin_token = Some(token.to_vec());
        let encrypted = shared
            .encrypt(entropy, &token)
            .map_err(|_| StatusCode::KeyStoreFull)?;
        let out = ClientPinResponse {
            pin_uv_auth_token: Some(encrypted),
            ..ClientPinResponse::default()
        };
        Ok(out)
    }
}

/// The clientPIN state (add-client-pin): PIN hash, retry and mismatch
/// counters, per-protocol key-agreement registers.
pub(crate) struct ClientPinState {
    /// LEFT(SHA-256(PIN), 16); `None` = PIN-less (PIN_NOT_SET paths).
    pub(crate) pin_hash: Option<Vec<u8>>,
    /// Remaining PIN attempts before lockout (default
    /// [`MAX_PIN_RETRIES`]).
    pub(crate) retries: u8,
    /// Consecutive PIN mismatches (3 → 0x34 power-cycle lock,
    /// §6.5.5.7.2).
    pub(crate) consecutive_mismatches: u8,
    /// Per-protocol key-agreement registers ([0] = P1, [1] = P2).
    pub(crate) key_agreement: [PinAgreement; 2],
    /// The power-cycle lock (0x34 semantics: even a correct PIN is
    /// refused until harness "power cycle" = clear via `set_pin`).
    pub(crate) power_cycle_locked: bool,
}

/// One protocol's key-agreement register: the authenticator's P-256
/// key pair plus the minted pinUvAuthToken (§6.5.6/§6.5.7). The
/// register's protocol is implicit in its index ([0] = one, [1] =
/// two — see [`protocol_index`]); the token answers per the REQUEST's
/// protocol selector (§6.5.5.4), so none is stored here.
pub(crate) struct PinAgreement {
    /// The protocol selector recorded for this register (defaults to
    /// the request's; the `wrong_protocol_echo` knob records the other
    /// one, steering the later KDF choice).
    pub(crate) protocol: Option<PinUvAuthProtocol>,
    pub(crate) secret: Option<p256::SecretKey>,
    pub(crate) public_cose_key: Option<fidoh_core::cbor::CborValue>,
    pub(crate) pin_token: Option<Vec<u8>>,
}

impl PinAgreement {
    fn new() -> Self {
        Self {
            protocol: None,
            secret: None,
            public_cose_key: None,
            pin_token: None,
        }
    }

    fn generate(
        protocol: PinUvAuthProtocol,
        entropy: &mut dyn fidoh_core::crypto::PinEntropySource,
    ) -> Result<Self, fidoh_core::StatusCode> {
        // Draw a valid P-256 scalar (bounded retries against the group
        // order rejection).
        for _ in 0..8 {
            let mut bytes = [0u8; 32];
            entropy
                .fill_random(&mut bytes)
                .map_err(|_| fidoh_core::StatusCode::KeyStoreFull)?;
            if let Ok(sk) = p256::SecretKey::from_slice(&bytes) {
                let holder = PlatformKeyHolder { secret: sk.clone() };
                return Ok(Self {
                    protocol: None,
                    secret: Some(sk),
                    public_cose_key: Some(holder.cose_key()),
                    pin_token: None,
                });
            }
        }
        let _ = protocol; // register identity is the index, not the protocol
        Err(fidoh_core::StatusCode::KeyStoreFull)
    }

    /// decapsulate the platform's COSE_Key → Z (the shared-point
    /// x-coordinate).
    fn decapsulate(
        &self,
        peer_key: &fidoh_core::cbor::CborValue,
    ) -> Result<[u8; 32], fidoh_core::StatusCode> {
        let entries = match peer_key {
            fidoh_core::cbor::CborValue::Map(entries) => entries,
            _ => return Err(fidoh_core::StatusCode::InvalidParameter),
        };
        let mut x: Option<Vec<u8>> = None;
        let mut y: Option<Vec<u8>> = None;
        for (k, v) in entries {
            if let (fidoh_core::cbor::CborValue::Int(-2), fidoh_core::cbor::CborValue::Bytes(bx)) =
                (k, v)
            {
                x = Some(bx.clone());
            }
            if let (fidoh_core::cbor::CborValue::Int(-3), fidoh_core::cbor::CborValue::Bytes(by)) =
                (k, v)
            {
                y = Some(by.clone());
            }
        }
        let (Some(x), Some(y)) = (x, y) else {
            return Err(fidoh_core::StatusCode::InvalidParameter);
        };
        if x.len() != 32 || y.len() != 32 {
            return Err(fidoh_core::StatusCode::InvalidParameter);
        }
        let mut sec1 = Vec::with_capacity(65);
        sec1.push(0x04);
        sec1.extend_from_slice(&x);
        sec1.extend_from_slice(&y);
        let pk = p256::PublicKey::from_sec1_bytes(&sec1)
            .map_err(|_| fidoh_core::StatusCode::InvalidParameter)?;
        let Some(secret) = &self.secret else {
            return Err(fidoh_core::StatusCode::InvalidParameter);
        };
        let shared_point =
            p256::elliptic_curve::ecdh::diffie_hellman(secret.to_nonzero_scalar(), pk.as_affine());
        let raw: [u8; 32] = <[u8; 32]>::try_from(shared_point.raw_secret_bytes().as_ref())
            .map_err(|_| fidoh_core::StatusCode::InvalidParameter)?;
        Ok(raw)
    }
}

/// Thin holder giving the soft token the same COSE emission as the
/// platform (add-client-pin D2: one construction, two sides).
struct PlatformKeyHolder {
    secret: p256::SecretKey,
}

impl PlatformKeyHolder {
    fn cose_key(&self) -> fidoh_core::cbor::CborValue {
        use p256::elliptic_curve::sec1::ToEncodedPoint as _;
        let point = self.secret.public_key().to_encoded_point(false);
        let x = point.x().expect("uncompressed P-256 point carries x");
        let y = point.y().expect("uncompressed P-256 point carries y");
        fidoh_core::cbor::CborValue::Map(alloc::vec![
            (
                fidoh_core::cbor::CborValue::Int(1),
                fidoh_core::cbor::CborValue::Int(2)
            ),
            (
                fidoh_core::cbor::CborValue::Int(3),
                fidoh_core::cbor::CborValue::Int(-25)
            ),
            (
                fidoh_core::cbor::CborValue::Int(-1),
                fidoh_core::cbor::CborValue::Int(1)
            ),
            (
                fidoh_core::cbor::CborValue::Int(-2),
                fidoh_core::cbor::CborValue::Bytes(x.to_vec())
            ),
            (
                fidoh_core::cbor::CborValue::Int(-3),
                fidoh_core::cbor::CborValue::Bytes(y.to_vec())
            ),
        ])
    }
}

/// Maximum PIN retries before lockout (harness default; the spec does
/// not pin the authenticator's maximum-counter value).
pub const MAX_PIN_RETRIES: u8 = 8;

/// The default advertised pinUvAuthProtocols list (the authenticator's
/// decreasing preference order — protocol 2 preferred, CTAP2.1 §6.4);
/// used when the harness does not override the advertisement.
pub(crate) const DEFAULT_PIN_PROTOCOLS: [PinUvAuthProtocol; 2] =
    [PinUvAuthProtocol::Two, PinUvAuthProtocol::One];

/// LEFT(SHA-256(PIN), 16) — the stored/computed PIN hash (CTAP2.1
/// §6.5.5.7.2 pinHashEnc payload).
fn pin_hash_of(pin: &[u8]) -> Option<Vec<u8>> {
    let digest = Sha256::digest(pin);
    Some(digest[..16].to_vec())
}

/// Register index for a protocol ([0] = P1, [1] = P2).
fn protocol_index(protocol: PinUvAuthProtocol) -> usize {
    match protocol {
        PinUvAuthProtocol::One => 0,
        _ => 1,
    }
}

/// COSE encode a verifying key per RFC 9053 §7.1.1:
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
