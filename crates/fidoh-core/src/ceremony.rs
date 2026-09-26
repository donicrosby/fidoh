//! The getAssertion ceremony (CTAP2.1 §6.2): the orchestration that
//! ties transport discovery, deterministic device selection, the
//! mandatory authenticatorGetInfo probe, the §6.2 exchange with its
//! keepalive loop, and the §6.3 multi-assertion drain together —
//! bounded by ONE caller-supplied budget (async-core design D4).
//!
//! The library is RP-agnostic: the caller supplies the
//! `clientDataHash`; `clientDataJSON` construction, origin semantics,
//! and signature verification are the CALLER's responsibility
//! (WebAuthn L2 §7.2). The ceremony returns raw assertion fields
//! exactly as decoded from the CTAP2.1 §6.2 response.
//!
//! Sequence (ceremony spec, "Ceremony sequence per CTAP2.1 §6.2"):
//! 1. discovery: enumerate every registered transport, collecting
//!    candidates; a transport's failure never hides another's
//!    candidates (design D2);
//! 2. selection: explicit [`SelectionPolicy`], default `Fail` (stack
//!    invariant: never silently pick among multiple candidates);
//! 3. connect: exactly once, for the selected candidate only;
//! 4. mandatory authenticatorGetInfo probe (CTAP2.1 §6.4; design
//!    OQ-2, resolved: ALWAYS run, every ceremony — the capabilities
//!    drive request construction and ride in the outcome);
//! 5. authenticatorGetAssertion with keepalives surfaced as progress
//!    (never errors) until a terminal response arrives (design D5);
//! 6. multi-assertion drain via the caller-supplied [`Drain`] hook
//!    when `numberOfCredentials > 1` (design D6).
//!
//! Every wait is bounded by the single remaining budget; expiry at any
//! hop returns [`CeremonyError::Timeout`] naming the expired phase.
//! Dropping the ceremony future mid-run is cancellation-safe (the
//! device remains usable for a subsequent ceremony, worst case after
//! one channel re-handshake, CTAP2.1 §11.2.5.3).

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::future::Future;
use core::time::Duration;

use crate::cbor::CborValue;
use crate::crypto::{
    pin_uv_auth_param_message, PinCryptoError, PinEntropySource, PlatformKeyAgreement,
};
use crate::device::{CtapCommand, Device, DeviceEvent};
use crate::error::{CeremonyError, DecodePolicy, DiscoveryDiagnostic, Error, TransportError};
use crate::get_assertion::{
    GetAssertionOptions, GetAssertionRequest, GetAssertionResponse, PublicKeyCredentialDescriptor,
};
use crate::get_info::GetInfoResponse;
use crate::pin::{
    permissions, ClientPinRequest, ClientPinResponse, ClientPinSubCommand, PinProvider,
    PinProviderHandle, PinUvAuthParam, PinUvAuthProtocol, MAX_PIN_BYTES,
};
use crate::sleep::SleepHandle;
use crate::status::StatusCode;
use crate::time::{Deadline, Phase};
use crate::transport::{
    apply_selection, CandidateDescriptor, DeviceInfo, SelectionPolicy, Transport,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

// ----------------------------------------------------------------------
// The async-core `Ceremony` trait: the single orchestration entry point.
// ----------------------------------------------------------------------

/// A ceremony: the orchestration entry over a connected device.
///
/// Generic in `D: Device` and RPITIT-`Send` per async-core design
/// D1/A4 — the ceremony hot path stays monomorphized and alloc-free
/// beyond the response payload itself.
pub trait Ceremony {
    /// The typed ceremony output: the raw assertion for getAssertion
    /// (authenticatorData, signature, userHandle, credential id per
    /// CTAP2.1 §6.2) or the parsed info structure for getInfo
    /// (CTAP2.1 §6.4).
    type Output;

    /// Run the ceremony against `device`, bounded by the single
    /// caller-supplied `deadline` budget, with every wait driven
    /// through `sleep` (async-core spec: "a ceremony consumes a
    /// connected `Device`, a `Sleep` factory, and a single deadline
    /// budget").
    ///
    /// Expiry at any hop returns a typed
    /// `Timeout(Phase)` naming the phase (async-core spec:
    /// single-budget timeout model). Dropping the returned future
    /// mid-run is safe per the cancellation contract: no poisoned
    /// state, the device remains usable for a subsequent ceremony
    /// (worst case after one channel re-handshake, CTAP2.1 §11.2.5.3).
    ///
    /// `D: Send + 'static` is required so the run can be hosted by a
    /// `spawn_blocking`-style adapter (async-core design D3): the
    /// device handle and its in-flight futures cross onto the blocking
    /// pool.
    fn run<D: Device + Send + 'static>(
        self,
        device: D,
        deadline: &Deadline,
        sleep: SleepHandle<'_>,
    ) -> impl Future<Output = Result<Self::Output, CeremonyError>> + Send;
}

/// A no-op ceremony: echoes one command exchange through the device.
///
/// Proof-of-seam for the trait (async-core spec: trait compile tests
/// "proving the seams exist... driving a trivial exchange through
/// them"): it shows a `Ceremony` driving a generic `D: Device` through
/// `send` with the budget + sleep plumbing exactly as the real
/// ceremonies do. Not a real ceremony — the real getAssertion
/// orchestration is [`GetAssertionCeremony`] (full entry) and
/// [`GetAssertionExchange`] (exchange-only trait path).
#[derive(Clone, Copy, Debug, Default)]
pub struct EchoCeremony;

impl Ceremony for EchoCeremony {
    type Output = DeviceEvent;

    async fn run<D: Device + Send + 'static>(
        self,
        mut device: D,
        deadline: &Deadline,
        sleep: SleepHandle<'_>,
    ) -> Result<Self::Output, CeremonyError> {
        device
            .send(&CtapCommand::GetInfo, deadline, sleep)
            .await
            .map_err(CeremonyError::from_core)
    }
}

// ----------------------------------------------------------------------
// Ceremony input surface.
// ----------------------------------------------------------------------

/// User-verification policy for the ceremony input (design D4).
///
/// v2 (add-client-pin): a caller holding a token passes it via
/// [`CeremonyInput::pin_uv_auth`]; a caller supplying a PIN provider
/// lets the ceremony ACQUIRE a token per CTAP2.1 §6.5.5 (see the
/// "pinUvAuthToken acquisition flow" requirement). A `Preferred`
/// policy with neither — on a key whose probe shows clientPin support
/// without a built-in verifier — now fails typed
/// ([`CeremonyError::PinRequired`], naming the fix) instead of v1's
/// silent degradation to the `Discouraged` wire shape; on a key
/// advertising the `uv` capability it still sends `options.uv = true`.
/// The effective posture is always REPORTED in the outcome
/// ([`GetAssertionOutcome::uv_effective`]), never silent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UvPolicy {
    /// The request omits `options.uv` (CTAP2.1 §6.2 default false) and
    /// carries no pinUvAuthParam unless the caller supplied one
    /// explicitly. The default. Never triggers PIN acquisition: no PIN
    /// prompt is shown for a discouraged request.
    #[default]
    Discouraged,
    /// Request user verification. Resolution order: (a) caller-held
    /// pinUvAuthToken → sent (and `options.uv` is never set alongside,
    /// CTAP2.1 §6.2); (b) caller-supplied PIN provider → acquire a
    /// token per CTAP2.1 §6.5.5; (c) neither → `options.uv = true`
    /// when the probe advertised the `uv` capability, else the typed
    /// [`CeremonyError::PinRequired`] on PIN-capable keys (reported
    /// degradation paths stay in the outcome).
    Preferred,
}

/// The RP-agnostic input surface shared by both ceremony entries
/// (ceremony spec: "Ceremony inputs and RP-agnostic boundary").
struct CeremonyInput {
    /// The relying-party identifier (CTAP2.1 §6.2 request key 0x01).
    rp_id: String,
    /// Caller-supplied hash of the serialized client data (key 0x02).
    /// The library never constructs `clientDataJSON` (WebAuthn L2
    /// §6.5 is the RP's responsibility).
    client_data_hash: Vec<u8>,
    /// Optional allowList (key 0x03). An empty list is stored as
    /// `None` — omitted on the wire identically to absence (CTAP2.1
    /// §6.2: "A platform MUST NOT send an empty allowList").
    allow_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    /// User-verification policy (design D4).
    user_verification: UvPolicy,
    /// Caller-held pinUvAuth material, passed through opaquely when
    /// the caller already holds a pinUvAuthToken (CTAP2.1 §6.2 keys
    /// 0x06/0x07). Takes PRECEDENCE over acquisition.
    pin_uv_auth: Option<(PinUvAuthParam, PinUvAuthProtocol)>,
    /// Caller-owned PIN provider (add-client-pin design D3). Consumed
    /// at most once per run, only by the acquisition flow.
    pin_provider: Option<PinProviderHandle>,
    /// Caller-pinned pinUvAuth protocol (§6.5.5.4 alternative to
    /// following the authenticator's preference order). Rejected typed
    /// when the probe does not advertise it.
    pin_uv_auth_protocol: Option<PinUvAuthProtocol>,
    /// Entropy for platform key pairs and P2 IVs (add-client-pin
    /// design D2). Harnesses inject a deterministic stream.
    entropy: Option<alloc::boxed::Box<dyn PinEntropySource + Send>>,
}

impl CeremonyInput {
    /// Capability-driven request construction (design OQ-2 + D4 +
    /// D8). The §6.2 wire rules are enforced here by construction —
    /// empty-allowList omission, uv/pinUvAuthParam mutual exclusion,
    /// and no extensions (key 0x04 absent) — and re-checked by the
    /// model at encode time (CTAP2.1 §6.2).
    fn build_request(&self, info: &GetInfoResponse) -> Result<GetAssertionRequest, CeremonyError> {
        let mut request =
            GetAssertionRequest::new(self.rp_id.clone(), self.client_data_hash.clone()).map_err(
                |e| {
                    CeremonyError::Transport(TransportError::new(
                        "ceremony",
                        format!("request construction: {e}"),
                    ))
                },
            )?;
        // Empty allowList → None (key 0x03 omitted on the wire, D8).
        request.allow_list = match &self.allow_credentials {
            Some(list) if !list.is_empty() => Some(list.clone()),
            _ => None,
        };
        // No extensions: key 0x04 stays absent by construction
        // (ceremony spec: "the extensions parameter (0x04) SHALL be
        // absent").

        // Caller-held pinUvAuth material passes through only when the
        // authenticator supports the chosen protocol (CTAP2.1 §6.5.5,
        // core-model scenario "rejected at the ceremony layer").
        if let Some((param, protocol)) = &self.pin_uv_auth {
            let supported = info
                .pin_uv_auth_protocols
                .as_ref()
                .is_some_and(|list| protocol.is_supported_by(list));
            if !supported {
                return Err(CeremonyError::Transport(TransportError::new(
                    "ceremony",
                    format!(
                        "pinUvAuthProtocol {} is not among the authenticator's supported \
                         pinUvAuthProtocols (CTAP2.1 §6.5.5)",
                        protocol.to_u32()
                    ),
                )));
            }
            // The §6.2 mutual-exclusion rule is structural: a request
            // carrying pinUvAuthParam NEVER sets options.uv.
            request.pin_uv_auth_param = Some(param.clone());
            request.pin_uv_auth_protocol = Some(*protocol);
        }
        Ok(request)
    }

    /// The v2 UV decision for a request built WITHOUT caller-held
    /// material: shape `options.uv`, demand acquisition, or accept the
    /// reported degradation (add-client-pin design D4 steps 9–10).
    /// `Preferred` + PIN-capable key + no provider + no built-in
    /// verifier is the typed `PinRequired` — the motivating case of
    /// the change (Vaultwarden + PIN-only YubiKey).
    fn uv_posture_without_token(&self, info: &GetInfoResponse) -> Result<UvShape, CeremonyError> {
        match self.user_verification {
            UvPolicy::Discouraged => Ok(UvShape::Omit),
            UvPolicy::Preferred => {
                let uv_capable = info.option(crate::get_info::OptionId::Uv);
                if uv_capable {
                    // Built-in verifier advertised: keep the v1 shape.
                    return Ok(UvShape::UvOption);
                }
                // No built-in verifier. PIN-capable? (clientPin true —
                // an absent/false clientPin means the key cannot do UV
                // at all; keep the v1 degradation report there.)
                let pin_capable = info.option(crate::get_info::OptionId::ClientPin);
                if pin_capable {
                    // PIN-only key: the fix is to supply a provider —
                    // never a silent downgrade again.
                    return Err(CeremonyError::PinRequired);
                }
                Ok(UvShape::Omit)
            }
        }
    }

    /// The effective UV posture of the wire request (D4 reporting).
    fn uv_effective(request: &GetAssertionRequest) -> UvEffective {
        if request.pin_uv_auth_param.is_some() {
            UvEffective::PinUvAuth
        } else if request.options.is_some_and(|o| o.uv == Some(true)) {
            UvEffective::UvOption
        } else {
            UvEffective::NotRequested
        }
    }
}

/// The `options.uv` shaping decision for a token-less request (design
/// D4 step 9).
enum UvShape {
    /// Omit `options.uv` (the §6.2 default-false wire shape).
    Omit,
    /// Send `options.uv = true` (probe advertised the `uv`
    /// capability).
    UvOption,
}

/// The effective UV posture of the sent request (design D4: reported,
/// never silent).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UvEffective {
    /// No UV was requested on the wire (Discouraged, or Preferred
    /// degraded for lack of a caller-held token and `uv` capability).
    NotRequested,
    /// Caller-supplied pinUvAuthParam/protocol were sent (Preferred
    /// with a caller-held token).
    PinUvAuth,
    /// `options.uv = true` was sent (Preferred without a token, where
    /// the probe advertised the `uv` capability).
    UvOption,
    /// A pinUvAuthToken was acquired during this ceremony (CTAP2.1
    /// §6.5.5 flow) and the request carries its pinUvAuthParam
    /// (add-client-pin: `Preferred` + PIN provider end to end).
    PinUvAuthToken,
}
/// The multi-assertion continuation seam (CTAP2.1 §6.3).
///
/// `CtapCommand` (async-core scope) carries GetInfo and GetAssertion
/// only; authenticatorGetNextAssertion is per-device continuation
/// state, so the drain is a caller-supplied hook bound to the
/// connected device. It is invoked exactly `numberOfCredentials − 1`
/// times, each invocation racing the remaining ceremony budget
/// (`Phase::GetNextAssertion` names any expiry); a returned status
/// byte maps through the same §8.2 table as any other hop
/// (`0x30 CTAP2_ERR_NOT_ALLOWED` surfaces as [`CeremonyError::Ctap`]
/// without retry).
pub struct Drain {
    #[allow(clippy::type_complexity)]
    f: Box<dyn FnMut() -> Result<DeviceEvent, Error> + Send>,
}

impl Drain {
    /// Bind the drain hook to a closure (typically capturing the
    /// connected device and calling its getNextAssertion method).
    pub fn new(f: impl FnMut() -> Result<DeviceEvent, Error> + Send + 'static) -> Self {
        Self { f: Box::new(f) }
    }

    fn next(&mut self) -> Result<DeviceEvent, Error> {
        (self.f)()
    }
}

impl core::fmt::Debug for Drain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Drain(..)")
    }
}

/// The typed ceremony output. The raw assertion list is exactly as
/// decoded from the wire (ceremony spec: "Returned assertion
/// fidelity"); the mandatory getInfo capabilities ride along (design
/// OQ-2, resolved).
#[derive(Clone, Debug, PartialEq)]
pub struct GetAssertionOutcome {
    /// The ordered raw assertion list: the §6.2 response first,
    /// followed by the §6.3 responses in arrival order. Always
    /// non-empty; `numberOfCredentials` rides on each element.
    pub assertions: Vec<GetAssertionResponse>,
    /// The parsed authenticatorGetInfo (CTAP2.1 §6.4) capabilities of
    /// the selected authenticator — the mandatory probe's response.
    pub info: GetInfoResponse,
    /// The effective UV posture after capability-driven request
    /// construction (design D4): never a silent fallback.
    pub uv_effective: UvEffective,
    /// Per-transport discovery errors observed while at least one
    /// candidate was still found elsewhere (D2: diagnostics, not
    /// failures). Empty on a clean discovery; only the full-entry
    /// ceremony produces these.
    pub discovery_diagnostics: Vec<DiscoveryDiagnostic>,
}

impl GetAssertionOutcome {
    /// The first (§6.2) assertion.
    pub fn first(&self) -> &GetAssertionResponse {
        // Invariant upheld by the run pipeline: never empty.
        &self.assertions[0]
    }
}

// ----------------------------------------------------------------------
// Shared exchange pipeline (phases 4–7): probe → build → exchange →
// verify allow-list membership → drain.
// ----------------------------------------------------------------------

/// Run phases 4–7 over an already-connected device, bounded by
/// `deadline`. Shared by [`GetAssertionCeremony::run`] (which does
/// discovery/selection/connect first) and the [`Ceremony`] trait impl
/// for [`GetAssertionExchange`].
///
/// Phase 4a (add-client-pin): the CTAP2.1 §6.5.5 pinUvAuthToken
/// acquisition, when the preconditions hold (see
/// [`acquire_pin_uv_auth_token`]). Its hops are named
/// `Phase::ClientPin` and consume the SAME single budget.
async fn exchange_pipeline<D: Device + Send>(
    mut device: D,
    mut input: CeremonyInput,
    mut drain: Option<Drain>,
    deadline: &Deadline,
    sleep: SleepHandle<'_>,
) -> Result<GetAssertionOutcome, CeremonyError> {
    // ---- Phase 4: MANDATORY authenticatorGetInfo probe (design
    // OQ-2, resolved): always, every ceremony. Its failure fails the
    // ceremony — the request cannot be constructed safely without
    // capability data.
    let info = decode_info(
        race(
            device.send(&CtapCommand::GetInfo, deadline, sleep),
            sleep,
            deadline,
            Phase::GetInfo,
        )
        .await?,
    )?;

    // ---- Phase 4a: pinUvAuthToken acquisition (add-client-pin
    // design D4) — before request construction, per §6.2.1 step 1.1.
    let mut acquired_token = false;
    if input.pin_uv_auth.is_none() {
        let wants_uv = input.user_verification == UvPolicy::Preferred;
        let pin_capable = info.option(crate::get_info::OptionId::ClientPin);
        let protocols_advertised = info
            .pin_uv_auth_protocols
            .as_ref()
            .is_some_and(|list| !list.is_empty());
        if wants_uv && pin_capable && protocols_advertised {
            // Split the input fields the acquisition needs from the
            // mutable provider (borrow discipline: the provider is
            // taken out; the flow below rebuilds `input` state).
            let CeremonyInput {
                ref rp_id,
                ref client_data_hash,
                ref pin_uv_auth_protocol,
                ref mut entropy,
                pin_provider,
                ..
            } = input;
            let Some(mut provider) = pin_provider else {
                return Err(CeremonyError::PinRequired);
            };
            let (param, protocol) = acquire_pin_uv_auth_token(
                &mut device,
                &info,
                rp_id,
                client_data_hash,
                *pin_uv_auth_protocol,
                &mut provider,
                entropy
                    .as_deref_mut()
                    .expect("entropy injected by the caller for PIN acquisition"),
                deadline,
                sleep,
            )
            .await?;
            // §6.2: the param rides with its protocol; options.uv is
            // never set alongside (mutual exclusion). The provider is
            // consumed (at most one prompt per run).
            input.pin_provider = None;
            input.pin_uv_auth = Some((param, protocol));
            acquired_token = true;
        }
    }

    // ---- Phase 5: capability-driven request construction.
    let mut wire_request = input.build_request(&info)?;
    if input.pin_uv_auth.is_none() {
        // Token-less shaping: uv option / PinRequired / reported
        // degradation (design D4 step 9).
        match input.uv_posture_without_token(&info)? {
            UvShape::UvOption => {
                wire_request.options = Some(GetAssertionOptions {
                    up: None,
                    uv: Some(true),
                });
            }
            UvShape::Omit => {}
        }
    }

    // ---- Phase 6: the §6.2 exchange with its keepalive progress loop
    // (D5), bounded by the single remaining budget.
    let cmd = CtapCommand::GetAssertion(wire_request.clone());
    let (status, body) = response_of(keepalive_loop(&mut device, &cmd, deadline, sleep).await?)?;
    if let Some(err) = CeremonyError::from_status(StatusCode::from_u8(status)) {
        return Err(err);
    }
    let first = decode_assertion(&body)?;

    // Library-safety rule (design OQ-3a): the returned credential id
    // must be a member of the caller's allow list; bail early with a
    // truncated-safe identification rather than return the foreign
    // assertion.
    if let Some(allow) = &wire_request.allow_list {
        if !allow.iter().any(|d| d.id == first.credential.id) {
            return Err(CeremonyError::CredentialMismatch {
                returned: first.credential.id.clone(),
                allowed: allow.iter().map(|d| d.id.clone()).collect(),
            });
        }
    }

    // ---- Phase 7: multi-assertion drain (D6) when the response
    // reports more than one credential.
    let extra = if first.number_of_credentials > 1 {
        Some(first.number_of_credentials.saturating_sub(1))
    } else {
        None
    };
    let mut assertions = vec![first];
    if let Some(extra) = extra {
        let Some(drain) = drain.as_mut() else {
            return Err(CeremonyError::Transport(TransportError::new(
                "ceremony",
                format!(
                    "authenticator reports {} credentials; multi-assertion drain requires a \
                     `Drain` hook on the ceremony input (CTAP2.1 §6.3)",
                    extra + 1
                ),
            )));
        };
        for _ in 0..extra {
            assertions.push(drain_hop(drain, deadline)?);
        }
    }

    let uv_effective = if acquired_token {
        UvEffective::PinUvAuthToken
    } else {
        CeremonyInput::uv_effective(&wire_request)
    };

    Ok(GetAssertionOutcome {
        assertions,
        info,
        uv_effective,
        discovery_diagnostics: Vec::new(),
    })
}

/// The CTAP2.1 §6.5.5 pinUvAuthToken acquisition flow (add-client-pin
/// design D4 steps 1–8; spec requirement "pinUvAuthToken acquisition
/// flow"). Preconditions are checked by the caller: `Preferred`
/// policy, a PIN provider present, no caller-held material, and a
/// probe advertising clientPin + non-empty pinUvAuthProtocols.
///
/// Every device hop is bounded by the remaining budget and named
/// `Phase::ClientPin`; there are no independent timeouts (async-core
/// D4). The PIN is collected AFTER the shared secret is established
/// and BEFORE the token request (§6.5.5.7.2 step 1: collect before
/// use — NFC field-removal note).
///
/// Returns the shaped getAssertion material:
/// `pinUvAuthParam = authenticate(pinToken, clientDataHash)` (the
/// message construction centralized in
/// [`crate::crypto::pin_uv_auth_param_message`], OQ-9) and the
/// selected protocol.
#[allow(clippy::too_many_arguments)]
async fn acquire_pin_uv_auth_token<D: Device + Send>(
    device: &mut D,
    info: &GetInfoResponse,
    rp_id: &str,
    client_data_hash: &[u8],
    pinned_protocol: Option<PinUvAuthProtocol>,
    provider: &mut PinProviderHandle,
    entropy: &mut (dyn PinEntropySource + Send),
    deadline: &Deadline,
    sleep: SleepHandle<'_>,
) -> Result<(PinUvAuthParam, PinUvAuthProtocol), CeremonyError> {
    // Step 1: protocol selection (§6.5.5.4). A caller-pinned protocol
    // is honored when advertised; otherwise the FIRST advertised entry
    // the library implements (the authenticator's preference order).
    let advertised = info.pin_uv_auth_protocols.as_deref().unwrap_or(&[]);
    let selected = match pinned_protocol {
        Some(pinned) => {
            if !pinned.is_supported_by(advertised) {
                return Err(CeremonyError::Transport(TransportError::new(
                    "clientPIN",
                    format!(
                        "pinned pinUvAuthProtocol {} is not among the authenticator's \
                         pinUvAuthProtocols (CTAP2.1 §6.5.5)",
                        pinned.to_u32()
                    ),
                )));
            }
            pinned
        }
        None => advertised
            .iter()
            .copied()
            .find(|p| matches!(p, PinUvAuthProtocol::One | PinUvAuthProtocol::Two))
            .ok_or_else(|| {
                CeremonyError::Transport(TransportError::new(
                    "clientPIN",
                    String::from(
                        "no mutually supported pinUvAuthProtocol (need protocol 1 or 2, \
                         CTAP2.1 §6.5.5.4)",
                    ),
                ))
            })?,
    };

    // Entropy is the caller-injected source (passed in; the caller
    // owns the OS-backed stream — design D2).

    // Step 2: getKeyAgreement (0x02) → encapsulate (§6.5.5.4).
    let platform = PlatformKeyAgreement::generate(entropy)
        .map_err(pin_crypto_err("clientPIN key generation"))?;
    let ka_request = ClientPinRequest {
        protocol: selected,
        sub_command: ClientPinSubCommand::GetKeyAgreement,
        key_agreement: Some(platform.cose_key()),
        pin_uv_auth_param: None,
        pin_hash_enc: None,
        permissions: None,
        rp_id: None,
    };
    let ka_response = client_pin_hop(device, &ka_request, deadline, sleep).await?;
    let peer_key = ka_response.key_agreement.ok_or_else(|| {
        CeremonyError::Transport(TransportError::new(
            "clientPIN",
            String::from(
                "getKeyAgreement response carries no keyAgreement member (CTAP2.1 §6.5.5)",
            ),
        ))
    })?;
    let shared = platform
        .encapsulate(&peer_key, selected)
        .map_err(pin_crypto_err("clientPIN key agreement"))?;

    // Step 3: collect the PIN via the provider (at most once; §6.5.5
    // maximum 63 UTF-8 bytes, checked BEFORE any further device
    // traffic).
    let pin = provider
        .provide_pin()
        .map_err(|_| CeremonyError::PinProviderFailed)?;
    if pin.len() > MAX_PIN_BYTES {
        return Err(CeremonyError::PinTooLong);
    }
    // pinHash source: LEFT(SHA-256(PIN), 16) (CTAP2.1 §6.5.6/§6.5.7
    // encrypt input). Zeroized after use (no-secrets rule).
    let pin_hash_full = Sha256::digest(&pin);
    let mut pin_hash = Zeroizing::new([0u8; 16]);
    pin_hash.copy_from_slice(&pin_hash_full[..16]);
    let mut pin = pin;
    pin.zeroize();

    // Step 4: the token request — 0x09 with permissions=ga + rpId
    // when the probe advertises the pinUvAuthToken option ID,
    // otherwise the CTAP2.0-token fallback getPinToken (0x05).
    let puat_option = info.option(crate::get_info::OptionId::PinUvAuthToken);
    let sub_command = if puat_option {
        ClientPinSubCommand::GetPinUvAuthTokenUsingPinWithPermissions
    } else {
        ClientPinSubCommand::GetPinToken
    };
    let pin_hash_enc = shared
        .encrypt(entropy, pin_hash.as_ref())
        .map_err(pin_crypto_err("pinHashEnc encryption"))?;
    let token_request = ClientPinRequest {
        protocol: selected,
        sub_command,
        key_agreement: Some(platform.cose_key()),
        pin_uv_auth_param: None,
        pin_hash_enc: Some(pin_hash_enc),
        permissions: puat_option.then_some(permissions::GA),
        rp_id: puat_option.then(|| alloc::string::String::from(rp_id)),
    };
    let token_response = match client_pin_hop(device, &token_request, deadline, sleep).await {
        Ok(resp) => resp,
        // 0x31 with a pinRetries member: surface the count (design
        // D5). The ceremony does not retry (mirrors OQ-1).
        Err(err @ CeremonyError::IncorrectPin { .. }) => return Err(err),
        Err(other) => return Err(other),
    };
    let encrypted_token = token_response.pin_uv_auth_token.ok_or_else(|| {
        CeremonyError::Transport(TransportError::new(
            "clientPIN",
            String::from(
                "token request succeeded without a pinUvAuthToken member (CTAP2.1 §6.5.5)",
            ),
        ))
    })?;

    // Step 5: decrypt the token; compute the getAssertion material.
    let token = shared
        .decrypt(&encrypted_token)
        .map_err(pin_crypto_err("pinUvAuthToken decryption"))?;
    let param_message = pin_uv_auth_param_message(client_data_hash);
    let param = shared.authenticate(&token, &param_message);
    let mut token = token;
    token.zeroize();

    Ok((PinUvAuthParam::new(param), selected))
}

/// One authenticatorClientPIN (0x06) hop: encode → send (racing the
/// remaining budget, phase `ClientPin`) → status check → decode.
async fn client_pin_hop<D: Device + Send>(
    device: &mut D,
    request: &ClientPinRequest,
    deadline: &Deadline,
    sleep: SleepHandle<'_>,
) -> Result<ClientPinResponse, CeremonyError> {
    let body = request.encode().map_err(|e| {
        CeremonyError::Transport(TransportError::new(
            "clientPIN",
            format!("clientPIN request encode: {e}"),
        ))
    })?;
    let cmd = CtapCommand::ClientPin(request.clone());
    let event = race(
        device.send(&cmd, deadline, sleep),
        sleep,
        deadline,
        Phase::ClientPin,
    )
    .await?;
    let _ = body; // the model carries the wire shape; encode() is the canonical-form check
    let (status, response_body) = response_of(event)?;
    if status == StatusCode::PinInvalid.to_u8() {
        // Extract pinRetries from the (possibly empty-bodied) error.
        let retries = if response_body.is_empty() {
            None
        } else {
            CborValue::decode_map(&response_body, DecodePolicy::Tolerant)
                .ok()
                .and_then(|v| ClientPinResponse::from_cbor(&v).ok())
                .and_then(|r| r.pin_retries)
        };
        return Err(CeremonyError::IncorrectPin {
            remaining_retries: retries,
        });
    }
    if let Some(err) = CeremonyError::from_status(StatusCode::from_u8(status)) {
        return Err(err);
    }
    let value = CborValue::decode_map(&response_body, DecodePolicy::Strict).map_err(|e| {
        CeremonyError::Transport(TransportError::new(
            "clientPIN",
            format!("clientPIN response: {e}"),
        ))
    })?;
    ClientPinResponse::from_cbor(&value).map_err(|e| {
        CeremonyError::Transport(TransportError::new(
            "clientPIN",
            format!("clientPIN response: {e}"),
        ))
    })
}

/// Map the crypto layer's typed errors onto the ceremony taxonomy as
/// `Transport` details naming the clientPIN layer (design D5: the
/// taxonomy stays closed; the cause is carried in the detail).
fn pin_crypto_err(layer: &'static str) -> impl Fn(PinCryptoError) -> CeremonyError {
    move |e| CeremonyError::Transport(TransportError::new("clientPIN", format!("{layer}: {e}")))
}

/// The entropy default when the caller injected none: always a typed
/// failure. Production callers inject an OS-backed source; the soft
/// harness injects its deterministic stream.
#[cfg(test)]
#[allow(dead_code)]
struct DeadEntropy;

#[cfg(test)]
impl PinEntropySource for DeadEntropy {
    fn fill_random(&mut self, _dest: &mut [u8]) -> Result<(), PinCryptoError> {
        Err(PinCryptoError::Random)
    }
}

/// Split a terminal response event into its status byte and body,
/// typed: a keepalive where a response is required is a transport
/// error (continuations must resolve to terminal responses).
fn response_of(event: DeviceEvent) -> Result<(u8, Vec<u8>), CeremonyError> {
    match event {
        DeviceEvent::Response { status, body } => Ok((status, body)),
        DeviceEvent::Keepalive { .. } => Err(CeremonyError::Transport(TransportError::new(
            "ceremony",
            String::from(
                "keepalive progress signal where a terminal response was required; continuation \
                 must resolve to a response",
            ),
        ))),
    }
}

/// One authenticatorGetNextAssertion hop (CTAP2.1 §6.3): bounded by
/// the remaining budget (expiry before the hop names
/// `GetNextAssertion`), and the response status maps through the §8.2
/// table without retry (0x30 surfaces as `Ctap`).
fn drain_hop(
    drain: &mut Drain,
    deadline: &Deadline,
) -> Result<GetAssertionResponse, CeremonyError> {
    if deadline.remaining().is_zero() {
        return Err(CeremonyError::Timeout(Phase::GetNextAssertion));
    }
    let (status, body) = response_of(drain.next().map_err(CeremonyError::from_core)?)?;
    if let Some(err) = CeremonyError::from_status(StatusCode::from_u8(status)) {
        return Err(err);
    }
    decode_assertion(&body)
}

/// The keepalive progress loop (design D5): re-issue the command until
/// a terminal response arrives, WITHOUT ever resetting the deadline.
/// Keepalives are surfaced progress, not errors; every iteration is
/// bounded by the remaining budget.
///
/// Phase naming: before any keepalive has flowed the hop is the §6.2
/// command exchange (`GetAssertion`); once the authenticator has
/// signaled UP_NEEDED the observable wait IS user presence, so budget
/// expiry is named `UserPresence` (ceremony spec scenario "Budget
/// expires during user-presence wait").
async fn keepalive_loop<D: Device + Send>(
    device: &mut D,
    cmd: &CtapCommand,
    deadline: &Deadline,
    sleep: SleepHandle<'_>,
) -> Result<DeviceEvent, CeremonyError> {
    let mut seen_keepalive = false;
    loop {
        let phase = if seen_keepalive {
            Phase::UserPresence
        } else {
            cmd.phase()
        };
        // The hop future races the remaining budget; expiry (or an
        // exhausted budget) returns `Timeout(phase)`. Dropping the hop
        // on expiry is the cancellation path.
        let hop = device.send(cmd, deadline, sleep);
        let event = match deadline.wait(sleep, phase, core::pin::pin!(hop)).await {
            Err(e) => return Err(CeremonyError::from_core(e)),
            Ok(inner) => match inner {
                Ok(event) => event,
                Err(e) => {
                    // The device's internal budget check names the
                    // command phase; after a keepalive the observable
                    // wait is user presence — rename so the typed
                    // timeout matches the ceremony spec.
                    let mapped = CeremonyError::from_core(e);
                    return Err(match mapped {
                        CeremonyError::Timeout(_) if seen_keepalive => {
                            CeremonyError::Timeout(Phase::UserPresence)
                        }
                        other => other,
                    });
                }
            },
        };
        match event {
            DeviceEvent::Keepalive { .. } => {
                seen_keepalive = true;
                continue;
            }
            DeviceEvent::Response { .. } => return Ok(event),
        }
    }
}

/// Decode the getInfo probe response: a terminal response with
/// `status = 0x00` plus a parseable body. Every failure path is typed.
fn decode_info(event: DeviceEvent) -> Result<GetInfoResponse, CeremonyError> {
    let (status, body) = match event {
        DeviceEvent::Response { status, body } => (status, body),
        DeviceEvent::Keepalive { .. } => {
            return Err(CeremonyError::Transport(TransportError::new(
                "ceremony",
                String::from("getInfo probe produced a keepalive progress signal"),
            )));
        }
    };
    if let Some(err) = CeremonyError::from_status(StatusCode::from_u8(status)) {
        return Err(err);
    }
    let value = CborValue::decode_map(&body, DecodePolicy::Strict).map_err(|e| {
        CeremonyError::Transport(TransportError::new(
            "ceremony",
            format!("getInfo probe: {e}"),
        ))
    })?;
    GetInfoResponse::from_cbor(&value).map_err(|e| {
        CeremonyError::Transport(TransportError::new(
            "ceremony",
            format!("getInfo probe: {e}"),
        ))
    })
}

/// Decode one assertion body (§6.2 or §6.3 response).
fn decode_assertion(body: &[u8]) -> Result<GetAssertionResponse, CeremonyError> {
    let value = CborValue::decode_map(body, DecodePolicy::Strict).map_err(|e| {
        CeremonyError::Transport(TransportError::new(
            "ceremony",
            format!("assertion response: {e}"),
        ))
    })?;
    GetAssertionResponse::from_cbor(&value).map_err(|e| {
        CeremonyError::Transport(TransportError::new(
            "ceremony",
            format!("assertion response: {e}"),
        ))
    })
}

/// Race a hop future against the remaining budget: the budget wins
/// with `Timeout(phase)` when it expires first (async-core D4); the
/// hop future is dropped, which is the cancellation path.
async fn race<T, F>(
    hop: F,
    sleep: SleepHandle<'_>,
    deadline: &Deadline,
    phase: Phase,
) -> Result<T, CeremonyError>
where
    F: Future<Output = Result<T, Error>>,
{
    // `wait` races the hop against the remaining budget; the hop's own
    // output is a `Result`, so the deadline layer and the hop layer
    // both map onto the ceremony taxonomy.
    match deadline.wait(sleep, phase, core::pin::pin!(hop)).await {
        Ok(inner) => inner.map_err(CeremonyError::from_core),
        Err(e) => Err(CeremonyError::from_core(e)),
    }
}

// ----------------------------------------------------------------------
// Full entry (design D1, two stages): discover + select + connect, then
// the shared exchange pipeline. One budget, consumed in order.
// ----------------------------------------------------------------------

/// The orchestration input for one full getAssertion run (ceremony
/// spec: "Ceremony inputs and RP-agnostic boundary").
pub struct GetAssertionCeremony<T> {
    /// Every transport to enumerate, in deterministic order (D1).
    pub transports: Vec<T>,
    /// The relying-party identifier (CTAP2.1 §6.2 request key 0x01).
    pub rp_id: String,
    /// Caller-supplied hash of the serialized client data (key 0x02).
    pub client_data_hash: Vec<u8>,
    /// Optional allowList (key 0x03); empty is omitted on the wire.
    pub allow_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    /// User-verification policy (design D4).
    pub user_verification: UvPolicy,
    /// Caller-held pinUvAuth material (keys 0x06/0x07), passed through
    /// when the authenticator supports the protocol. Takes precedence
    /// over PIN acquisition.
    pub pin_uv_auth: Option<(PinUvAuthParam, PinUvAuthProtocol)>,
    /// Caller-owned PIN provider (add-client-pin design D3): enables
    /// the CTAP2.1 §6.5.5 token acquisition under
    /// [`UvPolicy::Preferred`]. Consumed at most once per run.
    pub pin_provider: Option<PinProviderHandle>,
    /// Caller-pinned pinUvAuth protocol (§6.5.5.4); default follows
    /// the authenticator's preference order.
    pub pin_uv_auth_protocol: Option<PinUvAuthProtocol>,
    /// Entropy for platform key pairs and protocol-2 IVs (design D2).
    /// Production callers MUST inject an OS-backed source; leaving
    /// this `None` fails the acquisition typed (no silent insecure
    /// fallback).
    pub entropy: Option<alloc::boxed::Box<dyn crate::crypto::PinEntropySource + Send>>,
    /// The single total ceremony budget (async-core D4): discovery,
    /// connect, probe, exchange, and every drain hop consume its
    /// remainder.
    pub deadline: Duration,
    /// Explicit device-selection policy. The default `Fail` refuses to
    /// pick among multiple candidates (stack invariant).
    pub selection: SelectionPolicy,
    /// Continuation hook for the multi-assertion drain (CTAP2.1
    /// §6.3). Required only when an authenticator reports
    /// `numberOfCredentials > 1`; see [`Drain`].
    pub drain: Option<Drain>,
}

impl<T> GetAssertionCeremony<T> {
    /// Minimal ceremony input: transports, `rpId`, `clientDataHash`,
    /// budget — the "Minimal ceremony input" scenario shape.
    /// Selection defaults to `Fail`; no drain hook is installed.
    pub fn new(
        transports: Vec<T>,
        rp_id: String,
        client_data_hash: Vec<u8>,
        deadline: Duration,
    ) -> Self {
        Self {
            transports,
            rp_id,
            client_data_hash,
            allow_credentials: None,
            user_verification: UvPolicy::default(),
            pin_uv_auth: None,
            pin_provider: None,
            pin_uv_auth_protocol: None,
            entropy: None,
            deadline,
            selection: SelectionPolicy::default(),
            drain: None,
        }
    }
}

/// The ordered candidate pool (each candidate with its owning
/// transport index) plus per-transport diagnostics produced by the
/// discovery phase (D2: collect, never short-circuit).
struct Discovered {
    candidates: Vec<(DeviceInfo, usize)>,
    diagnostics: Vec<DiscoveryDiagnostic>,
}

impl<T: Transport> GetAssertionCeremony<T>
where
    T::Device: Device + Send + 'static,
{
    /// Run the full ceremony against all configured transports,
    /// bounded by `self.deadline`.
    ///
    /// Failure is always a [`CeremonyError`]; every wait is bounded by
    /// the single remaining budget and cancellation (dropping the
    /// future) is safe.
    pub async fn run(
        mut self,
        sleep: SleepHandle<'_>,
    ) -> Result<GetAssertionOutcome, CeremonyError> {
        let deadline = Deadline::new(self.deadline);

        // ---- Phase 1: discovery (D2: collect, never short-circuit).
        // The whole phase is bounded by the remaining budget; expiry
        // names the discovery phase.
        let Discovered {
            candidates,
            diagnostics,
        } = Self::discover(&self.transports, &deadline, sleep).await?;
        let descriptors: Vec<CandidateDescriptor> = candidates
            .iter()
            .map(|(info, _)| info.descriptor())
            .collect();

        // ---- Phase 2: selection (explicit, deterministic; default
        // Fail). Zero candidates → NoDevice carrying every
        // per-transport discovery error.
        if descriptors.is_empty() {
            return Err(CeremonyError::NoDevice(diagnostics));
        }
        let selected = apply_selection(&self.selection, &descriptors)
            .map_err(CeremonyError::from_core)?
            .ok_or_else(|| CeremonyError::NoDevice(diagnostics.clone()))?;
        // The selected descriptor maps back to its owning transport by
        // position (descriptors are the candidates, in order).
        let owner_idx = descriptors
            .iter()
            .position(|d| d == &selected)
            .ok_or_else(|| {
                CeremonyError::Transport(TransportError::new(
                    "ceremony",
                    format!("selected device {} has no owning transport", selected.id),
                ))
            })?;
        let selected_owner = candidates[owner_idx].1;

        // ---- Phase 3: connect — exactly once, for the selected
        // candidate only, bounded by the remaining budget.
        let input = CeremonyInput {
            rp_id: self.rp_id,
            client_data_hash: self.client_data_hash,
            allow_credentials: self.allow_credentials,
            user_verification: self.user_verification,
            pin_uv_auth: self.pin_uv_auth,
            pin_provider: self.pin_provider,
            pin_uv_auth_protocol: self.pin_uv_auth_protocol,
            entropy: self.entropy,
        };
        // The candidate carries the index of the transport that
        // enumerated it, so the selected descriptor always maps back
        // to the right transport (a failing transport contributes no
        // candidates; two transports listing the same id are distinct
        // candidates).
        // Deterministic order (D1) fixed the owning transport;
        // remove it so the transport moves into `connect`.
        let transport = self.transports.swap_remove(selected_owner);
        let device = race(
            transport.connect(&selected.id, &deadline, sleep),
            sleep,
            &deadline,
            Phase::Connect,
        )
        .await?;

        // ---- Phases 4–7 over the connected device.
        let mut outcome = exchange_pipeline(device, input, self.drain, &deadline, sleep).await?;
        outcome.discovery_diagnostics = diagnostics;
        Ok(outcome)
    }

    /// Enumerate every transport, collecting candidates with the
    /// owning transport's index plus per-transport errors (D2). Each
    /// enumeration races the remaining budget; expiry returns the
    /// typed discovery-phase timeout. A transport's failure never
    /// hides other transports' candidates and never aborts discovery.
    async fn discover(
        transports: &[T],
        deadline: &Deadline,
        sleep: SleepHandle<'_>,
    ) -> Result<Discovered, CeremonyError> {
        let mut candidates: Vec<(DeviceInfo, usize)> = Vec::new();
        let mut diagnostics = Vec::new();
        for (idx, transport) in transports.iter().enumerate() {
            match race(
                transport.enumerate(deadline, sleep),
                sleep,
                deadline,
                Phase::Enumeration,
            )
            .await
            {
                Ok(devices) => {
                    candidates.extend(devices.into_iter().map(|info| (info, idx)));
                }
                // A transport's failure never hides other transports'
                // candidates and never aborts discovery (D2); it is
                // collected as a typed diagnostic. Budget expiry is
                // NOT a transport failure: it ends the phase.
                Err(err @ CeremonyError::Timeout(_)) => return Err(err),
                Err(err) => {
                    let kind = transport_kind(transport);
                    let cause = match err {
                        CeremonyError::Transport(e) => Error::Transport(e),
                        other => Error::Transport(TransportError::new(
                            "ceremony",
                            format!("enumeration failed: {other}"),
                        )),
                    };
                    diagnostics.push(DiscoveryDiagnostic::new(kind, cause));
                }
            }
        }
        Ok(Discovered {
            candidates,
            diagnostics,
        })
    }
}

/// The transport kind for per-transport diagnostics: each transport
/// names its own layer via [`Transport::kind()`] (add-client-pin:
/// replaces the v1 hardcoded `Soft` label; ceremony OQ-6 superseded).
fn transport_kind<T: Transport>(transport: &T) -> crate::transport::TransportKind {
    transport.kind()
}

// ----------------------------------------------------------------------
// Exchange-only entry: the async-core `Ceremony` trait over a device
// the caller has already discovered, selected, and connected.
// ----------------------------------------------------------------------

/// Exchange-only ceremony input for the [`Ceremony`] trait path
/// (device already connected by the caller). Phases 4–7 of the
/// ceremony: the probe stays mandatory here too (design OQ-2).
pub struct GetAssertionExchange {
    /// The relying-party identifier (CTAP2.1 §6.2 key 0x01).
    pub rp_id: String,
    /// Caller-supplied clientDataHash (key 0x02).
    pub client_data_hash: Vec<u8>,
    /// Optional allowList; empty is omitted on the wire (CTAP2.1 §6.2).
    pub allow_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    /// User-verification policy (design D4).
    pub user_verification: UvPolicy,
    /// Caller-held pinUvAuth material (keys 0x06/0x07), passed through
    /// when the authenticator supports the protocol. Takes precedence
    /// over PIN acquisition.
    pub pin_uv_auth: Option<(PinUvAuthParam, PinUvAuthProtocol)>,
    /// Caller-owned PIN provider (add-client-pin design D3): enables
    /// the CTAP2.1 §6.5.5 token acquisition under
    /// [`UvPolicy::Preferred`]. Consumed at most once per run.
    pub pin_provider: Option<PinProviderHandle>,
    /// Caller-pinned pinUvAuth protocol (§6.5.5.4); default follows
    /// the authenticator's preference order.
    pub pin_uv_auth_protocol: Option<PinUvAuthProtocol>,
    /// Entropy for platform key pairs and protocol-2 IVs (design D2).
    /// Production callers MUST inject an OS-backed source; leaving this
    /// `None` fails the acquisition typed (no silent insecure fallback).
    pub entropy: Option<alloc::boxed::Box<dyn crate::crypto::PinEntropySource + Send>>,
    /// Continuation hook for the §6.3 drain (see [`Drain`]).
    pub drain: Option<Drain>,
}

impl Ceremony for GetAssertionExchange {
    type Output = GetAssertionOutcome;

    async fn run<D: Device + Send + 'static>(
        self,
        device: D,
        deadline: &Deadline,
        sleep: SleepHandle<'_>,
    ) -> Result<Self::Output, CeremonyError> {
        let input = CeremonyInput {
            rp_id: self.rp_id,
            client_data_hash: self.client_data_hash,
            allow_credentials: self.allow_credentials,
            user_verification: self.user_verification,
            pin_uv_auth: self.pin_uv_auth,
            pin_provider: self.pin_provider,
            pin_uv_auth_protocol: self.pin_uv_auth_protocol,
            entropy: self.entropy,
        };
        exchange_pipeline(device, input, self.drain, deadline, sleep).await
    }
}
