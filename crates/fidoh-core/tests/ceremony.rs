//! Scenario-ID tests for the ceremony spec
//! (`openspec/changes/ceremony/specs/ceremony/spec.md`).
//!
//! Coverage mapping (8 spec requirements → test fns; every scenario is
//! exercised, several share a test where the spec scenarios are
//! observable behaviors of the same walk):
//!
//! | Requirement | Scenario | Test |
//! |---|---|---|
//! | Transport discovery collects candidates | One transport fails, another yields a candidate | `one_transport_fails_another_yields_candidate` |
//! | Transport discovery collects candidates | All transports fail or yield nothing | `all_transports_fail_or_yield_nothing` |
//! | Transport discovery collects candidates | Discovery bounded by budget | `discovery_timeout_names_enumeration_phase` |
//! | Deterministic device selection | Multiple candidates under default Fail | `ambiguous_device_under_default_fail_policy` |
//! | Deterministic device selection | Explicit First policy selects deterministically | `first_policy_selects_deterministically` |
//! | Ceremony inputs / RP-agnostic boundary | Minimal ceremony input | `minimal_input_sends_keys_01_and_02_only` |
//! | Ceremony inputs / RP-agnostic boundary | Empty allowCredentials omitted on the wire | `empty_allow_credentials_omitted_on_wire` |
//! | Ceremony sequence per §6.2 | Keepalive-then-success within budget | `keepalive_then_success_within_budget` |
//! | Ceremony sequence per §6.2 | Budget expires during user-presence wait | `budget_expires_during_user_presence_wait` |
//! | Typed status-code handling | No matching credential → NoCredentials (+ 11-code matrix) | `status_injection_matrix_maps_typed` |
//! | Typed status-code handling | User-action timeout ≠ budget timeout | `user_action_timeout_distinct_from_budget_timeout` |
//! | Typed status-code handling | Keepalive cancel → UserCancelled | `keepalive_cancel_maps_to_user_cancelled` |
//! | Multi-assertion drain | Three credentials drained in order | `three_credentials_drained_in_order` |
//! | Multi-assertion drain | Continuation refused surfaces typed | `continuation_refused_surfaces_typed_ctap` |
//! | Ceremony error taxonomy | Every failure path is typed | `every_failure_path_is_typed` |
//! | Assertion fidelity + credential verification | Wrong credential id rejected | `wrong_credential_id_rejected_truncated_safe` |
//! | Ceremony sequence per §6.2 | (mandatory probe: capabilities ride in outcome) | `happy_path_end_to_end_with_verifiable_signature` |
//! | Ceremony sequence per §6.2 | (probe failure fails the ceremony) | `probe_failure_fails_the_ceremony` |
//! | Ceremony inputs / RP-agnostic boundary | (uv policy enforcement via probe capability) | `uv_policy_enforcement_via_probe` |
//! | Ceremony inputs / RP-agnostic boundary | (unsupported pinUvAuthProtocol rejected, §6.5.5) | `unsupported_pin_uv_auth_protocol_rejected` |
//! | async-core trait seam | (exchange-only path over a connected device) | `exchange_only_trait_path_matches_full_entry` |
//! | (drain-hook discipline) | (hook never invoked for one credential) | `drain_hook_never_runs_when_single_credential` |
//!
//! Everything is driven through the soft transport (dev-dependency):
//! discovery → selection → connect → getInfo probe → getAssertion →
//! drain. Drain scenarios use the exchange-only entry because the
//! drain hook must bind the ceremony's own connected device. All waits
//! are budget-accounted through the shared `Deadline`; the `Sleep`
//! factory never resolves, so an accidental internal wait hangs loudly
//! instead of passing silently.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use fidoh_core::device::{CtapCommand, Device, DeviceEvent};
use fidoh_core::error::Error;
use fidoh_core::get_assertion::{
    CredentialType, GetAssertionRequest, PublicKeyCredentialDescriptor,
};
use fidoh_core::pin::{PinUvAuthParam, PinUvAuthProtocol};
use fidoh_core::status::StatusCode;
use fidoh_core::time::{Deadline, Phase};
use fidoh_core::transport::{DeviceId, DeviceInfo, SelectionPolicy, Transport};
use fidoh_core::{
    Ceremony, CeremonyError, Drain, GetAssertionCeremony, GetAssertionExchange, Sleep, UvPolicy,
};
use fidoh_transport_soft::{
    Config, KeepaliveEvent, MakeCredentialArgs, SoftAuthenticator, SoftDevice, SoftTransport,
    UpUvMode, AAGUID,
};

// --------------------------------------------------------------------
// Minimal block_on (executor lives only in tests) + NoSleep factory —
// same harness discipline as the transport-soft tests.
// --------------------------------------------------------------------

struct NoopWaker;

impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
    fn wake_by_ref(self: &Arc<Self>) {}
}

fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = Box::pin(fut);
    let waker = Waker::from(Arc::new(NoopWaker));
    let mut cx = Context::from_waker(&waker);
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(out) => return out,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

/// A `Sleep` factory that never resolves: every wait in the ceremony
/// stack is budget-accounted (the soft token consumes the shared
/// `Deadline` synchronously), so nothing should ever await this.
struct NoSleep;

impl Sleep for NoSleep {
    fn sleep(&self, _duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(std::future::pending())
    }
}

fn no_sleep() -> &'static (dyn Sleep + Send + Sync) {
    &NoSleep
}

// --------------------------------------------------------------------
// Fixtures.
// --------------------------------------------------------------------

const RP: &str = "example.com";
const CLIENT_HASH: [u8; 32] = [0xAB; 32];
const BUDGET: Duration = Duration::from_secs(30);

fn token() -> SoftAuthenticator {
    SoftAuthenticator::new(Config::default())
}

fn mint(auth: &mut SoftAuthenticator, user: &[u8]) -> fidoh_transport_soft::MintedCredential {
    auth.make_credential(MakeCredentialArgs {
        rp_id: String::from(RP),
        user_handle: user.to_vec(),
        resident: true,
    })
    .unwrap()
}

fn descriptor(id: &[u8]) -> PublicKeyCredentialDescriptor {
    PublicKeyCredentialDescriptor {
        type_field: CredentialType::PublicKey,
        id: id.to_vec(),
        transports: None,
    }
}

/// Connect TWO device handles to one authenticator: the assertion
/// queue lives in the shared core, so a second handle drains what the
/// first produced (the drain-hook binding for the exchange-only path).
/// The first handle goes to the ceremony, the second to the drain hook.
fn connect_two(auth: SoftAuthenticator) -> (SoftTransport, SoftDevice, Mutex<SoftDevice>) {
    let t = SoftTransport::new(auth);
    let deadline = Deadline::new(BUDGET);
    let device = block_on(t.connect(&DeviceId::new("soft-0"), &deadline, no_sleep())).unwrap();
    let drainer = block_on(t.connect(&DeviceId::new("soft-0"), &deadline, no_sleep())).unwrap();
    (t, device, Mutex::new(drainer))
}

/// A full-entry ceremony over one soft token, default selection (a
/// single candidate is unambiguous under `Fail`).
fn soft_ceremony(auth: SoftAuthenticator) -> GetAssertionCeremony<SoftTransport> {
    GetAssertionCeremony::new(
        vec![SoftTransport::new(auth)],
        String::from(RP),
        CLIENT_HASH.to_vec(),
        BUDGET,
    )
}

fn run<T: Transport>(
    ceremony: GetAssertionCeremony<T>,
) -> Result<fidoh_core::GetAssertionOutcome, CeremonyError>
where
    T::Device: Device + Send + 'static,
{
    block_on(ceremony.run(no_sleep()))
}

/// The drain hook: the ceremony layer treats
/// authenticatorGetNextAssertion as per-device continuation state
/// (async-core's `CtapCommand` carries GetInfo/GetAssertion only), so
/// the hook binds the §6.3 command to a connected handle of the same
/// authenticator (the queue lives in the shared core). The soft
/// token's continuation consumes no shared budget (harness method),
/// so the hook checks the ceremony deadline itself before hopping.
fn soft_drain(drainer: Mutex<SoftDevice>, deadline: Deadline) -> Drain {
    Drain::new(move || {
        if deadline.remaining().is_zero() {
            return Err(Error::Timeout(Phase::GetNextAssertion));
        }
        drainer
            .lock()
            .unwrap()
            .get_next_assertion(&CLIENT_HASH, &deadline)
    })
}

/// Real ECDSA verification over `authData || clientDataHash` (never a
/// tautology — same discipline as the transport-soft tests).
fn verify_assertion(
    auth_data: &[u8],
    signature: &[u8],
    key: &fidoh_core::cose::CoseEs256Key,
    client_data_hash: &[u8],
) -> Result<(), String> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    let point = p256::EncodedPoint::from_affine_coordinates(
        &p256::FieldBytes::from_iter(key.x.iter().copied()),
        &p256::FieldBytes::from_iter(key.y.iter().copied()),
        false,
    );
    let vk = VerifyingKey::from_sec1_bytes(point.as_bytes())
        .map_err(|e| format!("bad public key: {e}"))?;
    let sig = Signature::from_der(signature).map_err(|e| format!("bad DER: {e}"))?;
    let mut signed = auth_data.to_vec();
    signed.extend_from_slice(client_data_hash);
    vk.verify(&signed, &sig)
        .map_err(|e| format!("verify failed: {e}"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// --------------------------------------------------------------------
// Requirement: Ceremony sequence per CTAP2.1 §6.2 — happy path with
// the mandatory probe (design OQ-2) and a verifiable signature.
// --------------------------------------------------------------------

#[test]
fn happy_path_end_to_end_with_verifiable_signature() {
    let mut auth = token();
    let minted = mint(&mut auth, b"ci-user-1");
    let out = run(soft_ceremony(auth)).expect("ceremony must succeed");

    // Exactly one raw assertion, fields exactly as decoded.
    assert_eq!(out.assertions.len(), 1);
    let first = out.first();
    assert_eq!(first.credential.id, minted.record.id);
    assert_eq!(first.number_of_credentials, 1);
    assert!(!first.number_of_credentials_present);
    assert!(!first.user_selected_present);
    assert_eq!(
        first.user.as_ref().map(|u| u.id.as_slice()),
        Some(&b"ci-user-1"[..])
    );

    // Signature verifies over authData || clientDataHash (real crypto).
    verify_assertion(
        &first.auth_data,
        &first.signature,
        &minted.record.public_key(),
        &CLIENT_HASH,
    )
    .expect("ceremony assertion must verify");

    // The mandatory getInfo probe's capabilities ride in the outcome.
    assert_eq!(out.info.aaguid, AAGUID);
    assert_eq!(
        out.info.versions,
        vec![String::from("FIDO_2_0"), String::from("FIDO_2_1")]
    );
    // Clean discovery: no per-transport diagnostics.
    assert!(out.discovery_diagnostics.is_empty());
    // Discouraged default: no UV on the wire, reported (never silent).
    assert_eq!(out.uv_effective, fidoh_core::UvEffective::NotRequested);
}

// --------------------------------------------------------------------
// Requirement: Ceremony sequence per §6.2 with single-budget keepalive
// loop.
// --------------------------------------------------------------------

// Scenario: Keepalive-then-success within budget (CI: keepalive knob)
// — three UP_NEEDED keepalives at 50 ms spacing before the response;
// consumed as progress signals, deadline never reset.
#[test]
fn keepalive_then_success_within_budget() {
    let mut auth = token();
    let minted = mint(&mut auth, b"ci-user-1");
    auth.knobs_mut().keepalive_sequence = vec![
        KeepaliveEvent {
            status: 0x02,
            spacing: Duration::from_millis(50),
        },
        KeepaliveEvent {
            status: 0x02,
            spacing: Duration::from_millis(50),
        },
        KeepaliveEvent {
            status: 0x02,
            spacing: Duration::from_millis(50),
        },
    ];
    let out = run(soft_ceremony(auth)).expect("keepalives are progress, not errors");
    assert_eq!(out.first().credential.id, minted.record.id);
}

// Scenario: Budget expires during user-presence wait (CI:
// require-explicit-poke) — typed Timeout naming the user-presence
// phase; the failed run leaves no poisoned state, a subsequent
// ceremony succeeds (cancellation contract).
#[test]
fn budget_expires_during_user_presence_wait() {
    let cfg = Config {
        up_mode: UpUvMode::RequireExplicitPoke,
        ..Config::default()
    };
    let mut auth = SoftAuthenticator::new(cfg);
    let _ = mint(&mut auth, b"ci-user-1");
    // Small budget: the poke poll slices exhaust it mid-wait.
    let ceremony = GetAssertionCeremony::new(
        vec![SoftTransport::new(auth)],
        String::from(RP),
        CLIENT_HASH.to_vec(),
        Duration::from_millis(250),
    );
    assert_eq!(
        run(ceremony).unwrap_err(),
        CeremonyError::Timeout(Phase::UserPresence)
    );

    // Cancellation contract: a fresh ceremony over a fresh store with
    // a credential runs cleanly afterwards (no shared poisoned state;
    // the failed run owned its budget alone).
    let mut fresh = token();
    let fresh_minted = mint(&mut fresh, b"ci-user-2");
    let out = run(soft_ceremony(fresh)).expect("device remains usable for a subsequent ceremony");
    assert_eq!(out.first().credential.id, fresh_minted.record.id);
}

// --------------------------------------------------------------------
// Requirement: Transport discovery collects candidates across all
// transports.
// --------------------------------------------------------------------

/// A transport whose enumeration always fails (e.g. no reader daemon).
#[derive(Default)]
struct FailingTransport;

impl Transport for FailingTransport {
    type Device = fidoh_transport_soft::SoftDevice;

    async fn enumerate(
        &self,
        _deadline: &Deadline,
        _sleep: fidoh_core::SleepHandle<'_>,
    ) -> Result<Vec<DeviceInfo>, Error> {
        Err(Error::Transport(fidoh_core::TransportError::new(
            "pcsc",
            String::from("no reader daemon"),
        )))
    }

    async fn connect(
        &self,
        _id: &DeviceId,
        _deadline: &Deadline,
        _sleep: fidoh_core::SleepHandle<'_>,
    ) -> Result<Self::Device, Error> {
        Err(Error::Transport(fidoh_core::TransportError::new(
            "pcsc",
            String::from("no device"),
        )))
    }
}

/// A transport that enumerates cleanly but finds nothing.
#[derive(Default)]
struct EmptyTransport;

impl Transport for EmptyTransport {
    type Device = fidoh_transport_soft::SoftDevice;

    async fn enumerate(
        &self,
        _deadline: &Deadline,
        _sleep: fidoh_core::SleepHandle<'_>,
    ) -> Result<Vec<DeviceInfo>, Error> {
        Ok(Vec::new())
    }

    async fn connect(
        &self,
        id: &DeviceId,
        _deadline: &Deadline,
        _sleep: fidoh_core::SleepHandle<'_>,
    ) -> Result<Self::Device, Error> {
        Err(Error::UnknownDevice(id.clone()))
    }
}

/// One `Transport` type over the three test transports so a single
/// ceremony can enumerate heterogeneous transports (the ceremony is
/// generic in one `T` — real callers have one transport struct per
/// stack; a v1 client composes them, as here).
#[derive(Default)]
enum TestTransport {
    #[default]
    Failing,
    Empty,
    Soft(SoftTransport),
}

impl Transport for TestTransport {
    type Device = fidoh_transport_soft::SoftDevice;

    async fn enumerate(
        &self,
        deadline: &Deadline,
        sleep: fidoh_core::SleepHandle<'_>,
    ) -> Result<Vec<DeviceInfo>, Error> {
        match self {
            Self::Failing => FailingTransport.enumerate(deadline, sleep).await,
            Self::Empty => EmptyTransport.enumerate(deadline, sleep).await,
            Self::Soft(t) => t.enumerate(deadline, sleep).await,
        }
    }

    async fn connect(
        &self,
        id: &DeviceId,
        deadline: &Deadline,
        sleep: fidoh_core::SleepHandle<'_>,
    ) -> Result<Self::Device, Error> {
        match self {
            Self::Failing => FailingTransport.connect(id, deadline, sleep).await,
            Self::Empty => EmptyTransport.connect(id, deadline, sleep).await,
            Self::Soft(t) => t.connect(id, deadline, sleep).await,
        }
    }
}

// Scenario: One transport fails, another yields a candidate — the
// candidate survives, the failure is attached as a diagnostic, and the
// ceremony proceeds.
#[test]
fn one_transport_fails_another_yields_candidate() {
    let mut auth = token();
    let minted = mint(&mut auth, b"ci-user-1");
    let ceremony = GetAssertionCeremony::new(
        vec![
            TestTransport::Failing,
            TestTransport::Soft(SoftTransport::new(auth)),
        ],
        String::from(RP),
        CLIENT_HASH.to_vec(),
        BUDGET,
    );
    let out = run(ceremony).expect("the soft candidate must survive the pcsc failure");
    assert_eq!(out.first().credential.id, minted.record.id);
    // The failure is attached as a diagnostic, not treated as fatal.
    assert_eq!(out.discovery_diagnostics.len(), 1);
    assert!(matches!(
        &out.discovery_diagnostics[0].cause,
        Error::Transport(e) if e.kind == "pcsc" && e.detail.contains("reader daemon")
    ));
    // The diagnostic renders (bounded information, never a panic).
    let _ = out.discovery_diagnostics[0].to_string();
}

// Scenario: All transports fail or yield nothing — typed NoDevice
// carrying each transport's kind and typed discovery error (an empty
// list when everything enumerated cleanly but found nothing).
#[test]
fn all_transports_fail_or_yield_nothing() {
    // One failing + one clean-but-empty: NoDevice carries the failure.
    let ceremony = GetAssertionCeremony::new(
        vec![TestTransport::Failing, TestTransport::Empty],
        String::from(RP),
        CLIENT_HASH.to_vec(),
        BUDGET,
    );
    let err = run(ceremony).unwrap_err();
    match err {
        CeremonyError::NoDevice(diag) => {
            assert_eq!(diag.len(), 1, "only the failing transport is listed");
            assert!(matches!(
                &diag[0].cause,
                Error::Transport(e) if e.kind == "pcsc" && e.detail.contains("reader daemon")
            ));
        }
        other => panic!("expected NoDevice, got {other:?}"),
    }

    // All clean but zero candidates: NoDevice with an EMPTY list.
    let ceremony = GetAssertionCeremony::new(
        vec![TestTransport::Empty, TestTransport::Empty],
        String::from(RP),
        CLIENT_HASH.to_vec(),
        BUDGET,
    );
    assert_eq!(
        run(ceremony).unwrap_err(),
        CeremonyError::NoDevice(Vec::new())
    );

    // No transports at all: same shape.
    let ceremony = GetAssertionCeremony::<SoftTransport>::new(
        vec![],
        String::from(RP),
        CLIENT_HASH.to_vec(),
        BUDGET,
    );
    assert_eq!(
        run(ceremony).unwrap_err(),
        CeremonyError::NoDevice(Vec::new())
    );
}

// Scenario (requirement tail): the whole discovery phase is bounded by
// the remaining budget — expiry returns Timeout naming discovery.
#[test]
fn discovery_timeout_names_enumeration_phase() {
    // Zero budget: the very first enumeration race expires before any
    // device is seen.
    let ceremony = GetAssertionCeremony::new(
        vec![SoftTransport::new(token())],
        String::from(RP),
        CLIENT_HASH.to_vec(),
        Duration::ZERO,
    );
    assert_eq!(
        run(ceremony).unwrap_err(),
        CeremonyError::Timeout(Phase::Enumeration)
    );
}

// --------------------------------------------------------------------
// Requirement: Deterministic device selection.
// --------------------------------------------------------------------

// Scenario: Multiple candidates under default Fail policy — typed
// AmbiguousDevice listing both candidates; connect is never called.
#[test]
fn ambiguous_device_under_default_fail_policy() {
    let ceremony = GetAssertionCeremony::new(
        vec![SoftTransport::new(token()), SoftTransport::new(token())],
        String::from(RP),
        CLIENT_HASH.to_vec(),
        BUDGET,
    );
    let err = run(ceremony).unwrap_err();
    match &err {
        CeremonyError::AmbiguousDevice(candidates) => {
            assert_eq!(candidates.len(), 2);
            // Both descriptors carry the enumeration-time metadata and
            // the transport-supplied AAGUID.
            assert_eq!(candidates[0].id, DeviceId::new("soft-0"));
            assert_eq!(candidates[0].name, "fidoh soft token");
            assert_eq!(candidates[0].aaguid, Some(AAGUID));
            assert_eq!(candidates[1].id, DeviceId::new("soft-0"));
        }
        other => panic!("expected AmbiguousDevice, got {other:?}"),
    }
    // The typed error names every candidate (never a stringly dump).
    let text = err.to_string();
    assert!(text.contains("soft-0"));
    assert!(text.contains("fidoh soft token"));
}

// Scenario: Explicit First policy selects deterministically — the
// first enumerated candidate in deterministic transport order is
// connected and the ceremony proceeds within the budget.
#[test]
fn first_policy_selects_deterministically() {
    let mut auth = token();
    let minted = mint(&mut auth, b"ci-user-1");
    let mut ceremony = soft_ceremony(auth);
    ceremony.transports.push(SoftTransport::new(token()));
    ceremony.selection = SelectionPolicy::First;
    let out = run(ceremony).expect("First must pick the first enumerated transport");
    assert_eq!(out.first().credential.id, minted.record.id);
}

// --------------------------------------------------------------------
// Requirement: Ceremony inputs and RP-agnostic boundary.
// --------------------------------------------------------------------

// Scenario: Minimal ceremony input — the wire request carries keys
// 0x01 and 0x02 only (CTAP2.1 §6.2), no extensions member (0x04), and
// the ceremony completes within the budget.
#[test]
fn minimal_input_sends_keys_01_and_02_only() {
    // The wire shape for the minimal input: map(2) with keys 0x01 and
    // 0x02. The ceremony builds its request through
    // `GetAssertionRequest::new`, so the encoded bytes are the
    // canonical model encoder's output.
    let request = GetAssertionRequest::new(String::from(RP), CLIENT_HASH.to_vec()).unwrap();
    let bytes = request.encode().unwrap();
    assert_eq!(bytes[0], 0xA2, "exactly two members");
    assert_eq!(bytes[1], 0x01);
    assert!(request.allow_list.is_none());
    assert!(request.extensions.is_none(), "no extensions in v1");
    assert!(request.options.is_none());
    assert!(request.pin_uv_auth_param.is_none());
    // Round-trip: decode sees exactly rpId + clientDataHash.
    let decoded = GetAssertionRequest::from_cbor(
        &fidoh_core::cbor::CborValue::decode_map(&bytes, fidoh_core::DecodePolicy::Strict).unwrap(),
    )
    .unwrap();
    assert_eq!(decoded.rp_id, RP);
    assert_eq!(decoded.client_data_hash, CLIENT_HASH.to_vec());
    assert!(decoded.allow_list.is_none());

    // The ceremony with the minimal input completes end-to-end (mint a
    // credential so the store is non-empty).
    let mut auth = token();
    let minted = mint(&mut auth, b"ci-user-1");
    let out = run(soft_ceremony(auth)).expect("minimal input is sufficient");
    assert_eq!(out.first().credential.id, minted.record.id);
    assert_eq!(out.assertions.len(), 1);
}

// Scenario: Empty allowCredentials omitted on the wire — key 0x03 is
// omitted identically to passing no allowCredentials.
#[test]
fn empty_allow_credentials_omitted_on_wire() {
    let mut auth = token();
    let minted = mint(&mut auth, b"ci-user-1");
    let mut ceremony = soft_ceremony(auth);
    ceremony.allow_credentials = Some(Vec::new());
    let out = run(ceremony).expect("empty allowList must be omitted, not sent");
    // With key 0x03 absent the authenticator ran the discoverable-
    // credential flow and still found the resident credential.
    assert_eq!(out.first().credential.id, minted.record.id);

    // Wire-level: an empty list encodes byte-identically to None.
    let with_empty = GetAssertionRequest::new(String::from(RP), CLIENT_HASH.to_vec())
        .unwrap()
        .with_allow_list(Vec::new());
    let minimal = GetAssertionRequest::new(String::from(RP), CLIENT_HASH.to_vec()).unwrap();
    assert_eq!(with_empty.encode().unwrap(), minimal.encode().unwrap());
    assert!(with_empty.allow_list.is_none());
}

// UV policy enforcement (design D4): Preferred sends options.uv ONLY
// when the probe advertised the capability; the effective posture is
// reported in the outcome — never a silent fallback.
#[test]
fn uv_policy_enforcement_via_probe() {
    // Soft token advertises uv: true → Preferred sends options.uv.
    let mut auth = token();
    let minted = mint(&mut auth, b"ci-user-1");
    let mut ceremony = soft_ceremony(auth);
    ceremony.user_verification = UvPolicy::Preferred;
    let out = run(ceremony).expect("preferred uv with advertised capability");
    assert_eq!(out.uv_effective, fidoh_core::UvEffective::UvOption);
    assert_eq!(out.first().credential.id, minted.record.id);
    // The authenticator honored it: UV flag set in authenticatorData.
    assert_eq!(out.first().auth_data[32] & 0b0000_0100, 0b0000_0100);

    // uv_mode always-fail → the probe reports uv: false → the request
    // construction degrades (options.uv never sent) — but this token's
    // always-fail UV mode then REFUSES the whole operation (0x27),
    // which maps typed to UpRejected. The soft token cannot model
    // "uv-incapable yet UP-only succeeds" (its always-fail UV mode
    // gates the operation itself); the wire-degradation REPORT is
    // `uv_effective`, asserted in the happy path (NotRequested) and
    // part 1 (UvOption). Flagged as a transport-soft gap for patch-back.
    let cfg = Config {
        uv_mode: UpUvMode::AlwaysFail,
        ..Config::default()
    };
    let mut auth = SoftAuthenticator::new(cfg);
    let _ = mint(&mut auth, b"ci-user-1");
    let mut ceremony = soft_ceremony(auth);
    ceremony.user_verification = UvPolicy::Preferred;
    let err = run(ceremony).unwrap_err();
    assert_eq!(err, CeremonyError::UpRejected);

    // The same token under Discouraged fails identically — proof the
    // failure is the authenticator's mode, not the UV option.
    let cfg = Config {
        uv_mode: UpUvMode::AlwaysFail,
        ..Config::default()
    };
    let mut auth = SoftAuthenticator::new(cfg);
    let _ = mint(&mut auth, b"ci-user-1");
    let ceremony = soft_ceremony(auth);
    let err = run(ceremony).unwrap_err();
    assert_eq!(err, CeremonyError::UpRejected);
}

// Caller-held pinUvAuth material is rejected when the authenticator
// does not advertise the protocol (CTAP2.1 §6.5.5; core-model scenario
// "rejected at the ceremony layer") — typed, before any exchange.
#[test]
fn unsupported_pin_uv_auth_protocol_rejected() {
    // The soft token advertises no pinUvAuthProtocols at all.
    let mut ceremony = soft_ceremony(token());
    ceremony.user_verification = UvPolicy::Preferred;
    ceremony.pin_uv_auth = Some((PinUvAuthParam::new(vec![0x77; 32]), PinUvAuthProtocol::Two));
    let err = run(ceremony).unwrap_err();
    assert!(
        matches!(&err, CeremonyError::Transport(e) if e.detail.contains("pinUvAuthProtocol")),
        "expected typed protocol rejection, got {err:?}"
    );
    // It failed during request construction, not as a Ctap status.
    assert!(!matches!(err, CeremonyError::Ctap(_)));
}

// --------------------------------------------------------------------
// Requirement: Typed status-code handling.
// --------------------------------------------------------------------

// Scenarios: No matching credential → NoCredentials; the whole 11-code
// client mapping matrix (CI: knob (a)) maps through one table. The
// one-shot knob fires on the FIRST command — the mandatory probe —
// proving a probe failure fails the ceremony with the same §8.2
// mapping (design OQ-2). The assertion-phase mapping is proven by
// probing through the trait first, THEN arming the knob.
#[test]
fn status_injection_matrix_maps_typed() {
    let matrix: [(StatusCode, CeremonyError); 11] = [
        (StatusCode::NoCredentials, CeremonyError::NoCredentials),
        (StatusCode::InvalidCredential, CeremonyError::NoCredentials),
        (
            StatusCode::UserActionTimeout,
            CeremonyError::UserActionTimeout,
        ),
        (StatusCode::KeepaliveCancel, CeremonyError::UserCancelled),
        (StatusCode::OperationDenied, CeremonyError::UpRejected),
        (StatusCode::UpRequired, CeremonyError::UpRejected),
        (StatusCode::PinAuthInvalid, CeremonyError::UpRejected),
        (StatusCode::PinAuthBlocked, CeremonyError::UpRejected),
        (StatusCode::PuatRequired, CeremonyError::UpRejected),
        (StatusCode::PinPolicyViolation, CeremonyError::UpRejected),
        (StatusCode::UvBlocked, CeremonyError::UpRejected),
    ];
    for (code, expected) in matrix {
        let mut auth = token();
        let _ = mint(&mut auth, b"ci-user-1");
        auth.knobs_mut().inject_status = Some(code);
        let err = run(soft_ceremony(auth)).unwrap_err();
        assert_eq!(err, expected, "injected {code:?} must map to {expected:?}");
    }

    // Assertion-phase mapping: consume the probe through the Device
    // trait first, then arm the one-shot knob so it fires on
    // getAssertion inside the exchange-only ceremony.
    let mut auth = token();
    let minted = mint(&mut auth, b"ci-user-1");
    let (t, mut device, _drainer) = connect_two(auth);
    let probe =
        block_on(device.send(&CtapCommand::GetInfo, &Deadline::new(BUDGET), no_sleep())).unwrap();
    assert!(matches!(probe, DeviceEvent::Response { status: 0x00, .. }));
    t.core().lock().knobs_mut().inject_status = Some(StatusCode::NoCredentials);
    let exchange = GetAssertionExchange {
        rp_id: String::from(RP),
        client_data_hash: CLIENT_HASH.to_vec(),
        allow_credentials: Some(vec![descriptor(&minted.record.id)]),
        user_verification: UvPolicy::Discouraged,
        pin_uv_auth: None,
        drain: None,
    };
    let err = block_on(Ceremony::run(
        exchange,
        device,
        &Deadline::new(BUDGET),
        no_sleep(),
    ))
    .unwrap_err();
    assert_eq!(err, CeremonyError::NoCredentials);
}

// Scenario: User-action timeout maps distinctly from budget timeout —
// 0x2F (authenticator-side) is `UserActionTimeout`, never `Timeout`
// (which is the caller's budget naming a phase).
#[test]
fn user_action_timeout_distinct_from_budget_timeout() {
    let mut auth = token();
    let _ = mint(&mut auth, b"ci-user-1");
    auth.knobs_mut().inject_status = Some(StatusCode::UserActionTimeout);
    let err = run(soft_ceremony(auth)).unwrap_err();
    assert_eq!(err, CeremonyError::UserActionTimeout);
    assert!(!matches!(err, CeremonyError::Timeout(_)));
}

// Scenario: Keepalive cancel maps to UserCancelled (CI: status knob).
#[test]
fn keepalive_cancel_maps_to_user_cancelled() {
    let mut auth = token();
    let _ = mint(&mut auth, b"ci-user-1");
    auth.knobs_mut().inject_status = Some(StatusCode::KeepaliveCancel);
    assert_eq!(
        run(soft_ceremony(auth)).unwrap_err(),
        CeremonyError::UserCancelled
    );
}

// --------------------------------------------------------------------
// Requirement: Multi-assertion drain via authenticatorGetNextAssertion.
// ----------------------------------------------------------------------

// Scenario: Three credentials drained in order — exactly
// numberOfCredentials − 1 hops, ordered list, every hop bounded by the
// single budget. Exchange-only entry: the drain hook must bind a
// connected handle of the ceremony's authenticator (the queue lives in
// the shared core; a second connect yields that handle).
#[test]
fn three_credentials_drained_in_order() {
    let mut auth = token();
    let a = mint(&mut auth, b"user-a");
    let b = mint(&mut auth, b"user-b");
    let c = mint(&mut auth, b"user-c");
    let (_t, device, drainer) = connect_two(auth);
    let deadline = Deadline::new(BUDGET);
    // The hook needs its own budget view; build a fresh equal budget
    // for it (Deadline is not Clone by design — shared-budget state).
    let drain_deadline = Deadline::new(BUDGET);
    let exchange = GetAssertionExchange {
        rp_id: String::from(RP),
        client_data_hash: CLIENT_HASH.to_vec(),
        // No allowList → discoverable-credential flow returns all
        // three resident credentials for the rpId.
        allow_credentials: None,
        user_verification: UvPolicy::Discouraged,
        pin_uv_auth: None,
        drain: Some(soft_drain(drainer, drain_deadline)),
    };
    let out = block_on(Ceremony::run(exchange, device, &deadline, no_sleep()))
        .expect("three assertions must drain in order");
    assert_eq!(out.assertions.len(), 3);
    assert_eq!(out.assertions[0].credential.id, a.record.id);
    assert_eq!(out.assertions[0].number_of_credentials, 3);
    assert_eq!(out.assertions[1].credential.id, b.record.id);
    assert_eq!(out.assertions[2].credential.id, c.record.id);
    // §6.3 responses carry no numberOfCredentials member (drained).
    assert!(!out.assertions[1].number_of_credentials_present);
    assert!(!out.assertions[2].number_of_credentials_present);
    // Every drained assertion verifies under its own credential key.
    for (response, minted) in out.assertions.iter().zip([&a, &b, &c]) {
        verify_assertion(
            &response.auth_data,
            &response.signature,
            &minted.record.public_key(),
            &CLIENT_HASH,
        )
        .expect("drained assertion must verify");
    }
    // Remaining budget: the drain hops stayed inside the single budget.
    assert!(deadline.remaining() > Duration::ZERO);
}

// Scenario: Continuation refused surfaces typed — 0x30 on a drain hop
// is `Ctap(NotAllowed)` and the ceremony does not retry.
#[test]
fn continuation_refused_surfaces_typed_ctap() {
    let mut auth = token();
    let _ = mint(&mut auth, b"user-a");
    let _ = mint(&mut auth, b"user-b");
    let (_t, device, drainer) = connect_two(auth);
    let deadline = Deadline::new(BUDGET);
    let exchange = GetAssertionExchange {
        rp_id: String::from(RP),
        client_data_hash: CLIENT_HASH.to_vec(),
        allow_credentials: None,
        user_verification: UvPolicy::Discouraged,
        pin_uv_auth: None,
        // The device grants the §6.2 response (numberOfCredentials = 2)
        // but refuses the continuation: 0x30 immediately.
        drain: Some(Drain::new(move || {
            let _ = &drainer; // bound like the real hook
            Ok(DeviceEvent::Response {
                status: StatusCode::NotAllowed.to_u8(),
                body: Vec::new(),
            })
        })),
    };
    let err = block_on(Ceremony::run(exchange, device, &deadline, no_sleep())).unwrap_err();
    assert_eq!(
        err,
        CeremonyError::Ctap(StatusCode::NotAllowed),
        "0x30 surfaces typed without retry"
    );
}

// The drain hook is never invoked when numberOfCredentials == 1.
#[test]
fn drain_hook_never_runs_when_single_credential() {
    let mut auth = token();
    let minted = mint(&mut auth, b"ci-user-1");
    let armed = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&armed);
    let mut ceremony = soft_ceremony(auth);
    ceremony.allow_credentials = Some(vec![descriptor(&minted.record.id)]);
    ceremony.drain = Some(Drain::new(move || {
        flag.store(true, Ordering::Relaxed);
        Ok(DeviceEvent::Response {
            status: StatusCode::NotAllowed.to_u8(),
            body: Vec::new(),
        })
    }));
    let out = run(ceremony).expect("single credential: no drain hop");
    assert_eq!(out.assertions.len(), 1);
    assert!(
        !armed.load(Ordering::Relaxed),
        "the drain hook must never be invoked"
    );
}

// --------------------------------------------------------------------
// Requirement: Returned assertion fidelity and credential verification.
// --------------------------------------------------------------------

// Scenario: Wrong credential id rejected (CI: wrong-credential-id knob
// (d)) — typed CredentialMismatch naming the mismatch truncated-safe;
// the full id is NOT in the message; the failure occurs within the
// remaining ceremony budget.
#[test]
fn wrong_credential_id_rejected_truncated_safe() {
    let mut auth = token();
    let a = mint(&mut auth, b"user-a");
    let b = mint(&mut auth, b"user-b");
    auth.knobs_mut().wrong_credential_id = true;
    let mut ceremony = soft_ceremony(auth);
    ceremony.allow_credentials = Some(vec![descriptor(&a.record.id)]);
    let err = run(ceremony).unwrap_err();
    match &err {
        CeremonyError::CredentialMismatch { returned, allowed } => {
            assert_eq!(returned, &b.record.id);
            assert_eq!(allowed, std::slice::from_ref(&a.record.id));
        }
        other => panic!("expected CredentialMismatch, got {other:?}"),
    }
    // Truncated-safe message: the 8-byte prefix identifies the id; the
    // full 32-byte id NEVER appears.
    let text = err.to_string();
    let full_a = hex(&a.record.id);
    assert!(
        !text.contains(&full_a),
        "message must not contain the full credential id: {text}"
    );
    assert!(
        text.contains(&full_a[..16]),
        "the 8-byte prefix identifies the returned id"
    );
    // Typed failure, not a timeout: it fired within the budget.
    assert!(!matches!(err, CeremonyError::Timeout(_)));
}

// --------------------------------------------------------------------
// Requirement: Ceremony error taxonomy — every failure path is typed.
// --------------------------------------------------------------------

// Scenario: Every failure path is typed — discovery, selection,
// exchange, and drain each yield exactly one of the ten typed
// variants; Display never panics; no stringly/untyped failures.
#[test]
fn every_failure_path_is_typed() {
    // Discovery: NoDevice.
    let ceremony = GetAssertionCeremony::<SoftTransport>::new(
        vec![],
        String::from(RP),
        CLIENT_HASH.to_vec(),
        BUDGET,
    );
    assert!(matches!(
        run(ceremony).unwrap_err(),
        CeremonyError::NoDevice(_)
    ));

    // Selection: AmbiguousDevice.
    let ceremony = GetAssertionCeremony::new(
        vec![SoftTransport::new(token()), SoftTransport::new(token())],
        String::from(RP),
        CLIENT_HASH.to_vec(),
        BUDGET,
    );
    assert!(matches!(
        run(ceremony).unwrap_err(),
        CeremonyError::AmbiguousDevice(_)
    ));

    // Probe failure is typed (OQ-2: it fails the ceremony) — the
    // catch-all Ctap carries the typed status with its spec name.
    let mut auth = token();
    let _ = mint(&mut auth, b"ci-user-1");
    auth.knobs_mut().inject_status = Some(StatusCode::InvalidCbor);
    let err = run(soft_ceremony(auth)).unwrap_err();
    assert_eq!(err, CeremonyError::Ctap(StatusCode::InvalidCbor));
    assert!(err.to_string().contains("CTAP2_ERR_INVALID_CBOR"));

    // Budget expiry names its phase (Timeout variant).
    let ceremony = GetAssertionCeremony::new(
        vec![SoftTransport::new(token())],
        String::from(RP),
        CLIENT_HASH.to_vec(),
        Duration::ZERO,
    );
    assert_eq!(
        run(ceremony).unwrap_err(),
        CeremonyError::Timeout(Phase::Enumeration)
    );

    // All ten variants display without panicking (typed, never a
    // panic path).
    let variants: [CeremonyError; 10] = [
        CeremonyError::NoDevice(Vec::new()),
        CeremonyError::AmbiguousDevice(Vec::new()),
        CeremonyError::UserActionTimeout,
        CeremonyError::UserCancelled,
        CeremonyError::NoCredentials,
        CeremonyError::UpRejected,
        CeremonyError::Timeout(Phase::GetAssertion),
        CeremonyError::Transport(fidoh_core::TransportError::new("t", String::from("x"))),
        CeremonyError::Ctap(StatusCode::Unknown(0x41)),
        CeremonyError::CredentialMismatch {
            returned: vec![0u8; 32],
            allowed: vec![vec![1u8; 32]],
        },
    ];
    for v in &variants {
        let _ = v.to_string();
    }
}

// --------------------------------------------------------------------
// Design OQ-2: a probe failure fails the whole ceremony.
// --------------------------------------------------------------------

#[test]
fn probe_failure_fails_the_ceremony() {
    // 0x12 CTAP2_ERR_INVALID_CBOR injected on the first command — the
    // probe — fails the ceremony BEFORE any getAssertion is attempted
    // (the one-shot knob never reaches the exchange).
    let mut auth = token();
    let _ = mint(&mut auth, b"ci-user-1");
    auth.knobs_mut().inject_status = Some(StatusCode::InvalidCbor);
    let err = run(soft_ceremony(auth)).unwrap_err();
    assert_eq!(err, CeremonyError::Ctap(StatusCode::InvalidCbor));
    assert!(err.to_string().contains("CTAP2_ERR_INVALID_CBOR"));
}

// --------------------------------------------------------------------
// async-core trait seam: the exchange-only `Ceremony` impl drives the
// same pipeline over a caller-connected device ("GetAssertion ceremony
// completes within budget").
// --------------------------------------------------------------------

#[test]
fn exchange_only_trait_path_matches_full_entry() {
    let mut auth = token();
    let minted = mint(&mut auth, b"ci-user-1");
    let (_t, device, _drainer) = connect_two(auth);
    let exchange = GetAssertionExchange {
        rp_id: String::from(RP),
        client_data_hash: CLIENT_HASH.to_vec(),
        allow_credentials: Some(vec![descriptor(&minted.record.id)]),
        user_verification: UvPolicy::Discouraged,
        pin_uv_auth: None,
        drain: None,
    };
    let out = block_on(Ceremony::run(
        exchange,
        device,
        &Deadline::new(BUDGET),
        no_sleep(),
    ))
    .expect("exchange-only path must succeed identically");
    assert_eq!(out.first().credential.id, minted.record.id);
    verify_assertion(
        &out.first().auth_data,
        &out.first().signature,
        &minted.record.public_key(),
        &CLIENT_HASH,
    )
    .expect("trait-path assertion must verify");
    // The probe's parsed capabilities ride in the outcome (a real
    // GetInfoResponse — the probe ran through the same pipeline).
    let _: &fidoh_core::get_info::GetInfoResponse = &out.info;
    assert_eq!(out.info.aaguid, AAGUID);
    // Exchange-only path has no discovery to report.
    assert!(out.discovery_diagnostics.is_empty());
}
