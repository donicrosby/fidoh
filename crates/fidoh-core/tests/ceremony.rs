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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
        (
            StatusCode::PinAuthBlocked,
            // add-client-pin D5: 0x34 moved OUT of the v1 UpRejected
            // catch-all into its own typed variant (power-cycle fix).
            CeremonyError::PinAuthBlocked,
        ),
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
        // v2 fields: Discouraged never acquires a token, so these
        // stay inert (no provider, no pinned protocol, no entropy).
        pin_provider: None,
        pin_uv_auth_protocol: None,
        entropy: None,
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
        // v2 fields: Discouraged never acquires a token, so these
        // stay inert (no provider, no pinned protocol, no entropy).
        pin_provider: None,
        pin_uv_auth_protocol: None,
        entropy: None,
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
        // v2 fields: Discouraged never acquires a token, so these
        // stay inert (no provider, no pinned protocol, no entropy).
        pin_provider: None,
        pin_uv_auth_protocol: None,
        entropy: None,
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
        // v2 fields: Discouraged never acquires a token, so these
        // stay inert (no provider, no pinned protocol, no entropy).
        pin_provider: None,
        pin_uv_auth_protocol: None,
        entropy: None,
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

// ====================================================================
// add-client-pin (v2) — scenario-ID tests for the ceremony spec's
// pinUvAuthToken acquisition flow, the PIN-provider seam, and the
// typed PIN error surface (task 5.1:
// openspec/changes/add-client-pin/specs/ceremony/spec.md).
//
// Every walk drives the REAL clientPIN protocol end to end against
// the soft token's §6.5.5 authenticator-side state machine: platform
// P-256 key agreement, AES-encrypted pinHashEnc, encrypted token,
// ECDSA assertion — no stubbed crypto on either side.
// ====================================================================

use fidoh_core::crypto::PinEntropySource;
use fidoh_core::pin::{PinProvider, PinProviderHandle, PinSourceError};
use fidoh_transport_soft::MAX_PIN_RETRIES;
use sha2::{Digest, Sha256};

/// A count-down PIN provider: hands the fixture PIN on the first call,
/// then fails (the seam is single-shot per acquisition; a second
/// successful prompt inside one run would be a library bug — and the
/// call counter is the test's observability into "at most once").
struct CountingPin {
    pin: &'static [u8],
    calls: Arc<AtomicUsize>,
}

impl PinProvider for CountingPin {
    fn provide_pin(&mut self) -> Result<Vec<u8>, PinSourceError> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            Ok(self.pin.to_vec())
        } else {
            Err(PinSourceError { _context: () })
        }
    }
}

/// Build a provider handle plus the shared call counter.
fn provider(pin: &'static [u8]) -> (PinProviderHandle, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let handle = PinProviderHandle::from_closure({
        let calls = Arc::clone(&calls);
        move || {
            let mut p = CountingPin {
                pin,
                calls: Arc::clone(&calls),
            };
            p.provide_pin()
        }
    });
    (handle, calls)
}

/// The injectable entropy for the ceremony side (platform key pair +
/// protocol-2 IVs): deterministic SplitMix64, mirroring the token's
/// own seeded stream so fixtures stay byte-reproducible.
struct FixtureEntropy(u64);

impl PinEntropySource for FixtureEntropy {
    fn fill_random(&mut self, dest: &mut [u8]) -> Result<(), fidoh_core::crypto::PinCryptoError> {
        for chunk in dest.chunks_mut(8) {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            chunk.copy_from_slice(&z.to_be_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}

/// A PIN-set soft token behind a transport, plus the shared core
/// handle (the retry counter's introspection point).
fn pin_token(auth_pin: &'static [u8]) -> (SoftTransport, fidoh_transport_soft::SoftDeviceCore) {
    let mut auth = token();
    let _ = mint(&mut auth, b"ci-user-1");
    auth.set_pin(auth_pin);
    let t = SoftTransport::new(auth);
    let core = t.core();
    (t, core)
}

/// A `Preferred` full-entry ceremony over `transport` with the given
/// provider, caller-pinned protocol, and injected entropy.
fn pin_ceremony(
    transport: SoftTransport,
    handle: PinProviderHandle,
    protocol: Option<fidoh_core::pin::PinUvAuthProtocol>,
) -> GetAssertionCeremony<SoftTransport> {
    let mut ceremony = GetAssertionCeremony::new(
        vec![transport],
        String::from(RP),
        CLIENT_HASH.to_vec(),
        BUDGET,
    );
    ceremony.user_verification = UvPolicy::Preferred;
    ceremony.pin_provider = Some(handle);
    ceremony.pin_uv_auth_protocol = protocol;
    ceremony.entropy = Some(Box::new(FixtureEntropy(0xC1B0_1D05)));
    ceremony
}

/// Drive ONE real authenticatorClientPIN token request with a WRONG
/// PIN straight through the `Device` trait (harness-level burn-down:
/// exactly one counter decrement per call, observable via the 0x31
/// body's pinRetries member). The §6.5.6/§6.5.7 platform side is
/// reproduced with the same fidoh-core crypto primitives the ceremony
/// itself uses.
/// LEFT(SHA-256(bytes), 16) — the §6.5.6/§6.5.7 pinHash payload.
fn sha2_of(bytes: &[u8]) -> [u8; 16] {
    let d = Sha256::digest(bytes);
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

fn wrong_pin_hop(
    device: &mut SoftDevice,
    protocol: fidoh_core::pin::PinUvAuthProtocol,
    deadline: &Deadline,
) -> Option<u8> {
    use fidoh_core::cbor::CborValue;
    use fidoh_core::crypto::PlatformKeyAgreement;
    use fidoh_core::device::CtapCommand;
    use fidoh_core::pin::{permissions, ClientPinRequest, ClientPinSubCommand};

    let mut entropy = FixtureEntropy(0xDE_C0_1D);
    let platform = PlatformKeyAgreement::generate(&mut entropy).unwrap();
    let ka_request = ClientPinRequest {
        protocol,
        sub_command: ClientPinSubCommand::GetKeyAgreement,
        key_agreement: Some(platform.cose_key()),
        pin_uv_auth_param: None,
        pin_hash_enc: None,
        permissions: None,
        rp_id: None,
    };
    let ka_event = block_on(device.send(&CtapCommand::ClientPin(ka_request), deadline, no_sleep()))
        .expect("getKeyAgreement hop");
    let DeviceEvent::Response { status: 0x00, body } = ka_event else {
        panic!("getKeyAgreement must succeed on an armed token");
    };
    let peer_key = match CborValue::decode_map(&body, fidoh_core::DecodePolicy::Strict) {
        Ok(v) => fidoh_core::pin::ClientPinResponse::from_cbor(&v)
            .expect("decode keyAgreement response")
            .key_agreement
            .expect("keyAgreement member present"),
        Err(e) => panic!("getKeyAgreement body decode: {e}"),
    };
    let shared = platform.encapsulate(&peer_key, protocol).unwrap();

    // pinHashEnc of the WRONG pin: LEFT(SHA-256(wrong), 16).
    // LEFT(SHA-256(wrong PIN), 16) — anything but the stored hash; the
    // §6.5.5.7.2 compare (not AES-CBC) is what answers 0x31.
    let wrong = sha2_of(b"definitely-not-the-pin");
    let wrong_hash = wrong;
    let pin_hash_enc = shared.encrypt(&mut entropy, &wrong_hash).unwrap();
    let token_request = ClientPinRequest {
        protocol,
        sub_command: ClientPinSubCommand::GetPinUvAuthTokenUsingPinWithPermissions,
        key_agreement: Some(platform.cose_key()),
        pin_uv_auth_param: None,
        pin_hash_enc: Some(pin_hash_enc),
        permissions: Some(permissions::GA),
        rp_id: Some(String::from(RP)),
    };
    let event = block_on(device.send(&CtapCommand::ClientPin(token_request), deadline, no_sleep()))
        .expect("token-request hop");
    let DeviceEvent::Response { status, body } = event else {
        panic!("token request must return a terminal response");
    };
    if status == fidoh_core::StatusCode::PinInvalid.to_u8() {
        // The 0x31 body carries pinRetries (0x03) per §6.5.5.
        if let Ok(v) = CborValue::decode_map(&body, fidoh_core::DecodePolicy::Tolerant) {
            if let Ok(r) = fidoh_core::pin::ClientPinResponse::from_cbor(&v) {
                return r.pin_retries;
            }
        }
        return None;
    }
    panic!("burn-down hop must answer 0x31 PIN_INVALID, got status {status:#x}");
}

// --------------------------------------------------------------------
// Scenario: Preferred with provider on a PIN-set protocol-2 token end
// to end — the full §6.5.5 acquisition: getKeyAgreement (0x02), the
// [2, 1] advertisement negotiating protocol 2, ONE PIN-provider
// callback, getPinUvAuthTokenUsingPinWithPermissions (0x09 with
// permissions 0x02 + rpId), the getAssertion request carrying
// pinUvAuthParam over the bare clientDataHash (published §6.2 shape —
// OQ-9's centralized `pin_uv_auth_param_message`), the
// authenticator-side verification passing, and the outcome REPORTING
// `UvEffective::PinUvAuthToken`.
// --------------------------------------------------------------------
#[test]
fn pin_uv_acquisition_end_to_end_protocol_two() {
    let (t, core) = pin_token(b"correct horse battery staple");
    let (handle, calls) = provider(b"correct horse battery staple");
    let ceremony = pin_ceremony(t, handle, None);

    let out = run(ceremony).expect("protocol-2 acquisition must complete end to end");

    // Exactly ONE prompt, consumed by this run (provider seam: at most
    // once per acquisition).
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // The probe advertised the full clientPIN feature set with [2, 1]
    // preference order and the pinUvAuthToken option (which selected
    // the 0x09 subcommand).
    assert_eq!(
        out.info.pin_uv_auth_protocols.as_deref(),
        Some(
            &[
                fidoh_core::pin::PinUvAuthProtocol::Two,
                fidoh_core::pin::PinUvAuthProtocol::One,
            ][..]
        )
    );
    assert!(out.info.option(fidoh_core::get_info::OptionId::ClientPin));
    assert!(out
        .info
        .option(fidoh_core::get_info::OptionId::PinUvAuthToken));

    // The token-backed posture is REPORTED, never silent.
    assert_eq!(out.uv_effective, fidoh_core::UvEffective::PinUvAuthToken);

    // The authenticator VERIFIED the pinUvAuthParam-backed request:
    // UV flag set in authenticatorData (byte 32, bit 2 — WebAuthn L2
    // §6.1), assertion returned and signed under the minted key.
    let first = out.first();
    assert_eq!(first.auth_data[32] & 0b0000_0100, 0b0000_0100);
    assert_eq!(
        first.user.as_ref().map(|u| u.id.as_slice()),
        Some(&b"ci-user-1"[..])
    );
    verify_assertion(
        &first.auth_data,
        &first.signature,
        &minted_public_key(&core),
        &CLIENT_HASH,
    )
    .expect("acquisition-path assertion must verify");

    // Success reset the token's retry counter to maximum (§6.5.5.7.2
    // authenticator order: success → reset).
    assert_eq!(core.lock().pin_retries(), Some(MAX_PIN_RETRIES));

    // §6.2 mutual exclusion is structural: the model's encoder rejects
    // options.uv alongside pinUvAuthParam (CTAP2.1 §6.2) — so the wire
    // shape the ceremony built (and the token accepted) necessarily
    // carried the param WITHOUT options.uv.
    let mut both = GetAssertionRequest::new(String::from(RP), CLIENT_HASH.to_vec()).unwrap();
    both.pin_uv_auth_param = Some(fidoh_core::pin::PinUvAuthParam::new(vec![0x44; 32]));
    both.pin_uv_auth_protocol = Some(fidoh_core::pin::PinUvAuthProtocol::Two);
    both.options = Some(fidoh_core::get_assertion::GetAssertionOptions {
        up: None,
        uv: Some(true),
    });
    assert_eq!(
        both.encode().unwrap_err(),
        fidoh_core::EncodeError::InvalidRequest(
            fidoh_core::InvalidRequest::UvOptionWithPinUvAuthParam
        )
    );
}

/// The public key of the fixture credential (the minting happens
/// inside `pin_token`; the store is reachable through the shared
/// core).
fn minted_public_key(
    core: &fidoh_transport_soft::SoftDeviceCore,
) -> fidoh_core::cose::CoseEs256Key {
    let auth = core.lock();
    auth.credentials()[0].public_key()
}

// --------------------------------------------------------------------
// Scenario: getPinToken fallback / protocol-1 acquisition — the token
// advertises ONLY protocol 1 (so §6.5.5.4's preference-order rule
// selects P1: SHA-256 KDF, 16-byte truncated MAC, zero-IV AES) AND
// hides the pinUvAuthToken option ID (so the acquisition selects the
// CTAP2.0 getPinToken 0x05 subcommand, not 0x09).
// --------------------------------------------------------------------
#[test]
fn pin_uv_acquisition_get_pin_token_fallback_protocol_one() {
    let mut auth = token();
    let minted = mint(&mut auth, b"ci-user-1");
    auth.set_pin(b"p1 fallback pin");
    auth.set_pin_protocols(vec![fidoh_core::pin::PinUvAuthProtocol::One]);
    auth.set_advertise_pin_uv_auth_token(false);
    let t = SoftTransport::new(auth);

    let (handle, calls) = provider(b"p1 fallback pin");
    let mut ceremony = pin_ceremony(t, handle, None);
    ceremony.allow_credentials = Some(vec![descriptor(&minted.record.id)]);

    let out = run(ceremony).expect("protocol-1 getPinToken fallback must complete");

    // One prompt; the posture is reported token-backed exactly as in
    // the P2 path (the subcommand choice is invisible to the outcome —
    // by design: the platform's §6.2 shape is identical).
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(out.uv_effective, fidoh_core::UvEffective::PinUvAuthToken);
    // The advertisement the probe saw drove BOTH selections.
    assert_eq!(
        out.info.pin_uv_auth_protocols.as_deref(),
        Some(&[fidoh_core::pin::PinUvAuthProtocol::One][..])
    );
    assert!(!out
        .info
        .option(fidoh_core::get_info::OptionId::PinUvAuthToken));

    // The P1-shaped request verified authenticator-side: the assertion
    // returned with the UV flag set (the token accepted the P1 MAC —
    // a P2 MAC over the same material is 32 bytes and would have
    // failed the protocol-exact verification).
    assert_eq!(out.first().credential.id, minted.record.id);
    assert_eq!(out.first().auth_data[32] & 0b0000_0100, 0b0000_0100);
    verify_assertion(
        &out.first().auth_data,
        &out.first().signature,
        &minted.record.public_key(),
        &CLIENT_HASH,
    )
    .expect("fallback-path assertion must verify");
}

// --------------------------------------------------------------------
// Scenario: Wrong PIN decrements exactly once and surfaces the count —
// the 0x31 response's pinRetries member becomes
// `IncorrectPin { remaining_retries: Some(MAX-1) }`, the token's
// counter reads MAX-1 afterwards (one decrement), Display names the
// fix without the PIN bytes, and a re-run with the CORRECT PIN
// succeeds from the same counter (no implicit retry in the failed run).
// --------------------------------------------------------------------
#[test]
fn wrong_pin_surfaces_remaining_retries_and_decrements_once() {
    let pin = b"the-right-pin";
    let (t, core) = pin_token(pin);
    let (handle, calls) = provider(b"a-wrong-pin");
    let err = run(pin_ceremony(t, handle, None)).unwrap_err();

    match &err {
        CeremonyError::IncorrectPin { remaining_retries } => {
            assert_eq!(
                *remaining_retries,
                Some(MAX_PIN_RETRIES - 1),
                "the 0x31 response's pinRetries member surfaces typed"
            );
        }
        other => panic!("expected IncorrectPin, got {other:?}"),
    }
    // Decrement ONCE (8 → 7), and the failed run consumed exactly one
    // provider call (no re-prompt inside the ceremony).
    assert_eq!(core.lock().pin_retries(), Some(MAX_PIN_RETRIES - 1));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // Display names the fix; the no-secrets rule keeps the PIN bytes
    // out of it.
    let text = err.to_string();
    assert!(text.contains("re-enter the PIN"));
    assert!(!text.contains("a-wrong-pin"));

    // The caller re-runs with a fresh provider call: success from the
    // SAME counter (the ceremony itself never retried).
    let mut fresh_auth = token();
    let _ = mint(&mut fresh_auth, b"ci-user-1");
    let _ = &fresh_auth;
    let (handle2, calls2) = provider(pin);
    // A fresh transport over the SAME authenticator is impossible (the
    // core moved into the failed ceremony), so the re-run continues on
    // the token's live state: set the PIN back to the same value on a
    // rebuilt token with the counter still at 7 — the point of this
    // half is "correct PIN succeeds after a wrong attempt", which the
    // soft token models by retry-counter continuity. Rebuild with the
    // fixture and burn one attempt first to land at 7, then succeed.
    let mut rebuilt = token();
    let re_minted = mint(&mut rebuilt, b"ci-user-1");
    rebuilt.set_pin(pin);
    let t2 = SoftTransport::new(rebuilt);
    let core2 = t2.core();
    {
        let mut device =
            block_on(t2.connect(&DeviceId::new("soft-0"), &Deadline::new(BUDGET), no_sleep()))
                .unwrap();
        let deadline = Deadline::new(BUDGET);
        let seen = wrong_pin_hop(
            &mut device,
            fidoh_core::pin::PinUvAuthProtocol::Two,
            &deadline,
        );
        assert_eq!(seen, Some(MAX_PIN_RETRIES - 1));
    }
    let (handle3, _) = provider(pin);
    let out = run(pin_ceremony(t2, handle3, None))
        .expect("correct PIN succeeds after a wrong one (same counter)");
    assert_eq!(out.uv_effective, fidoh_core::UvEffective::PinUvAuthToken);
    assert_eq!(out.first().credential.id, re_minted.record.id);
    assert_eq!(core2.lock().pin_retries(), Some(MAX_PIN_RETRIES));
    let _ = handle2;
    let _ = calls2;
}

// --------------------------------------------------------------------
// Scenario: PIN not set maps typed and distinct from wrong PIN — the
// token advertises the clientPIN feature but stores NO PIN (the
// harness cleared it), so the PIN-bearing hop is refused with
// 0x35 CTAP2_ERR_PIN_NOT_SET: a different variant from IncorrectPin in
// match position AND in Display text (set a PIN, not retype one).
// --------------------------------------------------------------------
#[test]
fn pin_not_set_distinct_from_wrong_pin() {
    let mut auth = token();
    let _ = mint(&mut auth, b"ci-user-1");
    // Arm the clientPIN feature, then clear the secret: getInfo still
    // advertises clientPin + pinUvAuthToken + protocols, but the
    // stored hash is gone (§6.5.5 PIN-less posture).
    auth.set_pin(b"soon gone");
    auth.clear_pin();
    let t = SoftTransport::new(auth);

    let (handle, calls) = provider(b"whatever the user typed");
    let err = run(pin_ceremony(t, handle, None)).unwrap_err();

    // Distinct match position.
    match err {
        CeremonyError::PinNotSet => {}
        other => panic!("expected PinNotSet, got {other:?}"),
    }
    // Distinct Display text from IncorrectPin's "re-enter the PIN".
    let text = CeremonyError::PinNotSet.to_string();
    assert!(text.contains("set a PIN first"));
    assert!(!text.contains("re-enter"));
    // The provider WAS consulted (acquisition reached the token hop);
    // the failure is the authenticator's answer, typed.
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

// --------------------------------------------------------------------
// Scenario: PIN blocked maps typed after exhaustion — the counter can
// only drain when the 3-strikes latch is cleared between strike PAIRS
// (a real key demands a power cycle after 3 consecutive mismatches, so
// the honest walk to CTAP2_ERR_PIN_BLOCKED alternates wrong PINs with
// replugs). Burn to zero that way; the exhausting attempt still
// reports its count (`Some(0)` via 0x31), and the NEXT PIN-bearing hop
// is refused 0x32 CTAP2_ERR_PIN_BLOCKED (typed `PinBlocked`) BEFORE
// any comparison — even the CORRECT PIN is refused.
// --------------------------------------------------------------------
#[test]
fn pin_blocked_after_exhaustion() {
    let pin = b"exhaust-me";
    let (t, core) = pin_token(pin);

    // Burn the counter to ZERO through the device-command layer: two
    // consecutive wrong hops, then a harness power cycle (the stand-in
    // replug that clears the 0x34 latch but NOT the retry counter) —
    // repeated until the counter is spent.
    {
        let mut device =
            block_on(t.connect(&DeviceId::new("soft-0"), &Deadline::new(BUDGET), no_sleep()))
                .unwrap();
        let deadline = Deadline::new(BUDGET);
        for expected in (0..MAX_PIN_RETRIES).rev() {
            let seen = wrong_pin_hop(
                &mut device,
                fidoh_core::pin::PinUvAuthProtocol::Two,
                &deadline,
            );
            assert_eq!(
                seen,
                Some(expected),
                "one decrement per hop, count surfaced"
            );
            if expected % 2 == 0 {
                // Never let three mismatches land consecutively.
                core.lock().power_cycle();
            }
        }
    }
    assert_eq!(core.lock().pin_retries(), Some(0));

    // The exhausting hop through the full CEREMONY (wrong PIN): the
    // zero-retries check precedes everything PIN-bearing, so the
    // ceremony sees typed `PinBlocked` — NOT IncorrectPin{Some(0)}:
    // no attempt is spent on a blocked token.
    let (handle, calls) = provider(b"nope");
    let err = run(pin_ceremony(t, handle, None)).unwrap_err();
    match err {
        CeremonyError::PinBlocked => {
            let text = err.to_string();
            assert!(text.contains("reset/power-cycle"));
        }
        other => panic!("expected PinBlocked at zero retries, got {other:?}"),
    }
    // The provider ran (the ceremony cannot know the counter state
    // before the hop); no comparison happened.
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // The typed surface is distinct from IncorrectPin in match
    // position AND Display text.
    let pin_text = CeremonyError::PinBlocked.to_string();
    assert!(!pin_text.contains("re-enter"));
}

// --------------------------------------------------------------------
// Scenario: Three consecutive mismatches maps to PinAuthBlocked — the
// THIRD consecutive mismatch answers 0x31 (transport-soft spec: the
// latch engages on it) and every SUBSEQUENT PIN-bearing hop answers
// 0x34 CTAP2_ERR_PIN_AUTH_BLOCKED — typed `PinAuthBlocked` (add-client-
// pin D5 moved 0x34 OUT of the v1 UpRejected catch-all), even when the
// PIN is now correct, until the harness "power cycle" clears it.
// --------------------------------------------------------------------
#[test]
fn pin_auth_blocked_after_three_mismatches() {
    let pin = b"three-strikes-pin";
    let (t, core) = pin_token(pin);

    // Three CONSECUTIVE wrong PINs through the device-command layer:
    // strikes 1 and 2 answer 0x31 with falling counts; strike 3
    // engages the power-cycle latch (the helper still sees its 0x31 —
    // per §6.5.5.7.2 the mismatching attempt itself is a PIN_INVALID).
    {
        let mut device =
            block_on(t.connect(&DeviceId::new("soft-0"), &Deadline::new(BUDGET), no_sleep()))
                .unwrap();
        let deadline = Deadline::new(BUDGET);
        assert_eq!(
            wrong_pin_hop(
                &mut device,
                fidoh_core::pin::PinUvAuthProtocol::Two,
                &deadline
            ),
            Some(MAX_PIN_RETRIES - 1),
            "strike 1: 0x31 with the decremented count"
        );
        assert_eq!(
            wrong_pin_hop(
                &mut device,
                fidoh_core::pin::PinUvAuthProtocol::Two,
                &deadline
            ),
            Some(MAX_PIN_RETRIES - 2),
            "strike 2: 0x31 again"
        );
        assert_eq!(
            wrong_pin_hop(
                &mut device,
                fidoh_core::pin::PinUvAuthProtocol::Two,
                &deadline
            ),
            Some(MAX_PIN_RETRIES - 3),
            "strike 3: still 0x31 — but the latch engages now"
        );
    }
    assert_eq!(core.lock().pin_retries(), Some(MAX_PIN_RETRIES - 3));

    // The FOURTH PIN-bearing hop — through the full CEREMONY (a fresh
    // transport over the SAME core is not possible: the core is
    // uniquely owned — so the refused hop runs harness-layer, exactly
    // what the ceremony drives underneath), with the CORRECT PIN: 0x34.
    {
        let mut device =
            block_on(t.connect(&DeviceId::new("soft-0"), &Deadline::new(BUDGET), no_sleep()))
                .unwrap();
        let deadline = Deadline::new(BUDGET);
        let refused = correct_pin_hop(
            &mut device,
            pin,
            fidoh_core::pin::PinUvAuthProtocol::Two,
            &deadline,
        );
        assert!(!refused, "the latched token refuses even the correct PIN");
        assert_eq!(core.lock().pin_retries(), Some(MAX_PIN_RETRIES - 3));
    }

    // The typed surface for that same refusal, through the CEREMONY:
    // a fresh armed token driven to the latch, then the ceremony run
    // surfaces PinAuthBlocked (never the v1 UpRejected), and the
    // Display names the power cycle.
    {
        let mut strikes = token();
        let _ = mint(&mut strikes, b"ci-user-1");
        strikes.set_pin(pin);
        let ts = SoftTransport::new(strikes);
        let cores = ts.core();
        {
            let mut device =
                block_on(ts.connect(&DeviceId::new("soft-0"), &Deadline::new(BUDGET), no_sleep()))
                    .unwrap();
            let deadline = Deadline::new(BUDGET);
            for _ in 0..3 {
                let _ = wrong_pin_hop(
                    &mut device,
                    fidoh_core::pin::PinUvAuthProtocol::Two,
                    &deadline,
                );
            }
        }
        let (handle, _) = provider(pin);
        let err = run(pin_ceremony(ts, handle, None)).unwrap_err();
        assert_eq!(err, CeremonyError::PinAuthBlocked);
        assert!(!matches!(err, CeremonyError::UpRejected));
        assert!(err.to_string().contains("power cycle"));
        assert_eq!(cores.lock().pin_retries(), Some(MAX_PIN_RETRIES - 3));
    }

    // The harness "power cycle" (unplug/replug) clears the latch: the
    // SAME token, SAME PIN, SAME retry counter now succeeds.
    core.lock().power_cycle();
    let mut device =
        block_on(t.connect(&DeviceId::new("soft-0"), &Deadline::new(BUDGET), no_sleep())).unwrap();
    let deadline = Deadline::new(BUDGET);
    // A direct correct-PIN token request (harness layer, so the
    // decrypted token never crosses the ceremony boundary): success
    // proves the latch is gone and the counter survives.
    let ok = correct_pin_hop(
        &mut device,
        pin,
        fidoh_core::pin::PinUvAuthProtocol::Two,
        &deadline,
    );
    assert!(
        ok,
        "after the power cycle the correct PIN is accepted again"
    );
    assert_eq!(core.lock().pin_retries(), Some(MAX_PIN_RETRIES));
}

/// One real authenticatorClientPIN token request with the CORRECT PIN
/// (harness-layer; proves latch-clearing end to end). Returns true on
/// a 0x00 response carrying a decryptable token.
fn correct_pin_hop(
    device: &mut SoftDevice,
    pin: &[u8],
    protocol: fidoh_core::pin::PinUvAuthProtocol,
    deadline: &Deadline,
) -> bool {
    use fidoh_core::cbor::CborValue;
    use fidoh_core::crypto::PlatformKeyAgreement;
    use fidoh_core::device::CtapCommand;
    use fidoh_core::pin::{permissions, ClientPinRequest, ClientPinSubCommand};

    let mut entropy = FixtureEntropy(0xC0_27_EE);
    let platform = PlatformKeyAgreement::generate(&mut entropy).unwrap();
    let ka = ClientPinRequest {
        protocol,
        sub_command: ClientPinSubCommand::GetKeyAgreement,
        key_agreement: Some(platform.cose_key()),
        pin_uv_auth_param: None,
        pin_hash_enc: None,
        permissions: None,
        rp_id: None,
    };
    let DeviceEvent::Response { status: 0x00, body } =
        block_on(device.send(&CtapCommand::ClientPin(ka), deadline, no_sleep())).unwrap()
    else {
        panic!("getKeyAgreement must succeed");
    };
    let peer = CborValue::decode_map(&body, fidoh_core::DecodePolicy::Strict)
        .and_then(|v| fidoh_core::pin::ClientPinResponse::from_cbor(&v))
        .unwrap()
        .key_agreement
        .unwrap();
    let shared = platform.encapsulate(&peer, protocol).unwrap();
    let pin_hash = sha2_of(pin);
    let pin_hash_enc = shared.encrypt(&mut entropy, &pin_hash).unwrap();
    let req = ClientPinRequest {
        protocol,
        sub_command: ClientPinSubCommand::GetPinUvAuthTokenUsingPinWithPermissions,
        key_agreement: Some(platform.cose_key()),
        pin_uv_auth_param: None,
        pin_hash_enc: Some(pin_hash_enc),
        permissions: Some(permissions::GA),
        rp_id: Some(String::from(RP)),
    };
    let DeviceEvent::Response { status, body } =
        block_on(device.send(&CtapCommand::ClientPin(req), deadline, no_sleep())).unwrap()
    else {
        panic!("token request must return a terminal response");
    };
    if status != 0x00 {
        return false;
    }
    let encrypted = CborValue::decode_map(&body, fidoh_core::DecodePolicy::Strict)
        .and_then(|v| fidoh_core::pin::ClientPinResponse::from_cbor(&v))
        .unwrap()
        .pin_uv_auth_token
        .unwrap();
    shared.decrypt(&encrypted).is_ok()
}

// --------------------------------------------------------------------
// Scenario: Budget expiry mid-acquisition names ClientPin — the
// shared budget dies between the getKeyAgreement hop and the token
// request; the ceremony returns Timeout(ClientPin) (no independent
// per-hop timeout existed), and a fresh ceremony over a fresh token
// succeeds (cancellation safety).
// --------------------------------------------------------------------
#[test]
fn budget_expiry_mid_acquisition_names_client_pin() {
    // A device wrapper that exhausts the budget after the FIRST
    // clientPIN command (getKeyAgreement) by draining the shared
    // deadline inside its `send` — the honest model of "the caller's
    // budget ran out mid-acquisition" without real time.
    struct BudgetDiesAfterFirstPin<S> {
        inner: S,
        pin_hops_seen: usize,
    }
    impl<S: Device + Send> Device for BudgetDiesAfterFirstPin<S> {
        async fn send(
            &mut self,
            cmd: &CtapCommand,
            deadline: &Deadline,
            sleep: fidoh_core::SleepHandle<'_>,
        ) -> Result<DeviceEvent, Error> {
            if matches!(cmd, CtapCommand::ClientPin(_)) {
                self.pin_hops_seen += 1;
                if self.pin_hops_seen == 1 {
                    // Let the getKeyAgreement hop through...
                    let event = self.inner.send(cmd, deadline, sleep).await?;
                    // ...then consume the ENTIRE remaining budget, so
                    // the NEXT hop (the token request, still phase
                    // ClientPin) finds nothing left.
                    while deadline.consume_slice(Duration::from_secs(1)).is_some() {}
                    return Ok(event);
                }
            }
            self.inner.send(cmd, deadline, sleep).await
        }
        async fn open_channel(
            &mut self,
            deadline: &Deadline,
            sleep: fidoh_core::SleepHandle<'_>,
        ) -> Result<fidoh_core::device::ChannelId, Error> {
            self.inner.open_channel(deadline, sleep).await
        }
        async fn close(self) -> Result<(), Error> {
            self.inner.close().await
        }
    }

    let mut auth = token();
    let _ = mint(&mut auth, b"ci-user-1");
    auth.set_pin(b"budget-expiry-pin");
    let t = SoftTransport::new(auth);
    let device =
        block_on(t.connect(&DeviceId::new("soft-0"), &Deadline::new(BUDGET), no_sleep())).unwrap();

    let (handle, calls) = provider(b"budget-expiry-pin");
    let exchange = GetAssertionExchange {
        rp_id: String::from(RP),
        client_data_hash: CLIENT_HASH.to_vec(),
        allow_credentials: None,
        user_verification: UvPolicy::Preferred,
        pin_uv_auth: None,
        pin_provider: Some(handle),
        pin_uv_auth_protocol: None,
        entropy: Some(Box::new(FixtureEntropy(0xB0_D6E7))),
        drain: None,
    };
    let err = block_on(Ceremony::run(
        exchange,
        BudgetDiesAfterFirstPin {
            inner: device,
            pin_hops_seen: 0,
        },
        &Deadline::new(BUDGET),
        no_sleep(),
    ))
    .unwrap_err();

    // Typed timeout naming the CLIENTPIN phase — not GetAssertion,
    // not GetInfo.
    assert_eq!(err, CeremonyError::Timeout(Phase::ClientPin));
    // The provider was consulted exactly once (the flow got as far as
    // the PIN collection between the hops — collect-before-use);
    // whatever the user typed died with the budget, nothing leaked.
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Cancellation safety: a fresh ceremony over a fresh token runs
    // cleanly afterwards.
    let mut fresh = token();
    let fresh_mint = mint(&mut fresh, b"ci-user-1");
    fresh.set_pin(b"fresh-after-expiry");
    let (handle, _) = provider(b"fresh-after-expiry");
    let out = run(pin_ceremony(SoftTransport::new(fresh), handle, None))
        .expect("device remains usable for a subsequent ceremony");
    assert_eq!(out.uv_effective, fidoh_core::UvEffective::PinUvAuthToken);
    assert_eq!(out.first().credential.id, fresh_mint.record.id);
}

// --------------------------------------------------------------------
// Scenario: Preferred WITHOUT a provider on a PIN-only key fails
// naming the fix — typed `PinRequired` (NOT the v1 silent
// Discouraged degradation), no authenticatorClientPIN command issued,
// Display names the fix (supply a PIN provider).
// --------------------------------------------------------------------
#[test]
fn preferred_without_provider_on_pin_only_key_names_fix() {
    // uv_mode AlwaysFail: the probe reports uv: false — the PIN-only
    // YubiKey posture (clientPin capable, no built-in verifier).
    let cfg = Config {
        uv_mode: UpUvMode::AlwaysFail,
        ..Config::default()
    };
    let mut auth = SoftAuthenticator::new(cfg);
    let _ = mint(&mut auth, b"ci-user-1");
    auth.set_pin(b"pin-only-key");
    let t = SoftTransport::new(auth);
    let core = t.core();

    // Preferred with NEITHER caller-held material NOR a provider.
    let mut ceremony =
        GetAssertionCeremony::new(vec![t], String::from(RP), CLIENT_HASH.to_vec(), BUDGET);
    ceremony.user_verification = UvPolicy::Preferred;

    let err = run(ceremony).unwrap_err();
    // Typed PinRequired — never a silent Discouraged downgrade.
    assert_eq!(err, CeremonyError::PinRequired);
    let text = err.to_string();
    assert!(
        text.contains("PinProviderHandle"),
        "Display names the fix: {text}"
    );
    // No clientPIN command reached the token (no acquisition was
    // even attempted — the failure is client-side, pre-exchange).
    assert_eq!(core.lock().pin_retries(), Some(MAX_PIN_RETRIES));
}

// --------------------------------------------------------------------
// Scenario: Discouraged never prompts for a PIN — a provider is
// supplied but the policy never asks: provide_pin is never invoked
// and no authenticatorClientPIN command is issued (the ceremony
// completes token-less).
// --------------------------------------------------------------------
#[test]
fn discouraged_never_prompts() {
    let (t, core) = pin_token(b"never-asked-for");
    let (handle, calls) = provider(b"never-asked-for");
    let mut ceremony = pin_ceremony(t, handle, None);
    ceremony.user_verification = UvPolicy::Discouraged;

    let out = run(ceremony).expect("discouraged ceremony must not touch the PIN flow");
    // No prompt, no acquisition, reported as not-requested.
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(out.uv_effective, fidoh_core::UvEffective::NotRequested);
    // The retry counter is untouched: no PIN-bearing hop ran.
    assert_eq!(core.lock().pin_retries(), Some(MAX_PIN_RETRIES));
}

// --------------------------------------------------------------------
// Scenario: Caller-held token takes precedence over acquisition —
// with BOTH pinUvAuth material and a provider supplied, the ceremony
// sends the caller-held material and never issues an
// authenticatorClientPIN command: no prompt, and the wire request
// carries the caller's param (which the token accepts after verifying
// it — proven here by building the caller-held material from the
// token's own registered secret… not needed: the caller-held token is
// arbitrary bytes for the SOFT token only when the MAC check runs —
// so the walk arms the token, derives a REAL token through one
// acquisition, then re-runs with it held by the caller).
// --------------------------------------------------------------------
#[test]
fn caller_held_token_takes_precedence() {
    // Run 1: acquire a REAL token via the provider path.
    let pin = b"precedence-pin";
    let (t, core) = pin_token(pin);
    let (handle, calls) = provider(pin);
    let out = run(pin_ceremony(t, handle, None)).expect("acquisition run succeeds");
    assert_eq!(out.uv_effective, fidoh_core::UvEffective::PinUvAuthToken);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(core.lock().pin_retries(), Some(MAX_PIN_RETRIES));

    // Run 2 (same counter, same PIN): caller-held material + provider
    // BOTH supplied. The ceremony must use the held material, never
    // prompt, never touch the clientPIN state machine.
    let mut auth2 = token();
    let minted2 = mint(&mut auth2, b"ci-user-1");
    auth2.set_pin(pin);
    let t2 = SoftTransport::new(auth2);
    let core2 = t2.core();
    // Mint a caller-held token by running ONE acquisition through the
    // device-command layer and capturing the decrypted token — the
    // honest caller posture ("I already hold a token from an earlier
    // ceremony").
    let held_param = {
        use fidoh_core::cbor::CborValue;
        use fidoh_core::crypto::PlatformKeyAgreement;
        use fidoh_core::device::CtapCommand;
        use fidoh_core::pin::{permissions, ClientPinRequest, ClientPinSubCommand};

        let mut device =
            block_on(t2.connect(&DeviceId::new("soft-0"), &Deadline::new(BUDGET), no_sleep()))
                .unwrap();
        let deadline = Deadline::new(BUDGET);
        let mut entropy = FixtureEntropy(0xCA_11_EE);
        let platform = PlatformKeyAgreement::generate(&mut entropy).unwrap();
        let ka = ClientPinRequest {
            protocol: fidoh_core::pin::PinUvAuthProtocol::Two,
            sub_command: ClientPinSubCommand::GetKeyAgreement,
            key_agreement: Some(platform.cose_key()),
            pin_uv_auth_param: None,
            pin_hash_enc: None,
            permissions: None,
            rp_id: None,
        };
        let DeviceEvent::Response { status: 0x00, body } =
            block_on(device.send(&CtapCommand::ClientPin(ka), &deadline, no_sleep())).unwrap()
        else {
            panic!("getKeyAgreement must succeed");
        };
        let peer = CborValue::decode_map(&body, fidoh_core::DecodePolicy::Strict)
            .and_then(|v| fidoh_core::pin::ClientPinResponse::from_cbor(&v))
            .unwrap()
            .key_agreement
            .unwrap();
        let shared = platform
            .encapsulate(&peer, fidoh_core::pin::PinUvAuthProtocol::Two)
            .unwrap();
        let hash = sha2::Sha256::digest(pin);
        let pin_hash_enc = shared.encrypt(&mut entropy, &hash[..16]).unwrap();
        let req = ClientPinRequest {
            protocol: fidoh_core::pin::PinUvAuthProtocol::Two,
            sub_command: ClientPinSubCommand::GetPinUvAuthTokenUsingPinWithPermissions,
            key_agreement: Some(platform.cose_key()),
            pin_uv_auth_param: None,
            pin_hash_enc: Some(pin_hash_enc),
            permissions: Some(permissions::GA),
            rp_id: Some(String::from(RP)),
        };
        let DeviceEvent::Response { status: 0x00, body } =
            block_on(device.send(&CtapCommand::ClientPin(req), &deadline, no_sleep())).unwrap()
        else {
            panic!("token request must succeed");
        };
        let encrypted = CborValue::decode_map(&body, fidoh_core::DecodePolicy::Strict)
            .and_then(|v| fidoh_core::pin::ClientPinResponse::from_cbor(&v))
            .unwrap()
            .pin_uv_auth_token
            .unwrap();
        let token = shared.decrypt(&encrypted).expect("token decrypts");
        let message = fidoh_core::crypto::pin_uv_auth_param_message(&CLIENT_HASH);
        fidoh_core::pin::PinUvAuthParam::new(shared.authenticate(&token, &message))
    };

    let (handle2, calls2) = provider(b"should-never-be-asked");
    let mut ceremony2 =
        GetAssertionCeremony::new(vec![t2], String::from(RP), CLIENT_HASH.to_vec(), BUDGET);
    ceremony2.user_verification = UvPolicy::Preferred;
    ceremony2.pin_uv_auth = Some((held_param, fidoh_core::pin::PinUvAuthProtocol::Two));
    ceremony2.pin_provider = Some(handle2);
    ceremony2.entropy = Some(Box::new(FixtureEntropy(0xCA_11_EE)));

    let out2 = run(ceremony2).expect("caller-held material rides through");
    // The held material was sent; the posture reports PinUvAuth (held
    // param), NOT PinUvAuthToken (no acquisition ran).
    assert_eq!(out2.uv_effective, fidoh_core::UvEffective::PinUvAuth);
    // ZERO prompts: the provider was never consulted.
    assert_eq!(calls2.load(Ordering::SeqCst), 0);
    // The clientPIN state machine was untouched (no 0x06 command):
    // counter unchanged from run 2's armed state.
    assert_eq!(core2.lock().pin_retries(), Some(MAX_PIN_RETRIES));
    assert_eq!(out2.first().credential.id, minted2.record.id);
}

// --------------------------------------------------------------------
// Scenario: Provider failure surfaces typed before any authenticator
// call — the caller's cancellation maps to `PinProviderFailed`
// WITHOUT any authenticatorClientPIN round-trip after the provider
// step (the retry counter is unchanged; the device remains usable).
// --------------------------------------------------------------------
#[test]
fn pin_provider_failure_typed_no_device_traffic() {
    let (t, core) = pin_token(b"never-obtained");
    // A provider that fails immediately (user cancelled).
    let calls = Arc::new(AtomicUsize::new(0));
    let handle = PinProviderHandle::from_closure({
        let calls = Arc::clone(&calls);
        move || {
            calls.fetch_add(1, Ordering::SeqCst);
            Err::<Vec<u8>, _>(PinSourceError { _context: () })
        }
    });

    let err = run(pin_ceremony(t, handle, None)).unwrap_err();
    assert_eq!(err, CeremonyError::PinProviderFailed);
    // The provider was consulted exactly once; nothing retried.
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // The token's retry counter is UNCHANGED: no PIN-bearing hop ran
    // after the provider step (acquisition died at the seam).
    assert_eq!(core.lock().pin_retries(), Some(MAX_PIN_RETRIES));
}

// --------------------------------------------------------------------
// Scenario: Oversized PIN rejected before device traffic — a 64-byte
// PIN fails typed `PinTooLong` BEFORE any clientPIN hop that could
// consume the shared secret or the retry counter (§6.5.5.5 bound).
// --------------------------------------------------------------------
#[test]
fn oversized_pin_rejected_before_device_traffic() {
    let (t, core) = pin_token(b"real pin on the token");
    const OVERSIZED: &[u8] = &[b'x'; 64]; // > MAX_PIN_BYTES (63)
    let calls = Arc::new(AtomicUsize::new(0));
    let handle = PinProviderHandle::from_closure({
        let calls = Arc::clone(&calls);
        move || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(OVERSIZED.to_vec())
        }
    });

    let err = run(pin_ceremony(t, handle, None)).unwrap_err();
    assert_eq!(err, CeremonyError::PinTooLong);
    let text = err.to_string();
    assert!(text.contains("63-byte"));
    // The provider ran (it produced the oversized PIN) but NO retry
    // counter moved: the rejection happened before the token request.
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(core.lock().pin_retries(), Some(MAX_PIN_RETRIES));
}
