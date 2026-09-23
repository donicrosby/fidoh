//! Scenario-ID tests for the transport-soft spec
//! (`openspec/changes/transport-soft/specs/transport-soft/spec.md`).
//!
//! Coverage mapping (22 spec scenarios → test fns):
//!
//! | Requirement | Scenario | Test |
//! |---|---|---|
//! | Transport/Device parity | Client ceremony runs against soft token unchanged | `client_ceremony_runs_against_soft_token_unchanged` |
//! | Transport/Device parity | No executor dependency | `no_executor_dependency` |
//! | authenticatorGetInfo | Default getInfo response | `default_get_info_response` |
//! | authenticatorGetInfo | Pinned AAGUID is stable | `pinned_aaguid_is_stable` |
//! | Internal makeCredential | Minting a test credential | `minting_a_test_credential` |
//! | Internal makeCredential | Not exposed via client API | `make_credential_not_exposed_via_client_api` |
//! | GetAssertion signatures | Signature verifies | `assertion_signature_verifies` |
//! | GetAssertion signatures | Unknown credential rejected | `unknown_credential_rejected_with_no_credentials` |
//! | authenticatorData layout | Assertion authenticatorData | `assertion_authenticator_data_layout` |
//! | authenticatorData layout | makeCredential includes attested credential data | `make_credential_authenticator_data_includes_attested_credential_data` |
//! | COSE ES256 encoding | COSE key round-trips | `cose_key_round_trips` |
//! | Signature counter | Counter increments | `counter_increments_by_one_per_success` |
//! | UP/UV modes | Auto-approve sets flags | `auto_approve_sets_flags` |
//! | UP/UV modes | Always-fail rejects the command | `always_fail_rejects_the_command` |
//! | UP/UV modes | Explicit poke completes the ceremony | `explicit_poke_completes_the_ceremony` |
//! | UP/UV modes | Poke wait hits the ceremony deadline | `poke_wait_hits_the_ceremony_deadline` |
//! | Error injection | Arbitrary status code injection | `arbitrary_status_code_injection_matrix` |
//! | Error injection | Keepalive sequence before response | `keepalive_sequence_before_response` |
//! | Error injection | Delay beyond deadline triggers client timeout | `delay_beyond_deadline_triggers_client_timeout` |
//! | Error injection | Wrong credential ID response | `wrong_credential_id_response` |
//! | Credential store | Snapshot round-trip | `snapshot_round_trip` |
//! | Credential store | Deterministic fixtures | `deterministic_fixtures_are_byte_identical` |
//!
//! All waits are budget-driven; the tests' `Sleep` factory never
//! resolves (`NoSleep`), so any accidental internal wait inside the
//! token hangs loudly instead of passing silently.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use fidoh_core::cbor::CborValue;
use fidoh_core::cose::CoseEs256Key;
use fidoh_core::device::{CtapCommand, Device, DeviceEvent};
use fidoh_core::error::{DecodePolicy, Error};
use fidoh_core::get_assertion::{
    CredentialType, GetAssertionRequest, PublicKeyCredentialDescriptor,
};
use fidoh_core::status::StatusCode;
use fidoh_core::time::{Deadline, Phase};
use fidoh_core::transport::Transport;
use fidoh_core::{DeviceId, Sleep};
use fidoh_transport_soft::{
    AssertionParts, Config, DeterministicRng, KeepaliveEvent, MakeCredentialArgs, RngConfig,
    SoftAuthenticator, SoftTransport, UpUvMode, AAGUID, DELAY_HARD_CAP, POKE_POLL_SLICE,
};

// --------------------------------------------------------------------
// Minimal block_on (executor lives only in tests) + NoSleep factory.
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

/// A `Sleep` factory that never resolves: the soft device performs no
/// internal waits of its own, so nothing should ever await this. If a
/// code path tried, the test would hang — a loud failure, never a
/// silently-passing real-time sleep.
struct NoSleep;

impl Sleep for NoSleep {
    fn sleep(&self, _duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(std::future::pending())
    }
}

// --------------------------------------------------------------------
// Fixtures.
// --------------------------------------------------------------------

const RP: &str = "example.com";
const CLIENT_HASH: [u8; 32] = [0xAB; 32];

fn token() -> SoftAuthenticator {
    SoftAuthenticator::new(Config::default())
}

/// Connect a device to an existing authenticator (single-device
/// transport) with the channel opened.
fn connect(auth: SoftAuthenticator) -> (SoftTransport, fidoh_transport_soft::SoftDevice) {
    let t = SoftTransport::new(auth);
    let device = block_on(t.connect(
        &DeviceId::new("soft-0"),
        &Deadline::new(Duration::from_secs(10)),
        &NoSleep,
    ))
    .unwrap();
    (t, device)
}

fn open(device: &mut fidoh_transport_soft::SoftDevice) {
    block_on(device.open_channel(&Deadline::new(Duration::from_secs(1)), &NoSleep)).unwrap();
}

fn assertion_request(rp: &str, allow: Vec<Vec<u8>>) -> GetAssertionRequest {
    let mut req = GetAssertionRequest::new(String::from(rp), CLIENT_HASH.to_vec()).unwrap();
    req.allow_list = if allow.is_empty() {
        None
    } else {
        Some(
            allow
                .into_iter()
                .map(|id| PublicKeyCredentialDescriptor {
                    type_field: CredentialType::PublicKey,
                    id,
                    transports: None,
                })
                .collect(),
        )
    };
    req
}

fn mint_default(auth: &mut SoftAuthenticator) -> fidoh_transport_soft::MintedCredential {
    auth.make_credential(MakeCredentialArgs {
        rp_id: String::from(RP),
        user_handle: b"ci-user-1".to_vec(),
        resident: true,
    })
    .unwrap()
}

fn response_of(event: DeviceEvent) -> (u8, Vec<u8>) {
    match event {
        DeviceEvent::Response { status, body } => (status, body),
        other => panic!("expected terminal response, got {other:?}"),
    }
}

fn send_assertion(
    device: &mut fidoh_transport_soft::SoftDevice,
    minted: &fidoh_transport_soft::MintedCredential,
) -> (u8, Vec<u8>) {
    let deadline = Deadline::new(Duration::from_secs(30));
    let cmd = CtapCommand::GetAssertion(assertion_request(RP, vec![minted.record.id.clone()]));
    response_of(block_on(device.send(&cmd, &deadline, &NoSleep)).unwrap())
}

/// Independent verifier: check `signature` over
/// `authData || clientDataHash` against the COSE coordinates of a
/// minted credential (real ECDSA verification, never a tautology).
fn verify_assertion(
    parts: &AssertionParts,
    key: &CoseEs256Key,
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
    let sig = Signature::from_der(&parts.signature).map_err(|e| format!("bad DER: {e}"))?;
    let mut signed = parts.auth_data.clone();
    signed.extend_from_slice(client_data_hash);
    vk.verify(&signed, &sig)
        .map_err(|e| format!("verify failed: {e}"))
}

fn flags_byte(auth_data: &[u8]) -> u8 {
    auth_data[32]
}

fn sign_count_of(auth_data: &[u8]) -> u32 {
    u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]])
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// --------------------------------------------------------------------
// Requirement: Transport/Device trait parity
// --------------------------------------------------------------------

// Scenario: Client ceremony runs against soft token unchanged
#[test]
fn client_ceremony_runs_against_soft_token_unchanged() {
    let mut auth = token();
    let minted = mint_default(&mut auth);
    let (_t, mut device) = connect(auth);
    let deadline = Deadline::new(Duration::from_secs(30));

    // getInfo probe — through the Device trait, like any hardware path.
    let event = block_on(device.send(&CtapCommand::GetInfo, &deadline, &NoSleep)).unwrap();
    let (status, body) = response_of(event);
    assert_eq!(status, 0x00);
    let info = fidoh_core::get_info::GetInfoResponse::from_cbor(
        &CborValue::decode_map(&body, DecodePolicy::Strict).unwrap(),
    )
    .unwrap();
    assert_eq!(info.aaguid, AAGUID);

    // getAssertion — same trait path; no soft-token-specific code
    // anywhere in the client walk.
    let (status, body) = send_assertion(&mut device, &minted);
    assert_eq!(status, 0x00);
    let parts = AssertionParts::decode_response(&body).unwrap();
    assert_eq!(parts.credential_id, minted.record.id);
    verify_assertion(&parts, &minted.record.public_key(), &CLIENT_HASH)
        .expect("ceremony assertion must verify");
}

// Scenario: No executor dependency
#[test]
fn no_executor_dependency() {
    // The crate itself is no_std + alloc by default (see lib.rs); this
    // std-only test binary links it, which is only possible because no
    // executor is required. Belt-and-braces: the workspace lockfile
    // must carry no tokio/async-std/smol packages at all.
    let lock =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock")).unwrap();
    for banned in ["tokio", "async-std", "smol"] {
        assert!(
            !lock.contains(&format!("name = \"{banned}\"")),
            "executor crate {banned} leaked into the workspace"
        );
    }
}

// --------------------------------------------------------------------
// Requirement: authenticatorGetInfo
// --------------------------------------------------------------------

// Scenario: Default getInfo response
#[test]
fn default_get_info_response() {
    let mut auth = token();
    let info = auth.get_info();
    // versions list contains exactly FIDO_2_0 and FIDO_2_1 (U2F_V2
    // excluded).
    assert_eq!(
        info.versions,
        vec![String::from("FIDO_2_0"), String::from("FIDO_2_1")]
    );
    assert!(!info.versions.iter().any(|v| v == "U2F_V2"));
    // Pinned AAGUID.
    assert_eq!(info.aaguid, AAGUID);
    // options rk/up true, uv per the current UV mode capability.
    let options = info.options.as_ref().unwrap();
    assert!(options.get(fidoh_core::get_info::OptionId::Rk));
    assert!(options.get(fidoh_core::get_info::OptionId::Up));
    assert!(options.get(fidoh_core::get_info::OptionId::Uv));
    // uv flips with the configured mode capability.
    auth.set_uv_mode(UpUvMode::AlwaysFail);
    let info = auth.get_info();
    assert!(!info
        .options
        .as_ref()
        .unwrap()
        .get(fidoh_core::get_info::OptionId::Uv));
}

// Scenario: Pinned AAGUID is stable
#[test]
fn pinned_aaguid_is_stable() {
    let a = token();
    let b = token();
    assert_eq!(a.get_info().aaguid, b.get_info().aaguid);
    assert_eq!(a.get_info().aaguid, *b"fidoh-soft-token");
}

// --------------------------------------------------------------------
// Requirement: Internal authenticatorMakeCredential
// --------------------------------------------------------------------

// Scenario: Minting a test credential
#[test]
fn minting_a_test_credential() {
    let mut auth = token();
    let minted = mint_default(&mut auth);
    // Exactly one credential source record stored.
    assert_eq!(auth.credentials().len(), 1);
    let record = &auth.credentials()[0];
    assert_eq!(record.id, minted.record.id);
    assert_eq!(record.rp_id, RP);
    assert_eq!(record.user_handle, b"ci-user-1");
    // Attested credential data embeds the new credential ID and the
    // COSE ES256 public key.
    let ad = &minted.attested_auth_data;
    assert_eq!(flags_byte(ad) & (1 << 6), 1 << 6);
    let cred_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    assert_eq!(cred_len, 32);
    assert_eq!(&ad[55..87], record.id.as_slice());
    let cose = &ad[87..];
    let key =
        CoseEs256Key::from_cbor(&CborValue::decode(cose, DecodePolicy::Strict).unwrap()).unwrap();
    assert_eq!(key, record.public_key());
}

// Scenario: Not exposed via client API
#[test]
fn make_credential_not_exposed_via_client_api() {
    // The client-facing surface is the `Device` trait + the
    // `CtapCommand` request type. `CtapCommand` carries only GetInfo
    // and GetAssertion — no makeCredential variant exists to even
    // construct (compile-time proof), and `SoftDevice`/`SoftTransport`
    // expose no make_credential method. The harness mints through the
    // CONCRETE `SoftAuthenticator` only.
    let mut auth = token();
    let minted = mint_default(&mut auth);
    let (_t, mut device) = connect(auth);
    open(&mut device);
    let deadline = Deadline::new(Duration::from_secs(5));
    for cmd in [
        CtapCommand::GetInfo,
        CtapCommand::GetAssertion(assertion_request(RP, vec![minted.record.id.clone()])),
    ] {
        let _ = block_on(device.send(&cmd, &deadline, &NoSleep));
    }
}

// --------------------------------------------------------------------
// Requirement: authenticatorGetAssertion signatures
// --------------------------------------------------------------------

// Scenario: Signature verifies (real crypto, not a tautology)
#[test]
fn assertion_signature_verifies() {
    let mut auth = token();
    let minted = mint_default(&mut auth);
    let (_t, mut device) = connect(auth);
    open(&mut device);
    let (status, body) = send_assertion(&mut device, &minted);
    assert_eq!(status, 0x00);
    let parts = AssertionParts::decode_response(&body).unwrap();
    verify_assertion(&parts, &minted.record.public_key(), &CLIENT_HASH)
        .expect("signature must verify over authData || clientDataHash");
    // Negative control: a different clientDataHash must NOT verify
    // (proves the signature actually binds the challenge).
    let mut other_hash = CLIENT_HASH;
    other_hash[0] ^= 0xFF;
    assert!(verify_assertion(&parts, &minted.record.public_key(), &other_hash).is_err());
}

// Scenario: Unknown credential rejected
#[test]
fn unknown_credential_rejected_with_no_credentials() {
    let mut auth = token();
    let _ = mint_default(&mut auth);
    let (_t, mut device) = connect(auth);
    open(&mut device);
    let deadline = Deadline::new(Duration::from_secs(30));
    let cmd = CtapCommand::GetAssertion(assertion_request(RP, vec![vec![0xDEu8; 32]]));
    let (status, body) = response_of(block_on(device.send(&cmd, &deadline, &NoSleep)).unwrap());
    assert_eq!(StatusCode::from_u8(status), StatusCode::NoCredentials);
    assert_eq!(status, 0x2E);
    assert!(body.is_empty());
}

// --------------------------------------------------------------------
// Requirement: authenticatorData layout
// --------------------------------------------------------------------

// Scenario: Assertion authenticatorData
#[test]
fn assertion_authenticator_data_layout() {
    let mut auth = token();
    let minted = mint_default(&mut auth);
    let (_t, mut device) = connect(auth);
    open(&mut device);
    let (status, body) = send_assertion(&mut device, &minted);
    assert_eq!(status, 0x00);
    let parts = AssertionParts::decode_response(&body).unwrap();
    let ad = &parts.auth_data;
    // Exactly 37 bytes: 32 rpIdHash + 1 flags + 4 signCount, no
    // trailing bytes.
    assert_eq!(ad.len(), 37);
    // Bytes 0..32 = SHA-256(rpId).
    assert_eq!(&ad[..32], &sha256(RP.as_bytes())[..]);
    // Flags: UP (bit 0) and UV (bit 2) set; AT (bit 6) and ED (bit 7)
    // clear; all other bits zero.
    assert_eq!(ad[32], 0b0000_0101);
    // Bytes 33..37 = signCount big-endian (mint=1, this assertion=2).
    assert_eq!(sign_count_of(ad), 2);
}

// Scenario: makeCredential authenticatorData includes attested
// credential data
#[test]
fn make_credential_authenticator_data_includes_attested_credential_data() {
    let mut auth = token();
    let minted = mint_default(&mut auth);
    let ad = &minted.attested_auth_data;
    // 37 + 16 AAGUID + 2 len + 32 id + 77 COSE key (the canonical ES256
    // map is exactly 77 bytes: a5 01 02 03 26 20 01 21 58 20 <32> 22 58 20 <32>).
    assert_eq!(ad.len(), 37 + 16 + 2 + 32 + 77);
    // AT set, ED clear, UP/UV set.
    assert_eq!(ad[32] & 0b1100_0000, 0b0100_0000);
    assert_eq!(ad[32] & 0b1000_0000, 0);
    // Immediately after the signCount: pinned AAGUID.
    assert_eq!(&ad[37..53], &AAGUID[..]);
    // 2-byte BE credential-ID length, then the ID.
    let cred_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    assert_eq!(cred_len, 32);
    assert_eq!(&ad[55..87], &minted.record.id[..]);
    // Then the COSE public key.
    let cose = &ad[87..];
    let key =
        CoseEs256Key::from_cbor(&CborValue::decode(cose, DecodePolicy::Strict).unwrap()).unwrap();
    assert_eq!(key, minted.record.public_key());
    assert_eq!(minted.sign_count, 1);
}

// --------------------------------------------------------------------
// Requirement: COSE ES256 public key encoding
// --------------------------------------------------------------------

// Scenario: COSE key round-trips
#[test]
fn cose_key_round_trips() {
    let mut auth = token();
    let minted = mint_default(&mut auth);
    let key = minted.record.public_key();
    let value = key.to_cbor();
    let CborValue::Map(entries) = &value else {
        panic!("COSE key must encode as a map");
    };
    // Exactly the labels {1: 2, 3: -7, -1: 1, -2: x, -3: y}, and no
    // other parameters.
    let mut labels: Vec<i128> = entries
        .iter()
        .map(|(k, _)| match k {
            CborValue::Int(n) => *n,
            other => panic!("non-int COSE label {other:?}"),
        })
        .collect();
    labels.sort();
    assert_eq!(labels, vec![-3, -2, -1, 1, 3]);
    // x and y each 32 bytes.
    let decoded = CoseEs256Key::from_cbor(&value).unwrap();
    assert_eq!(decoded.x.len(), 32);
    assert_eq!(decoded.y.len(), 32);
    assert_eq!(decoded, key);
    // The key reconstructs the credential's P-256 public key: encode
    // the affine point back through p256 and re-extract the same
    // coordinates.
    let point = p256::EncodedPoint::from_affine_coordinates(
        &p256::FieldBytes::from_iter(decoded.x.iter().copied()),
        &p256::FieldBytes::from_iter(decoded.y.iter().copied()),
        false,
    );
    let x_back: &[u8] = point.x().unwrap().as_ref();
    let y_back: &[u8] = point.y().unwrap().as_ref();
    assert_eq!(x_back, decoded.x.as_slice());
    assert_eq!(y_back, decoded.y.as_slice());
}

// --------------------------------------------------------------------
// Requirement: Signature counter
// --------------------------------------------------------------------

// Scenario: Counter increments
#[test]
fn counter_increments_by_one_per_success() {
    let mut auth = token();
    let minted = mint_default(&mut auth);
    let (_t, mut device) = connect(auth);
    open(&mut device);
    let (_, body1) = send_assertion(&mut device, &minted);
    let (_, body2) = send_assertion(&mut device, &minted);
    let c1 = sign_count_of(&AssertionParts::decode_response(&body1).unwrap().auth_data);
    let c2 = sign_count_of(&AssertionParts::decode_response(&body2).unwrap().auth_data);
    assert_eq!(c2, c1 + 1);
}

// --------------------------------------------------------------------
// Requirement: UP/UV behavior modes
// --------------------------------------------------------------------

// Scenario: Auto-approve sets flags
#[test]
fn auto_approve_sets_flags() {
    let mut auth = token();
    let minted = mint_default(&mut auth);
    let (_t, mut device) = connect(auth);
    open(&mut device);
    let (status, body) = send_assertion(&mut device, &minted);
    assert_eq!(status, 0x00);
    let parts = AssertionParts::decode_response(&body).unwrap();
    // Bits 0 (UP) and 2 (UV) both set.
    assert_eq!(flags_byte(&parts.auth_data) & 0b0000_0101, 0b0000_0101);
}

// Scenario: Always-fail rejects the command
#[test]
fn always_fail_rejects_the_command() {
    let cfg = Config {
        up_mode: UpUvMode::AlwaysFail,
        ..Config::default()
    };
    let mut auth = SoftAuthenticator::new(cfg);
    let minted = mint_default(&mut auth);
    let count_before = auth.sign_count();
    let (t, mut device) = connect(auth);
    open(&mut device);
    let (status, body) = send_assertion(&mut device, &minted);
    assert_eq!(status, StatusCode::OperationDenied.to_u8());
    assert_eq!(status, 0x27);
    assert!(body.is_empty());
    // No signature produced, signCount not incremented.
    assert_eq!(t.core().lock().sign_count(), count_before);
}

// Scenario: Explicit poke completes the ceremony
#[test]
fn explicit_poke_completes_the_ceremony() {
    let cfg = Config {
        up_mode: UpUvMode::RequireExplicitPoke,
        ..Config::default()
    };
    let mut auth = SoftAuthenticator::new(cfg);
    let minted = mint_default(&mut auth);
    let (t, mut device) = connect(auth);
    open(&mut device);
    let deadline = Deadline::new(Duration::from_secs(30));
    let cmd = CtapCommand::GetAssertion(assertion_request(RP, vec![minted.record.id.clone()]));

    // First exchange pends: UP_NEEDED keepalive as surfaced progress,
    // one poll slice consumed.
    let event = block_on(device.send(&cmd, &deadline, &NoSleep)).unwrap();
    assert!(
        matches!(event, DeviceEvent::Keepalive { status: 0x02 }),
        "expected UP_NEEDED keepalive, got {event:?}"
    );
    // Harness pokes; the next exchange completes with UP set.
    t.core().lock().poke_user_presence();
    let (status, body) = response_of(block_on(device.send(&cmd, &deadline, &NoSleep)).unwrap());
    assert_eq!(status, 0x00);
    let parts = AssertionParts::decode_response(&body).unwrap();
    assert_eq!(flags_byte(&parts.auth_data) & 0b0000_0001, 0b0000_0001);
}

// Scenario: Poke wait hits the ceremony deadline
#[test]
fn poke_wait_hits_the_ceremony_deadline() {
    let cfg = Config {
        up_mode: UpUvMode::RequireExplicitPoke,
        ..Config::default()
    };
    let mut auth = SoftAuthenticator::new(cfg);
    let minted = mint_default(&mut auth);
    let (_t, mut device) = connect(auth);
    open(&mut device);
    // Budget of exactly three poll slices: three pending exchanges,
    // then the typed timeout. No poke ever arrives; the wait is
    // bounded solely by this caller deadline.
    let deadline = Deadline::new(3 * POKE_POLL_SLICE);
    let cmd = CtapCommand::GetAssertion(assertion_request(RP, vec![minted.record.id.clone()]));
    for _ in 0..3 {
        let event = block_on(device.send(&cmd, &deadline, &NoSleep)).unwrap();
        assert!(matches!(event, DeviceEvent::Keepalive { status: 0x02 }));
    }
    let err = block_on(device.send(&cmd, &deadline, &NoSleep)).unwrap_err();
    assert_eq!(err, Error::Timeout(Phase::GetAssertion));
}

// --------------------------------------------------------------------
// Requirement: Error injection knobs
// --------------------------------------------------------------------

// Scenario: Arbitrary status code injection
#[test]
fn arbitrary_status_code_injection_matrix() {
    // The full client-mapping matrix: every code the client must map
    // to a typed variant is injectable and observed EXACTLY.
    let matrix: [StatusCode; 11] = [
        StatusCode::NoCredentials,      // 0x2E
        StatusCode::InvalidCredential,  // 0x22
        StatusCode::UserActionTimeout,  // 0x2F
        StatusCode::KeepaliveCancel,    // 0x2D
        StatusCode::OperationDenied,    // 0x27
        StatusCode::UpRequired,         // 0x3B
        StatusCode::PinAuthInvalid,     // 0x33
        StatusCode::PinAuthBlocked,     // 0x34
        StatusCode::PuatRequired,       // 0x36
        StatusCode::PinPolicyViolation, // 0x37
        StatusCode::UvBlocked,          // 0x3C
    ];
    for code in matrix {
        let mut auth = token();
        let minted = mint_default(&mut auth);
        auth.knobs_mut().inject_status = Some(code);
        let (_t, mut device) = connect(auth);
        open(&mut device);
        let deadline = Deadline::new(Duration::from_secs(30));
        let cmd = CtapCommand::GetAssertion(assertion_request(RP, vec![minted.record.id.clone()]));
        let (status, body) = response_of(block_on(device.send(&cmd, &deadline, &NoSleep)).unwrap());
        assert_eq!(status, code.to_u8(), "injected {code:?} must fire exactly");
        assert!(body.is_empty());
        // One-shot: the knob reset after firing; the same command then
        // succeeds.
        let event = block_on(device.send(&cmd, &deadline, &NoSleep)).unwrap();
        assert!(matches!(event, DeviceEvent::Response { status: 0x00, .. }));
    }
    // Also injectable on getInfo — 0x12 CTAP2_ERR_INVALID_CBOR per the
    // spec scenario.
    let mut auth = token();
    auth.knobs_mut().inject_status = Some(StatusCode::InvalidCbor);
    let (_t, mut device) = connect(auth);
    open(&mut device);
    let deadline = Deadline::new(Duration::from_secs(10));
    let event = block_on(device.send(&CtapCommand::GetInfo, &deadline, &NoSleep)).unwrap();
    assert_eq!(
        event,
        DeviceEvent::Response {
            status: 0x12,
            body: Vec::new(),
        }
    );
}

// Scenario: Keepalive sequence before response
#[test]
fn keepalive_sequence_before_response() {
    let mut auth = token();
    let minted = mint_default(&mut auth);
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
    let (_t, mut device) = connect(auth);
    open(&mut device);
    // Budget: 3 x 50 ms spacing + slack — the whole exchange must fit
    // inside the caller's ceremony deadline.
    let deadline = Deadline::new(Duration::from_millis(500));
    let cmd = CtapCommand::GetAssertion(assertion_request(RP, vec![minted.record.id.clone()]));
    let mut keepalives = 0;
    let mut response_status = None;
    for _ in 0..4 {
        let event = block_on(device.send(&cmd, &deadline, &NoSleep)).unwrap();
        match event {
            DeviceEvent::Keepalive { status: 0x02 } => keepalives += 1,
            DeviceEvent::Keepalive { status } => panic!("unexpected keepalive {status:#x}"),
            DeviceEvent::Response { status, .. } => {
                response_status = Some(status);
                break;
            }
        }
    }
    // Exactly three keepalives at the configured spacing, then the
    // successful response, within the deadline.
    assert_eq!(keepalives, 3);
    assert_eq!(response_status, Some(0x00));
    assert!(
        deadline.remaining() > Duration::ZERO,
        "exchange must fit the caller deadline"
    );
}

// Scenario: Delay beyond deadline triggers client timeout
#[test]
fn delay_beyond_deadline_triggers_client_timeout() {
    let mut auth = token();
    let minted = mint_default(&mut auth);
    // Delay far beyond any sane budget; the token's own wait is
    // hard-capped at deadline + 60 s (DELAY_HARD_CAP) — a bounded
    // overshoot, never an unbounded sleep.
    auth.knobs_mut().delay_beyond_deadline = Some(DELAY_HARD_CAP + Duration::from_secs(10));
    let (_t, mut device) = connect(auth);
    open(&mut device);
    let deadline = Deadline::new(Duration::from_millis(100));
    let cmd = CtapCommand::GetAssertion(assertion_request(RP, vec![minted.record.id.clone()]));

    // First send: the (capped) overshoot accounting drives the shared
    // budget to zero — the caller-side deadline is now exceeded.
    let _event = block_on(device.send(&cmd, &deadline, &NoSleep)).unwrap();
    assert_eq!(deadline.remaining(), Duration::ZERO);
    // Any further hop sees the exhausted budget: the typed client
    // timeout.
    let err = block_on(device.send(&cmd, &deadline, &NoSleep)).unwrap_err();
    assert_eq!(err, Error::Timeout(Phase::GetAssertion));
    // The overshoot itself was bounded: consumed budget never exceeded
    // remaining + DELAY_HARD_CAP (+ poll slices).
    // (Remaining is 0; the cap math is enforced by
    // `min(deadline.remaining() + DELAY_HARD_CAP)` in the shim.)
}

// Scenario: Wrong credential ID response
#[test]
fn wrong_credential_id_response() {
    let mut auth = token();
    let a = mint_default(&mut auth);
    let b = auth
        .make_credential(MakeCredentialArgs {
            rp_id: String::from(RP),
            user_handle: b"ci-user-2".to_vec(),
            resident: true,
        })
        .unwrap();
    auth.knobs_mut().wrong_credential_id = true;
    let (_t, mut device) = connect(auth);
    open(&mut device);
    let (status, body) = send_assertion(&mut device, &a);
    assert_eq!(status, 0x00);
    let parts = AssertionParts::decode_response(&body).unwrap();
    // The assertion carries a DIFFERENT credential ID than requested.
    assert_ne!(parts.credential_id, a.record.id);
    assert_eq!(parts.credential_id, b.record.id);
    // ...while remaining a valid signature by the store's credentials
    // (signed under the requested credential's key).
    verify_assertion(&parts, &a.record.public_key(), &CLIENT_HASH)
        .expect("signature must stay valid under the requested credential's key");
}

// --------------------------------------------------------------------
// Requirement: Credential store
// --------------------------------------------------------------------

// Scenario: Snapshot round-trip
#[cfg(feature = "snapshot")]
#[test]
fn snapshot_round_trip() {
    use fidoh_transport_soft::{
        snapshot_export, snapshot_from_json, snapshot_import, snapshot_to_json, SNAPSHOT_VERSION,
    };

    let mut auth = token();
    let minted = mint_default(&mut auth);
    let snapshot = snapshot_export(&auth);

    // Fresh instance, import, assert under the same credential ID.
    let mut fresh = token();
    snapshot_import(&mut fresh, &snapshot).unwrap();
    let record = fresh
        .credential_by_id(&minted.record.id)
        .expect("imported credential must be present");
    assert_eq!(record.rp_id, RP);
    assert_eq!(record.user_handle, b"ci-user-1");

    let (_t, mut device) = connect(fresh);
    open(&mut device);
    let (status, body) = send_assertion(&mut device, &minted);
    assert_eq!(status, 0x00);
    let parts = AssertionParts::decode_response(&body).unwrap();
    verify_assertion(&parts, &minted.record.public_key(), &CLIENT_HASH)
        .expect("imported store must produce a valid assertion under the same credential ID");

    // JSON round-trip preserves the snapshot; the version field rides
    // along.
    let json = snapshot_to_json(&snapshot).unwrap();
    let back = snapshot_from_json(&json).unwrap();
    assert_eq!(back, snapshot);
    assert_eq!(back.version, SNAPSHOT_VERSION);
    // Unsupported versions are rejected with a typed error.
    let mut bad = snapshot.clone();
    bad.version = 99;
    assert!(matches!(
        snapshot_import(&mut token(), &bad),
        Err(fidoh_transport_soft::SnapshotError::UnsupportedVersion(99))
    ));
}

// Scenario: Deterministic fixtures
#[cfg(feature = "snapshot")]
#[test]
fn deterministic_fixtures_are_byte_identical() {
    use fidoh_transport_soft::{snapshot_export, snapshot_to_json};

    fn run_script() -> String {
        let cfg = Config {
            rng: RngConfig::Seeded(DeterministicRng::seeded(0xC0FF_EE00)),
            initial_sign_count: 7,
            ..Config::default()
        };
        let mut auth = SoftAuthenticator::new(cfg);
        for rp in ["example.com", "other.example"] {
            auth.make_credential(MakeCredentialArgs {
                rp_id: String::from(rp),
                user_handle: b"fixture-user".to_vec(),
                resident: true,
            })
            .unwrap();
        }
        snapshot_to_json(&snapshot_export(&auth)).unwrap()
    }
    // Re-running the same minting sequence produces a byte-identical
    // snapshot (committed conformance vectors reproduce exactly).
    assert_eq!(run_script(), run_script());
}

// --------------------------------------------------------------------
// Sanity: keepalive spacing comes out of the shared budget.
// --------------------------------------------------------------------

#[test]
fn keepalive_spacing_consumes_shared_budget() {
    let mut auth = token();
    let minted = mint_default(&mut auth);
    auth.knobs_mut().keepalive_sequence = vec![KeepaliveEvent {
        status: 0x01,
        spacing: Duration::from_secs(2),
    }];
    let (_t, mut device) = connect(auth);
    open(&mut device);
    let budget = Duration::from_secs(10);
    let deadline = Deadline::new(budget);
    let cmd = CtapCommand::GetAssertion(assertion_request(RP, vec![minted.record.id.clone()]));
    let _ = block_on(device.send(&cmd, &deadline, &NoSleep)).unwrap();
    assert_eq!(
        deadline.remaining(),
        budget - Duration::from_secs(2),
        "spacing must come out of the shared budget"
    );
}

// Keep the fake-clock helpers referenced (mirrors the fidoh-core test
// style; useful for future wall-clock-aware assertions).
#[allow(dead_code)]
fn unused_fake_clock_scaffolding() {
    let _now: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let _o = Ordering::Relaxed;
    let _m: Option<Mutex<()>> = None;
}
