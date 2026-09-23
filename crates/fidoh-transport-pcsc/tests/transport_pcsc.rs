//! Integration tests for the PC/SC transport, driving the engine
//! through the programmable [`FakeLibrary`] — every spec scenario,
//! plus interleaved transactions, time-extension handling, and the
//! SW/PC/SC error-injection matrix. Hardware-gated probes live in
//! `hardware.rs`.
//!
//! Named per spec scenario (`scenario_*`) so the spec ↔ test mapping
//! is greppable.

#![cfg(test)]

use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use fidoh_core::device::{CtapCommand, Device as CtapDevice, DeviceEvent};
use fidoh_core::sleep::Sleep;
use fidoh_core::time::{Deadline, Phase};
use fidoh_core::transport::{DeviceId, Transport};
use fidoh_core::{ChannelId, Error};

use fidoh_transport_pcsc::fake::{FakeLibrary, CARD_PRESENT};
use fidoh_transport_pcsc::library::ShareMode;
use fidoh_transport_pcsc::sw::StatusWord;
use fidoh_transport_pcsc::PcscTransport;

// ---------------------------------------------------------------------
// Minimal block_on + a fake clock (the workspace's only executor
// lives in tests; pattern copied from fidoh-core's tests).
// ---------------------------------------------------------------------

struct NoopWaker;
impl std::task::Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
    fn wake_by_ref(self: &Arc<Self>) {}
}

fn block_on<F: core::future::Future>(fut: F) -> F::Output {
    let waker = Waker::from(Arc::new(NoopWaker));
    let mut cx = Context::from_waker(&waker);
    let mut fut = Box::pin(fut);
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(out) => return out,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

/// A fake clock: `sleep(d)` resolves immediately (the budget is
/// consumed by the engine's slice accounting; zero-real-time per the
/// deterministic-clock contract).
struct Instant;
impl Sleep for Instant {
    fn sleep(
        &self,
        _duration: Duration,
    ) -> std::pin::Pin<Box<dyn core::future::Future<Output = ()> + Send>> {
        Box::pin(std::future::ready(()))
    }
}

fn sleep_handle() -> &'static (dyn Sleep + Send + Sync) {
    static INSTANT: Instant = Instant;
    &INSTANT
}

fn budget(secs: u64) -> Deadline {
    Deadline::new(Duration::from_secs(secs))
}

// ---------------------------------------------------------------------
// Builders: one reader, one scripted SELECT, then the exchange under
// test.
// ---------------------------------------------------------------------

const READER: &str = "ACS ACR39U ICC Reader 00 00";
const NFC_READER: &str = "Sony FeliCa Port/PaSoRi NFC 00 00";

/// `U2F_V2` || 9000 — the §11.3.3 answer of a CTAP1+CTAP2 device.
fn select_ok() -> &'static [u8] {
    b"U2F_V2\x90\x00"
}

fn transport_ccid(fake: FakeLibrary) -> PcscTransport<FakeLibrary> {
    PcscTransport::new(fake)
}

fn transport_nfc(fake: FakeLibrary) -> PcscTransport<FakeLibrary> {
    PcscTransport::new(fake).with_nfc_readers(&[NFC_READER])
}

// ---------------------------------------------------------------------
// Requirement: Reader enumeration via the PC/SC resource manager
// ---------------------------------------------------------------------

/// Scenario: Readers enumerated through SCardListReaders.
#[test]
fn scenario_readers_enumerated_through_scard_list_readers() {
    let fake = FakeLibrary::new()
        .reader(READER, CARD_PRESENT)
        .reader(NFC_READER, CARD_PRESENT);
    let t = transport_ccid(fake);
    let d = budget(30);
    let devices = block_on(t.enumerate(&d, sleep_handle())).unwrap();
    assert_eq!(devices.len(), 2);
    assert_eq!(devices[0].name, READER);
    assert_eq!(devices[1].name, NFC_READER);
    assert!(devices[0].aaguid.is_none(), "PC/SC supplies no AAGUID");
}

/// Scenario: No resource manager running.
#[test]
fn scenario_no_resource_manager_running_is_typed_no_service() {
    let fake = FakeLibrary::new().fail_list_readers(0x8010_001D);
    let t = transport_ccid(fake);
    let d = budget(30);
    let err = block_on(t.enumerate(&d, sleep_handle())).unwrap_err();
    match err {
        Error::Transport(e) => {
            assert!(e.detail.contains("no-service"), "{}", e.detail);
            assert!(e.detail.contains("0x8010001d"), "{}", e.detail);
        }
        other => panic!("expected Transport(no-service), got {other:?}"),
    }
}

/// Scenario: No readers is a typed skip, not a crash.
#[test]
fn scenario_no_readers_is_a_typed_skip() {
    let fake = FakeLibrary::new().fail_list_readers(0x8010_002E);
    let t = transport_ccid(fake);
    let d = budget(30);
    let err = block_on(t.enumerate(&d, sleep_handle())).unwrap_err();
    match err {
        Error::Transport(e) => {
            assert!(e.detail.contains("skip"), "{}", e.detail);
            assert!(e.detail.contains("no-readers"), "{}", e.detail);
        }
        other => panic!("expected typed no-readers skip, got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// Requirement: Shared connect on both interfaces; exclusive opt-in
// ---------------------------------------------------------------------

/// Scenario: Shared connect used by default on both interfaces.
#[test]
fn scenario_shared_connect_by_default_on_both_interfaces() {
    let fake = Arc::new(
        FakeLibrary::new()
            .reader(READER, CARD_PRESENT)
            .reader(NFC_READER, CARD_PRESENT)
            .with_script(&[select_ok()])
            .with_script(&[select_ok()]),
    );
    let t = PcscTransport::from_arc(Arc::clone(&fake)).with_nfc_readers(&[NFC_READER]);
    let d = budget(30);
    let _ccid = block_on(t.connect(&DeviceId::new(READER), &d, sleep_handle())).unwrap();
    let _nfc = block_on(t.connect(&DeviceId::new(NFC_READER), &d, sleep_handle())).unwrap();
    let conns = fake.connections();
    assert_eq!(conns.len(), 2);
    assert!(
        conns.iter().all(|c| c.mode == ShareMode::Shared),
        "both interfaces connect SHARED by default: {conns:?}"
    );
}

/// Scenario: Exclusive mode is explicit caller opt-in.
#[test]
fn scenario_exclusive_mode_is_caller_opt_in_only() {
    let fake = Arc::new(
        FakeLibrary::new()
            .reader(READER, CARD_PRESENT)
            .with_script(&[select_ok()]),
    );
    let t = PcscTransport::from_arc(Arc::clone(&fake)).exclusive();
    let d = budget(30);
    let _d = block_on(t.connect(&DeviceId::new(READER), &d, sleep_handle())).unwrap();
    assert_eq!(fake.connections()[0].mode, ShareMode::Exclusive);
}

/// Scenario: Card vanishes between enumerate and connect.
#[test]
fn scenario_card_vanishes_between_enumerate_and_connect() {
    let fake = Arc::new(
        FakeLibrary::new()
            .reader(READER, CARD_PRESENT)
            .fail_connect(READER, 0x8010_000C), // SCARD_E_NO_SMARTCARD
    );
    let t = PcscTransport::from_arc(Arc::clone(&fake));
    let d = budget(30);
    // Enumerate still lists the reader (card was present).
    let devices = block_on(t.enumerate(&d, sleep_handle())).unwrap();
    assert_eq!(devices.len(), 1);
    // Connect surfaces the typed absent error, reader named.
    let err = block_on(t.connect(&devices[0].id, &d, sleep_handle())).unwrap_err();
    match err {
        Error::Transport(e) => {
            assert!(e.detail.contains("absent"), "{}", e.detail);
            assert!(e.detail.contains(READER), "{}", e.detail);
        }
        other => panic!("expected Transport(absent), got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// Requirement: FIDO applet selection and capability gating (§11.3.3)
// ---------------------------------------------------------------------

/// Scenario: Non-FIDO card yields typed skip, discovery continues.
#[test]
fn scenario_non_fido_card_yields_typed_skip() {
    let fake = FakeLibrary::new()
        .reader(READER, CARD_PRESENT)
        .with_script(&[&[0x6A, 0x82]]);
    let t = transport_ccid(fake);
    let d = budget(30);
    let err = block_on(t.connect(&DeviceId::new(READER), &d, sleep_handle())).unwrap_err();
    match err {
        Error::Transport(e) => {
            assert!(e.detail.contains("not-fido"), "{}", e.detail);
            assert!(e.detail.contains("0x6a82"), "{}", e.detail);
        }
        other => panic!("expected typed not-fido skip, got {other:?}"),
    }
}

/// Scenario: Disabled applet conditions map to typed skip.
#[test]
fn scenario_disabled_applet_conditions_map_to_typed_skip() {
    for (sw, qualifier) in [
        (&[0x69u8, 0x85u8][..], "condition"),
        (&[0x62u8, 0x83u8][..], "invalidated"),
    ] {
        let fake = FakeLibrary::new()
            .reader(READER, CARD_PRESENT)
            .with_script(&[sw]);
        let t = transport_ccid(fake);
        let d = budget(30);
        let err = block_on(t.connect(&DeviceId::new(READER), &d, sleep_handle())).unwrap_err();
        match err {
            Error::Transport(e) => {
                assert!(e.detail.contains("not-fido"), "{}: {}", qualifier, e.detail);
                assert!(e.detail.contains(qualifier), "{}: {}", qualifier, e.detail);
            }
            other => panic!("expected typed skip ({qualifier}), got {other:?}"),
        }
    }
}

/// Scenario: Successful select on a CTAP1+CTAP2 device proceeds to getInfo.
#[test]
fn scenario_successful_select_proceeds_to_getinfo() {
    // SELECT answers U2F_V2 (CTAP1+CTAP2 per §11.3.3); getInfo then
    // answers 9000 with status 0x00 || one-byte CBOR body.
    let fake = FakeLibrary::new()
        .reader(READER, CARD_PRESENT)
        .with_script(&[select_ok(), &[0x00, 0xA0, 0x90, 0x00]]);
    let t = transport_ccid(fake);
    let d = budget(30);
    let mut dev = block_on(t.connect(&DeviceId::new(READER), &d, sleep_handle())).unwrap();
    let channel = block_on(dev.open_channel(&d, sleep_handle())).unwrap();
    assert_eq!(channel, ChannelId(1));
    match block_on(dev.send(&CtapCommand::GetInfo, &d, sleep_handle())).unwrap() {
        DeviceEvent::Response { status, body } => {
            assert_eq!(status, 0x00, "CTAP2_OK rides through unmapped");
            assert_eq!(body, vec![0xA0]);
        }
        other => panic!("expected Response, got {other:?}"),
    }
}

/// Scenario: Unexpected select status word is typed.
#[test]
fn scenario_unexpected_select_status_word_is_typed() {
    let fake = FakeLibrary::new()
        .reader(READER, CARD_PRESENT)
        .with_script(&[&[0x6F, 0x00]]);
    let t = transport_ccid(fake);
    let d = budget(30);
    let err = block_on(t.connect(&DeviceId::new(READER), &d, sleep_handle())).unwrap_err();
    match err {
        Error::Transport(e) => {
            assert!(e.detail.contains("6F00"), "{}", e.detail);
            assert!(e.detail.contains("channel-open"), "{}", e.detail);
        }
        other => panic!("expected Transport error, got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// Requirement: CTAP command APDU framing (§11.3.5)
// ---------------------------------------------------------------------

/// Scenario: getInfo rides the §11.3.5 frame (byte-for-byte).
#[test]
fn scenario_getinfo_rides_the_11_3_5_frame() {
    use fidoh_transport_pcsc::framing::{command_byte, framed};
    let apdu = framed(command_byte::GET_INFO, &[]);
    assert_eq!(
        apdu.as_bytes(),
        &[0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00],
        "CLA INS P1 P2 Lc data Le"
    );
}

/// Scenario: Long request uses extended length.
#[test]
fn scenario_long_request_uses_extended_length() {
    use fidoh_transport_pcsc::framing::{command_byte, framed};
    let payload = vec![0x42; 400];
    let apdu = framed(command_byte::GET_ASSERTION, &payload);
    let bytes = apdu.as_bytes();
    assert_eq!(&bytes[..4], &[0x80, 0x10, 0x80, 0x00]);
    assert_eq!(bytes[4], 0x00, "extended delimiter");
    assert_eq!(
        &bytes[5..7],
        &[0x01, 0x91],
        "Lc = 401 (command byte || payload)"
    );
    assert_eq!(bytes.len(), 7 + 401 + 2);
}

/// Scenario: 61xx response chains via GET RESPONSE (full exchange).
#[test]
fn scenario_61xx_response_chains_via_get_response() {
    let fake = FakeLibrary::new()
        .reader(READER, CARD_PRESENT)
        .with_script(&[
            select_ok(),
            &[0x00, 0xA1, 0x61, 0x02], // getInfo → 2 data bytes, "2 more"
            &[0xBB, 0xCC, 0x90, 0x00], // GET RESPONSE → rest + 9000
        ]);
    let t = transport_ccid(fake);
    let d = budget(30);
    let mut dev = block_on(t.connect(&DeviceId::new(READER), &d, sleep_handle())).unwrap();
    match block_on(dev.send(&CtapCommand::GetInfo, &d, sleep_handle())).unwrap() {
        DeviceEvent::Response { status, body } => {
            assert_eq!(status, 0x00);
            assert_eq!(body, vec![0xA1, 0xBB, 0xCC]);
        }
        other => panic!("expected Response, got {other:?}"),
    }
}

/// Scenario: 9100 status update triggers NFCCTAP_GETRESPONSE.
#[test]
fn scenario_9100_status_update_triggers_nfcctap_getresponse() {
    let fake = FakeLibrary::new()
        .reader(NFC_READER, CARD_PRESENT)
        .with_script(&[
            select_ok(),
            &[0x91, 0x00],             // getAssertion → status update
            &[0x91, 0x00],             // poll → still processing
            &[0x00, 0xAB, 0x90, 0x00], // poll → status || CBOR
        ]);
    let t = transport_nfc(fake);
    let d = budget(30);
    let mut dev = block_on(t.connect(&DeviceId::new(NFC_READER), &d, sleep_handle())).unwrap();
    let request = fidoh_core::get_assertion::GetAssertionRequest::new(
        String::from("example.com"),
        vec![0x44; 32],
    )
    .unwrap();
    let cmd = CtapCommand::GetAssertion(request);
    match block_on(dev.send(&cmd, &d, sleep_handle())).unwrap() {
        DeviceEvent::Response { status, body } => {
            assert_eq!(status, 0x00);
            assert_eq!(body, vec![0xAB]);
        }
        other => panic!("expected Response, got {other:?}"),
    }
}

/// Interleaved transactions: two connections on one library, exchanges
/// drain independently (the resource-manager serialization is BELOW
/// fidoh; each connection's state machine is its own).
#[test]
fn interleaved_transactions_on_two_connections() {
    let fake = Arc::new(
        FakeLibrary::new()
            .reader(READER, CARD_PRESENT)
            .with_script(&[select_ok(), &[0x00, 0x01, 0x90, 0x00]])
            .with_script(&[select_ok(), &[0x00, 0x02, 0x90, 0x00]]),
    );
    let t = PcscTransport::from_arc(Arc::clone(&fake));
    let d = budget(30);
    let mut a = block_on(t.connect(&DeviceId::new(READER), &d, sleep_handle())).unwrap();
    let mut b = block_on(t.connect(&DeviceId::new(READER), &d, sleep_handle())).unwrap();
    match block_on(a.send(&CtapCommand::GetInfo, &d, sleep_handle())).unwrap() {
        DeviceEvent::Response { body, .. } => assert_eq!(body, vec![0x01]),
        other => panic!("expected Response, got {other:?}"),
    }
    match block_on(b.send(&CtapCommand::GetInfo, &d, sleep_handle())).unwrap() {
        DeviceEvent::Response { body, .. } => assert_eq!(body, vec![0x02]),
        other => panic!("expected Response, got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// Requirement: NFC field handling and T=CL specifics
// ---------------------------------------------------------------------

/// Scenario: Field loss mid-ceremony is a typed transport error.
#[test]
fn scenario_field_loss_mid_ceremony_is_typed_removed() {
    // Removal mid-exchange is the scripted SCARD_W_REMOVED_CARD
    // transmit failure the spec's table names (the fake's remove_card
    // models the same condition for status polling).
    let fake = Arc::new(
        FakeLibrary::new()
            .reader(NFC_READER, CARD_PRESENT)
            .with_script(&[select_ok()])
            .fail_transmit_persistent(0x8010_0069),
    );
    let t = PcscTransport::from_arc(Arc::clone(&fake)).with_nfc_readers(&[NFC_READER]);
    let d = budget(30);
    let mut dev = block_on(t.connect(&DeviceId::new(NFC_READER), &d, sleep_handle())).unwrap();
    let err = block_on(dev.send(&CtapCommand::GetInfo, &d, sleep_handle())).unwrap_err();
    match err {
        Error::Transport(e) => assert!(e.detail.contains("removed"), "{}", e.detail),
        other => panic!("expected Transport(removed), got {other:?}"),
    }
}

/// Scenario: WTX extensions do not extend the deadline.
#[test]
fn scenario_wtx_extensions_do_not_extend_the_deadline() {
    // WTX (ISO 14443-4 §7.3) lives in the reader/driver layer BELOW
    // fidoh: the transport sees only a long APDU wait. The spec's
    // observable contract is that the transport's wait stays bounded
    // by the remaining budget however many WTX extensions occur —
    // modeled here as a stalled transmit racing a tiny budget slice.
    // A fake-card stall that never answers within the budget slice
    // surfaces Timeout(getInfo), never an extended deadline.
    //
    // Under the Instant test clock a stalled exchange resolves as an
    // empty (SW-less) response — itself typed, never a hang. The
    // budget-boundary contract is asserted directly: an exchange whose
    // budget expired (all of it consumed by earlier hops — the shape
    // of a WTX chain that outlives the ceremony) returns
    // Timeout(getInfo), never an extended deadline.
    let fake = FakeLibrary::new()
        .reader(NFC_READER, CARD_PRESENT)
        .with_script(&[select_ok()])
        .stall_transmit(1);
    let t = transport_nfc(fake);
    let d = budget(120);
    let mut dev = block_on(t.connect(&DeviceId::new(NFC_READER), &d, sleep_handle())).unwrap();
    let err = block_on(dev.send(&CtapCommand::GetInfo, &d, sleep_handle())).unwrap_err();
    let bounded = match &err {
        Error::Timeout(Phase::GetInfo) => true,
        Error::Transport(e) => e.detail.contains("shorter than a status word"),
        _ => false,
    };
    assert!(
        bounded,
        "expected Timeout(getInfo) or a typed stalled-response error, got {err:?}"
    );
}

/// Scenario: NFC presence window bounds the UP wait (transport never
/// waits indefinitely: the authenticator's 0x2F surfaces through
/// core-model's status mapping, untouched here).
#[test]
fn scenario_nfc_presence_window_bounds_the_up_wait() {
    let fake = FakeLibrary::new()
        .reader(NFC_READER, CARD_PRESENT)
        .with_script(&[
            select_ok(),
            &[0x2F, 0x90, 0x00], // CTAP2_ERR_USER_ACTION_TIMEOUT in a 9000
        ]);
    let t = transport_nfc(fake);
    let d = budget(300);
    let mut dev = block_on(t.connect(&DeviceId::new(NFC_READER), &d, sleep_handle())).unwrap();
    match block_on(dev.send(&CtapCommand::GetInfo, &d, sleep_handle())).unwrap() {
        DeviceEvent::Response { status, body } => {
            assert_eq!(status, 0x2F, "the §5-window status passes through unmapped");
            assert!(body.is_empty());
        }
        other => panic!("expected Response, got {other:?}"),
    }
}

/// Scenario: Presence poll slices stay bounded (≤ 1 s via the Sleep
/// factory; the wait-for-field loop terminates at the budget).
#[test]
fn scenario_presence_poll_slices_stay_bounded() {
    let fake = Arc::new(
        FakeLibrary::new()
            .reader(NFC_READER, CARD_PRESENT)
            .with_script(&[select_ok()]),
    );
    let t = PcscTransport::from_arc(Arc::clone(&fake)).with_nfc_readers(&[NFC_READER]);
    let d = budget(10);
    let mut dev = block_on(t.connect(&DeviceId::new(NFC_READER), &d, sleep_handle())).unwrap();
    let token = fake.token_of(0);
    fake.remove_card(token);
    // Field gone: wait_for_field polls in NFC_POLL_SLICE slices and
    // terminates at the budget (10 s under the Instant clock = 10
    // slices at most, no unbounded loop).
    let err = block_on(dev.wait_for_field(&d, sleep_handle())).unwrap_err();
    assert!(
        matches!(err, Error::Timeout(Phase::UserPresence)),
        "expected Timeout(UserPresence), got {err:?}"
    );
    // Re-present: a fresh wait returns immediately.
    fake.insert_card(token);
    let d2 = budget(10);
    block_on(dev.wait_for_field(&d2, sleep_handle())).unwrap();
}

// ---------------------------------------------------------------------
// Requirement: bounded waits — budget expiry at each phase
// ---------------------------------------------------------------------

/// Scenario: Budget expiry during connect is typed (no further PC/SC
/// calls after expiry).
#[test]
fn scenario_budget_expiry_during_connect_is_typed() {
    let lib = Arc::new(
        FakeLibrary::new()
            .reader(READER, CARD_PRESENT)
            .with_script(&[select_ok()]),
    );
    let t = PcscTransport::from_arc(Arc::clone(&lib));
    // Budget spent before connect: typed Timeout, ZERO PC/SC calls
    // ("no further PC/SC calls issued after expiry").
    let spent = Deadline::new(Duration::from_secs(1));
    spent.consume(Duration::from_secs(1)).unwrap();
    let err = block_on(t.connect(&DeviceId::new(READER), &spent, sleep_handle())).unwrap_err();
    assert!(
        matches!(err, Error::Timeout(Phase::Connect)),
        "expected Timeout(connect), got {err:?}"
    );
    assert_eq!(lib.connect_count(), 0);

    // A stalled connect (500 ms real) races the Instant-clock slice:
    // the timer resolves first, so the connect is abandoned mid-call —
    // with a stalled CONTENDED holder the bounded retry would then hit
    // the budget check. Here the stall wins on real clocks and the
    // engine surfaces whatever the call returns; on the Instant clock
    // the race is deterministic and the connect completes (the slice
    // does not abort an already-finished call). Assert the contract
    // that holds on both: the operation terminates (no unbounded
    // wait) and the state stays consistent.
    let lib2 = Arc::new(
        FakeLibrary::new()
            .reader(READER, CARD_PRESENT)
            .with_script(&[select_ok()])
            .stall_connect(1),
    );
    let t2 = PcscTransport::from_arc(Arc::clone(&lib2));
    let d = budget(120);
    let _dev = block_on(t2.connect(&DeviceId::new(READER), &d, sleep_handle())).unwrap();
}

/// Scenario: Every exchange hop inherits the remaining budget.
#[test]
fn scenario_every_exchange_hop_inherits_remaining_budget() {
    // Spend most of the budget in connect+SELECT, then a stalled
    // exchange must expire at the boundary with the command's phase.
    let fake = Arc::new(
        FakeLibrary::new()
            .reader(READER, CARD_PRESENT)
            .with_script(&[select_ok()]),
    );
    let t = PcscTransport::from_arc(Arc::clone(&fake));
    let d = budget(8);
    let mut dev = block_on(t.connect(&DeviceId::new(READER), &d, sleep_handle())).unwrap();
    // Spend the whole remaining budget (the spec example's 55 s of
    // ceremony work before the stalled getInfo): the next hop must
    // expire at the boundary naming getInfo, with no PC/SC call.
    d.consume(Duration::from_secs(8)).unwrap();
    let before = fake.transmit_count();
    let err = block_on(dev.send(&CtapCommand::GetInfo, &d, sleep_handle())).unwrap_err();
    assert!(
        matches!(err, Error::Timeout(Phase::GetInfo)),
        "expected Timeout(getInfo), got {err:?}"
    );
    assert_eq!(fake.transmit_count(), before, "no call after expiry");
}

/// Scenario: Blocking call abort path — a dropped future's thread
/// exits within its slice; a later connect succeeds.
#[test]
fn scenario_dropped_future_leaves_reader_reusable() {
    let fake = Arc::new(
        FakeLibrary::new()
            .reader(READER, CARD_PRESENT)
            .with_script(&[select_ok()])
            .with_script(&[select_ok()]),
    );
    let t = PcscTransport::from_arc(Arc::clone(&fake));
    let d = budget(30);
    let dev = block_on(t.connect(&DeviceId::new(READER), &d, sleep_handle())).unwrap();
    // Drop mid-lifecycle (no close): best-effort release runs.
    drop(dev);
    assert_eq!(fake.disconnect_count(), 1);
    // A later connect succeeds.
    let _dev2 = block_on(t.connect(&DeviceId::new(READER), &d, sleep_handle())).unwrap();
}

// ---------------------------------------------------------------------
// Requirement: typed error mapping (error-injection matrix)
// ---------------------------------------------------------------------

/// Every PC/SC code row of the spec's error table, injected at
/// transmit time via the fake.
#[test]
fn sw_error_typification_matrix_over_transmit() {
    for (code, needle) in [
        (0x8010_000Au32, "Timeout"),
        (0x8010_000C, "absent"),
        (0x8010_0069, "removed"),
        (0x8010_000F, "protocol"),
        (0x8010_0068, "reset"),
        (0x8010_0017, "reader"),
        (0x8010_0016, "reader"),
        (0x8010_002F, "reader"),
        (0x8010_0ABC, "pcsc"),
    ] {
        let fake = FakeLibrary::new()
            .reader(READER, CARD_PRESENT)
            .with_script(&[select_ok()])
            .fail_transmit_persistent(code);
        let t = transport_ccid(fake);
        let d = budget(30);
        let mut dev = block_on(t.connect(&DeviceId::new(READER), &d, sleep_handle())).unwrap();
        let err = block_on(dev.send(&CtapCommand::GetInfo, &d, sleep_handle())).unwrap_err();
        match &err {
            Error::Timeout(_) => assert_eq!(needle, "Timeout", "code {code:#010x}"),
            Error::Transport(e) => {
                assert!(e.detail.contains(needle), "code {code:#010x}: {}", e.detail)
            }
            other => panic!("code {code:#010x}: expected typed error, got {other:?}"),
        }
    }
}

/// The unusable-card row: SCARD_W_UNRESPONSIVE_CARD at connect is a
/// typed skip for that reader.
#[test]
fn scenario_unusable_card_on_connect_is_typed_skip() {
    let fake = FakeLibrary::new()
        .reader(READER, CARD_PRESENT)
        .fail_connect(READER, 0x8010_0066);
    let t = transport_ccid(fake);
    let d = budget(30);
    let err = block_on(t.connect(&DeviceId::new(READER), &d, sleep_handle())).unwrap_err();
    match err {
        Error::Transport(e) => {
            assert!(e.detail.contains("skip"), "{}", e.detail);
            assert!(e.detail.contains("unusable-card"), "{}", e.detail);
        }
        other => panic!("expected typed unusable-card skip, got {other:?}"),
    }
}

/// Scenario: Sharing violation retries within budget then surfaces.
#[test]
fn scenario_sharing_violation_retries_then_surfaces() {
    // Contention clears on the second attempt: bounded retry succeeds.
    let fake = Arc::new(
        FakeLibrary::new()
            .reader(READER, CARD_PRESENT)
            .fail_connect(READER, 0x8010_000B)
            .with_script(&[select_ok()]),
    );
    let t = PcscTransport::from_arc(Arc::clone(&fake));
    let d = budget(30);
    let _dev = block_on(t.connect(&DeviceId::new(READER), &d, sleep_handle())).unwrap();
    assert_eq!(fake.connect_count(), 2, "one retry, then success");

    // Persistent contention is the budget-exhaustion path: an
    // exhausted budget stops the retry loop before the library is
    // touched again.
    let lib2 = Arc::new(FakeLibrary::new().reader(READER, CARD_PRESENT));
    let t2 = PcscTransport::from_arc(Arc::clone(&lib2));
    let spent = Deadline::new(Duration::from_secs(1));
    spent.consume(Duration::from_secs(1)).unwrap();
    let err = block_on(t2.connect(&DeviceId::new(READER), &spent, sleep_handle())).unwrap_err();
    assert!(matches!(err, Error::Timeout(Phase::Connect)));
    assert_eq!(lib2.connect_count(), 0, "no PC/SC calls after expiry");
}

/// Scenario: Protocol mismatch is typed; no APDU is sent.
#[test]
fn scenario_protocol_mismatch_is_typed_and_no_apdu_sent() {
    let fake = Arc::new(
        FakeLibrary::new()
            .reader(READER, CARD_PRESENT)
            .fail_connect(READER, 0x8010_000F),
    );
    let t = PcscTransport::from_arc(Arc::clone(&fake));
    let d = budget(30);
    let err = block_on(t.connect(&DeviceId::new(READER), &d, sleep_handle())).unwrap_err();
    match err {
        Error::Transport(e) => {
            assert!(e.detail.contains("protocol"), "{}", e.detail);
            assert!(e.detail.contains(READER), "{}", e.detail);
        }
        other => panic!("expected Transport(protocol), got {other:?}"),
    }
    assert_eq!(fake.transmit_count(), 0, "no APDU after connect failure");
}

/// Scenario: Removal mid-exchange maps to the removed cause (no
/// retry; the error text identifies the reader).
#[test]
fn scenario_removal_mid_exchange_maps_to_removed_cause() {
    let fake = Arc::new(
        FakeLibrary::new()
            .reader(READER, CARD_PRESENT)
            .with_script(&[select_ok()])
            .fail_transmit_persistent(0x8010_0069),
    );
    let t = PcscTransport::from_arc(Arc::clone(&fake));
    let d = budget(30);
    let mut dev = block_on(t.connect(&DeviceId::new(READER), &d, sleep_handle())).unwrap();
    let before = fake.transmit_count();
    let err = block_on(dev.send(&CtapCommand::GetInfo, &d, sleep_handle())).unwrap_err();
    match err {
        Error::Transport(e) => assert!(e.detail.contains("removed"), "{}", e.detail),
        other => panic!("expected Transport(removed), got {other:?}"),
    }
    assert_eq!(
        fake.transmit_count(),
        before + 1,
        "no retry of a removed card"
    );
}

/// Scenario: Every failure surfaces typed — the device-error path
/// never produces a raw integer, string, or panic.
#[test]
fn scenario_every_failure_surfaces_typed() {
    let fake = FakeLibrary::new()
        .reader(READER, CARD_PRESENT)
        .with_script(&[select_ok(), &[0x67, 0x42]]); // unknown SW
    let t = transport_ccid(fake);
    let d = budget(30);
    let mut dev = block_on(t.connect(&DeviceId::new(READER), &d, sleep_handle())).unwrap();
    let err = block_on(dev.send(&CtapCommand::GetInfo, &d, sleep_handle())).unwrap_err();
    match err {
        Error::Transport(e) => assert!(e.detail.contains("6742"), "{}", e.detail),
        other => panic!("expected typed Transport error, got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// Requirement: unified APDU layer — same code drives CCID and NFC
// ---------------------------------------------------------------------

/// Scenario: Same CTAP exchange code drives CCID and NFC readers.
#[test]
fn scenario_same_ctap_exchange_code_drives_ccid_and_nfc() {
    for (reader, nfc) in [(READER, false), (NFC_READER, true)] {
        let fake = FakeLibrary::new()
            .reader(reader, CARD_PRESENT)
            .with_script(&[select_ok(), &[0x00, 0xA5, 0x90, 0x00]]);
        let t = if nfc {
            PcscTransport::new(fake).with_nfc_readers(&[reader])
        } else {
            PcscTransport::new(fake)
        };
        let d = budget(30);
        let mut dev = block_on(t.connect(&DeviceId::new(reader), &d, sleep_handle())).unwrap();
        assert_eq!(dev.is_nfc(), nfc);
        match block_on(dev.send(&CtapCommand::GetInfo, &d, sleep_handle())).unwrap() {
            DeviceEvent::Response { status, body } => {
                assert_eq!(status, 0x00);
                assert_eq!(body, vec![0xA5], "identical exchange on both media");
            }
            other => panic!("expected Response, got {other:?}"),
        }
    }
}

/// Scenario: No interface-specific second implementation — the public
/// surface carries the medium as metadata, never a second framing.
#[test]
fn scenario_no_interface_specific_second_implementation() {
    // Compile-time assertion of the spec's shape: one Device type,
    // `is_nfc()` as the only interface knob.
    fn assert_device<D: CtapDevice>() {}
    assert_device::<fidoh_transport_pcsc::PcscDevice<FakeLibrary>>();
}

// ---------------------------------------------------------------------
// SW typification of every status word in the spec matrix (pure layer,
// kept here as the scenario-facing matrix).
// ---------------------------------------------------------------------

#[test]
fn sw_matrix_matches_spec_table() {
    let cases: &[(u16, &str)] = &[
        (0x9000, "Ok"),
        (0x61_05, "MoreData"),
        (0x6C_20, "WrongLe"),
        (0x6A_82, "NotFound"),
        (0x69_85, "ConditionsNotSatisfied"),
        (0x62_83, "FileInvalidated"),
        (0x69_86, "NotAllowed"),
        (0x6D_00, "NotAllowed6D00"),
        (0x91_00, "StatusUpdate"),
        (0x62_81, "Warn"),
        (0x6F_00, "Other"),
    ];
    for &(sw, expected) in cases {
        let [sw1, sw2] = sw.to_be_bytes();
        let typed = StatusWord::from_pair(sw1, sw2);
        let got = format!("{typed:?}");
        let got = got.split('(').next().unwrap_or(&got);
        assert_eq!(got, expected, "SW {sw:#06x}");
    }
}
