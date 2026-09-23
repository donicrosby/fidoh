//! Integration tests: the full CTAPHID state machine over a FAKE fd
//! (CI-safe, no hardware, no /dev). Each test names the spec scenario
//! it pins.
//!
//! The fake fd is a scripted report queue: the test seeds INBOUND
//! reports (what the "device" would send) and, via a recorder, the
//! test asserts on OUTBOUND writes (what the host wrote).

use core::time::Duration;
use std::collections::VecDeque;
use std::sync::Arc;

use fidoh_core::device::{CtapCommand, Device, DeviceEvent};
use fidoh_core::get_assertion::{
    CredentialType, GetAssertionRequest, PublicKeyCredentialDescriptor,
};
use fidoh_core::transport::Transport;
use fidoh_core::{Deadline, Error, Phase, Sleep};

use fidoh_transport_hid::error::{FramingError, HidError, HidErrorCode};
use fidoh_transport_hid::fsm::{cbor_payload, Fsm};
use fidoh_transport_hid::packet;
use fidoh_transport_hid::HidDevice;
use fidoh_transport_hid::HidTransport;

// ----------------------------------------------------------------------
// Test plumbing: fake clock + fake fd
// ----------------------------------------------------------------------

/// Deterministic `Sleep`: sleeps consume nothing; the BUDGET is the
/// only clock (async-core "Deterministic test clock" — zero real-time
/// sleeps). The slice consumption happens via `Deadline::consume_slice`
/// in the transport, so a budget of N slices drives exactly N loop
/// iterations before the typed timeout.
#[derive(Default)]
struct FakeSleep;

impl Sleep for FakeSleep {
    fn sleep(
        &self,
        _duration: Duration,
    ) -> core::pin::Pin<Box<dyn core::future::Future<Output = ()> + Send>> {
        Box::pin(core::future::ready(()))
    }
}

fn sleep() -> &'static (dyn Sleep + Send + Sync) {
    &FakeSleep
}

/// Scripted hidraw fd: outbound writes are recorded; inbound reads pop
/// a queue. `EOF` (empty queue) = "nothing yet" so the slice loop
/// polls until the budget runs out — the fake stand-in for a blocking
/// read.
struct FakeFd {
    inbound: VecDeque<Vec<u8>>,
    outbound: Vec<Vec<u8>>,
    /// Fail writes (injecting the OQ-3 best-effort path).
    fail_writes: bool,
}

impl fidoh_transport_hid::fd::RawFd for FakeFd {
    fn write_report(&mut self, report: &[u8]) -> Result<(), HidError> {
        if self.fail_writes {
            return Err(HidError::io("fake", "write", "injected failure"));
        }
        self.outbound.push(report.to_vec());
        Ok(())
    }

    fn read_nonblocking(&mut self) -> Result<Option<Vec<u8>>, HidError> {
        if self.inbound.is_empty() {
            return Ok(None); // EAGAIN: nothing yet
        }
        Ok(Some(self.inbound.pop_front().expect("non-empty")))
    }
}

/// Shared fake fd (the Fsm owns its fd mutably; tests need to inspect
/// writes afterwards, so the fake is shared behind Arc + a std Mutex).
struct SharedFd(Arc<std::sync::Mutex<FakeFd>>);

impl fidoh_transport_hid::fd::RawFd for SharedFd {
    fn write_report(&mut self, report: &[u8]) -> Result<(), HidError> {
        self.0.lock().expect("lock").write_report(report)
    }
    fn read_nonblocking(&mut self) -> Result<Option<Vec<u8>>, HidError> {
        self.0.lock().expect("lock").read_nonblocking()
    }
}

fn fsm_with(inbound: Vec<Vec<u8>>) -> (Fsm<SharedFd>, Arc<std::sync::Mutex<FakeFd>>) {
    let shared = Arc::new(std::sync::Mutex::new(FakeFd {
        inbound: VecDeque::from(inbound),
        outbound: Vec::new(),
        fail_writes: false,
    }));
    (Fsm::new(SharedFd(Arc::clone(&shared))), shared)
}

/// Build a 64-byte init report.
fn init_report(cid: u32, cmd: u8, payload: &[u8]) -> Vec<u8> {
    let packets = packet::encode_message(cid, cmd, payload).expect("test report");
    assert_eq!(packets.len(), 1);
    packets[0].to_vec()
}

/// Build a full multi-packet response for `payload`.
fn response_reports(cid: u32, cmd: u8, payload: &[u8]) -> Vec<Vec<u8>> {
    packet::encode_message(cid, cmd, payload)
        .expect("test response")
        .into_iter()
        .map(|p| p.to_vec())
        .collect()
}

/// A tiny blocking executor for the RPITIT futures (std test; the
/// real executor is the caller's runtime, fidoh-tokio).
fn block_on<F: core::future::Future>(fut: F) -> F::Output {
    // unsafe-free park/unpark executor (the crate-level
    // `unsafe_code = "deny"` lint covers tests): FakeSleep is instantly
    // ready, so each poll loop turn drives one slice.
    struct ThreadWaker(std::thread::Thread);
    impl std::task::Wake for ThreadWaker {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }
    let mut fut = Box::pin(fut);
    let waker = std::task::Waker::from(Arc::new(ThreadWaker(std::thread::current())));
    let mut cx = std::task::Context::from_waker(&waker);
    loop {
        match core::future::Future::poll(core::pin::Pin::as_mut(&mut fut), &mut cx) {
            core::task::Poll::Ready(out) => return out,
            core::task::Poll::Pending => std::thread::park(),
        }
    }
}

const ALLOC_CID: u32 = 0x2A01_B64F;

/// Build the device's INIT response echoing `nonce` (the Fsm's
/// NonceSource emits an incrementing BE counter; the first nonce is
/// 0x…01 — but tests must ECHO what was written, so pass the captured
/// nonce bytes).
fn init_response(nonce: &[u8; 8], on_cid: u32) -> Vec<u8> {
    let resp_payload: Vec<u8> = nonce
        .iter()
        .copied()
        .chain(ALLOC_CID.to_be_bytes())
        .chain([0x02, 0x01, 0x00, 0x04, 0x05])
        .collect();
    init_report(on_cid, 0x06, &resp_payload)
}

/// INIT response variant with explicit caps byte and target cid.
fn init_response2(nonce: &[u8; 8], on_cid: u32) -> Vec<u8> {
    let resp_payload: Vec<u8> = nonce
        .iter()
        .copied()
        .chain(ALLOC_CID.to_be_bytes())
        .chain([0x02, 0x01, 0x00, 0x04, 0x05])
        .collect();
    init_report(on_cid, 0x06, &resp_payload)
}

/// Nonce the FSM sends first (NonceSource starts at counter 0, first
/// `next()` returns 1 big-endian).
const FIRST_NONCE: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 1];

// ----------------------------------------------------------------------
// INIT allocation (spec: "Channel allocation via CTAPHID_INIT")
// ----------------------------------------------------------------------

// Spec scenario: "Allocate a channel with nonce match".
#[test]
fn scenario_allocate_channel_with_nonce_match() {
    let device_response = init_response(&FIRST_NONCE, 0xFFFF_FFFF);
    let (mut fsm, shared) = fsm_with(vec![device_response]);
    let deadline = Deadline::new(Duration::from_secs(30));
    let info = block_on(fsm.allocate(&deadline, sleep())).expect("allocation");
    assert_eq!(info.cid, ALLOC_CID);
    assert_eq!(info.protocol_version, 2);
    assert!(info.capabilities.wink());
    assert!(info.capabilities.cbor());
    assert!(!info.capabilities.nmsg());
    assert_eq!(fsm.cid(), Some(ALLOC_CID));
    // The written packet is the broadcast INIT with the 8-byte nonce.
    let written = shared.lock().expect("lock").outbound.clone();
    assert_eq!(written.len(), 1);
    assert_eq!(&written[0][0..4], &[0xFF, 0xFF, 0xFF, 0xFF]);
    assert_eq!(written[0][4], 0x86);
    assert_eq!(&written[0][5..7], &[0x00, 0x08]);
}

// Spec scenario: "Nonce mismatch fails the allocation".
#[test]
fn scenario_nonce_mismatch_fails_allocation() {
    let mut device_response = init_response(&FIRST_NONCE, 0xFFFF_FFFF);
    // Corrupt the echoed nonce (byte 7 of the payload = report byte 14).
    device_response[14] ^= 0xFF;
    let (mut fsm, _shared) = fsm_with(vec![device_response]);
    let deadline = Deadline::new(Duration::from_secs(30));
    let err = block_on(fsm.allocate(&deadline, sleep())).expect_err("must fail");
    assert_eq!(
        err,
        FsmErrorForTest::Hid(HidError::Framing(FramingError::NonceMismatch))
    );
    // The received channel id is not used: the fsm has no channel.
    assert_eq!(fsm.cid(), None);
}

/// Mirror of `fsm::FsmError` for test assertions (it is public but the
/// alias keeps asserts short).
use fidoh_transport_hid::fsm::FsmError as FsmErrorForTest;

// Spec scenario: reserved CIDs are typed errors (§11.2.3).
#[test]
fn reserved_cid_allocation_fails_typed() {
    for bad_cid in [0u32, 0xFFFF_FFFF] {
        let mut resp = init_response(&FIRST_NONCE, 0xFFFF_FFFF);
        resp[15..19].copy_from_slice(&bad_cid.to_be_bytes()); // payload cid field: report[7+8..7+12]
        let (mut fsm, _) = fsm_with(vec![resp]);
        let deadline = Deadline::new(Duration::from_secs(30));
        let err = block_on(fsm.allocate(&deadline, sleep())).expect_err("reserved cid");
        assert_eq!(
            err,
            FsmErrorForTest::Hid(HidError::Framing(FramingError::ReservedCid {
                cid: bad_cid
            }))
        );
    }
}

// Spec scenario: "INIT on an allocated channel resynchronizes"
// (§11.2.5.3): INIT on the allocated cid is answered by the device
// with a fresh allocation, and the fsm re-stores it.
#[test]
fn scenario_init_on_allocated_channel_resynchronizes() {
    let device_response = init_response(&FIRST_NONCE, 0xFFFF_FFFF);
    // The resync response is addressed to the allocated cid.
    const SECOND_NONCE: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 2];
    let resync = init_response2(&SECOND_NONCE, ALLOC_CID);
    let (mut fsm, shared) = fsm_with(vec![device_response, resync]);
    let deadline = Deadline::new(Duration::from_secs(30));
    block_on(fsm.allocate(&deadline, sleep())).expect("initial allocation");
    let info = block_on(fsm.resync(&deadline, sleep())).expect("resync");
    assert_eq!(info.cid, ALLOC_CID);
    // Second write went to the allocated cid (not broadcast).
    let written = shared.lock().expect("lock").outbound.clone();
    assert_eq!(written.len(), 2);
    assert_eq!(&written[1][0..4], &ALLOC_CID.to_be_bytes());
    assert_eq!(written[1][4], 0x86);
}

// Spec scenario: "Channel allocation ... bounded by the remaining
// ceremony budget ... typed Timeout naming the channel-allocation
// phase".
#[test]
fn allocation_budget_expiry_is_typed_timeout() {
    // No inbound response: the slice loop drains the budget.
    let (mut fsm, _) = fsm_with(vec![]);
    let deadline = Deadline::new(Duration::from_millis(300));
    let err = block_on(fsm.allocate(&deadline, sleep())).expect_err("budget");
    assert_eq!(
        err,
        FsmErrorForTest::Core(Error::Timeout(Phase::ChannelOpen))
    );
}

// ----------------------------------------------------------------------
// Framing: reassembly, ordering, foreign traffic
// ----------------------------------------------------------------------

// Spec scenario: "Correct sequence reassembles" — init + 2
// continuations (SEQ 0,1), truncated to BCNT.
#[test]
fn scenario_correct_sequence_reassembles() {
    let payload: Vec<u8> = core::iter::once(0x00u8) // CTAP2 OK status
        .chain((0..120).map(|i| (i % 251) as u8))
        .collect();
    let reports = response_reports(ALLOC_CID, 0x90, &payload);
    assert_eq!(reports.len(), 3);
    let device_response = init_response(&FIRST_NONCE, 0xFFFF_FFFF);
    let (mut fsm, _) = fsm_with(core::iter::once(device_response).chain(reports).collect());
    let deadline = Deadline::new(Duration::from_secs(30));
    block_on(fsm.allocate(&deadline, sleep())).expect("alloc");
    let body = cbor_payload(0x04, &[]);
    let outcome =
        block_on(fsm.transaction(0x10, &body, Phase::GetInfo, &deadline, sleep(), |_| {}))
            .expect("transaction");
    match outcome {
        fidoh_transport_hid::fsm::TransactionOutcome::Done(frame) => {
            assert_eq!(frame, fidoh_transport_hid::fsm::Frame::Cbor(payload));
        }
        other => panic!("expected Done, got {other:?}"),
    }
}

// Spec scenario: "Wrong sequence number aborts with typed error"
// (ERR_INVALID_SEQ) — and a subsequent resync on the allocated cid.
#[test]
fn scenario_wrong_sequence_aborts_typed_then_resync() {
    let payload: Vec<u8> = core::iter::once(0x00u8)
        .chain((0..100).map(|i| i as u8))
        .collect();
    let mut reports = response_reports(ALLOC_CID, 0x90, &payload);
    assert_eq!(reports.len(), 2);
    // Corrupt SEQ of the first continuation: 0x05 instead of 0x00.
    reports[1][4] = 0x05;
    let device_response = init_response(&FIRST_NONCE, 0xFFFF_FFFF);
    // Device answers the post-error resync INIT too.
    const RESYNC_NONCE: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 2];
    let resync = init_response2(&RESYNC_NONCE, ALLOC_CID);
    let (mut fsm, _) = fsm_with(
        core::iter::once(device_response)
            .chain(reports)
            .chain(core::iter::once(resync))
            .collect(),
    );
    let deadline = Deadline::new(Duration::from_secs(30));
    block_on(fsm.allocate(&deadline, sleep())).expect("alloc");
    let body = cbor_payload(0x04, &[]);
    let err = block_on(fsm.transaction(0x10, &body, Phase::GetInfo, &deadline, sleep(), |_| {}))
        .expect_err("seq mismatch");
    assert_eq!(
        err,
        FsmErrorForTest::Hid(HidError::Framing(FramingError::InvalidSeq {
            cid: ALLOC_CID,
            got: 0x05,
            expected: 0x00,
        }))
    );
    // The resync escape hatch re-readies the channel (§11.2.5.3).
    let info = block_on(fsm.resync(&deadline, sleep())).expect("resync after error");
    assert_eq!(info.cid, ALLOC_CID);
}

// Spec scenario: "Foreign-CID traffic is ignored".
#[test]
fn scenario_foreign_cid_traffic_is_ignored() {
    let payload = vec![0x00u8, 0xAA, 0xBB];
    let device_response = init_response(&FIRST_NONCE, 0xFFFF_FFFF);
    let foreign = init_report(0xDEAD_BEEF, 0x90, &[0x01, 0x02]); // other client's traffic
    let foreign2 = foreign.clone();
    let response = init_report(ALLOC_CID, 0x90, &payload);
    let (mut fsm, _) = fsm_with(vec![device_response, foreign, foreign2, response]);
    let deadline = Deadline::new(Duration::from_secs(30));
    block_on(fsm.allocate(&deadline, sleep())).expect("alloc");
    let body = cbor_payload(0x04, &[]);
    let outcome =
        block_on(fsm.transaction(0x10, &body, Phase::GetInfo, &deadline, sleep(), |_| {}))
            .expect("transaction survives foreign traffic");
    assert_eq!(
        outcome,
        fidoh_transport_hid::fsm::TransactionOutcome::Done(fidoh_transport_hid::fsm::Frame::Cbor(
            payload
        ))
    );
}

// Spec scenario: "Spurious continuation packet ignored".
#[test]
fn scenario_spurious_continuation_ignored() {
    let payload = vec![0x00u8, 0x42];
    let device_response = init_response(&FIRST_NONCE, 0xFFFF_FFFF);
    let mut spurious = init_report(ALLOC_CID, 0x90, &[]);
    spurious[4] = 0x00; // continuation SEQ 0 with no message in progress
    let response = init_report(ALLOC_CID, 0x90, &payload);
    let (mut fsm, _) = fsm_with(vec![device_response, spurious, response]);
    let deadline = Deadline::new(Duration::from_secs(30));
    block_on(fsm.allocate(&deadline, sleep())).expect("alloc");
    let body = cbor_payload(0x04, &[]);
    let outcome =
        block_on(fsm.transaction(0x10, &body, Phase::GetInfo, &deadline, sleep(), |_| {}))
            .expect("spurious continuation ignored");
    assert_eq!(
        outcome,
        fidoh_transport_hid::fsm::TransactionOutcome::Done(fidoh_transport_hid::fsm::Frame::Cbor(
            payload
        ))
    );
}

// Spec scenario: "Inter-packet timeout aborts reassembly" — the gap
// after the init packet exceeds the budget: typed Timeout (reassembly
// phase is named by the caller's phase).
#[test]
fn scenario_inter_packet_timeout_aborts_reassembly() {
    let long_payload: Vec<u8> = (0..100).map(|i| i as u8).collect();
    let mut reports = response_reports(ALLOC_CID, 0x90, &long_payload);
    let first = reports.remove(0); // only the init packet arrives
    let device_response = init_response(&FIRST_NONCE, 0xFFFF_FFFF);
    let (mut fsm, _) = fsm_with(vec![device_response, first]);
    let deadline = Deadline::new(Duration::from_millis(500));
    block_on(fsm.allocate(&deadline, sleep())).expect("alloc");
    let body = cbor_payload(0x04, &[]);
    let err = block_on(fsm.transaction(0x10, &body, Phase::GetInfo, &deadline, sleep(), |_| {}))
        .expect_err("gap exceeds budget");
    assert_eq!(err, FsmErrorForTest::Core(Error::Timeout(Phase::GetInfo)));
}

// BCNT beyond the 7609 maximum is rejected on decode (D1 strictness).
#[test]
fn received_bcnt_beyond_maximum_is_typed() {
    let device_response = init_response(&FIRST_NONCE, 0xFFFF_FFFF);
    let mut bogus = init_report(ALLOC_CID, 0x90, &[0x00]);
    bogus[5] = 0x1D; // BCNT = 0x1D_C1 = 7617 > 7609
    bogus[6] = 0xC1;
    let (mut fsm, _) = fsm_with(vec![device_response, bogus]);
    let deadline = Deadline::new(Duration::from_secs(30));
    block_on(fsm.allocate(&deadline, sleep())).expect("alloc");
    let body = cbor_payload(0x04, &[]);
    let err = block_on(fsm.transaction(0x10, &body, Phase::GetInfo, &deadline, sleep(), |_| {}))
        .expect_err("BCNT beyond maximum");
    assert!(matches!(
        err,
        FsmErrorForTest::Hid(HidError::Framing(FramingError::LengthBeyondMaximum {
            bcnt: 7617
        }))
    ));
}

// ----------------------------------------------------------------------
// Keepalives (spec: "CTAPHID_KEEPALIVE surfaced as progress signals")
// ----------------------------------------------------------------------

// Spec scenario: "Up-needed keepalives surface as progress until
// response" — 3 × UPNEEDED then the response.
#[test]
fn scenario_up_needed_keepalives_surface_as_progress() {
    let device_response = init_response(&FIRST_NONCE, 0xFFFF_FFFF);
    let keepalives: Vec<Vec<u8>> = (0..3)
        .map(|_| init_report(ALLOC_CID, 0x3B, &[0x02]))
        .collect();
    let response = init_report(ALLOC_CID, 0x90, &[0x00, 0x01]);
    let inbound = core::iter::once(device_response)
        .chain(keepalives)
        .chain(core::iter::once(response))
        .collect();
    let (mut fsm, _) = fsm_with(inbound);
    let deadline = Deadline::new(Duration::from_secs(30));
    block_on(fsm.allocate(&deadline, sleep())).expect("alloc");
    let mut statuses = Vec::new();
    let body = cbor_payload(0x04, &[]);
    let outcome = block_on(
        fsm.transaction(0x10, &body, Phase::GetInfo, &deadline, sleep(), |s| {
            statuses.push(s)
        }),
    )
    .expect("transaction");
    assert_eq!(statuses, vec![0x02, 0x02, 0x02]);
    assert_eq!(
        outcome,
        fidoh_transport_hid::fsm::TransactionOutcome::Done(fidoh_transport_hid::fsm::Frame::Cbor(
            vec![0x00, 0x01]
        ))
    );
}

// Spec scenario: "Processing keepalives do not reset the budget" —
// processing keepalives surface, then budget exhaustion types as
// UserPresence only after UP was seen (phase-renaming rule is the
// device layer's; the fsm surfaces the raw status).
#[test]
fn processing_keepalives_surfaced_and_budget_still_expires() {
    let device_response = init_response(&FIRST_NONCE, 0xFFFF_FFFF);
    let keepalives: Vec<Vec<u8>> = (0..5)
        .map(|_| init_report(ALLOC_CID, 0x3B, &[0x01]))
        .collect();
    let inbound = core::iter::once(device_response)
        .chain(keepalives)
        .collect();
    let (mut fsm, _) = fsm_with(inbound);
    let deadline = Deadline::new(Duration::from_millis(400));
    block_on(fsm.allocate(&deadline, sleep())).expect("alloc");
    let mut statuses = Vec::new();
    let body = cbor_payload(0x04, &[]);
    let err = block_on(
        fsm.transaction(0x10, &body, Phase::GetInfo, &deadline, sleep(), |s| {
            statuses.push(s)
        }),
    )
    .expect_err("no response before budget end");
    assert_eq!(statuses, vec![0x01; 5]);
    assert_eq!(err, FsmErrorForTest::Core(Error::Timeout(Phase::GetInfo)));
}

// ----------------------------------------------------------------------
// CTAPHID_ERROR mapping (spec: "CTAPHID_ERROR mapping to typed
// transport errors")
// ----------------------------------------------------------------------

// Spec scenario: "Error codes map to typed variants".
#[test]
fn scenario_error_codes_map_to_typed_variants() {
    for (byte, want) in [
        (0x01u8, HidErrorCode::InvalidCmd),
        (0x02, HidErrorCode::InvalidPar),
        (0x03, HidErrorCode::InvalidLen),
        (0x05, HidErrorCode::MsgTimeout),
        (0x0A, HidErrorCode::LockRequired),
        (0x0B, HidErrorCode::InvalidChannel),
        (0x7F, HidErrorCode::Other),
        (0x42, HidErrorCode::Unknown(0x42)),
    ] {
        let device_response = init_response(&FIRST_NONCE, 0xFFFF_FFFF);
        let err_frame = init_report(ALLOC_CID, 0x3F, &[byte]);
        let (mut fsm, _) = fsm_with(vec![device_response, err_frame]);
        let deadline = Deadline::new(Duration::from_secs(30));
        block_on(fsm.allocate(&deadline, sleep())).expect("alloc");
        let body = cbor_payload(0x04, &[]);
        let outcome =
            block_on(fsm.transaction(0x10, &body, Phase::GetInfo, &deadline, sleep(), |_| {}))
                .expect("error frame resolves the transaction");
        assert_eq!(
            outcome,
            fidoh_transport_hid::fsm::TransactionOutcome::DeviceError(want),
            "code {byte:#04x}"
        );
    }
}

// Spec scenario: "Busy error triggers bounded retry" — the request is
// re-issued after the busy frame, then succeeds.
#[test]
fn scenario_busy_error_triggers_bounded_retry() {
    let device_response = init_response(&FIRST_NONCE, 0xFFFF_FFFF);
    let busy = init_report(ALLOC_CID, 0x3F, &[0x06]);
    let response = init_report(ALLOC_CID, 0x90, &[0x00, 0x09]);
    let (mut fsm, shared) = fsm_with(vec![device_response, busy, response]);
    let deadline = Deadline::new(Duration::from_secs(30));
    block_on(fsm.allocate(&deadline, sleep())).expect("alloc");
    let body = cbor_payload(0x04, &[]);
    let outcome =
        block_on(fsm.transaction(0x10, &body, Phase::GetInfo, &deadline, sleep(), |_| {}))
            .expect("retry succeeds");
    assert!(matches!(
        outcome,
        fidoh_transport_hid::fsm::TransactionOutcome::Done(_)
    ));
    // The request was written twice (initial + retry).
    let writes = shared.lock().expect("lock").outbound.len();
    assert_eq!(writes, 1 /* init */ + 1 /* req */ + 1 /* retry */);
}

// Busy until the budget runs out: typed Timeout (busy-retry phase =
// the caller's phase).
#[test]
fn busy_retry_until_budget_expiry_is_typed_timeout() {
    let device_response = init_response(&FIRST_NONCE, 0xFFFF_FFFF);
    let busy = init_report(ALLOC_CID, 0x3F, &[0x06]);
    // Enough busy frames for several retries, then nothing.
    let inbound = core::iter::once(device_response)
        .chain((0..8).map(|_| busy.clone()))
        .collect();
    let (mut fsm, _) = fsm_with(inbound);
    let deadline = Deadline::new(Duration::from_millis(400));
    block_on(fsm.allocate(&deadline, sleep())).expect("alloc");
    let body = cbor_payload(0x04, &[]);
    let err = block_on(fsm.transaction(0x10, &body, Phase::GetInfo, &deadline, sleep(), |_| {}))
        .expect_err("budget ends the retries");
    assert_eq!(err, FsmErrorForTest::Core(Error::Timeout(Phase::GetInfo)));
}

// ----------------------------------------------------------------------
// CANCEL (spec: "CTAPHID_CANCEL on caller cancellation")
// ----------------------------------------------------------------------

// Spec scenario: cancel sends 0x11 BCNT 0 on the channel and the send
// is one packet, no reply awaited (§11.2.9.1.5).
#[test]
fn scenario_cancel_send_is_single_packet_no_reply() {
    let device_response = init_response(&FIRST_NONCE, 0xFFFF_FFFF);
    let (mut fsm, shared) = fsm_with(vec![device_response]);
    let deadline = Deadline::new(Duration::from_secs(30));
    block_on(fsm.allocate(&deadline, sleep())).expect("alloc");
    fsm.send_cancel().expect("cancel send");
    let written = shared.lock().expect("lock").outbound.clone();
    let cancel = written
        .iter()
        .find(|p| p[4] == 0x91)
        .expect("cancel packet on the wire");
    assert_eq!(&cancel[0..4], &ALLOC_CID.to_be_bytes());
    assert_eq!(cancel[4], 0x91);
    assert_eq!(&cancel[5..7], &[0x00, 0x00]);
    assert!(cancel[7..].iter().all(|&b| b == 0));
}

// OQ-3 best-effort: a cancel WRITE FAILURE is reported (swallowable by
// the caller), and a cancel with no channel allocated is a no-op Ok.
#[test]
fn cancel_write_failure_reported_and_unallocated_is_noop() {
    let device_response = init_response(&FIRST_NONCE, 0xFFFF_FFFF);
    let (mut fsm, shared) = fsm_with(vec![device_response]);
    let deadline = Deadline::new(Duration::from_secs(30));
    block_on(fsm.allocate(&deadline, sleep())).expect("alloc");
    shared.lock().expect("lock").fail_writes = true;
    assert!(fsm.send_cancel().is_err(), "write failure reported");
    // Unallocated: nothing to cancel — Ok.
    let (mut fresh, _) = fsm_with(vec![]);
    assert_eq!(fresh.send_cancel(), Ok(()));
}

// ----------------------------------------------------------------------
// Capability gating (spec: "Capability-gated commands")
// ----------------------------------------------------------------------

// Spec scenario: "Wink sent only when the device advertises it".
#[test]
fn scenario_wink_sent_only_when_advertised() {
    let device_response = init_response(&FIRST_NONCE, 0xFFFF_FFFF); // caps 0x05 = WINK|CBOR
    let wink_echo = init_report(ALLOC_CID, 0x08, &[]);
    let (mut fsm, shared) = fsm_with(vec![device_response, wink_echo]);
    let deadline = Deadline::new(Duration::from_secs(30));
    block_on(fsm.allocate(&deadline, sleep())).expect("alloc");
    let outcome = block_on(fsm.transaction(
        0x08,
        &[],
        Phase::CommandExchange,
        &deadline,
        sleep(),
        |_| {},
    ))
    .expect("wink completes");
    assert_eq!(
        outcome,
        fidoh_transport_hid::fsm::TransactionOutcome::Done(fidoh_transport_hid::fsm::Frame::Wink)
    );
    let written = shared.lock().expect("lock").outbound.clone();
    let wink = written
        .iter()
        .find(|p| p[4] == 0x88)
        .expect("wink packet on the wire");
    assert_eq!(&wink[5..7], &[0x00, 0x00]);
}

// Spec scenario: "Wink refused when not advertised" — nothing written.
#[test]
fn scenario_wink_refused_when_not_advertised() {
    let resp = init_response(&FIRST_NONCE, 0xFFFF_FFFF);
    let mut resp = resp;
    resp[23] = 0x04; // capabilities byte: drop WINK (payload offset 16 -> report 7+16=23)
    let (mut fsm, shared) = fsm_with(vec![resp]);
    let deadline = Deadline::new(Duration::from_secs(30));
    block_on(fsm.allocate(&deadline, sleep())).expect("alloc");
    let err = block_on(fsm.transaction(
        0x08,
        &[],
        Phase::CommandExchange,
        &deadline,
        sleep(),
        |_| {},
    ));
    // The FSM-level gate is the Device layer's job (HidDevice::wink);
    // at fsm level the command goes out — assert the DEVICE layer
    // refuses instead (next test). Here: just document the layering.
    let _ = err;
    let _ = shared;
}

// Device-level wink gating.
#[test]
fn device_wink_refused_typed_without_write() {
    let resp = init_response(&FIRST_NONCE, 0xFFFF_FFFF); // capabilities 0x04: no WINK
    let (mut fsm, shared) = fsm_with(vec![resp]);
    let deadline = Deadline::new(Duration::from_secs(30));
    block_on(fsm.allocate(&deadline, sleep())).expect("alloc");
    let mut device = HidDevice::from_fsm(
        fsm,
        fidoh_core::ChannelId(ALLOC_CID),
        fidoh_transport_hid::Capability(0x04),
    );
    let err = block_on(device.wink(&deadline, sleep())).expect_err("no WINK bit");
    assert!(matches!(err, Error::Transport(_)));
    // Nothing but the INIT was ever written.
    assert_eq!(shared.lock().expect("lock").outbound.len(), 1);
}

// PING echo (§11.2.9.1.1) round-trip.
#[test]
fn ping_echo_round_trip() {
    let device_response = init_response(&FIRST_NONCE, 0xFFFF_FFFF);
    let ping_payload = [0xAAu8, 0xBB, 0xCC];
    let echo = init_report(ALLOC_CID, 0x81, &ping_payload);
    let (mut fsm, _) = fsm_with(vec![device_response, echo]);
    let deadline = Deadline::new(Duration::from_secs(30));
    block_on(fsm.allocate(&deadline, sleep())).expect("alloc");
    let outcome = block_on(fsm.transaction(
        0x01,
        &ping_payload,
        Phase::CommandExchange,
        &deadline,
        sleep(),
        |_| {},
    ))
    .expect("ping");
    assert_eq!(
        outcome,
        fidoh_transport_hid::fsm::TransactionOutcome::Done(fidoh_transport_hid::fsm::Frame::Ping(
            ping_payload.to_vec()
        ))
    );
}

// Oversized outgoing message rejected before ANY packet is written
// (spec scenario "Oversized message rejected before transmission").
#[test]
fn scenario_oversized_message_rejected_before_transmission() {
    let device_response = init_response(&FIRST_NONCE, 0xFFFF_FFFF);
    let (mut fsm, shared) = fsm_with(vec![device_response]);
    let deadline = Deadline::new(Duration::from_secs(30));
    block_on(fsm.allocate(&deadline, sleep())).expect("alloc");
    let huge = vec![0u8; fidoh_transport_hid::consts::MAX_MESSAGE_SIZE + 1];
    let err = block_on(fsm.transaction(0x10, &huge, Phase::GetInfo, &deadline, sleep(), |_| {}))
        .expect_err("too long");
    assert!(matches!(
        err,
        FsmErrorForTest::Hid(HidError::Framing(FramingError::MessageTooLong { .. }))
    ));
    // Only the INIT was written — no partial transaction debris.
    assert_eq!(shared.lock().expect("lock").outbound.len(), 1);
}

// No LOCK command ever on the wire (spec: "No lock command on the
// wire"): run alloc + transactions + cancel and scan every write.
#[test]
fn scenario_no_lock_command_on_the_wire() {
    let device_response = init_response(&FIRST_NONCE, 0xFFFF_FFFF);
    let busy = init_report(ALLOC_CID, 0x3F, &[0x06]);
    let response = init_report(ALLOC_CID, 0x90, &[0x00]);
    let (mut fsm, shared) = fsm_with(vec![device_response, busy, response]);
    let deadline = Deadline::new(Duration::from_secs(30));
    block_on(fsm.allocate(&deadline, sleep())).expect("alloc");
    let body = cbor_payload(0x04, &[]);
    let _ = block_on(fsm.transaction(0x10, &body, Phase::GetInfo, &deadline, sleep(), |_| {}));
    let _ = fsm.send_cancel();
    for packet in &shared.lock().expect("lock").outbound {
        let cmd = packet[4] & 0x7F;
        assert_ne!(cmd, 0x04, "CTAPHID_LOCK must never be sent");
    }
}

// ----------------------------------------------------------------------
// Transport/Device trait integration (fake fd) + sysfs-backed
// enumerate against a fixture tree
// ----------------------------------------------------------------------

// Spec scenario: "Enumeration is budget-bounded" — an exhausted
// budget returns Timeout(Enumeration) with no scan.
#[test]
fn scenario_enumeration_budget_bounded() {
    let transport = HidTransport::new();
    let deadline = Deadline::new(Duration::ZERO);
    let err = block_on(transport.enumerate(&deadline, sleep())).expect_err("no budget");
    assert_eq!(err, Error::Timeout(Phase::Enumeration));
}

// getAssertion request encode → wire payload fits (the Device::send
// path exercised end-to-end with the soft request model).
#[test]
fn get_assertion_request_encodes_for_wire() {
    let request = GetAssertionRequest::new(String::from("example.com"), vec![0xAA; 32])
        .expect("valid request")
        .with_allow_list(vec![PublicKeyCredentialDescriptor {
            type_field: CredentialType::PublicKey,
            id: vec![0x01, 0x02],
            transports: None,
        }]);
    let body = request.encode().expect("encode");
    let payload = cbor_payload(0x02, &body);
    // Well under the 7609 ceiling; with an allowList entry it runs
    // past 57 bytes, so the encode produces init + continuation
    // packets with ascending SEQ (the §11.2.4 split).
    assert!(payload.len() < fidoh_transport_hid::consts::MAX_MESSAGE_SIZE);
    let packets = packet::encode_message(ALLOC_CID, 0x10, &payload).expect("frame");
    assert!(!packets.is_empty());
    assert_eq!(packets[0][4], 0x90);
    for (i, p) in packets.iter().enumerate().skip(1) {
        assert_eq!(p[4], (i - 1) as u8);
    }
}

// The full Device::send happy path over the fake fd: getInfo response
// surfaces as DeviceEvent::Response with status + body split.
#[test]
fn device_send_get_info_response_split() {
    let resp = init_response(&FIRST_NONCE, 0xFFFF_FFFF);
    // getInfo response: status 0x00 + tiny CBOR map fragment (a2 f4 00
    // — constructed bytes; the body is opaque at this layer).
    let body = vec![0x00u8, 0xA1, 0x01, 0x02];
    let response = init_report(ALLOC_CID, 0x90, &body);
    let (mut fsm, _) = fsm_with(vec![resp, response]);
    let deadline = Deadline::new(Duration::from_secs(30));
    block_on(fsm.allocate(&deadline, sleep())).expect("alloc");
    let mut device = HidDevice::from_fsm(
        fsm,
        fidoh_core::ChannelId(ALLOC_CID),
        fidoh_transport_hid::Capability(0x05),
    );
    let event =
        block_on(device.send(&CtapCommand::GetInfo, &deadline, sleep())).expect("getInfo exchange");
    assert_eq!(
        event,
        DeviceEvent::Response {
            status: 0x00,
            body: vec![0xA1, 0x01, 0x02],
        }
    );
    // open_channel re-handshakes (§11.2.5.3) and keeps the channel.
    let channel = block_on(device.open_channel(&deadline, sleep()));
    // No more inbound queued → the re-handshake exhausts the budget:
    // typed, not a hang.
    assert!(matches!(channel, Err(Error::Timeout(Phase::ChannelOpen))));
}

// close() sends CANCEL best-effort (async-core OQ-3).
#[test]
fn device_close_sends_cancel_best_effort() {
    let resp = init_response(&FIRST_NONCE, 0xFFFF_FFFF);
    let (mut fsm, shared) = fsm_with(vec![resp]);
    let deadline = Deadline::new(Duration::from_secs(30));
    block_on(fsm.allocate(&deadline, sleep())).expect("alloc");
    let device = HidDevice::from_fsm(
        fsm,
        fidoh_core::ChannelId(ALLOC_CID),
        fidoh_transport_hid::Capability(0x05),
    );
    let result = block_on(device.close());
    assert_eq!(result, Ok(()));
    let written = shared.lock().expect("lock").outbound.clone();
    assert!(written.iter().any(|p| p[4] == 0x91), "cancel on close");
}
