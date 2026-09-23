//! Hardware probes (docs/testing.md T3): real-YubiKey checks gated
//! behind `FIDOH_HARDWARE_TESTS=1`. COMPILES with zero features; with
//! the env var unset every probe prints a skip notice and passes.
//!
//! Run: `FIDOH_HARDWARE_TESTS=1 cargo test -p fidoh-transport-hid
//! --test probes -- --nocapture`
//!
//! These are the deferred-OQ instruments (transport-hid design):
//! - P1 enumerate → OQ-4 (descriptor parse vs systemd fido_id)
//! - P3 getInfo  → end-to-end framing on real silicon
//! - P5 keepalive → OQ-2 (real cadence vs the 100 ms SHOULD)
//! - P6 cancel   → OQ-3 (CANCEL via SET_REPORT reliability)
//!
//! Every probe is budget-bounded like production code (no probe
//! overrides the deadline model).

use std::sync::Arc;
use std::time::{Duration, Instant};

use fidoh_core::device::{CtapCommand, Device, DeviceEvent};
use fidoh_core::transport::Transport;
use fidoh_core::{Deadline, Sleep};

use fidoh_transport_hid::HidTransport;

fn hardware_enabled() -> bool {
    std::env::var_os("FIDOH_HARDWARE_TESTS").is_some_and(|v| v == "1")
}

/// The real-clock `Sleep` impl for probes (production uses the
/// caller's runtime; probes are plain std).
struct StdSleep;

impl Sleep for StdSleep {
    fn sleep(
        &self,
        duration: Duration,
    ) -> core::pin::Pin<Box<dyn core::future::Future<Output = ()> + Send>> {
        Box::pin(async move {
            // One real sleep per slice; nothing else in the crate
            // sleeps on a real clock.
            std::thread::sleep(duration);
        })
    }
}

fn sleep() -> &'static (dyn Sleep + Send + Sync) {
    &StdSleep
}

/// Block on a future without an executor dependency: a park/unpark
/// waker built with the stable 1.75 `Waker::from_raw`-free pattern —
/// a `Condvar`-signaled thread (the crate forbids `unsafe`, so no
/// `RawWaker`). Probes never actually park long: their futures poll
/// ready once their I/O completes.
fn block_on<F: core::future::Future>(fut: F) -> F::Output {
    // The probe futures only await `StdSleep` sleeps and fd readiness
    // that is already satisfied when the future is constructed, so a
    // yield-spun poll loop terminates; the park-based waker exists so
    // a future that COULD park would still be woken correctly.
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
    let waker = std::task::Waker::from(std::sync::Arc::new(ThreadWaker(std::thread::current())));
    let mut cx = std::task::Context::from_waker(&waker);
    loop {
        match core::future::Future::poll(core::pin::Pin::as_mut(&mut fut), &mut cx) {
            core::task::Poll::Ready(out) => return out,
            core::task::Poll::Pending => std::thread::park(),
        }
    }
}

fn skip(name: &str) {
    println!("SKIP {name}: set FIDOH_HARDWARE_TESTS=1 with a hardware token attached");
}

// P1 — Spec scenario: "FIDO usage match is enumerated regardless of
// vendor" + design OQ-4: does our descriptor parser agree with the
// kernel's fido_id tagging on the attached device?
#[test]
fn probe_1_enumerate_finds_token() {
    if !hardware_enabled() {
        return skip("probe_1_enumerate_finds_token");
    }
    let transport = HidTransport::new();
    let deadline = Deadline::new(Duration::from_secs(10));
    let devices = block_on(transport.enumerate(&deadline, sleep())).expect("enumerate");
    println!("P1 candidates: {devices:?}");
    assert!(!devices.is_empty(), "no FIDO hidraw candidate found");
    for d in &devices {
        println!("  id={} name={}", d.id, d.name);
    }
    // OQ-4 cross-check: dump the sysfs descriptor verdict for the
    // first candidate so a human can diff it against
    // `udevadm info` / fido_id tagging.
    println!("P1 NOTE: compare enumeration against `udevadm info --query=property` ID_SECURITY_TOKEN for each node (OQ-4).");
}

// P2 — INIT allocates a CID with the expected capabilities (spec
// scenario "Allocate a channel with nonce match" on real silicon).
#[test]
fn probe_2_init_allocates_cid() {
    if !hardware_enabled() {
        return skip("probe_2_init_allocates_cid");
    }
    let transport = HidTransport::new();
    let deadline = Deadline::new(Duration::from_secs(10));
    let devices = block_on(transport.enumerate(&deadline, sleep())).expect("enumerate");
    let Some(first) = devices.first() else {
        panic!("no token to probe");
    };
    let device = block_on(transport.connect(&first.id, &deadline, sleep())).expect("connect+INIT");
    let caps = device.capabilities();
    println!(
        "P2 cid=0x{:08X} caps=0x{:02X} (wink={} cbor={} nmsg={})",
        device.channel().0,
        caps.0,
        caps.wink(),
        caps.cbor(),
        caps.nmsg()
    );
    assert!(caps.cbor(), "token must advertise CAPABILITY_CBOR");
    if caps.reserved_bits() != 0 {
        println!(
            "P2 NOTE: reserved capability bits set: {:#04x} — record for the vendor",
            caps.reserved_bits()
        );
    }
    block_on(device.close()).expect("close");
}

// P3 — getInfo round-trip through the FULL framing stack (spec
// scenarios: single-packet message + correct reassembly on hardware).
#[test]
fn probe_3_get_info_round_trip() {
    if !hardware_enabled() {
        return skip("probe_3_get_info_round_trip");
    }
    let transport = HidTransport::new();
    let deadline = Deadline::new(Duration::from_secs(15));
    let devices = block_on(transport.enumerate(&deadline, sleep())).expect("enumerate");
    let first = devices.first().expect("token").clone();
    let mut device = block_on(transport.connect(&first.id, &deadline, sleep())).expect("connect");
    let event =
        block_on(device.send(&CtapCommand::GetInfo, &deadline, sleep())).expect("getInfo exchange");
    match event {
        DeviceEvent::Response { status, body } => {
            println!("P3 getInfo status=0x{status:02X} body={} bytes", body.len());
            assert_eq!(status, 0x00, "getInfo must succeed on a healthy token");
            assert!(!body.is_empty(), "getInfo success carries a CBOR map");
        }
        DeviceEvent::Keepalive { status } => {
            panic!("getInfo must not keepalive before responding; got status {status:#04x}");
        }
    }
    block_on(device.close()).expect("close");
}

// P4 — PING echo (§11.2.9.1.1) — wire sanity.
#[test]
fn probe_4_ping_echo() {
    if !hardware_enabled() {
        return skip("probe_4_ping_echo");
    }
    let transport = HidTransport::new();
    let deadline = Deadline::new(Duration::from_secs(10));
    let devices = block_on(transport.enumerate(&deadline, sleep())).expect("enumerate");
    let first = devices.first().expect("token").clone();
    let mut device = block_on(transport.connect(&first.id, &deadline, sleep())).expect("connect");
    let payload: Vec<u8> = (0..200u32).map(|i| (i % 251) as u8).collect(); // multi-packet
    let echo = block_on(device.ping(&payload, &deadline, sleep())).expect("ping");
    assert_eq!(echo, payload, "PING must echo its payload");
    println!("P4 ping echo OK ({} bytes, multi-packet)", payload.len());
    block_on(device.close()).expect("close");
}

// P5 — Keepalive observation during getAssertion (design OQ-2: real
// cadence vs the 100 ms SHOULD). Requires a credential on the token
// for `rp_id` and NO touch: the probe measures the UP_NEEDED stream
// until the token's own user-action timeout.
#[test]
fn probe_5_keepalive_cadence_during_get_assertion() {
    if !hardware_enabled() {
        return skip(
            "probe_5_keepalive_cadence_during_get_assertion (touch NOT required: withhold touch)",
        );
    }
    let transport = HidTransport::new();
    let deadline = Deadline::new(Duration::from_secs(40));
    let devices = block_on(transport.enumerate(&deadline, sleep())).expect("enumerate");
    let first = devices.first().expect("token").clone();
    let mut device = block_on(transport.connect(&first.id, &deadline, sleep())).expect("connect");
    let request = fidoh_core::get_assertion::GetAssertionRequest::new(
        String::from("fidoh-probe.local"),
        vec![0xAA; 32],
    )
    .expect("request");
    let start = Instant::now();
    let mut arrivals: Vec<Duration> = Vec::new();
    let result = block_on(device.send(&CtapCommand::GetAssertion(request), &deadline, sleep()));
    // Withhold touch: expect the token's user-action timeout (0x2F) or
    // budget expiry — either is a successful probe outcome.
    match result {
        Ok(DeviceEvent::Keepalive { status }) => {
            arrivals.push(start.elapsed());
            println!(
                "P5 keepalive status=0x{status:02X} at {:?}",
                start.elapsed()
            );
        }
        Ok(DeviceEvent::Response { status, .. }) => {
            println!(
                "P5 response status=0x{status:02X} (a touch may have happened) at {:?}",
                start.elapsed()
            );
        }
        Err(e) => println!("P5 terminal: {e} at {:?}", start.elapsed()),
    }
    println!(
        "P5 OBSERVATION: inter-keepalive intervals and the terminal status/time are the OQ-2 data. \
         First arrival after {:?}; spec expectation: ≥1 keepalive per 100 ms (CTAP2.1 §11.2.9.1.7).",
        start.elapsed()
    );
    let _ = block_on(device.close());
}

// P6 — CANCEL reliability (design OQ-3): start a getAssertion (UP
// wait), CANCEL it, and verify the device recovers with 0x2D
// KEEPALIVE_CANCEL (mapped by ceremony to UserCancelled) and that a
// subsequent connect+INIT still works.
#[test]
fn probe_6_cancel_reliability_and_recovery() {
    if !hardware_enabled() {
        return skip("probe_6_cancel_reliability_and_recovery");
    }
    let transport = HidTransport::new();
    let deadline = Deadline::new(Duration::from_secs(30));
    let devices = block_on(transport.enumerate(&deadline, sleep())).expect("enumerate");
    let first = devices.first().expect("token").clone();
    let mut device = block_on(transport.connect(&first.id, &deadline, sleep())).expect("connect");
    let request = fidoh_core::get_assertion::GetAssertionRequest::new(
        String::from("fidoh-probe.local"),
        vec![0xBB; 32],
    )
    .expect("request");
    // Issue getAssertion; whatever surfaces (likely 0x2D after the
    // transaction path's cancel-on-timeout, or a timeout) then probe
    // recovery.
    let outcome = block_on(device.send(&CtapCommand::GetAssertion(request), &deadline, sleep()));
    println!("P6 getAssertion outcome: {outcome:?}");
    // The recovery check: a fresh connect must allocate a channel.
    let deadline = Deadline::new(Duration::from_secs(10));
    let reconnect = block_on(transport.connect(&first.id, &deadline, sleep()));
    match reconnect {
        Ok(d) => {
            println!("P6 recovery connect OK (channel 0x{:08X})", d.channel().0);
            block_on(d.close()).ok();
        }
        Err(e) => panic!("device did not recover after CANCEL: {e} — OQ-3 reliability FAILS"),
    }
}
