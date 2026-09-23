//! Hardware-gated probes (compile only under `FIDOH_HARDWARE_TESTS=1`):
//! enumerate real readers through pcscd, find a token, SELECT the
//! FIDO applet, and run the authenticatorGetInfo round-trip
//! (CTAP2.1 §11.3.3 + §6.4 through the §11.3.5 frame).
//!
//! These are evidence-class-3 cleanroom probes (openspec/config.yaml):
//! live behavior against our own hardware, never protocol truth.
//!
//! ```text
//! FIDOH_HARDWARE_TESTS=1 cargo test -p fidoh-transport-pcsc --test hardware -- --nocapture
//! ```

#![cfg(all(feature = "std", feature = "pcsc"))]

use std::time::Duration;

use fidoh_core::device::{CtapCommand, Device as _, DeviceEvent};
use fidoh_core::sleep::Sleep;
use fidoh_core::transport::{DeviceId, Transport};
#[cfg(feature = "pcsc")]
use fidoh_transport_pcsc::PcscLibrary;
use fidoh_transport_pcsc::PcscTransport;

/// A real-clock `Sleep` factory (hardware probes run on a real
/// executor substitute: a tiny block_on with a thread-based timer).
struct ThreadSleep;

impl Sleep for ThreadSleep {
    fn sleep(
        &self,
        duration: Duration,
    ) -> std::pin::Pin<Box<dyn core::future::Future<Output = ()> + Send>> {
        struct Timer(std::sync::mpsc::Receiver<()>);
        impl core::future::Future for Timer {
            type Output = ();
            fn poll(
                self: std::pin::Pin<&mut Self>,
                cx: &mut core::task::Context<'_>,
            ) -> core::task::Poll<()> {
                use core::task::Poll;
                match self.0.try_recv() {
                    Ok(()) => Poll::Ready(()),
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => Poll::Ready(()),
                }
            }
        }
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            std::thread::sleep(duration);
            let _ = tx.send(());
        });
        Box::pin(Timer(rx))
    }
}

fn block_on<F: core::future::Future>(fut: F) -> F::Output {
    use std::task::{Context, Poll, Waker};
    struct NoopWaker;
    impl std::task::Wake for NoopWaker {
        fn wake(self: std::sync::Arc<Self>) {}
        fn wake_by_ref(self: &std::sync::Arc<Self>) {}
    }
    let waker = Waker::from(std::sync::Arc::new(NoopWaker));
    let mut cx = Context::from_waker(&waker);
    let mut fut = Box::pin(fut);
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(out) => return out,
            // Hardware waits block in the library; the sleep future
            // self-wakes, so a yield loop is safe here.
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn sleep_handle() -> &'static (dyn Sleep + Send + Sync) {
    static S: ThreadSleep = ThreadSleep;
    &S
}

fn hw_enabled() -> bool {
    std::env::var("FIDOH_HARDWARE_TESTS").is_ok_and(|v| v == "1")
}

/// A probe needs BOTH the opt-in flag AND a reachable resource
/// manager (pcscd); missing either is a skip, not a failure — CI has
/// no hardware, and a stopped daemon is an environment condition.
fn hw_available() -> bool {
    #[cfg(feature = "pcsc")]
    {
        PcscLibrary::establish().is_ok()
    }
    #[cfg(not(feature = "pcsc"))]
    {
        false
    }
}

macro_rules! hw_or_skip {
    () => {
        if !hw_enabled() {
            eprintln!(
                "skipped: set FIDOH_HARDWARE_TESTS=1 with a CTAP-capable \
                 reader/token attached to run hardware probes"
            );
            return;
        }
        if !hw_available() {
            eprintln!(
                "skipped: FIDOH_HARDWARE_TESTS=1 but pcscd is not reachable \
                 (no resource manager / no hardware)"
            );
            return;
        }
    };
}

/// Probe 1: enumerate readers through the real resource manager.
#[test]
fn hw_enumerate_real_readers() {
    hw_or_skip!();
    let lib = PcscLibrary::establish().expect("pcscd must be running");
    let t = PcscTransport::new(lib);
    let deadline = fidoh_core::Deadline::new(Duration::from_secs(30));
    let devices = block_on(t.enumerate(&deadline, sleep_handle()))
        .expect("enumerate must succeed with pcscd running");
    println!("readers: {devices:?}");
    assert!(!devices.is_empty(), "attach at least one reader");
}

/// Probe 2: find a token and SELECT the FIDO applet (§11.3.3).
#[test]
fn hw_select_fido_applet() {
    hw_or_skip!();
    let lib = PcscLibrary::establish().expect("pcscd must be running");
    let t = PcscTransport::new(lib);
    let deadline = fidoh_core::Deadline::new(Duration::from_secs(30));
    let devices = block_on(t.enumerate(&deadline, sleep_handle())).expect("enumerate");
    assert!(
        !devices.is_empty(),
        "attach at least one reader with a token"
    );
    // Try each reader; the FIDO-capable one completes SELECT.
    let mut found = false;
    for info in &devices {
        match block_on(t.connect(&info.id, &deadline, sleep_handle())) {
            Ok(_dev) => {
                println!("FIDO applet selected on {}", info.name);
                found = true;
                break;
            }
            Err(e) => println!("{}: {e} (not FIDO on this interface)", info.name),
        }
    }
    assert!(found, "no reader exposed the FIDO applet");
}

/// Probe 3: full getInfo round-trip over the §11.3.5 frame.
#[test]
fn hw_get_info_round_trip() {
    hw_or_skip!();
    let lib = PcscLibrary::establish().expect("pcscd must be running");
    let t = PcscTransport::new(lib);
    let deadline = fidoh_core::Deadline::new(Duration::from_secs(30));
    let devices = block_on(t.enumerate(&deadline, sleep_handle())).expect("enumerate");
    assert!(
        !devices.is_empty(),
        "attach at least one reader with a token"
    );
    for info in &devices {
        let Ok(mut dev) =
            block_on(t.connect(&DeviceId::new(info.name.clone()), &deadline, sleep_handle()))
        else {
            continue;
        };
        match block_on(dev.send(&CtapCommand::GetInfo, &deadline, sleep_handle())) {
            Ok(DeviceEvent::Response { status, body }) => {
                println!(
                    "{}: getInfo status {status:#04x}, {} CBOR bytes",
                    info.name,
                    body.len()
                );
                assert_eq!(status, 0x00, "CTAP2_OK expected from a CTAP2 token");
                assert!(!body.is_empty(), "getInfo carries the CBOR capability map");
                return;
            }
            Ok(other) => println!("{}: {other:?}", info.name),
            Err(e) => println!("{}: {e}", info.name),
        }
    }
    panic!("no reader completed the getInfo round-trip");
}
