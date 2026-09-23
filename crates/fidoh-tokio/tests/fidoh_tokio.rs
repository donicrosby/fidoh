//! Scenario-ID tests for the fidoh-tokio adapter.
//!
//! The adapter's normative surface lives in the async-core spec
//! (`openspec/changes/async-core/specs/async-core/spec.md`) — the two
//! requirements that name `fidoh-tokio` ("Sleep trait as the sole
//! waiting mechanism", "Blocking-syscall transport policy with
//! spawn_blocking adapter") plus design D2/D3/D5. Scenario mapping:
//!
//! | async-core requirement | Scenario | Test |
//! |---|---|---|
//! | Sleep is the sole waiting mechanism | Runtime adapter supplies Sleep | `runtime_adapter_supplies_sleep` |
//! | Sleep is the sole waiting mechanism | Deterministic test clock | `deterministic_test_clock_paused` |
//! | Blocking-syscall policy w/ spawn_blocking adapter | Blocking HID read does not stall the executor | `blocking_op_runs_on_blocking_pool_not_executor` |
//! | Blocking-syscall policy w/ spawn_blocking adapter | Dropped future detaches from blocking thread | `dropped_future_detaches_from_blocking_thread` |
//! | Single-budget timeout model | Remaining budget propagates across hops | `slice_grant_is_capped_by_remaining_budget` |
//! | Single-budget timeout model | (expiry before any call issues) | `budget_exhaustion_fires_typed_timeout_before_spawn` |
//! | (design D3 abort path) | (slice expiry surfaces as typed timeout) | `blocking_side_observes_slice_expiry_as_typed_timeout` |
//! | (stack invariant: typed errors everywhere) | (panics propagate typed, never poison) | `panic_in_blocking_bridge_propagates_typed_error` |
//! | Ceremony usable from async context | GetAssertion completes within budget | `get_assertion_ceremony_completes_within_budget` |
//! | Ceremony expires during user-presence wait | (typed UserPresence via adapter) | `ceremony_up_wait_expires_typed_through_adapter` |
//! | (design A4/OQ-4 Send bounds) | (ceremony future spawns on multi-thread runtime) | `ceremony_future_is_send_multi_thread_runtime` |
//! | (OQ-3 safe cancellation) | (drop mid-ceremony leaves device reusable) | `device_reusable_after_dropped_ceremony` |
//! | Crate graph: only fidoh-tokio names tokio | Dependency audit | `only_tokio_adapter_names_tokio` |

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use fidoh_core::error::Error;
use fidoh_core::time::{Deadline, Phase};
use fidoh_core::transport::{DeviceId, Transport};
use fidoh_core::{Ceremony, GetAssertionCeremony, GetAssertionExchange, Sleep, UvPolicy};
use fidoh_tokio::{spawn_blocking_slice, SliceGrantArgs, TokioSleep};
use fidoh_transport_soft::{
    Config, MakeCredentialArgs, SoftAuthenticator, SoftTransport, UpUvMode,
};

const SLICE: Duration = Duration::from_millis(50);

fn mint_into(auth: &mut SoftAuthenticator, user: &[u8]) {
    auth.make_credential(MakeCredentialArgs {
        rp_id: String::from("example.com"),
        user_handle: user.to_vec(),
        resident: true,
    })
    .expect("mint fixture credential");
}

fn exchange() -> GetAssertionExchange {
    GetAssertionExchange {
        rp_id: String::from("example.com"),
        client_data_hash: vec![0xAB; 32],
        allow_credentials: None,
        user_verification: UvPolicy::Discouraged,
        pin_uv_auth: None,
        drain: None,
    }
}

/// Poll `fut` once (driving it to its first suspension or completion),
/// for drop-mid-flight tests.
async fn poll_once<F: std::future::Future + Unpin>(fut: &mut F) {
    std::future::poll_fn(|cx| {
        let _ = std::pin::Pin::new(&mut *fut).poll(cx);
        std::task::Poll::Ready(())
    })
    .await;
}

// --------------------------------------------------------------------
// Requirement: Sleep trait as the sole waiting mechanism.
// --------------------------------------------------------------------

/// Scenario: Runtime adapter supplies Sleep — the factory crosses as
/// `&dyn Sleep + Send + Sync` and its futures resolve via the tokio
/// timer (real clock here; the paused-clock variant below).
#[tokio::test]
async fn runtime_adapter_supplies_sleep() {
    let handle: &(dyn Sleep + Send + Sync) = TokioSleep.handle();
    let fut = handle.sleep(Duration::from_millis(1));
    // The future is Send by construction (OQ-4); prove it compiles.
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&fut);
    fut.await;

    // The Arc'd shape satisfies the same object-safe call shape (core's
    // `Sleep` blanket impls for Arc/Box forward transparently).
    let shared = TokioSleep::shared();
    shared.sleep(Duration::from_millis(1)).await;
}

/// Scenario: Deterministic test clock — under `start_paused` the
/// adapter's waits advance only under test control; a 1-hour wait
/// resolves instantly via the auto-advancing paused clock, with zero
/// real-time sleeps.
#[tokio::test(start_paused = true)]
async fn deterministic_test_clock_paused() {
    let t0 = std::time::Instant::now();
    TokioSleep.sleep(Duration::from_secs(3600)).await;
    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "paused clock must not real-sleep: {elapsed:?}"
    );
}

// --------------------------------------------------------------------
// Requirement: Blocking-syscall transport policy with spawn_blocking
// adapter.
// --------------------------------------------------------------------

/// Scenario: Blocking HID read does not stall the executor — the op
/// runs on the blocking pool (off the test task's worker thread); the
/// result crosses back typed. The op parks on an OS barrier until the
/// async side releases it: if the bridge ever ran the op inline on
/// the runtime thread, the release could never run and the test would
/// hang — instead it passes.
#[tokio::test]
async fn blocking_op_runs_on_blocking_pool_not_executor() {
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let deadline = Deadline::new(Duration::from_secs(5));
    let b2 = Arc::clone(&barrier);
    let join = tokio::spawn(async move {
        spawn_blocking_slice::<u8, _>(&deadline, Phase::CommandExchange, SLICE, move |g| {
            let _ = g.granted; // (slice capping is asserted elsewhere)
                               // Op thread (blocking pool): park until the async side
                               // proves it stayed free.
            b2.wait();
            Ok(0x21)
        })
        .await
    });
    // Give the op a moment to reach its barrier wait, then release.
    tokio::time::sleep(Duration::from_millis(20)).await;
    barrier.wait();
    let out = tokio::time::timeout(Duration::from_secs(2), join)
        .await
        .expect("op must finish after release (the executor was never blocked)")
        .expect("bridge task must not panic")
        .expect("op must succeed");
    assert_eq!(out, 0x21);
}

/// Scenario: Dropped future detaches from blocking thread — dropping
/// the bridge future leaves the op running to its granted slice on
/// the blocking pool; the caller is free immediately, and the op's
/// self-observed slice expiry is the abort path (bounded by the
/// slice, never by the caller's patience).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropped_future_detaches_from_blocking_thread() {
    const SLICE_MS: u64 = 150;
    let entered = Arc::new(AtomicBool::new(false));
    let released = Arc::new(AtomicBool::new(false));

    let deadline = Deadline::new(Duration::from_secs(5));
    let entered2 = Arc::clone(&entered);
    let released2 = Arc::clone(&released);
    let mut bridge = Box::pin(spawn_blocking_slice::<(), _>(
        &deadline,
        Phase::CommandExchange,
        Duration::from_millis(SLICE_MS),
        move |g: SliceGrantArgs| {
            entered2.store(true, Ordering::SeqCst);
            // Simulated blocking read: exits at the granted-slice
            // edge via its OWN deadline-driven abort path (the same
            // shape as a sliced hidraw read).
            let step = Duration::from_millis(10);
            let mut waited = Duration::ZERO;
            while waited < g.granted {
                std::thread::sleep(step.min(g.granted - waited));
                waited += step;
            }
            released2.store(true, Ordering::SeqCst);
            Err(Error::Timeout(g.phase))
        },
    ));

    // Poll once to let the spawn land, then drop the bridge future
    // mid-flight (the detach).
    poll_once(&mut bridge).await;
    drop(bridge);

    // The detached op still runs to its slice edge and self-reports
    // (latches flip), bounded by its granted slice — not by us.
    tokio::time::timeout(Duration::from_secs(2), async {
        while !entered.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        while !released.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("detached op must run to its slice edge and self-release");
}

/// Slice expiry on the blocking side surfaces as the typed timeout
/// naming the phase (design D3's deadline-driven abort path), and the
/// shared budget shows the grant consumed exactly.
#[tokio::test]
async fn blocking_side_observes_slice_expiry_as_typed_timeout() {
    const SLICE_MS: u64 = 80;
    let deadline = Deadline::new(Duration::from_secs(2));
    let out: Result<(), Error> = spawn_blocking_slice(
        &deadline,
        Phase::UserPresence,
        Duration::from_millis(SLICE_MS),
        |g: SliceGrantArgs| {
            assert_eq!(g.granted, Duration::from_millis(SLICE_MS));
            assert_eq!(g.phase, Phase::UserPresence);
            // Wait at most the slice, then report the typed expiry.
            std::thread::sleep(g.granted);
            Err(Error::Timeout(g.phase))
        },
    )
    .await;
    assert_eq!(out.unwrap_err(), Error::Timeout(Phase::UserPresence));
    // The grant was consumed from the shared budget before the spawn.
    let expected_cap = Duration::from_secs(2) - Duration::from_millis(SLICE_MS);
    assert!(
        deadline.remaining() <= expected_cap,
        "grant must be consumed from the shared budget: {:?}",
        deadline.remaining()
    );
}

/// The slice grant is the shorter of `max_slice` and the remaining
/// budget (single-budget model: no slice may exceed what the
/// ceremony still has — "Remaining budget propagates across hops").
#[tokio::test]
async fn slice_grant_is_capped_by_remaining_budget() {
    let deadline = Deadline::new(Duration::from_millis(30));
    let out: Result<Duration, Error> = spawn_blocking_slice(
        &deadline,
        Phase::ChannelOpen,
        Duration::from_secs(10), // max_slice >> remaining
        |g| Ok(g.granted),
    )
    .await;
    let granted = out.expect("grant must resolve");
    assert_eq!(granted, Duration::from_millis(30));
    assert!(deadline.remaining().is_zero());
}

/// Budget exhaustion fires the typed timeout BEFORE any blocking call
/// issues (grant-before-issue: the op never runs, nothing spawns).
#[tokio::test]
async fn budget_exhaustion_fires_typed_timeout_before_spawn() {
    let deadline = Deadline::new(Duration::ZERO);
    let spawned = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&spawned);
    let out: Result<(), Error> =
        spawn_blocking_slice(&deadline, Phase::GetAssertion, SLICE, move |_g| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .await;
    assert_eq!(out.unwrap_err(), Error::Timeout(Phase::GetAssertion));
    assert_eq!(spawned.load(Ordering::SeqCst), 0, "op must never run");
}

/// A panic inside the blocking bridge propagates as a typed
/// `Error::Transport` — never a panic across the bridge, nothing
/// poisoned; the same bridge works fine on the next call.
#[tokio::test]
async fn panic_in_blocking_bridge_propagates_typed_error() {
    let deadline = Deadline::new(Duration::from_secs(5));
    let out: Result<(), Error> = spawn_blocking_slice(&deadline, Phase::ChannelOpen, SLICE, |_g| {
        panic!("device exploded");
    })
    .await;
    let err = out.unwrap_err();
    assert!(
        matches!(err, Error::Transport(ref e) if e.kind == "tokio"),
        "panic must fold into Error::Transport, got {err:?}"
    );

    // Nothing poisoned: a follow-up op on the same bridge succeeds.
    let out2: Result<u8, Error> =
        spawn_blocking_slice(&deadline, Phase::ChannelOpen, SLICE, |_g| Ok(7u8)).await;
    assert_eq!(out2.expect("bridge still usable"), 7);
}

// --------------------------------------------------------------------
// Full ceremony through the adapter (async end-to-end) + Send bounds.
// --------------------------------------------------------------------

/// Scenario: GetAssertion ceremony completes within budget — the full
/// discovery→selection→connect→probe→exchange pipeline runs on the
/// tokio runtime with the adapter's Sleep factory; raw assertion
/// fields come back typed.
#[tokio::test]
async fn get_assertion_ceremony_completes_within_budget() {
    let mut auth = SoftAuthenticator::new(Config::default());
    mint_into(&mut auth, b"tokio-user");

    let ceremony = GetAssertionCeremony::new(
        vec![SoftTransport::new(auth)],
        String::from("example.com"),
        vec![0xAB; 32],
        Duration::from_secs(30),
    );
    let outcome = ceremony
        .run(TokioSleep.handle())
        .await
        .expect("ceremony must succeed over the adapter's Sleep");
    assert_eq!(outcome.assertions.len(), 1);
    let first = &outcome.assertions[0];
    assert_eq!(
        first.user.as_ref().map(|u| u.id.as_slice()),
        Some(&b"tokio-user"[..])
    );
    // The mandatory getInfo probe's capabilities ride in the outcome.
    assert!(!outcome.info.versions.is_empty());
    // Clean discovery: no per-transport diagnostics.
    assert!(outcome.discovery_diagnostics.is_empty());
}

/// Scenario: Ceremony expires during user-presence wait — with
/// `require-explicit-poke` and a small budget the poke poll slicing
/// exhausts the budget and the typed `Timeout(UserPresence)` error
/// comes back through the adapter (the budget stays the single source
/// of timeout truth on async).
#[tokio::test]
async fn ceremony_up_wait_expires_typed_through_adapter() {
    let cfg = Config {
        up_mode: UpUvMode::RequireExplicitPoke,
        ..Config::default()
    };
    let mut auth = SoftAuthenticator::new(cfg);
    mint_into(&mut auth, b"tokio-user");

    let ceremony = GetAssertionCeremony::new(
        vec![SoftTransport::new(auth)],
        String::from("example.com"),
        vec![0xAB; 32],
        Duration::from_millis(250),
    );
    let err = ceremony
        .run(TokioSleep.handle())
        .await
        .expect_err("budget must expire before any poke");
    assert_eq!(err, fidoh_core::CeremonyError::Timeout(Phase::UserPresence));
}

/// Design A4/OQ-4 Send bounds proven by compile + run: the ceremony
/// future is `Send` and completes on a multi-thread runtime (it may
/// hop workers across its awaits). `tokio::spawn` REQUIRES
/// `Future + Send + 'static`; if the ceremony future (or the adapter's
/// Sleep futures held across its awaits) were `!Send` — or if the
/// future captured a non-`'static` borrow — this would not compile.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ceremony_future_is_send_multi_thread_runtime() {
    let mut auth = SoftAuthenticator::new(Config::default());
    mint_into(&mut auth, b"send-user");

    let ceremony = GetAssertionCeremony::new(
        vec![SoftTransport::new(auth)],
        String::from("example.com"),
        vec![0xAB; 32],
        Duration::from_secs(30),
    );
    // The owned `Arc<dyn Sleep + Send + Sync>` is `'static`; the
    // `as_ref` borrow is internal to the spawned future.
    let sleep: Arc<dyn Sleep + Send + Sync> = TokioSleep::shared();
    let handle = tokio::spawn(async move {
        let outcome = ceremony.run(sleep.as_ref()).await;
        outcome.map(|o| o.assertions[0].credential.id.clone())
    });
    let cred = handle
        .await
        .expect("ceremony task must not panic")
        .expect("ceremony must succeed on the multi-thread runtime");
    assert!(!cred.is_empty());
}

/// OQ-3 cancellation contract: a ceremony future dropped mid
/// user-presence wait leaves no poisoned state, and the SAME
/// authenticator (fresh connect over the same transport) runs a clean
/// ceremony afterwards — the device-reusability half of "Drop
/// mid-user-presence is safe". (The soft token's exchange is
/// budget-accounted and never actually suspends on a timer — design
/// D3: "Soft transport: no blocking waits; responds immediately" — so
/// the true mid-await detach path is the blocking bridge's, covered
/// by `dropped_future_detaches_from_blocking_thread`.)
#[tokio::test]
async fn device_reusable_after_dropped_ceremony() {
    let cfg = Config {
        up_mode: UpUvMode::RequireExplicitPoke,
        ..Config::default()
    };
    let mut auth = SoftAuthenticator::new(cfg);
    mint_into(&mut auth, b"cancel-user");
    let transport = SoftTransport::new(auth);

    // Ceremony 1: enter the exchange, then drop the future.
    let deadline = Deadline::new(Duration::from_secs(30));
    let device = transport
        .connect(&DeviceId::new("soft-0"), &deadline, TokioSleep.handle())
        .await
        .expect("initial connect");
    let mut fut = Box::pin(exchange().run(device, &deadline, TokioSleep.handle()));
    poll_once(&mut fut).await;
    drop(fut); // cancellation: mid user-presence wait

    // Ceremony 2 over the SAME authenticator: connect again, poke,
    // and the full exchange succeeds (no poisoned shared state).
    let deadline2 = Deadline::new(Duration::from_secs(30));
    let device2 = transport
        .connect(&DeviceId::new("soft-0"), &deadline2, TokioSleep.handle())
        .await
        .expect("reconnect after dropped ceremony");
    device2.core().lock().poke_user_presence();
    let outcome = exchange()
        .run(device2, &deadline2, TokioSleep.handle())
        .await
        .expect("device remains usable after a dropped ceremony");
    assert_eq!(
        outcome.assertions[0].user.as_ref().map(|u| u.id.as_slice()),
        Some(&b"cancel-user"[..])
    );
}

// --------------------------------------------------------------------
// Requirement: Crate graph — only fidoh-tokio names tokio.
// --------------------------------------------------------------------

/// Scenario: Dependency audit — no workspace crate other than
/// fidoh-tokio names tokio in any dependency section, and the
/// adapter's LIB dependencies never include a transport crate (the
/// soft token rides only under [dev-dependencies] as the CI harness).
/// Manifests are read from disk so the audit stays honest as the
/// workspace evolves.
#[test]
fn only_tokio_adapter_names_tokio() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root resolves");
    for entry in std::fs::read_dir(root.join("crates")).expect("crates dir") {
        let entry = entry.expect("crate dir entry");
        if !entry.path().is_dir() {
            continue;
        }
        let manifest =
            std::fs::read_to_string(entry.path().join("Cargo.toml")).expect("manifest readable");
        let is_adapter = entry.path().ends_with("fidoh-tokio");
        // Walk section by section: only real dependency edges count.
        let mut section = String::new();
        for line in manifest.lines() {
            let line = line.trim();
            if line.starts_with('[') {
                section = line.to_string();
                continue;
            }
            let is_dep_section = section.starts_with("[dependencies]")
                || section.starts_with("[dev-dependencies]")
                || section.starts_with("[target.");
            if !is_dep_section || !line.contains("tokio") {
                continue;
            }
            assert!(
                is_adapter,
                "{} names tokio in {section} — only fidoh-tokio may",
                entry.path().display()
            );
        }
    }
    // The adapter's LIB surface never depends on a transport crate.
    let adapter =
        std::fs::read_to_string(root.join("crates/fidoh-tokio/Cargo.toml")).expect("manifest");
    let mut section = String::new();
    for line in adapter.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            section = line.to_string();
            continue;
        }
        if section == "[dependencies]" {
            for banned in [
                "fidoh-transport-hid",
                "fidoh-transport-pcsc",
                "fidoh-transport-soft",
            ] {
                assert!(
                    !line.contains(banned),
                    "adapter LIB surface must not depend on {banned}"
                );
            }
        }
    }
    assert!(
        adapter.contains("[dev-dependencies]"),
        "the soft-token harness edge must stay dev-only"
    );
}
