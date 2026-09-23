//! fidoh-tokio: the tokio adapter (async-core design D2/D3/D5).
//!
//! The ONLY crate in the workspace that names tokio (design D2 rule 3,
//! stack invariant: "Runtime-specific glue lives ONLY in separate
//! adapter crates"). It contributes two pieces of glue and zero
//! protocol logic:
//!
//! 1. **The [`Sleep`] factory** ([`TokioSleep`]) — the sole waiting
//!    mechanism every core/transport crate waits through. Tokio's
//!    timer is used directly: [`tokio::time::sleep`] futures are
//!    `Send` (async-core OQ-4), cancellation-safe (dropping cancels
//!    exactly that one wait), and resolve on a real clock. Tests drive
//!    a fake clock through `#[tokio::test(start_paused = true)]`
//!    (async-core spec: "Deterministic test clock").
//!
//! 2. **The blocking-call bridge** ([`spawn_blocking_slice`]) —
//!    async-core design D3's resolution: v1 transports may block
//!    internally (hidraw `read`/`write`, PC/SC calls), and the adapter
//!    wraps ONE budget-granted wait slice in ONE `spawn_blocking` op
//!    so async callers never block an executor worker thread. The
//!    slice is granted from the caller's shared [`Deadline`] (the
//!    single-budget model, design D4) via core's [`policy`] seams —
//!    the same grant-before-issue discipline the PC/SC engine uses —
//!    so the total wait stays bounded by the ceremony budget and a
//!    detached blocking thread always has a deadline-driven exit path.
//!
//! # Cancellation shape (design D3 tradeoffs, OQ-3)
//!
//! Dropping the bridge future detaches the caller from the in-flight
//! blocking op: `spawn_blocking` keeps running on the blocking pool,
//! and it is the *granted slice* (never the caller's patience) that
//! bounds when that thread's work ends. The blocking side observes
//! its [`SliceGrantArgs::granted`] bound and exits with the typed
//! `Error::Timeout(phase)` — the deadline-driven abort path the
//! blocking policy requires ("a detached... blocking thread exits
//! within the operation's timeout bound"). The slice bounds
//! cancellation latency only; it never extends the total wait.
//!
//! Panics inside the blocking bridge propagate as the typed
//! [`Error::Transport`] (stack invariant: "Typed errors everywhere";
//! the bridge never re-panics and holds no lock across the spawn), so
//! a panicking device op can never poison executor or shared state.
//!
//! # Crate-graph position (design D2)
//!
//! ```text
//!                  ┌────────────┐
//!                  │ fidoh-core │  traits, model, ceremony
//!                  └─────▲──────┘
//!      fidoh-transport-* ┘   fidoh-tokio (this crate)
//! ```
//!
//! Arrows point only toward fidoh-core: the library surface depends on
//! fidoh-core and never on any transport crate (the soft token rides
//! along as a dev-dependency of the test suite only).

#![forbid(unsafe_code)]

use std::time::Duration;

use fidoh_core::error::{Error, TransportError};
use fidoh_core::sleep::Sleep;
use fidoh_core::time::{Deadline, Phase};

pub use fidoh_core::policy::SliceGrant;
pub use fidoh_core::time::{DEFAULT_WAIT_SLICE, NFC_POLL_SLICE};

// --------------------------------------------------------------------
// The Sleep factory (async-core spec: "Sleep trait as the sole waiting
// mechanism" — "Runtime adapter supplies Sleep" scenario).
// --------------------------------------------------------------------

/// The tokio [`Sleep`] factory: every timed wait in a ceremony runs on
/// tokio's timer through this object.
///
/// Pass [`TokioSleep::handle`] into any fidoh-core
/// [`Transport`](fidoh_core::Transport), [`Device`](fidoh_core::Device),
/// or [`Ceremony`](fidoh_core::Ceremony) call; it composes as the
/// object-safe `&dyn Sleep + Send + Sync` handle (`SleepHandle`). Under
/// `#[tokio::test(start_paused = true)]` the same code path is driven
/// by the paused test clock with zero real-time sleeps.
///
/// The unit-struct shape makes [`Clone`]/[`Copy`] trivial so callers
/// can hand copies into moved closures (e.g. a [`Drain`](fidoh_core::Drain)
/// hook) without `Arc` ceremony; the type is a pure marker — tokio's
/// timers live in the returned futures, not here.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TokioSleep;

impl TokioSleep {
    /// The factory as a shared, object-safe handle, ready to pass to
    /// core/transport/ceremony calls.
    pub fn handle(&self) -> &(dyn Sleep + Send + Sync) {
        &TokioSleep
    }

    /// The factory as a leak-free owned handle for `'static` futures
    /// (e.g. a ceremony spawned onto a runtime): the caller drops the
    /// [`Arc`] when the spawned future is done.
    pub fn shared() -> std::sync::Arc<dyn Sleep + Send + Sync> {
        std::sync::Arc::new(TokioSleep)
    }
}

impl Sleep for TokioSleep {
    fn sleep(
        &self,
        duration: Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        // tokio::time::sleep is cancellation-safe (dropping it cancels
        // only this wait) and Send; boxing keeps the object-safe
        // `Sleep` return type (design A3). On a paused test clock the
        // future resolves exactly when the test advances time.
        Box::pin(tokio::time::sleep(duration))
    }
}

// --------------------------------------------------------------------
// The blocking-call bridge (async-core design D3; spec requirement
// "Blocking-syscall transport policy with spawn_blocking adapter").
// --------------------------------------------------------------------

/// What one blocking bridge resolved to.
///
/// `Err(Error::Timeout(phase))` is the slice-expiry abort path: the
/// blocking side observed its granted slice expire (or the budget was
/// already exhausted when the bridge was entered) and exited instead
/// of blocking unboundedly — the deadline-driven abort path design D3
/// mandates for every blocking operation.
pub type SliceOutcome<T> = Result<T, Error>;

/// What the blocking side knows about its granted slice (design D3:
/// the blocking op receives the slice so it can bound its own wait —
/// the exit path for a detached thread).
#[derive(Clone, Copy, Debug)]
pub struct SliceGrantArgs {
    /// The granted duration (≤ the requested `max_slice`, ≤ remaining
    /// budget). The blocking closure MUST arrange to finish within
    /// this bound — waiting at most this long before reporting
    /// `Err(Error::Timeout(phase))` from the closure.
    pub granted: Duration,
    /// The phase to name in the closure's own typed timeout.
    pub phase: Phase,
}

/// Run one blocking wait slice on tokio's blocking pool, bounded by
/// the caller's single ceremony budget (async-core design D3/D4).
///
/// The slice granted is the shorter of `max_slice` and the remaining
/// [`Deadline`] budget; it is consumed from the shared budget BEFORE
/// the op issues (an exhausted budget means the typed timeout fires
/// before any blocking call reaches the device). `max_slice` is the
/// policy bound for the op — [`DEFAULT_WAIT_SLICE`] for a CTAPHID
/// read, [`NFC_POLL_SLICE`] for an NFC field poll, `deadline.remaining()`
/// for a one-shot hop like a PC/SC transceive.
///
/// Resolution: the returned future resolves with the op's result as
/// soon as the blocking side finishes — success, failure, or its own
/// slice-expiry [`Error::Timeout`]. The async side does not race a
/// second timer against the op: the budget was already spent on the
/// grant, and re-checking it on resolution would double-charge the
/// hop. Dropping the returned future detaches the op (design D3: it
/// keeps running on the blocking pool and terminates by observing its
/// granted slice — "Dropped future detaches from blocking thread").
///
/// # Example
///
/// ```no_run
/// use std::time::Duration;
/// use fidoh_core::{Deadline, Phase};
/// use fidoh_tokio::{TokioSleep, spawn_blocking_slice, DEFAULT_WAIT_SLICE};
///
/// # async fn demo() {
/// let deadline = Deadline::new(Duration::from_secs(30));
/// let report: Vec<u8> = spawn_blocking_slice(
///     &deadline,
///     Phase::CommandExchange,
///     DEFAULT_WAIT_SLICE,
///     |slice| {
///         // blocking hidraw read, exiting within `slice.granted`...
/// #       let _ = slice.granted;
///         Ok(vec![0xA1])
///     },
/// )
/// .await
/// .expect("slice did not expire");
/// # let _ = report;
/// # }
/// ```
///
/// # Type parameters
///
/// - `T`: the op's success payload; `Send + 'static` to cross onto
///   the blocking pool (async-core design A4's visible `+ Send`
///   bounds are what make this usable).
/// - `F`: the blocking closure, `FnOnce` (one slice, one call).
pub async fn spawn_blocking_slice<T, F>(
    deadline: &Deadline,
    phase: Phase,
    max_slice: Duration,
    op: F,
) -> SliceOutcome<T>
where
    T: Send + 'static,
    F: FnOnce(SliceGrantArgs) -> SliceOutcome<T> + Send + 'static,
{
    // Grant-before-issue: consume the slice from the shared budget
    // first. `None` = budget exhausted → typed timeout, no blocking
    // call issued at all.
    let grant = match fidoh_core::policy::hop_slice(deadline, max_slice) {
        Some(grant) => grant,
        None => return Err(Error::Timeout(phase)),
    };
    let join = tokio::task::spawn_blocking(move || {
        op(SliceGrantArgs {
            granted: grant.granted,
            phase,
        })
    });
    // Fold every spawn-side failure into the typed taxonomy: an
    // `Err` from the JoinHandle means the blocking task PANICKED (a
    // running `spawn_blocking` task is never otherwise cancelled).
    // The panic surfaces as `Error::Transport` — typed, swallowable
    // by policy, and poisoning nothing.
    match join.await {
        Ok(outcome) => outcome,
        Err(join_err) => Err(Error::Transport(TransportError::new(
            "tokio",
            format!(
                "blocking bridge panicked during {phase} slice ({:?} granted): {join_err}",
                grant.granted
            ),
        ))),
    }
}
