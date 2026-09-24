//! Single-budget timeout model (async-core design D4) and the ceremony
//! phase names carried by typed timeouts.
//!
//! The ceremony runs on ONE caller-supplied budget: each hop receives
//! what remains. There are no per-hop timeouts — expiry at any hop
//! returns `Error::Timeout(Phase::…)` naming the phase (async-core spec:
//! "Single-budget timeout model with safe cancellation"). All waits are
//! driven through the [`Sleep`](crate::sleep::Sleep) factory; nothing in
//! this crate sleeps on a real clock.

use core::fmt;
use core::future::Future;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;

use crate::error::Error;
use crate::future::{select, Either};
use crate::sleep::SleepHandle;

/// Default per-wait slice for long keeps (CTAPHID read re-slicing per
/// design OQ-2, resolved: 30 s tunable named constant).
///
/// Exposed crate-public so transport crates can import a single default
/// instead of scattering literals; overridable per-ceremony by callers
/// (design OQ-2: "a tunable named constant... not a hard-coded literal
/// scattered through the transport").
pub const DEFAULT_WAIT_SLICE: Duration = Duration::from_secs(30);

/// Default NFC field-poll slice (async-core design D3: "NFC field
/// polling slices at max 1 s per poll so card removal surfaces
/// promptly").
pub const NFC_POLL_SLICE: Duration = Duration::from_secs(1);

/// Ceremony phase names for typed timeouts.
///
/// Each variant names one hop of the ceremony so `Error::Timeout`
/// identifies what expired without a string payload (async-core spec:
/// "expiry returns `Error::Timeout` naming the ... phase").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Phase {
    /// `Transport::enumerate` (async-core spec, discovery scenario:
    /// "on deadline expiry it returns `Error::Timeout` naming the
    /// enumeration phase").
    Enumeration,
    /// `Transport::connect` (async-core spec, "Connect with deadline"
    /// scenario).
    Connect,
    /// Channel open (CTAPHID INIT per CTAP2.1 §11.2.9.1.3, or APDU SELECT
    /// per CTAP2.1 §11).
    ChannelOpen,
    /// A CTAP command exchange (e.g. authenticatorGetInfo, CTAP2.1
    /// §6.4).
    CommandExchange,
    /// The user-presence wait, bounded by the remaining budget
    /// (async-core spec: "the ceremony returns `Error::Timeout` naming
    /// the user-presence phase").
    UserPresence,
    /// authenticatorGetAssertion exchange (CTAP2.1 §6.2).
    GetAssertion,
    /// authenticatorGetInfo exchange (CTAP2.1 §6.4).
    GetInfo,
    /// authenticatorGetNextAssertion drain (CTAP2.1 §6.3; named by the
    /// ceremony change).
    GetNextAssertion,
    /// Best-effort channel release on close/drop (design OQ-3, resolved:
    /// release attempt is mandatory; "if the release attempt itself
    /// fails or the deadline has already expired, the error is
    /// swallowable").
    Release,
}

impl Phase {
    /// The specification name of this phase for diagnostics.
    pub fn name(self) -> &'static str {
        match self {
            Self::Enumeration => "enumeration",
            Self::Connect => "connect",
            Self::ChannelOpen => "channel-open",
            Self::CommandExchange => "command-exchange",
            Self::UserPresence => "user-presence",
            Self::GetAssertion => "getAssertion",
            Self::GetInfo => "getInfo",
            Self::GetNextAssertion => "getNextAssertion",
            Self::Release => "release",
        }
    }
}

impl core::fmt::Display for Phase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// The single ceremony deadline budget (async-core design D4).
///
/// Constructed once at ceremony start; each hop consumes from it and
/// receives the remainder. Budget state is held in an atomic so the
/// budget can be shared as `&Deadline` across the `Send` futures the
/// traits return (design A4's visible `+ Send` bounds) without any
/// unsafe — the crate-level `deny(unsafe_code)` stands.
///
/// Stored as nanoseconds in a `u64`; a budget beyond ~584 years
/// saturates (a ceremony budget is seconds-to-minutes by design D4,
/// so saturation is unreachable in practice).
///
/// Cancellation safety: dropping a ceremony future drops the budget
/// with it — no shared state, no poisoned locks (async-core spec:
/// "Cancellation by dropping any ceremony or device future SHALL be
/// safe: it SHALL NOT leave shared state poisoned").
///
/// # Semantics
///
/// - [`consume`](Self::consume) spends wall-clock time a hop reports
///   and returns the remainder (`Error::Timeout` if nothing remains).
/// - [`consume_slice`](Self::consume_slice) spends the shorter of the
///   requested slice and what remains, returning the slice actually
///   granted (`None` once exhausted) — the keepalive/NFC poll loop
///   primitive (design D3 bounds).
/// - [`wait`](Self::wait) is the await primitive: races the hop against
///   the remaining budget through the [`Sleep`](crate::sleep::Sleep)
///   factory and returns the hop output or `Error::Timeout(Phase)`.
pub struct Deadline {
    /// Remaining budget in nanoseconds. Relaxed ordering: the budget
    /// guards no other data; it is consumed from one sequential
    /// ceremony flow at a time.
    remaining: AtomicU64,
}

/// Convert a `Duration` to nanoseconds, saturating at `u64::MAX`
/// (documented on [`Deadline`]: a budget beyond ~584 years is
/// out-of-model for a ceremony).
fn nanos(d: Duration) -> u64 {
    let n = d.as_nanos();
    u64::try_from(n).unwrap_or(u64::MAX)
}

fn from_nanos(n: u64) -> Duration {
    Duration::from_nanos(n)
}

impl Deadline {
    /// Build a budget of `total`.
    pub fn new(total: Duration) -> Self {
        Self {
            remaining: AtomicU64::new(nanos(total)),
        }
    }

    /// The remaining budget. Hops "receive what remains" — this is the
    /// value every operation is bounded by.
    pub fn remaining(&self) -> Duration {
        from_nanos(self.remaining.load(Ordering::Relaxed))
    }

    /// Spend `d` of the budget; returns what remains after the spend,
    /// or `Err(Error::Timeout(_))` if the spend exhausts the budget.
    ///
    /// `d` larger than remaining clamps the remaining side to zero
    /// (exhaustion) rather than panicking: the next
    /// [`consume_slice`][Self::consume_slice] reports `None`.
    pub fn consume(&self, d: Duration) -> Result<Duration, Error> {
        let left = self.remaining.load(Ordering::Relaxed);
        let d = nanos(d);
        if left < d {
            self.remaining.store(0, Ordering::Relaxed);
            return Err(Error::Timeout(Phase::CommandExchange));
        }
        let next = left - d;
        self.remaining.store(next, Ordering::Relaxed);
        Ok(from_nanos(next))
    }

    /// Grant the next wait slice: the shorter of `requested` and the
    /// remaining budget. `None` once the budget is exhausted — the
    /// loop-exit signal for keepalive/poll slices.
    pub fn consume_slice(&self, requested: Duration) -> Option<Duration> {
        let left = self.remaining.load(Ordering::Relaxed);
        if left == 0 {
            return None;
        }
        let granted = nanos(requested).min(left);
        self.remaining.store(left - granted, Ordering::Relaxed);
        Some(from_nanos(granted))
    }

    /// Race a hop future against the remaining budget.
    ///
    /// The deadline timer comes from the same [`Sleep`] factory as the
    /// hop's own waits, so this composes with the fake clock in tests
    /// (async-core spec: "Deterministic test clock" scenario: "zero
    /// real-time sleeps").
    ///
    /// Expiry: if the sleep resolves first, `Err(Error::Timeout(phase))`
    /// is returned and `hop` is dropped (which is the cancellation
    /// path — hop futures must be drop-safe per the async-core
    /// cancellation contract).
    pub async fn wait<T, F>(&self, sleep: SleepHandle<'_>, phase: Phase, hop: F) -> Result<T, Error>
    where
        F: Future<Output = T> + Unpin,
    {
        let remaining = self.remaining();
        if remaining.is_zero() {
            return Err(Error::Timeout(phase));
        }
        match select(hop, sleep.sleep(remaining)).await {
            Either::Left(out) => Ok(out),
            Either::Right(()) => Err(Error::Timeout(phase)),
        }
    }
}

impl fmt::Display for Deadline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} remaining", self.remaining())
    }
}

impl fmt::Debug for Deadline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Deadline")
            .field("remaining", &self.remaining())
            .finish()
    }
}
