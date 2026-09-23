//! The `Sleep` trait: the sole waiting mechanism (async-core spec:
//! "Sleep trait as the sole waiting mechanism").
//!
//! No core or transport crate invokes `std::thread::sleep` or any
//! executor-native timer; every wait — sleep, keepalive poll slice, NFC
//! field poll, APDU retry — goes through a caller-supplied `Sleep`
//! factory (stack invariant, openspec/config.yaml). `Sleep` is the ONE
//! trait in this crate required to be object-safe (design A3): it
//! crosses the caller/crate boundary, so it must compose as `&dyn
//! Sleep`, and its futures are boxed to keep that composition possible
//! with a stable `Duration -> Future` return.
//!
//! The real factory (tokio timer) lives in `fidoh-tokio`; tests inject
//! a fake clock (async-core spec: "Deterministic test clock" scenario).

use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::time::Duration;

/// A factory producing a future that completes after a given duration.
///
/// Object-safe by design (async-core spec: "`Sleep` SHALL be
/// object-safe so it can cross crate boundaries as `&dyn Sleep`").
/// The returned future is pinned-boxed so a single factory can hand out
/// independently owned waits; adapters box a runtime timer once per
/// call, which is allocation-per-wait at adapter boundaries only —
/// never on core's behalf.
///
/// Contract on the returned future: it resolves after *at least* the
/// requested duration on a real clock, and exactly when the test clock
/// advances under a fake clock. It is cancellation-safe: dropping it
/// cancels only that one wait.
pub trait Sleep {
    /// Produce a future completing after `duration`.
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()>>>;
}

/// The reference every wait-driven API accepts: a shared handle to an
/// object-safe [`Sleep`] factory that is `Send + Sync` so the `Send`
/// futures in [`Device`](crate::device::Device) and
/// [`Ceremony`](crate::ceremony::Ceremony) can hold it across await
/// points (design A4's visible `+ Send` bounds).
///
/// The factory trait object itself must be `Send + Sync` because the
/// caller's executor may move a ceremony future between worker threads
/// while a wait is in flight.
pub type SleepHandle<'a> = &'a (dyn Sleep + Send + Sync);

impl Sleep for alloc::sync::Arc<dyn Sleep + Send + Sync> {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()>>> {
        (**self).sleep(duration)
    }
}

impl Sleep for alloc::boxed::Box<dyn Sleep + Send + Sync> {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()>>> {
        (**self).sleep(duration)
    }
}
