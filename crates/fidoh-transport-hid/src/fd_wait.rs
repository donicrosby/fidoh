//! Budget-bounded report receipt: poll a nonblocking fd through
//! `Sleep`-driven ticks of at most [`READ_POLL_QUANTUM`] so a dropped
//! future re-detects cancellation at tick boundaries (async-core D3)
//! and the ceremony budget bounds the total wait (D4).
//!
//! Split from `fd.rs` to keep the fd layer synchronous and simple.

use alloc::vec::Vec;

use core::time::Duration;

use fidoh_core::{Deadline, Error, Phase, SleepHandle};

use crate::fd::RawFd;

/// Poll quantum of the budget-bounded read loop: the longest a single
/// `Sleep` tick can delay observing a report already sitting in the
/// kernel buffer. Each tick charges only its own slice from the shared
/// [`Deadline`], so total spend stays exact and the typed timeout
/// still names `phase` on exhaustion. (OQ-4 hardware-day finding: the
/// former pacing slept the FULL slice grant — 30 s — between drains,
/// starving ceremony budgets while completed replies waited unread in
/// the buffer; probes P2/P3/P4 burned their deadlines on it.)
pub const READ_POLL_QUANTUM: Duration = Duration::from_millis(5);

/// Budget-bounded next-report receive. Returns the next report, or the
/// typed timeout naming `phase` when the budget is exhausted.
///
/// Each tick is granted from the shared [`Deadline`] — a tick bounds
/// cancellation latency only and never extends the total wait
/// (async-core D4: the shorter of the quantum and what remains).
/// `pub` because `fsm` (public) uses it; callers should use the
/// `Fsm`/`Device` surface, not this.
pub async fn read_report_bounded<F: RawFd>(
    fd: &mut F,
    deadline: &Deadline,
    sleep: SleepHandle<'_>,
    phase: Phase,
) -> Result<Vec<u8>, Error> {
    loop {
        // Drain what is already queued before sleeping.
        match fd.read_nonblocking() {
            Ok(Some(report)) => return Ok(report),
            Ok(None) => {}
            Err(_e) => {
                // Device vanished mid-wait (ENODEV on unplug): typed
                // DeviceGone (async-core taxonomy) — the pending
                // transaction cannot complete. The I/O detail stays on
                // the error value for logging callers; the core
                // taxonomy folds it.
                return Err(Error::DeviceGone);
            }
        }
        // Grant the next tick: shorter of the quantum and the remaining
        // budget. None = budget exhausted → typed Timeout (D4).
        let Some(granted) = deadline.consume_slice(READ_POLL_QUANTUM) else {
            return Err(Error::Timeout(phase));
        };
        sleep.sleep(granted).await;
    }
}
