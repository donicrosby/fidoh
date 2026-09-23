//! Budget-bounded report receipt: poll a nonblocking fd through
//! `Sleep`-driven slices of at most [`WAIT_SLICE`] so a dropped future
//! re-detects cancellation at slice boundaries (async-core D3) and the
//! ceremony budget bounds the total wait (D4).
//!
//! Split from `fd.rs` to keep the fd layer synchronous and simple.

use alloc::vec::Vec;

use fidoh_core::{Deadline, Error, Phase, SleepHandle};

use crate::fd::RawFd;

/// Budget-bounded next-report receive. Returns the next report, or the
/// typed timeout naming `phase` when the budget is exhausted.
///
/// Each slice is granted from the shared [`Deadline`] — the slice
/// bounds cancellation latency only and never extends the total wait
/// (async-core D4: the shorter of WAIT_SLICE and what remains).
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
        // Grant the next slice: shorter of WAIT_SLICE and the remaining
        // budget. None = budget exhausted → typed Timeout (D4).
        let Some(granted) = deadline.consume_slice(crate::WAIT_SLICE) else {
            return Err(Error::Timeout(phase));
        };
        sleep.sleep(granted).await;
    }
}
