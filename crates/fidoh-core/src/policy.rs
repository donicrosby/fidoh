//! Blocking-syscall transport policy seams (async-core spec:
//! "Blocking-syscall transport policy with spawn_blocking adapter";
//! design D3).
//!
//! v1 transports MAY use blocking syscalls internally (Linux hidraw
//! `read`/`write`; PC/SC calls). Core owns no executor, so the
//! `spawn_blocking` adapter lives in `fidoh-tokio` later; what core
//! fixes here are the typed seams the adapter and transports share:
//! the slicing bounds (re-exported from [`crate::time`]) and
//! [`SliceGrant`], the unit of a bounded blocking slice.
//!
//! Invariants these seams encode:
//! - A blocking slice never exceeds the remaining ceremony budget.
//! - CTAPHID read slices re-slice at [`DEFAULT_WAIT_SLICE`] (30 s,
//!   design OQ-2 resolved) so a detached thread exits promptly after a
//!   dropped future.
//! - NFC field polls slice at [`NFC_POLL_SLICE`] (1 s) so card removal
//!   surfaces promptly (design D3).

use core::time::Duration;

use crate::time::Deadline;

pub use crate::time::{
    DEFAULT_WAIT_SLICE as CTAPHID_READ_SLICE, NFC_POLL_SLICE as NFC_FIELD_POLL_SLICE,
};

/// A single bounded wait slice granted against the remaining ceremony
/// budget.
///
/// The adapter wraps ONE such slice in one `spawn_blocking` op; on
/// wake the transport checks its result and re-slices against the
/// remaining budget. `None` signals budget exhaustion: the caller
/// converts to `Error::Timeout(Phase)` at its own boundary (the phase
/// is transport/hop-specific, so core does not bake it in here).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SliceGrant {
    /// The granted duration (≤ requested slice, ≤ remaining budget).
    pub granted: Duration,
    /// Budget remaining after the grant — what the NEXT slice will
    /// consume from.
    pub remaining_after: Duration,
}

/// Grant the next CTAPHID read slice (max [`CTAPHID_READ_SLICE`] per
/// slice, design D3: "CTAPHID reads re-sliced at a bounded interval
/// (default 30 s)").
///
/// `None` when the budget is exhausted: the transport's next wait
/// fails with a typed timeout instead of blocking unboundedly.
pub fn ctaphid_read_slice(deadline: &Deadline) -> Option<SliceGrant> {
    grant(deadline, CTAPHID_READ_SLICE)
}

/// Grant the next NFC field-poll slice (max [`NFC_FIELD_POLL_SLICE`]
/// per slice, design D3: "NFC field polls sliced at most 1 s").
pub fn nfc_field_poll_slice(deadline: &Deadline) -> Option<SliceGrant> {
    grant(deadline, NFC_FIELD_POLL_SLICE)
}

/// Grant the next arbitrary hop slice (used for APDU selects, channel
/// opens, and any wait not covered by the CTAPHID/NFC named slices).
pub fn hop_slice(deadline: &Deadline, requested: Duration) -> Option<SliceGrant> {
    grant(deadline, requested)
}

fn grant(deadline: &Deadline, requested: Duration) -> Option<SliceGrant> {
    let granted = deadline.consume_slice(requested)?;
    Some(SliceGrant {
        granted,
        remaining_after: deadline.remaining(),
    })
}
