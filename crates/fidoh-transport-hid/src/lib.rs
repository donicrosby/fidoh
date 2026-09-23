//! fidoh-transport-hid: CTAPHID over Linux hidraw (CTAP2.1 §11.2).
//!
//! Implements the `transport-hid` openspec change
//! (`openspec/changes/transport-hid/specs/transport-hid/spec.md`):
//! the USB HID transport behind the SAME
//! [`Transport`](fidoh_core::Transport)/[`Device`](fidoh_core::Device)
//! traits as the soft token (transport-soft), so client ceremony code
//! runs identically against hardware.
//!
//! # Layer map (design: pure vs fd split)
//!
//! ```text
//! HidTransport / HidDevice        trait impls (device.rs) — thin
//! ─ fsm.rs                        channel/transaction state machine
//! ─ packet.rs                     64-byte report encode/decode (pure)
//! ─ descriptor.rs                 HID report-descriptor usage parser (pure)
//! ─ sysfs.rs                      sysfs tree model + walker (pure)
//! ─ fd_wait.rs                    budget-sliced report receipt
//! ─ fd.rs / sysfs_fs.rs           the ONLY std::fs / /dev contact points
//! ─ error.rs / consts.rs          typed errors / verified §11.2 constants
//! ```
//! # Timeouts (design §Blocking waits table)
//!
//! Every wait is bounded by the caller's single ceremony
//! [`Deadline`](fidoh_core::Deadline) (async-core D4); every receive
//! poll is re-sliced at [`WAIT_SLICE`] (30 s default — the crate-public
//! re-export of `DEFAULT_WAIT_SLICE`) so a dropped future re-detects
//! cancellation within one slice (async-core D3). Expiry surfaces as
//! `Error::Timeout(Phase)` naming the phase. No wait in this crate
//! uses `std::thread::sleep` or an unbounded read.
//!
//! # Hardware probes
//!
//! `probes.rs` (integration test) is gated on `FIDOH_HARDWARE_TESTS=1`
//! (docs/testing.md T3 convention) and compiles with zero features.
//! Without the env var it prints a skip notice.

#![forbid(unsafe_code)]

// This crate is std-only (file I/O for /dev/hidrawN + sysfs), so
// `alloc` is not automatically in scope; house style still paths
// collection types through `alloc::` for consistency with the rest of
// the workspace.
extern crate alloc;

pub mod consts;
pub mod descriptor;
pub mod error;
pub mod fsm;
pub mod packet;
pub mod sysfs;

pub mod fd;
pub mod fd_wait;

mod device;
mod sysfs_fs;

pub use device::{HidDevice, HidTransport, WAIT_SLICE};
pub use error::{Capability, FramingError, HidError, HidErrorCode};
pub use fsm::{InitInfo, NonceSource};
pub use sysfs::{HidId, HidRawEntry};

use core::time::Duration;

/// The busy-retry delay for ERR_CHANNEL_BUSY (§11.2.9.1.6: the client
/// SHOULD retry "after a short delay"; §11.2.5.2 fixes no number, so
/// this is a documented, tunable host-side default — re-verify the
/// value on real hardware against actual device recovery times,
/// design OQ-1 probe item).
pub const BUSY_RETRY_DELAY: Duration = Duration::from_millis(50);
