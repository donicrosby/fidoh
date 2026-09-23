//! fidoh-transport-soft: in-process virtual CTAP2 authenticator.
//!
//! Implements the `transport-soft` openspec change
//! (`openspec/changes/transport-soft/specs/transport-soft/spec.md`): a
//! software CTAP2 authenticator that runs the SAME
//! [`Transport`](fidoh_core::Transport)/[`Device`](fidoh_core::Device)
//! traits as the hardware transports (CTAPHID, PC/SC), performs no OS
//! I/O, and serves as the CI harness so client ceremony code is
//! testable without hardware.
//!
//! Surface (transport-soft spec):
//!
//! - [`SoftAuthenticator`] — the authenticator core: credential store,
//!   global signature counter (CTAP2.1 §6.1.2), pinned [`AAGUID`], and
//!   behavior knobs. Implements [`Transport`](fidoh_core::Transport).
//! - [`SoftDevice`] — the [`Device`](fidoh_core::Device) impl handed
//!   out by `Transport::connect`. Shares the authenticator via
//!   `Arc<Mutex<_>>` (required for `Send` futures: `&mut self` on
//!   `Device::send` would otherwise hold a `&mut` borrow across
//!   `.await` points, and `&mut T` is not `Send`-usable through the
//!   trait's RPITIT bounds).
//! - [`MakeCredentialArgs`]/[`MintedCredential`] — the INTERNAL
//!   harness-only makeCredential (CTAP2.1 §6.1, WebAuthn L2 §4).
//!   Deliberately NOT reachable through the `Device` trait: the client
//!   v1 API has no makeCredential (stack invariants).
//! - [`Config`]/[`Knobs`]/[`UpUvMode`] — UP/UV behavior modes and the
//!   error-injection knobs (arbitrary CTAP status, keepalive sequences,
//!   delay-beyond-deadline, wrong-credential-id; all 11 matrix codes
//!   are injectable because `inject_status` takes any
//!   [`StatusCode`](fidoh_core::StatusCode)).
//! - [`Snapshot`] (feature `snapshot`) — versioned serde-JSON export
//!   of the full credential store (design OQ-3, resolved: JSON over
//!   CBOR for readability of committed fixtures).
//!
//! # Entropy (no_std note)
//!
//! The crate is `no_std` + `alloc` by default. Key generation takes an
//! injectable [`RngSource`]; the default is [`DeterministicRng`]
//! seeded by a compile-time build salt, so the crate needs NO OS
//! entropy and no `std` anywhere. Harnesses wanting collision-free
//! uniqueness across runs can supply a counter-seeded
//! `DeterministicRng` or any other [`RngSource`] impl; the docs call
//! this "csprng" but the injectable seam is what the spec actually
//! pins ("Randomness source is injectable", design §Cryptography).
//!
//! # Timeout bounds (design §Blocking waits)
//!
//! - `require-explicit-poke` UP/UV waits are bounded SOLELY by the
//!   caller's ceremony [`Deadline`](fidoh_core::Deadline): the token
//!   emits keepalive progress events and re-slices the remaining
//!   budget; expiry surfaces as `Error::Timeout(<command phase>)`.
//! - `delay_beyond_deadline` waits are hard-capped at
//!   `deadline + 60 s` ([`DELAY_HARD_CAP`]) so a misconfigured test
//!   cannot hang CI.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod auth;
mod config;
mod device;
mod rng;
#[cfg(feature = "snapshot")]
mod snapshot;
mod wire;

pub use auth::{
    CredentialRecord, MakeCredentialArgs, MintedCredential, SoftAuthenticator, AAGUID,
    MAX_ASSERTION_QUEUE,
};
pub use config::{Config, KeepaliveEvent, Knobs, RngConfig, UpUvMode};
pub use device::{SoftDevice, SoftDeviceCore, SoftTransport};
pub use rng::{DeterministicRng, RngSource};
#[cfg(feature = "snapshot")]
pub use snapshot::{
    export as snapshot_export, from_json as snapshot_from_json, import as snapshot_import,
    to_json as snapshot_to_json, Snapshot, SnapshotCredential, SnapshotError, SNAPSHOT_VERSION,
};
pub use wire::AssertionParts;

use core::time::Duration;

/// Hard cap for the `delay_beyond_deadline` knob's internal wait:
/// `deadline + 60 s` (design §Blocking waits). After this the token
/// responds even though the caller has long since timed out — the
/// point of the knob is exercising the CLIENT timeout path, and a
/// misconfigured test must never hang CI.
pub const DELAY_HARD_CAP: Duration = Duration::from_secs(60);

/// Default keepalive re-slice while pended on an explicit poke: the
/// token polls the poke flag at this cadence (bounded by the caller's
/// deadline, which always wins).
pub const POKE_POLL_SLICE: Duration = Duration::from_millis(100);
