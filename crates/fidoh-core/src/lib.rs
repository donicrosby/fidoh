//! fidoh-core: cleanroom CTAP2 core data model and async trait layer.
//!
//! Implements:
//! - the `core-model` openspec change: canonical CBOR per CTAP2.1 §8,
//!   the authenticatorGetInfo (§6.4) and authenticatorGetAssertion
//!   (§6.2) wire structures, the CTAP2 status code space (§8.2), PIN/UV
//!   auth parameter shapes (§6.2, §6.5.5), and the COSE ES256 key
//!   representation (RFC 9053 §7.1.1);
//! - the `async-core` openspec change: the [`Transport`],
//!   [`Device`], [`Ceremony`], and [`Sleep`] trait surface
//!   (design D1), the single-budget [`Deadline`] model (design D4),
//!   the blocking-syscall [`policy`] seams for `spawn_blocking`
//!   adaptation (design D3), and the feature-flag layout (design D5).
//!
//! Invariants honored (openspec/config.yaml):
//! - `#![no_std]` + `alloc`; runtime-agnostic, no executor dependency.
//!   Every wait goes through the caller-supplied [`Sleep`] factory —
//!   this crate contains no `thread::sleep` and no runtime-native
//!   timer.
//! - `deny(unsafe_code)` (workspace lints table).
//! - Typed errors everywhere; no `unwrap`/`expect` outside tests.
//!
//! # Crate graph (async-core design D2)
//!
//! ```text
//!                 ┌────────────┐
//!                 │ fidoh-core │  traits, CTAP model types, ceremony
//!                 └─────▲──────┘  orchestration. Deps: core + alloc only.
//!        ┌──────────────┼──────────────┬───────────────┐
//!        │              │              │               │
//! fidoh-transport-  fidoh-transport- fidoh-transport- fidoh-tokio
//!      hid              pcsc           soft           (Sleep impl,
//!   (CTAPHID,       (ISO 7816-4    (in-process;      spawn_blocking
//!   CTAP2.1 §11.2)   APDU layer,     CI harness)      wrapper)
//!                    CTAP2.1 §11)                         │
//!                                                  fidoh-cli-ui (opt)
//! ```
//!
//! Dependency arrows point ONLY toward `fidoh-core`; transport crates
//! and `fidoh-tokio` depend on `fidoh-core` and never on each other;
//! only `fidoh-tokio` names tokio; `fidoh-core` has NO runtime and NO
//! OS dependency beyond `alloc`/`core`. Feature flags `hid`, `pcsc`,
//! `tokio` enable the corresponding sibling crates (see the crate
//! manifest); `default = ["soft"]` keeps the default build
//! OS-dependency-free.
//!
//! [`Transport`]: transport::Transport
//! [`Device`]: device::Device
//! [`Ceremony`]: ceremony::Ceremony
//! [`Sleep`]: sleep::Sleep
//! [`Deadline`]: time::Deadline

#![no_std]

extern crate alloc;

pub mod cbor;
pub mod ceremony;
pub mod cose;
pub mod crypto;
pub mod device;
pub mod error;
pub mod future;
pub mod get_assertion;
pub mod get_info;
pub mod pin;
pub mod policy;
pub mod sleep;
pub mod status;
pub mod time;
pub mod transport;

pub use ceremony::{
    Ceremony, Drain, GetAssertionCeremony, GetAssertionExchange, GetAssertionOutcome, UvEffective,
    UvPolicy,
};
pub use device::{ChannelId, CtapCommand, Device, DeviceEvent};
pub use error::{
    CeremonyError, DecodeError, DecodePolicy, DiscoveryDiagnostic, EncodeError, Error,
    InvalidRequest, TransportError,
};
pub use sleep::{Sleep, SleepHandle};
pub use status::StatusCode;
pub use time::{Deadline, Phase, DEFAULT_WAIT_SLICE, NFC_POLL_SLICE};
pub use transport::{
    apply_selection, CandidateDescriptor, DeviceId, DeviceInfo, SelectionPolicy, Transport,
    TransportKind,
};
