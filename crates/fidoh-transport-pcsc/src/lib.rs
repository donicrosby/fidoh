//! fidoh-transport-pcsc: ISO 7816-4 APDU transport over PC/SC —
//! FIDO-over-CCID and NFC (CTAP2.1 §11) on the shared
//! [`Transport`](Transport)/[`Device`](CtapDevice) traits.
//!
//! Governing spec:
//! `openspec/changes/transport-pcsc/specs/transport-pcsc/spec.md`.
//! Layer map:
//!
//! - [`sw`] — ISO 7816-4 status words, typed (pure);
//! - [`apdu`] — command APDU encoding: short / extended length /
//!   short-form chaining (pure);
//! - [`select`] — FIDO AID selection per CTAP2.1 §11.3.3 (pure);
//! - [`framing`] — CTAP-over-APDU framing per §11.3.5 and the
//!   response-assembly state machine: `61xx` GET RESPONSE hops,
//!   `6Cxx` Le retry, `9100` NFCCTAP_GETRESPONSE loop (§11.3.7.2)
//!   (pure);
//! - [`error`] — the typed mapping from PC/SC codes and SWs onto the
//!   async-core/ceremony taxonomy;
//! - [`library`] — the PC/SC library seam (trait) + the real `pcsc`
//!   binding (feature `pcsc`);
//! - [`fake`] — the programmable fake library driving every scenario
//!   in CI;
//! - [`engine`] — the async [`Transport`]/[`Device`] over any
//!   [`Library`], budget-sliced per the single-budget model.
//!
//! Invariants honored (openspec/config.yaml): typed errors
//! everywhere; every wait bounded by the caller's budget (no
//! unbounded loop); `deny(unsafe_code)`; the crate depends only on
//! `fidoh-core` plus the spec-mandated PC/SC binding (feature-gated).

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(any(feature = "std", test))]
extern crate std;

pub mod apdu;
pub mod engine;
pub mod error;
#[cfg(feature = "std")]
pub mod fake;
pub mod framing;
pub mod library;
pub mod select;
pub mod sw;

pub use engine::{PcscDevice, PcscTransport};
pub use error::{PcscCause, PcscError, SkipCause};
#[cfg(feature = "pcsc")]
pub use library::PcscLibrary;
pub use library::{ActiveProtocol, CardState, ConnToken, Library, ReaderEntry, ShareMode};
pub use select::{evaluate_select, select_fido_aid, SelectOutcome, FIDO_AID};
pub use sw::StatusWord;

/// CTAP framing constants re-exported for tests and diagnostics
/// (CTAP2.1 §11.3.5).
pub use framing::{CLA_CHAIN, CLA_CTAP, INS_GETRESPONSE, INS_GET_RESPONSE, INS_MSG};
