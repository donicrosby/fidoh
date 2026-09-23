//! fidoh-core: cleanroom CTAP2 core data model.
//!
//! Implements the `core-model` openspec change: canonical CBOR per
//! CTAP2.1 §8, the authenticatorGetInfo (§6.4) and
//! authenticatorGetAssertion (§6.2) wire structures, the CTAP2 status
//! code space (§8.2), PIN/UV auth parameter shapes (§6.2, §6.5.5), and
//! the COSE ES256 key representation (RFC 9053 §7.1.1).
//!
//! Invariants honored (openspec/config.yaml):
//! - `#![no_std]` + `alloc`; runtime-agnostic, no executor dependency.
//! - `deny(unsafe_code)` (workspace lints table).
//! - Typed errors everywhere; no `unwrap`/`expect` outside tests.

#![no_std]

extern crate alloc;

pub mod cbor;
pub mod cose;
pub mod error;
pub mod get_assertion;
pub mod get_info;
pub mod pin;
pub mod status;

pub use error::{DecodeError, DecodePolicy, EncodeError, InvalidRequest};
pub use status::StatusCode;
