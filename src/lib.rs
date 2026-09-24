//! fidoh — the workspace facade crate.
//!
//! This crate exists to satisfy the async-core spec requirement
//! "Feature-flag layout with soft transport as default": plain
//! `cargo build` compiles fidoh-core + fidoh-transport-soft only (no
//! OS device APIs); `hid`, `pcsc`, and `tokio` are opt-in feature
//! edges on the root manifest. All real functionality lives in the
//! path-dependency crates; nothing here re-exports their surface (the
//! per-crate APIs stay the supported interface).
//!
//! Nothing in the workspace depends on this crate. It is the build
//! system's front door, not a library boundary.

#![forbid(unsafe_code)]
