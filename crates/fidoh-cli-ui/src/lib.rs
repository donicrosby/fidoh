//! fidoh-cli-ui: the reference caller (fidoh-cli-ui openspec change).
//!
//! A Linux-first CLI over the whole fidoh stack: `list` enumerates
//! every compiled-in transport with typed diagnostics, `info` runs the
//! mandatory authenticatorGetInfo probe (CTAP2.1 §6.4; ceremony design
//! OQ-2) standalone, and `assert` runs the full getAssertion ceremony
//! (CTAP2.1 §6.2) — discovery (collect-never-short-circuit), explicit
//! selection (default `Fail`), the probe, and the keepalive-driven
//! user-presence wait with display-level prompt dedup (design D4).
//!
//! # Crate-graph position (async-core design D2)
//!
//! Terminal leaf: this crate depends on `fidoh-core`, the runtime
//! adapter, and the transport crates; NOTHING in the workspace depends
//! on it. The soft token rides under the `demo` feature only (design
//! D5) — never in hardware discovery.
//!
//! # Runtime entry (design D2, extended to binaries)
//!
//! The binary never names the runtime: argument parsing (hand-rolled
//! per design D3), rendering, discovery, and the testable orchestration
//! layer (`args`, `render`, `discover`, `run`) are runtime-agnostic in
//! this lib; `src/exe.rs` is the thin `main` adapter.
//!
//! **Entry seam (crystallized):** the adapter owns the runtime entry —
//! `fidoh_tokio::run(future)` builds a fresh single-threaded runtime
//! and drives the ceremony future with the runtime's own `block_on`,
//! so real-timer deadlines (hardware keepalive waits) fire and wake
//! correctly. `exe::with_run` wraps that entry exactly once and hands
//! the adapter's `Sleep` factory to async subcommand bodies; the CLI
//! still writes zero runtime identifiers itself (greppable D2). The
//! earlier std park/unpark pump under a sync `block_on(async { body
//! () })` seam is gone: it parked the timer driver inside the body's
//! frame, so a real-timer wait could never be woken — banned shape,
//! see `exe` module docs.

#![forbid(unsafe_code)]

pub mod args;
pub mod discover;
pub mod exe;
pub mod render;
pub mod run;

pub use args::{AssertArgs, FailedFlag, Invocation, ParseOutcome};
pub use discover::{Enumeration, NodeOutcome};
pub use run::{TouchPrompt, DEFAULT_BUDGET, TOUCH_PROMPT};
