# fidoh-tokio — runtime adapter (Sleep factory + spawn_blocking bridge)

## Why

The async-core change names `fidoh-tokio` directly in its crate-graph
requirement (D2: "only `fidoh-tokio` SHALL name tokio as a dependency")
and defines the blocking-syscall transport policy (D3) and the tokio
feature marker (D5), but never gave the adapter crate its own change
directory: its contract lived only as requirements inside async-core.
The implementation landed 2026-09-23 (deleg_123d923a) against those
named requirements. This change gives the adapter a first-class spec so
the manifest-audit invariants, the slice-grant bridging discipline, and
the tokio MSRV floor are specified where future revisions will look for
them — not inferred from another change's text.

## What Changes

- Specify the **`Sleep` factory**: `TokioSleep` implements fidoh-core's
  `Sleep` trait on the tokio timer; produced futures are `Send` (async-core
  OQ-4) and resolve correctly under a paused (deterministic) test clock.
- Specify the **blocking-call bridge**: every blocking transport
  operation runs on `tokio::task::spawn_blocking`; the slice is granted
  from the shared `Deadline` **before** the task is spawned
  (grant-before-issue, mirroring the transport-pcsc engine debit
  discipline), the blocking closure receives its `SliceGrantArgs`
  (`granted`, `phase`) and exits at the slice edge with typed
  `Error::Timeout`; dropping the future detaches the blocking thread
  (no async-side second timer — the grant already debited the budget).
- Specify **typed panic folding**: a panic inside the blocking bridge
  propagates as `Error::Transport` (kind `"tokio"`), never poisons, never
  unwinds into the caller's async context.
- Specify the **tokio dependency exclusivity** as its own auditable
  requirement: only `fidoh-tokio` names tokio; library deps are
  `rt` + `time` only with default features off; test-only extras
  (`macros`, `rt-multi-thread`, `sync`, `test-util`) and the
  `fidoh-transport-soft` CI-harness edge are dev-dependencies.
- Specify the **MSRV-compatible tokio floor** (async-core OQ-1):
  requirement `tokio = "1.47"` — the first line declaring
  `rust-version = "1.70"`, under the workspace MSRV of 1.75 with
  headroom; the rationale is documented in the crate manifest.
