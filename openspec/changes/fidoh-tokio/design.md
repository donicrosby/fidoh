# fidoh-tokio — Design

Bridges fidoh-core's blocking-call trait contract into tokio. This
change retro-documents the implementation that landed 2026-09-23
(deleg_123d923a); the authoritative prior text is async-core's
design (D2 crate graph, D3 blocking policy, D5 tokio feature marker)
— nothing here overrides it.

## Decisions

### D1 — Grant-before-issue slicing (the core bridging discipline)

`spawn_blocking_slice(deadline, phase, max_slice, op)` grants
`min(max_slice, remaining budget)` from the shared `Deadline` **before**
spawning, and hands the closure `SliceGrantArgs { granted, phase }`.
Grant-before-issue mirrors the transport-pcsc engine's debit
discipline: the budget is charged exactly once, at issue time, by the
side that can observe it atomically. The blocking closure polls its
grant's expiry and exits at the slice edge with typed `Error::Timeout`
— this is the async-core OQ-3 abort path that guarantees a detached
thread cannot outlive its timeout bound. There is deliberately **no
async-side second timer** watching the JoinHandle: the grant already
debited the budget, and a second timer would double-charge and could
race the slice edge.

### D2 — Drop-detach semantics

Dropping the future detaches the blocking task (tokio's native
spawn_blocking behavior); the task runs to its slice edge and exits
there. The device/budget remain reusable; a later test proves
device-reuse after a dropped ceremony (async-core OQ-3).

### D3 — Panics fold to `Error::Transport` (kind `"tokio"`)

fidoh-core's error taxonomy has no async/adapter variant; inventing one
is error-diagnostics change territory (its spec already owns diagnostic
surfacing). A panic joined from the JoinHandle therefore folds into the
existing typed transport error with a `"tokio"` kind marker. No
poisoning: the shared state touched by the bridge is the budget, which
the grant already closed.

### D4 — TokioSleep stays thin; `shared()` for spawned futures

`TokioSleep` is only the timer mapping (tokio time → `Sleep`); zero
protocol logic. Because `tokio::spawn` demands `'static` futures, the
adapter exposes `TokioSleep::shared() -> Arc<dyn Sleep + Send + Sync>`
so ceremony futures can be spawned onto multi-thread runtimes — the
Send-bound proof test exercises exactly this path.

### D5 — Dependency shape

Library: `fidoh-core` + `tokio` (`rt`, `time`; default features off —
no net, no io, no macros in the library surface). Dev-only: `macros`
(`#[tokio::test]`, `start_paused`), `rt-multi-thread` (Send-proof
spawn), `sync` (cancellation tests), `test-util` (paused clock), and
`fidoh-transport-soft` as the CI harness. The soft edge is a
dev-dependency precisely so the D2 crate graph (arrows only toward
fidoh-core) holds for the library surface.

### D6 — Tokio MSRV floor

Workspace MSRV is 1.75 (async-core OQ-1). Tokio declares
`rust-version = 1.70` from 1.47 onward (1.53.x declares 1.71), so
requirement `"1.47"` admits only MSRV-compatible releases with
headroom; cargo resolved 1.53.1 locally. Compilation was verified on
stable 1.98.1; a `cargo check` on exactly 1.75 remains the one CI step
to confirm the floor empirically (recorded as a testing-strategy item,
not an open question — the declared rust-versions already prove it).

## Crystallization (2026-09-23, from the first implementation)

1. **The executor-inclusion audit that is load-bearing lives in
   fidoh-tokio** (`only_tokio_adapter_names_tokio` manifest audit).
   The pre-existing `transport_soft.rs::no_executor_dependency` test
   was narrowed from "zero tokio in the lockfile" (structurally
   incompatible with the now-required fidoh-tokio member) to the
   async-core D2 invariant: tokio allowed only via fidoh-tokio,
   async-std/smol fully banned.
2. **Known weakness, recorded not gold-plated:** the narrowed soft
   test's per-package dependency scan is vacuous — it splits on
   `[dependencies]` section headers, but Cargo.lock `[[package]]`
   blocks carry `dependencies = [ ... ]` arrays, so the scan never
   matches. The test still asserts executor *name presence* outside
   the tolerance branch. Tightening the lockfile parse belongs to the
   testing-strategy revision; the fidoh-tokio manifest audit carries
   the invariant until then.
3. `SliceGrant`/`DEFAULT_WAIT_SLICE`/`NFC_POLL_SLICE` are re-exported
   from fidoh-core — the adapter adds no constants of its own.
4. **The entry seam is async-shaped: `run(future)`, not a sync-body
   `within(fn)`.** (2026-09-23, orchestrator review of the cli-ui
   wiring.) The first implementation shipped `within(body: FnOnce)`
   running the body inline inside `block_on(async { body() })`. Any
   synchronous caller that pumps futures with its own `block_on`
   under that seam parks the runtime's timer driver inside `body`'s
   frame: the first REAL-timer wait (a hardware token's keepalive)
   can never be woken and hangs. Demo/CI paths never touch real
   timers, which is why every gate stayed green — the bug was found
   by reading the wiring, not by a test. `run` now takes the
   ceremony future itself and drives it with the runtime's own
   `block_on`, so deadlines fire correctly; the reference CLI
   (`exe::with_run`) hands each subcommand an async body. The
   std park/unpark pump was deleted from `exe` (a parked
   park/unpark waiter can only be woken by construction in tests);
   nesting/ambient-context entry failures stay typed `io::Error`s.
   Direct tests: `run_drives_a_future_with_real_timers`,
   `run_rejects_nesting_as_typed_error`,
   `run_rejects_ambient_runtime_context`.

## Open questions

- **OQ-1 — Empirical MSRV confirmation.** The 1.47 floor is proven by
  declared rust-versions, not by a toolchain run: no rust 1.75
  toolchain is installed in the dev container. CI should run one
  `cargo check --workspace` on 1.75 (or a rustup toolchain pin in CI
  config) to close this. *Status: open, non-blocking; declarative
  evidence already satisfies the invariant.*
