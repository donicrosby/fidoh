# fidoh-tokio Specification

The tokio runtime adapter for fidoh: the `Sleep` factory implementation
and the `spawn_blocking` bridge that keeps blocking transport syscalls
off the async executor. This change crystallizes the requirements
async-core already names for `fidoh-tokio` (crate graph D2, blocking
policy D3, tokio feature marker D5, OQ-1 MSRV floor, OQ-3 drop
semantics, OQ-4 Send futures) into a first-class spec.

## ADDED Requirements

### Requirement: The adapter supplies the Sleep implementation on the tokio timer

`fidoh-tokio` SHALL provide `TokioSleep`, an implementation of
fidoh-core's `Sleep` trait backed by the tokio timer, such that every
timed wait inside ceremonies and transports resolves via the caller-
supplied factory with no tokio dependency in fidoh-core itself. Futures
produced by its wait methods SHALL be `Send` (async-core OQ-4). The
implementation SHALL remain compatible with tokio's paused test clock
(`start_paused`) so CI tests run deterministically with zero real-time
sleeps.

#### Scenario: Runtime adapter supplies Sleep

- **WHEN** a tokio-based caller constructs the `fidoh-tokio` adapter
  and passes its `Sleep` implementation into a ceremony
- **THEN** every timed wait inside the ceremony and transports resolves
  via the adapter, and fidoh-core carries no tokio dependency

#### Scenario: Deterministic paused test clock

- **WHEN** the CI harness runs the adapter under a paused tokio clock
- **THEN** waits complete deterministically with zero real-time sleeps

### Requirement: Blocking transport calls are bridged via spawn_blocking with budget-sliced abort paths

Every blocking operation issued through the adapter SHALL run on
`tokio::task::spawn_blocking` — never inline on an executor worker and
never on an adapter-owned dedicated thread. The adapter SHALL grant the
operation a slice of `min(max_slice, remaining budget)` from the shared
`Deadline` **before** spawning the blocking task (grant-before-issue),
and SHALL pass the granted slice and phase to the blocking closure so a
detached thread (future dropped by the caller) exits at the slice edge
with typed `Error::Timeout` (async-core OQ-3 abort path). The adapter
SHALL NOT run a second async-side timer against the bridged operation:
the grant already debited the budget, and a second timer would
double-charge it. A panic inside the blocking closure SHALL propagate
to the awaiting caller as a typed `Error::Transport` (kind `"tokio"`)
and SHALL NOT poison shared state.

#### Scenario: Blocking HID read does not stall the executor

- **WHEN** a tokio caller runs a ceremony whose transport performs a
  long blocking read through the bridge
- **THEN** the read executes on the blocking pool and the executor's
  worker threads stay responsive for the duration

#### Scenario: Blocking side observes slice expiry as typed timeout

- **WHEN** the granted slice expires while the blocking closure runs
- **THEN** the closure observes expiry at the slice edge and the
  operation surfaces `Error::Timeout` naming the granted phase

#### Scenario: Budget exhaustion fires before spawn

- **WHEN** the shared budget is already exhausted when a blocking
  operation is requested
- **THEN** the adapter returns `Error::Timeout` without spawning any
  blocking task

#### Scenario: Dropped future detaches the blocking thread

- **WHEN** the caller drops the future while its blocking task runs
- **THEN** the blocking task continues to the slice edge and exits
  there, and the async side charges no additional budget

#### Scenario: Panic in the blocking bridge propagates typed

- **WHEN** the blocking closure panics
- **THEN** the awaiting caller receives a typed transport error and the
  adapter (device, budget) remains reusable

### Requirement: Only fidoh-tokio names tokio

`fidoh-tokio` SHALL be the only crate in the workspace permitted to
name tokio as a dependency (async-core D2). Its library dependency set
SHALL be exactly `fidoh-core` and `tokio` with default features off,
features `rt` and `time` only. Test-only capabilities (`macros`,
`rt-multi-thread`, `sync`, `test-util`) and the `fidoh-transport-soft`
CI-harness edge SHALL appear only under `[dev-dependencies]`. No other
workspace crate SHALL carry a tokio or other-executor
(`async-std`, `smol`) dependency edge.

#### Scenario: Dependency audit

- **WHEN** a manifest/lockfile audit runs over the workspace
- **THEN** the only tokio dependency edge belongs to `fidoh-tokio`, no
  workspace package depends on `async-std` or `smol`, and no transport
  crate depends on any adapter

#### Scenario: Adapter drives the full ceremony through the CI harness

- **WHEN** the adapter's test suite runs a getAssertion ceremony over
  the soft token via `TokioSleep` and the bridge
- **THEN** the ceremony completes within a single budget, timeouts
  surface as phase-named typed errors, and the device remains reusable
  after a dropped ceremony (async-core OQ-3)

### Requirement: The tokio requirement floor is MSRV-compatible

The tokio version requirement SHALL keep every satisfying tokio release
under the workspace MSRV (1.75). The floor SHALL be `"1.47"` — the
first tokio line declaring `rust-version = "1.70"` — and the MSRV
rationale SHALL be documented in the crate manifest (async-core OQ-1).

#### Scenario: Dependency resolution respects the MSRV

- **WHEN** the workspace dependency graph resolves the tokio
  requirement
- **THEN** every satisfying tokio release declares a rust-version at or
  below the workspace MSRV
