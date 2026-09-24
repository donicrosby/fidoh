# async-core — Design

## Phase

Phase A (specification / spec-authoring). This change produces
documents only; implementation tasks arrive in later change-sets per
the repo's tasks rules.

## Context

Linux hidraw exposes FIDO authenticators as character devices whose
`read`/`write` are blocking syscalls; there is no standard async
notification mechanism wired into the default executor ecosystem for
hidraw that works without either a blocking thread or an external
polling reactor. CTAPHID (CTAP2.1 §11.2) additionally requires
keepalive-driven polling loops (authenticator emits
`CTAPHID_KEEPALIVE` status 0x02 (UPNEEDED) in CTAPHID keepalive frames (cmd 0x3B) while waiting for user
presence, CTAP2.1 §11.2.9.1.7), so transport code inherently contains
"wait until response or deadline" logic. The project stack invariants
require: no executor dependency in core crates, every wait bounded by a
caller-visible timeout, and typed errors.

## Decisions

### D1: Trait surface in fidoh-core

```rust
// Sketch — normative behavior lives in specs/async-core/spec.md
pub trait Transport {
    type Device: Device;
    fn enumerate(&self)
        -> impl Future<Output = Result<Vec<DeviceInfo>, Error>>;
    fn connect(&self, id: &DeviceId, sleep: SleepFactory)
        -> impl Future<Output = Result<Self::Device, Error>>;
}

pub trait Device {
    fn send(&mut self, cmd: CtapCommand, deadline: Deadline)
        -> impl Future<Output = Result<CtapResponse, Error>>;
    fn open_channel(&mut self, deadline: Deadline)
        -> impl Future<Output = Result<ChannelId, Error>>;
    fn close(self) -> impl Future<Output = Result<(), Error>>;
}

pub trait Ceremony {
    type Output;
    fn run<D: Device>(self, device: D, sleep: SleepFactory,
                      deadline: Deadline)
        -> impl Future<Output = Result<Self::Output, Error>>;
}

pub trait Sleep {
    type Future: Future<Output = ()>;
    fn sleep(&self, d: Duration) -> Self::Future;
}
```

- `Transport` and `Device` are associated-type designs. Object safety
  is required "where sensible": `Sleep` is deliberately object-safe
  (`dyn Sleep` with a boxed future is acceptable at adapter boundaries)
  because it crosses crate boundaries from caller to core; `Transport`
  and `Device` are generic-constrained at ceremony call sites and need
  NOT be object-safe in v1 (monomorphization keeps the soft-token CI
  harness zero-cost).
- `Ceremony` consumes the device handle for the duration of the run and
  returns the assertion payload (authenticatorData, signature,
  userHandle, credential id) for getAssertion per CTAP2.1 §6.2, or the
  parsed authenticatorGetInfo response per CTAP2.1 §6.4.

### D2: Crate graph and dependency rules

```
                 ┌────────────┐
                 │ fidoh-core │  traits, CTAP model types, ceremony
                 └─────▲──────┘  orchestration. Deps: core + alloc only.
        ┌──────────────┼──────────────┬───────────────┐
        │              │              │               │
 fidoh-transport-  fidoh-transport- fidoh-transport- fidoh-tokio
      hid              pcsc           soft           (Sleep impl,
   (CTAPHID,       (ISO 7816-4    (in-process;      spawn_blocking
   CTAP2.1 §11.2)    APDU layer,     CI harness)      wrapper)
                    CTAP2.1 §11)                         │
                                                  fidoh-cli-ui (opt)
```

Rules:
1. Arrows point ONLY toward `fidoh-core`. Transport crates and
   `fidoh-tokio` depend on `fidoh-core`, never on each other.
2. `fidoh-core` has NO runtime and NO OS dependency beyond
   `alloc`/`core` (stack invariant).
3. `fidoh-tokio` is the ONLY crate allowed to name tokio.
4. `fidoh-cli-ui` depends on `fidoh-core` and `fidoh-tokio` and is
   never a dependency of any library crate.
5. `fidoh-transport-soft` has no I/O and must remain embeddable in
   `no_std`+alloc targets.

### D3: Blocking-vs-async transport policy — DECISION

**Decision: v1 transports MAY use blocking syscalls internally;
`fidoh-tokio` adapts them to async callers via `spawn_blocking`.**

Rationale:
- Linux hidraw `read`/`write` are blocking syscalls with no
  executor-native readiness story; any "async" hidraw transport is a
  blocking thread wearing a costume. Being honest about this in v1
  removes a whole class of pretend-async bugs.
- `spawn_blocking` on a dedicated thread pool bounds resource use and
  keeps the ceremony future cancellable at the await point: dropping
  the caller's future detaches from the blocking thread, and the
  transport's internal deadline (D4) guarantees the thread exits.
- PC/SC on all platforms is a blocking C API; a blocking-first policy
  treats HID and PC/SC uniformly instead of shipping two I/O policies.

Tradeoffs accepted:
- One blocking-pool thread per in-flight device operation. v1 targets
  single-device CLI use; this is fine. High-concurrency servers are
  out of scope for v1.
- Cancellation of an in-flight syscall is not instantaneous; it is
  bounded by the operation's timeout bound (D4), never by caller
  patience.

Named blocking waits and their timeout bounds (design rule):
- CTAPHID `read` awaiting a response packet: bounded by the remaining
  ceremony budget, max 30 s default per-wait slice (keepalive-driven
  re-slicing keeps the loop responsive to drop).
- CTAPHID INIT channel negotiation: bounded by the remaining ceremony
  budget (CTAP2.1 §11.2.9.1.3 INIT is a broadcast handshake).
- APDU select/transceive polling (FIDO-over-CCID / NFC): bounded by the
  remaining ceremony budget; NFC field polling slices at max 1 s per
  poll so card removal surfaces promptly.
- Soft transport: no blocking waits; responds immediately.

### D4: Timeout model

- Every wait — sleep, I/O await, keepalive poll, user-presence wait —
  goes through the `Sleep` trait. No `std::thread::sleep`, no unbounded
  blocking `read` without a deadline-driven abort path (stack
  invariant).
- The ceremony deadline is a SINGLE budget supplied by the caller at
  `Ceremony::run`. There are no per-hop timeouts: each hop receives the
  remaining budget. This matches how users think ("this sign-in may
  take up to 60 s of touching the key") and avoids combinatorial
  timeout configuration.
- Expiry at any hop returns a typed `Error::Timeout` naming the
  ceremony phase that expired.
- Cancellation via future drop MUST be safe: dropping a ceremony or
  device future mid-wait leaves no poisoned shared state; the next
  `connect` on the same authenticator MUST succeed (worst case after
  one INIT re-handshake, since CTAPHID channels are per-transaction,
  CTAP2.1 §11.2.3).

### D5: Feature-flag layout

- `default = ["soft"]` — the software token only; `cargo build` of the
  workspace yields a working CI harness with zero OS dependencies.
- `hid` — enables `fidoh-transport-hid` (Linux hidraw first).
- `pcsc` — enables `fidoh-transport-pcsc` (FIDO-over-CCID + NFC).
- `tokio` — enables `fidoh-tokio` adapter (`Sleep` impl +
  `spawn_blocking` glue).
- No feature may add a dependency to `fidoh-core`.

## Alternatives Considered

### A1: Fully-async transports via `async-io` (rejected for v1)

Wrap hidraw fds in `async-io::Async` and drive readiness through a
polling reactor, with no blocking threads.

- Pros: no blocking-pool threads; true readiness-based I/O where the OS
  supports it; one uniform async code path.
- Cons: hidraw readiness via `poll` is only as reliable as the kernel
  driver; PC/SC has no fd-based readiness API at all, so PC/SC would
  STILL need blocking threads, producing two I/O policies instead of
  one; adds a reactor dependency to transport crates, pressuring the
  "transport crates are runtime-light" goal; cancellation still cannot
  interrupt an in-flight kernel read on some drivers.
- Verdict: rejected as v1 default. Revisit if a future change targets
  high-concurrency servers; the `Sleep` + deadline model is compatible
  with a later async-io transport behind the same traits.

### A2: Per-hop timeouts instead of a single ceremony budget (rejected)

- Pros: finer-grained control (e.g. 2 s for INIT, 25 s for touch).
- Cons: configuration surface explodes; hops whose duration depends on
  humans (user presence) and hops that are machine-speed get conflated;
  callers guess wrong and ceremonies fail spuriously.
- Verdict: rejected. One budget, each hop gets what remains. Phases
  are still NAMED in `Error::Timeout` for diagnosability.

### A3: Object-safe `Transport`/`Device` via boxed futures (rejected for v1)

- Pros: heterogeneous device collections behind `dyn Device`; smaller
  binaries.
- Cons: boxed futures force `alloc` allocations per await and prevent
  inlining across the ceremony hot path; the soft-token CI harness and
  single-device CLI use cases don't need heterogeneity.
- Verdict: monomorphized generics for v1; `Sleep` alone is object-safe
  because it genuinely crosses caller/crate boundaries. Revisit if a
  multi-transport UI needs `Vec<Box<dyn Device>>`.

### A4: `async fn` in traits (AFIT) vs `impl Future` returns (chosen: RPITIT-style)

Edition 2021 with return-position `impl Trait` in traits (stable since
Rust 1.75) keeps the traits alloc-free and `Send`-bound-flexible.
Native `async fn` in traits is equivalent in expressiveness here; the
explicit `impl Future` form is chosen so `+ Send` bounds are visible at
the trait definition, since `fidoh-tokio`'s `spawn_blocking` requires
`Send`. Open question OQ-1 tracks MSRV pinning.

## Open Questions

- ~~OQ-1~~ RESOLVED 2026-09-22 (owner decision): **MSRV is pinned at Rust 1.75.**
  Rationale: RPITIT (return-position `impl Trait` in traits) requires ≥1.75
  and is a core design decision (D1/A4); pinning unlocks those efficiencies
  (no boxed futures on the ceremony hot path, visible `+ Send` bounds).
  Workspace MUST declare `rust-version = "1.75"` in the root `Cargo.toml`
  and CI MUST compile/test on exactly 1.75 plus stable.
- ~~OQ-2~~ RESOLVED 2026-09-22 (owner decision): **CTAPHID per-wait slice
  default is 30 s, as a tunable named constant.** It is a crate-public
  const (e.g. `DEFAULT_WAIT_SLICE`), overridable per-ceremony by the
  caller; 30 s is the default, not a hard-coded literal scattered through
  the transport. Live-hardware probes may refine the default later, but 30 s
  is the spec'd starting value.
- ~~OQ-3~~ RESOLVED 2026-09-22 (owner decision): **`Device::close` (and
  drop-cancellation) MUST attempt to release the channel/device.** An
  authenticator left holding an allocated channel blocks every other client
  (browser, other CLI) until the key's channel timeout expires. On
  drop-cancel the device MUST send a best-effort channel-release/close; if
  the release itself fails or the deadline has already passed, the error is
  logged and swallowable, but the attempt is mandatory, not optional.
- ~~OQ-4~~ RESOLVED 2026-09-22 (implementation crystallization): **`Sleep`
  futures are `Send`.** `Sleep::sleep` returns
  `Pin<Box<dyn Future<Output = ()> + Send>>` — a wait may be held across an
  await point inside any `Device`/`Ceremony` future, and those futures are
  `Send` by design (A4), which transitively requires every awaited future to
  be `Send`. The soft token's budget-driven device (spacing consumed from
  the shared `Deadline`, never wall-clock) needs no real timer; the tokio
  adapter's `spawn_blocking`-side waits are `Send` naturally. A thread-bound
  timer must bridge to a `Send` handle inside its `sleep` impl.
