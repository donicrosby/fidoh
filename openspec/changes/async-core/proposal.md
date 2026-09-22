# async-core — Runtime-Agnostic Async Core Trait Surface

## Why

fidoh needs a core crate that is async but runtime-agnostic (stack
invariant: no tokio/async-std/smol in core crates). Today the repo has a
workspace skeleton and project-level context but no specified trait
surface, crate graph, timeout model, or feature layout. This change
specifies those so implementation change-sets can proceed against a
stable contract instead of re-litigating architecture per crate.

## What Changes

- Define the core trait surface in `fidoh-core`:
  - `Transport` — enumerate candidate devices, connect to a chosen one.
  - `Device` — send a CTAP command, receive a response, manage channel
    lifecycle (open/close, init/negotiate per CTAP2.1 §8.1.4 INIT).
  - `Ceremony` — orchestration entry point for the v1 ceremonies
    (authenticatorGetAssertion, authenticatorGetInfo per CTAP2.1 §8).
  - `Sleep` — caller-provided timer future factory; the ONLY legal way
    to wait (stack invariant: every device wait has a caller-visible
    timeout).
- Define the crate graph: `fidoh-core` (traits + model + ceremony
  orchestration, no runtime, no OS deps beyond `alloc`/`core`),
  `fidoh-transport-hid` (CTAPHID framing per CTAP2.1 §8.1),
  `fidoh-transport-pcsc` (FIDO-over-CCID and NFC/ISO 14443 sharing one
  ISO 7816-4 APDU layer per CTAP2.1 §11), `fidoh-transport-soft`
  (in-process virtual authenticator, the CI harness),
  `fidoh-tokio` (runtime adapter: `Sleep` impl + `spawn_blocking`
  wrapper), optional `fidoh-cli-ui`. Dependency arrows point ONLY
  toward `fidoh-core`; transport crates never depend on each other or
  on runtime adapters.
- Decide the blocking-vs-async policy: v1 transport crates MAY issue
  blocking syscalls internally (Linux hidraw `read`/`write` are
  blocking); `fidoh-tokio` wraps blocking transport operations in
  `spawn_blocking`. Fully-async I/O via `async-io` is deferred (see
  design.md Alternatives Considered).
- Specify the timeout model: every wait goes through `Sleep`; the
  ceremony deadline is a single caller-provided budget, not per-hop
  timeouts; cancellation by future drop MUST be safe (no device left in
  a wedged state observable by the next caller).
- Specify the feature-flag layout: default features = soft transport
  only; `hid`, `pcsc`, `tokio` are opt-in features.

## Impact

- Affected specs: `async-core` (new).
- Affected code: none in this change — documents only (spec-authoring
  phase). Implementation arrives in later change-sets per repo rules.
- Downstream: all transport and ceremony implementation changes depend
  on this contract.

## Non-goals

- authenticatorMakeCredential as public client API (project rule:
  v1 non-goal; the soft token implements it internally as harness
  plumbing).
- clientPIN/UV protocols, credential management, large blobs,
  hmac-secret (project non-goals for v1).
- Fully-async transport I/O (e.g. `async-io`-based hidraw) in v1.
- Runtime adapters other than tokio (async-std, smol, embassy) in v1.
- RP-side semantics: `clientDataJSON` construction, origin handling
  (RP boundary rule: caller's responsibility, WebAuthn L2 §6.5 is the
  RP's spec, not ours).
