# fidoh architecture

Governing specs: `openspec/changes/async-core` (trait surface, I/O
policy, deadline model, feature matrix), `openspec/changes/ceremony`
(discovery/selection), plus the per-crate design docs under
`openspec/changes/*/design.md`.

**Status:** constructed documentation, written from the implemented
crates and their openspec change sets — not extracted from a published
source. Where this file and a spec disagree, the spec wins; file an
issue.

## The crate graph

```
                    ┌─────────────┐
                    │  fidoh (root │  facade package: no library
                    │  facade)    │  surface; owns the feature matrix
                    └──────┬──────┘
                           │ (build edges only)
        ┌──────────────────┼──────────────────────┐
        ▼                  ▼                      ▼
┌──────────────┐   ┌──────────────────┐   ┌──────────────────┐
│ fidoh-cli-ui │   │   fidoh-tokio    │   │ fidoh-transport-* │
│ (terminal    │   │ (Sleep impl +    │   │ (hid / pcsc /    │
│  leaf; opt)  │   │  spawn_blocking  │   │  soft)           │
└──────┬───────┘   │  bridge)         │   └────────┬─────────┘
       │           └────────┬─────────┘            │
       └──────────────┬─────┴──────────────────────┤
                      ▼                            │
              ┌──────────────┐                     │
              │  fidoh-core  │ ◀───────────────────┘
              │ (graph root; │   every arrow points here and
              │  zero deps)  │   ONLY here
              └──────────────┘
```

Rules (async-core design D2):

1. Arrows point ONLY toward `fidoh-core`. Transport crates and
   `fidoh-tokio` depend on `fidoh-core`, never on each other.
2. `fidoh-core` has NO runtime and NO OS dependency beyond
   `alloc`/`core`. Its `[dependencies]` section is empty and no feature
   flag anywhere may add to it (design D5).
3. `fidoh-tokio` is the ONLY crate allowed to name tokio.
4. `fidoh-cli-ui` is the terminal leaf: nothing depends on it.
5. The root `fidoh` package is a build-system facade — it re-exports
   nothing and no crate depends on it.

## Crates

| Crate | Role | Dependencies | Notes |
|---|---|---|---|
| `fidoh` (root) | Feature-matrix facade; plain `cargo build` = soft only | `fidoh-core` + optional transport/tokio edges | `src/lib.rs` is a doc stub by design |
| `fidoh-core` | CTAP2 data model, canonical CBOR, status codes, status→error mapping, `Transport`/`Device`/`Ceremony`/`Sleep` traits | none | `#![deny(unsafe_code)]`, no unwrap outside tests |
| `fidoh-transport-soft` | In-process virtual authenticator (real ES256) — the CI harness | `fidoh-core`, `p256`, `sha2`, `spin` (+ optional serde/serde_json snapshots) | never in hardware discovery |
| `fidoh-transport-hid` | CTAPHID over Linux hidraw + sysfs | `fidoh-core` | hand-rolled framing/descriptor parsing; no libudev, no libc |
| `fidoh-transport-pcsc` | FIDO over CCID/NFC via ISO 7816-4 APDUs | `fidoh-core` (+ optional `pcsc` binding behind the `Library` trait) | pure framing engine builds without the binding |
| `fidoh-tokio` | `TokioSleep` factory + `spawn_blocking_slice` bridge + `run()` entry seam | `fidoh-core`, `tokio` (rt, time only) | drop-detach semantics; panics fold into `Error::Transport` |
| `fidoh-cli-ui` | Reference caller CLI: `list` / `info` / `assert` (`assert --demo` hardwareless) | `fidoh-core`, `fidoh-tokio`, transports | the only crate allowed to ship a binary that names the stack |

## Trait surface (async-core)

- `Transport` — enumerate candidate devices, connect to a chosen one.
- `Device` — `open_channel` (CTAPHID INIT per CTAP2.1 §11.2.9.1.3, or
  APDU SELECT per ISO 7816-4 for PC/SC), `close_channel` (best-effort
  release), `exchange` (one CTAP command/response), `channel()`
  (`ChannelId`, CTAP2.1 §11.2.3 lifetime).
- `Ceremony` — the single orchestration entry point: consumes a
  connected `Device`, a `Sleep` factory, and one deadline budget;
  associated type `Output` = the raw getAssertion response
  (CTAP2.1 §6.2) or the parsed getInfo structure (CTAP2.1 §6.4).
- `Sleep` — caller-provided timer-future factory; the ONLY legal way to
  wait (stack invariant: every wait has a caller-visible timeout).
  Deliberately object-safe (`dyn Sleep`); `Transport`/`Device` are
  generic/monomorphized in v1 (design D-verdict).

## I/O policy (async-core design D3)

Transports MAY use blocking syscalls internally (hidraw
`read`/`write`, PC/SC calls). `fidoh-tokio` provides
`spawn_blocking_slice`: ONE budget-granted wait slice runs in ONE
`tokio::task::spawn_blocking` operation; a dropped future leaves the
blocking thread detached, which exits within the slice bound (drop-
detach semantics). Each slice is at most `DEFAULT_WAIT_SLICE`
(30 s, crate-public, caller-overridable) and never exceeds the
remaining ceremony budget; NFC field polls slice at ≤ 1 s. A
fully-async transport I/O policy is explicitly out of scope for v1.

Note: the shipped CLI enters through `fidoh_tokio::run` (the adapter
owns the runtime entry and drives the ceremony future with the
runtime's own `block_on`); hardware keepalive waits ride the
slice bridge from there.

## Single-budget deadline model (async-core D4)

One deadline is supplied at ceremony start and shared by every hop:
discovery, channel open, getInfo probe, getAssertion exchange, the
user-presence wait, and the getNextAssertion drain. Expiry at any hop
returns typed `Error::Timeout` naming the expired `Phase`.
Dropping the ceremony future mid-run is cancellation-safe: a
best-effort channel release runs, the device stays usable, worst case
after one INIT re-handshake (CTAP2.1 §11.2.5.3).

## Feature matrix (async-core spec §5.1)

`default = ["soft"]` on the root facade package. `hid`, `pcsc`, and
`tokio` are opt-in; `pcsc` forwards the transport crate's `pcsc`
binding feature. No feature edge adds a dependency to `fidoh-core`.

| Build | Command | Compiles |
|---|---|---|
| default (CI contract) | `cargo build` | `fidoh-core`, `fidoh-transport-soft`, facade |
| core only | `cargo build --no-default-features` | `fidoh-core`, facade |
| HID opt-in | `cargo build --features hid` | + `fidoh-transport-hid` |
| PC/SC opt-in | `cargo build --features pcsc` | + `fidoh-transport-pcsc` (with binding) |
| tokio opt-in | `cargo build --features tokio` | + `fidoh-tokio` |
| everything | `cargo build --features hid,pcsc,tokio` | whole graph |

The default-feature test job in CI installs no PC/SC system library:
if the default build ever grows an OS dependency, the build fails.

## CI

What runs (`.github/workflows/ci.yml`): `cargo fmt --check`;
`cargo clippy --workspace --all-features --all-targets -- -D warnings`;
test matrix (default-soft tier = the CI contract, all-features tier);
MSRV build on 1.75; `openspec validate --all --strict`.

Roadmap, not yet implemented (spec'd in `openspec/changes/testing-strategy/`):
CBOR decoder fuzz target over a committed seed corpus, and
`fixtures/` conformance vectors with regenerate-and-assert CI.

## Honest gap list

Implemented and verified (see `docs/testing.md` for the test pyramid):
core model, canonical CBOR, ceremony, all three transports, tokio
adapter, reference CLI; 311 default-tier tests green.

Pending, tracked by their openspec changes: structured
elapsed-vs-budget fields on `Error::Timeout`
(`error-diagnostics` change — `docs/errors.md` documents the current
phase-only shape); `docs/ceremony.md` operator guide
(`ceremony` tasks); fuzz target + fixtures (`testing-strategy`);
live-hardware T3 runs against a real YubiKey (the dev environment
currently has JetKVM USB emulation only).
