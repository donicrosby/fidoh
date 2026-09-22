# Spec delta: testing-strategy

This change ADDS the new capability `testing-strategy`: the verification
strategy for the fidoh client library — the three-tier test pyramid, the
mandatory soft-token CI scenario matrix, opt-in hardware test tiers,
conformance-vector provenance, MSRV/lint CI gates, and CBOR fuzzing.

Normative references: FIDO CTAP 2.1 (fidoalliance.org) §6 (commands), §8.2
(status codes); W3C WebAuthn Level 2 §6.5. This change defines no new
protocol behavior; it references the core-model, async-core, transport-soft,
ceremony, transport-hid, and transport-pcsc spec deltas and pins how their
requirements are verified.

## ADDED Requirements

### Requirement: Three-tier test pyramid

The library's tests SHALL be organized into three tiers with strictly
increasing environment requirements: **T1 unit tests** covering pure
CBOR/model logic per core-model (canonical encoding, strict decoding, wire
structures, the CTAP2.1 §8.2 status table) with no I/O and no async runtime;
**T2 soft-token integration tests** running the full client ceremony
(discovery → selection → getInfo probe → getAssertion → drain) against
transport-soft; and **T3 hardware tests** against physical authenticators.
T1 and T2 SHALL run by default in `cargo test` and in CI on every commit; T2
SHALL pass on a hosted CI runner with no hardware, no root privileges, and
no udev configuration. T3 SHALL be excluded from default builds and default
CI and SHALL require an explicit opt-in gate (cargo feature or environment
gate, per design OQ-1).

#### Scenario: Default CI runs T1 and T2 only

- **WHEN** a commit triggers default CI on a hosted runner with no USB
  devices, no root, and no udev rules
- **THEN** all T1 and T2 tests run and pass, and no T3 hardware test is
  compiled or executed

#### Scenario: Hardware tests never run by default

- **WHEN** `cargo test` is invoked locally with no hardware-test gate enabled
- **THEN** zero T3 tests execute and the suite passes on a machine with no
  authenticator attached

### Requirement: Mandatory soft-token CI failure-path matrix

T2 SHALL include, at minimum, one passing test per scenario below, each
driven by transport-soft configuration knobs (transport-soft requirement:
error-injection knobs). This matrix is the CI contract for the ceremony
error taxonomy: an implementation without all of these scenarios covered is
not CI-complete.

| # | Scenario | Knob / setup | Expected typed outcome |
|---|---|---|---|
| M1 | Keepalive-then-success | keepalive sequence (b): ≥1 UP_NEEDED event before success | Ceremony succeeds; keepalives consumed as progress, deadline not reset |
| M2 | Delay beyond deadline | delay-beyond-deadline (c) | `Error::Timeout` naming the expired phase |
| M3 | Status 0x2E CTAP2_ERR_NO_CREDENTIALS | inject_status (a) | `Error::NoCredentials` |
| M4 | Status 0x22 CTAP2_ERR_INVALID_CREDENTIAL | inject_status (a) | `Error::NoCredentials` |
| M5 | Status 0x2F CTAP2_ERR_USER_ACTION_TIMEOUT | inject_status (a) | `Error::UserActionTimeout` |
| M6 | Status 0x2D CTAP2_ERR_KEEPALIVE_CANCEL | inject_status (a) | `Error::UserCancelled` |
| M7 | Status 0x27 CTAP2_ERR_OPERATION_DENIED | inject_status (a) or UP always-fail | `Error::UpRejected` |
| M8 | Status 0x3B CTAP2_ERR_UP_REQUIRED | inject_status (a) | `Error::UpRejected` |
| M9 | Status 0x33 CTAP2_ERR_PIN_AUTH_INVALID | inject_status (a) | `Error::UpRejected` |
| M10 | Status 0x34 CTAP2_ERR_PIN_AUTH_BLOCKED | inject_status (a) | `Error::UpRejected` |
| M11 | Status 0x36 CTAP2_ERR_PUAT_REQUIRED | inject_status (a) | `Error::UpRejected` |
| M12 | Status 0x37 CTAP2_ERR_PIN_POLICY_VIOLATION | inject_status (a) | `Error::UpRejected` |
| M13 | Status 0x3C CTAP2_ERR_UV_BLOCKED | inject_status (a) | `Error::UpRejected` |
| M14 | Wrong credential id returned | wrong-credential-id (d) with caller allowList | `Error::CredentialMismatch` |
| M15 | Multi-assertion drain | store with ≥3 credentials for one rpId, no allowList | getNextAssertion (CTAP2.1 §6.3) issued exactly `numberOfCredentials − 1` times; ordered assertion list returned |
| M16 | Ambiguous device | two soft-token instances registered, default `Fail` selection policy | `Error::AmbiguousDevice` listing both candidate descriptors; `connect` never called |
| M17 | No device | zero transports registered | `Error::NoDevice` carrying per-transport diagnostics |

Every wait-bearing scenario (M1, M2) SHALL be bounded by the single
caller-supplied ceremony budget per the ceremony spec's single-budget model;
budget expiry SHALL surface as `Error::Timeout` naming the expired phase,
and no scenario SHALL rely on any wait beyond the delay knob's hard cap of
deadline + 60 s.

#### Scenario: Every mapped status code produces its typed error in CI

- **WHEN** the T2 suite runs with the soft token configured (knob (a)) to
  inject each of 0x2E, 0x22, 0x2F, 0x2D, 0x27, 0x3B, 0x33, 0x34, 0x36, 0x37,
  and 0x3C (CTAP2.1 §8.2) in turn
- **THEN** each injection produces exactly the typed ceremony error the
  ceremony spec's status-handling requirement assigns to that code, and no
  injection surfaces as an untyped error, string, or panic

#### Scenario: Delay beyond deadline yields typed Timeout within bounded time

- **WHEN** the soft token is configured with a response delay exceeding the
  ceremony deadline and the T2 test runs the ceremony
- **THEN** the ceremony returns `Error::Timeout` naming the expired phase at
  the deadline, and the token's own delayed response is delivered no later
  than deadline + 60 s, so the test itself terminates within that bound

#### Scenario: AmbiguousDevice and NoDevice reachable without hardware

- **WHEN** the T2 suite registers two soft-token instances (and separately
  zero transports) and runs the ceremony under the default `Fail` selection
  policy
- **THEN** the two-token case returns `Error::AmbiguousDevice` listing both
  descriptors and the zero-transport case returns `Error::NoDevice`, both
  without any hardware, root, or udev dependency

### Requirement: Hardware test tiers and gating

T3 hardware tests SHALL be organized as a two-dimensional matrix over device
classes and behaviors: device classes {pre-5.8 YubiKey over CTAPHID, 5.8+
YubiKey over CTAPHID, 5.8+ YubiKey over USB CCID (FIDO-over-CCID, CTAP 2.x
over ISO 7816 APDUs), NFC via PC/SC (CTAP2.1 §11.3, ISO 14443)} × behaviors
{UP-required getAssertion, wrong-allowCredential getAssertion}. Each matrix
row SHALL have a corresponding section in the `docs/testing.md` manual
runbook specifying setup steps, the expected typed outcome, and observable
LED/touch cues. T3 SHALL be gated behind a cargo feature or environment gate
(per design OQ-1) and SHALL NOT run in default CI or default `cargo test`.
Every hardware wait SHALL be bounded by the caller-supplied ceremony
deadline; a test not observing its expected outcome within the deadline
SHALL fail rather than hang.

#### Scenario: Hardware tests require explicit opt-in

- **WHEN** the hardware-test gate (cargo feature or env var) is not enabled
- **THEN** no T3 test is compiled or run, and enabling the gate without the
  required device class attached produces a clear skip/failure message
  naming the missing device class

#### Scenario: Runbook row completeness

- **WHEN** any row of the {device class} × {behavior} matrix is exercised
  manually per docs/testing.md
- **THEN** the runbook entry for that row states setup steps, the expected
  typed ceremony outcome (e.g. `Error::NoCredentials` for
  wrong-allowCredential), and the LED/touch cue the operator should observe,
  and the ceremony deadline bound for any touch wait is named

### Requirement: Conformance vector provenance

CBOR conformance vectors SHALL come from exactly two labeled sources:
(a) **spec-derived** — byte strings transcribed from the CTAP2
specification's own command/response examples where they exist (CTAP2.1 §6
examples), used as ground truth for canonical-CBOR encode/decode round
trips; and (b) **constructed** — generated from transport-soft snapshots
under the deterministic seeded RNG (transport-soft requirement:
deterministic fixtures) and labeled constructed per the config.yaml docs
rule. Vectors SHALL NOT be captured from third-party authenticators
(cleanroom rules). Every committed constructed vector set SHALL be
regenerable in CI: re-running the fixed generation script SHALL reproduce
the committed bytes identically, and CI SHALL assert this regeneration is
clean.

#### Scenario: Spec-derived vectors round-trip the canonical encoder

- **WHEN** a spec-derived CTAP2 example byte string is decoded by
  core-model's strict decoder and re-encoded
- **THEN** decoding succeeds and re-encoding reproduces the exact spec
  bytes, per core-model's canonical-CBOR encoding requirement (CTAP2.1
  §6 examples)

#### Scenario: Constructed vectors are labeled and regenerable

- **WHEN** constructed conformance vectors are committed from a
  transport-soft snapshot and CI re-runs the deterministic generation
  script
- **THEN** the vectors are labeled constructed (never captured), and the
  regenerated output is byte-identical to the committed fixtures

### Requirement: MSRV and lint CI gates

CI SHALL build and run the full T1+T2 test suite on exactly Rust 1.75 (the
pinned MSRV per async-core OQ-1; the workspace root `Cargo.toml` declares
`rust-version = "1.75"`) and on the current stable toolchain. CI SHALL
additionally gate on `cargo clippy` with zero warnings (warnings denied)
and `cargo fmt --check`. A failure of any of the four gates (MSRV
build+test, stable build+test, clippy, fmt) SHALL fail the commit.

#### Scenario: MSRV gate catches a too-new language feature

- **WHEN** a commit uses a Rust feature stabilized after 1.75 (e.g. a newer
  stdlib API) and CI runs
- **THEN** the 1.75 build+test job fails, blocking the commit, while the
  stable job's result does not substitute for the MSRV gate

#### Scenario: Clippy zero-warnings gate

- **WHEN** a commit introduces a clippy warning in any workspace crate
- **THEN** the clippy CI job fails with warnings denied, independent of
  whether tests pass

### Requirement: CBOR decoder fuzz target

The implementation phase SHALL provide a coverage-guided fuzz target for the
CBOR decoder (cargo-fuzz/libFuzzer or an equivalent), exercising decode of
arbitrary byte strings against core-model's strictness policy. Rationale:
the decoder parses fully attacker-controlled bytes arriving from a USB or
NFC device the host does not trust; panics, unbounded allocation, or
non-terminating parses there are reachable from hardware and are security
defects. The fuzz target SHALL run as a short time-boxed smoke run in CI
(per design OQ-2) with a committed seed corpus; longer campaign fuzzing MAY
run outside CI. The fuzz target SHALL assert: no panic, no abort, and every
input either decodes to a value that re-encodes canonically or is rejected
with a typed decode error.

#### Scenario: Fuzz smoke run gates CI

- **WHEN** the CI fuzz smoke run executes the decoder target for its
  time-boxed duration over the committed corpus plus generated inputs
- **THEN** any panic, abort, or non-terminating parse fails CI, and clean
  runs complete within the time box

#### Scenario: Decoder never panics on adversarial input

- **WHEN** the fuzz harness feeds arbitrary (including malformed, truncated,
  or deeply nested) CBOR byte strings to the decoder
- **THEN** each input produces either a decoded value whose canonical
  re-encoding round-trips, or a typed decode error per core-model's decode
  strictness policy — never a panic or unbounded allocation
