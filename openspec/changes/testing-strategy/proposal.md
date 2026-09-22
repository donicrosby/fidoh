# Proposal: testing-strategy — test pyramid, CI matrix, and conformance vectors

## Why

Six spec changes (core-model, async-core, transport-soft, ceremony,
transport-hid, transport-pcsc) define the library's behavior; none define how
that behavior is verified. Without an explicit testing strategy the
implementation phase risks (a) untested failure paths in the ceremony error
taxonomy, (b) CBOR edge cases exercised only by happy-path fixtures, and (c)
CI that either demands hardware (impossible on hosted runners) or silently
skips the failure matrix. This change pins the test pyramid, the mandatory
soft-token CI scenario matrix, the opt-in hardware test tiers, conformance
vector provenance rules, MSRV/lint CI gates, and the CBOR fuzzing requirement.

## What changes

- New spec capability `testing-strategy` covering:
  - The three-tier test pyramid: unit tests (pure CBOR/model logic per
    core-model), soft-token integration tests (full ceremony against
    transport-soft — the default-on tier, runnable in CI with no hardware, no
    root, no udev), and hardware tests (physical authenticators — explicit
    opt-in, never default CI).
  - The mandatory soft-token CI matrix: deterministic failure-path scenarios
    via transport-soft knobs — keepalive-then-success, delay-beyond-deadline →
    typed `Timeout`, status-code injection for every ceremony-mapped status
    (0x2E, 0x22, 0x2F, 0x2D, 0x27, 0x3B, 0x33, 0x34, 0x36, 0x37, 0x3C per
    CTAP2.1 §8.2 and the ceremony spec's mapping table), wrong-credential-id →
    `CredentialMismatch`, multi-assertion getNextAssertion drain (CTAP2.1
    §6.3), `AmbiguousDevice` (two soft tokens), `NoDevice` (zero transports).
  - Hardware test tiers: matrix over {pre-5.8 YubiKey HID, 5.8+ YubiKey HID,
    5.8+ YubiKey CCID, NFC via PC/SC} × {UP-required, wrong-allowCredential},
    gated behind a cargo feature or env gate, never run by default.
  - Conformance vectors: canonical-CBOR encode/decode vectors sourced from the
    CTAP2 spec's own examples where they exist (CTAP2.1 §6 examples); vectors
    generated from transport-soft snapshots labeled **constructed** per the
    config.yaml docs rule.
  - MSRV CI: build + test on exactly Rust 1.75 and on stable (async-core OQ-1
    resolution), clippy zero-warnings gate, fmt gate.
  - Fuzzing: the CBOR decoder is a mandatory fuzz target (cargo-fuzz or
    equivalent), specified as an implementation-phase requirement with
    rationale (attacker-controlled bytes arrive from a USB device).
- `docs/testing.md`: the manual hardware-test runbook — per-row setup steps,
  expected typed outcomes, LED/touch cues.

## Non-goals

- Writing the tests themselves (implementation-phase work; tasks.md here is
  spec-authoring only).
- Performance/benchmark harnesses, code-coverage thresholds.
- Fuzz targets beyond the CBOR decoder (e.g. CTAPHID framing) — may be added
  by later changes; only the decoder is mandatory here.
- Hardware-in-the-loop CI infrastructure (self-hosted runners with attached
  keys); hardware tests remain manual/opt-in for v1.
- Any change to the six existing spec deltas' behavior; this change references
  them, it does not modify them.

## Impact

- New spec: `openspec/specs/testing-strategy/` (via this change's delta).
- New doc: `docs/testing.md`.
- Depends on: all six existing changes (it enumerates their CI-testable
  scenarios; ceremony's error taxonomy and transport-soft's knob set in
  particular).
- Governs: every implementation-phase change set that follows.
