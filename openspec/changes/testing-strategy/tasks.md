# Tasks: testing-strategy

Spec-authoring phase — all tasks produce documents, not code.
Implementation tasks arrive in a later change set.

- [x] 1. Author proposal.md (why, scope, non-goals, impact) with standards citations per config rules.
- [x] 2. Author design.md: Phase D, layered architecture, named timeout bounds for every blocking wait, alternatives considered, open questions.
- [x] 3. Author specs/testing-strategy/spec.md delta with `## ADDED Requirements`, every requirement carrying at least one `#### Scenario:`; every wait scenario states timeout behavior.
- [x] 4. Specify the three-tier test pyramid: unit tests (core-model CBOR/model logic), soft-token integration tier (default-on, CI-safe: no hardware, no root, no udev), hardware tier (explicit opt-in, never default CI).
- [x] 5. Specify the mandatory soft-token CI matrix: keepalive-then-success; delay-beyond-deadline → typed Timeout; status-code injection for each ceremony-mapped status (0x2E, 0x22, 0x2F, 0x2D, 0x27, 0x3B, 0x33, 0x34, 0x36, 0x37, 0x3C); wrong-credential-id → CredentialMismatch; getNextAssertion multi-assertion drain (CTAP2.1 §6.3); AmbiguousDevice (two soft tokens); NoDevice (zero transports).
- [x] 6. Specify hardware test tiers: matrix over {pre-5.8 YubiKey HID, 5.8+ YubiKey HID, 5.8+ YubiKey CCID, NFC via PC/SC} × {UP-required, wrong-allowCredential}; cargo-feature/env gating; never default.
- [x] 7. Specify conformance vector provenance: CTAP2 spec's own examples where they exist (spec-derived); transport-soft snapshot vectors labeled constructed per config.yaml docs rule; regeneration check in CI.
- [x] 8. Specify MSRV CI: build + test on exactly Rust 1.75 and stable (async-core OQ-1); clippy zero-warnings gate; fmt gate.
- [x] 9. Specify CBOR decoder fuzzing as an implementation-phase requirement with rationale (attacker-controlled bytes from a USB device).
- [x] 10. Author docs/testing.md: manual hardware runbook — per-row setup steps, expected typed outcome, LED/touch cues; examples labeled constructed.
- [x] 11. Run `openspec validate testing-strategy --strict` until green.
