# Tasks: transport-soft

Spec-authoring phase — all tasks produce documents, not code.
Implementation tasks arrive in a later change set.

- [x] 1. Author proposal.md (why, scope, non-goals, impact) with standards citations per config rules.
- [x] 2. Author design.md: phase, architecture, named timeout bounds for every blocking wait, alternatives considered, open questions.
- [x] 3. Author specs/transport-soft/spec.md delta with `## ADDED Requirements`, every requirement carrying at least one `#### Scenario:`; every wait scenario states timeout behavior.
- [x] 4. Specify authenticatorGetInfo response shape: pinned AAGUID, versions `FIDO_2_0`+`FIDO_2_1`, options rk/up/uv (CTAP2.1 §6.4).
- [x] 5. Specify internal authenticatorMakeCredential: ES256 P-256 keypair minting, credential ID generation, credential source records; explicitly not client-facing (CTAP2.1 §6.1, WebAuthn L2 §4).
- [x] 6. Specify authenticatorGetAssertion: ECDSA P-256 signature over authenticatorData || clientDataHash (CTAP2.1 §6.2.2, WebAuthn L2 §6.5).
- [x] 7. Specify authenticatorData layout: rpIdHash, flags bits (UP 0 / UV 2 / AT 6 / ED 7), BE signCount, attested credential data only in makeCredential (WebAuthn L2 §6.5).
- [x] 8. Specify COSE ES256 public key encoding (RFC 9052 §7, RFC 9053 §7.1).
- [x] 9. Specify UP/UV behavior modes: auto-approve, always-fail, require-explicit-poke (with deadline semantics).
- [x] 10. Specify error-injection knobs: arbitrary CTAP status codes, keepalive sequences, delay-beyond-deadline, wrong-credential-id.
- [x] 11. Specify credential store: in-memory plus serde snapshot for fixtures.
- [x] 12. Specify Transport/Device trait parity with hardware transports (async-core).
- [x] 13. Author docs/transport-soft.md: CI usage examples, knob table, conformance-vector generation; worked examples labeled constructed.
- [x] 14. Run `openspec validate transport-soft --strict` until green.
