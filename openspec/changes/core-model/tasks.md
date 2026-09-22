# Tasks: core-model

Spec/doc-authoring tasks only (Phase A). No implementation tasks — those
arrive in a later change set per config.yaml rules.

- [x] 1. Author `openspec/changes/core-model/proposal.md` with Why, What changes, Non-goals, Impact (<500 words).
- [x] 2. Author `openspec/changes/core-model/design.md`: phase statement, decisions D1–D6 with standards citations, alternatives rejected, open questions.
- [x] 3. Author `specs/core-model/spec.md` section "CTAP2 Canonical CBOR Encoding" per CTAP2.1 §8: definite-length ints, length minimality, no indefinite-length items, no tags, sorted map keys, ≤4 nesting depth, no duplicate keys.
- [x] 4. Author spec requirements for strict-vs-tolerant decode policy and unknown-map-key tolerance (CTAP2.1 §8), each with scenarios.
- [x] 5. Author spec requirement table for authenticatorGetInfo response members 0x01–0x15 plus the option-ID table (CTAP2.1 §6.4), with scenarios.
- [x] 6. Author spec requirement tables for authenticatorGetAssertion request 0x01–0x07 and response 0x01–0x07 (CTAP2.1 §6.2), with scenarios.
- [x] 7. Author spec requirement enumerating the full CTAP2 status code space (CTAP2.1 §8.2) as a Rust-enum-ready list, with scenarios.
- [x] 8. Author spec requirement for PIN/UV auth parameter shapes (`pinUvAuthParam`, `pinUvAuthProtocol`) as types only (CTAP2.1 §6.2, §6.5.4–§6.5.7), with scenarios.
- [x] 9. Author spec requirement for the COSE ES256 key representation (RFC 9053 §7.1.1), with scenarios.
- [x] 10. Verify every requirement has ≥1 scenario and every protocol claim cites an exact spec section; run `openspec validate core-model --strict` until clean.
- Worked CBOR examples (constructed vs captured) — deferred to `docs/` in a later change per config.yaml ("worked examples belong in docs/").
