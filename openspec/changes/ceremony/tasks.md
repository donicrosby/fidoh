# ceremony — Tasks

Spec-authoring phase: tasks produce documents, not code. Implementation
arrives in later change-sets.

## 1. Discovery and selection

- [ ] 1.1 Draft `docs/ceremony.md` section on the discovery phase (enumerate all transports, collect candidates, error-collection rule) from specs/ceremony/spec.md
- [ ] 1.2 Document the `First | Select(fn) | Fail` selection policy and the `CandidateDescriptor` shape (transport kind, device path/handle, AAGUID-if-probed) in `docs/ceremony.md`

## 2. Ceremony inputs and wire delegation

- [ ] 2.1 Document the ceremony input surface (rpId, clientDataHash, allowCredentials, UvPolicy, no v1 extensions, single budget) in `docs/ceremony.md`, citing CTAP2.1 §6.2 and the RP boundary rule
- [ ] 2.2 Record in `docs/ceremony.md` that wire-shape rules (empty allowList omission, uv/pinUvAuthParam mutual exclusion) are enforced by core-model, with cross-references

## 3. Sequence, waits, and multi-assertion

- [ ] 3.1 Document the ceremony sequence (probe → §6.2 exchange → keepalive loop → §6.3 drain) with a sequence diagram in `docs/ceremony.md` (worked example; label as constructed, not captured)
- [ ] 3.2 Document every blocking wait and its timeout bound (single remaining budget per async-core D4) in `docs/ceremony.md`

## 4. Error taxonomy

- [ ] 4.1 Document the ceremony error taxonomy table and the CTAP2.1 §8.2 status-to-variant mapping in `docs/ceremony.md`
- [ ] 4.2 Record open questions OQ-1 (retriable-status retry policy) and OQ-2 (Preferred-UV probe behavior) in `docs/ceremony.md` with owners

## 5. CI testability and validation

- [ ] 5.1 Document the transport-soft CI scenarios (keepalive-then-success, wrong-credential-id, status-code injection, deadline expiry) in `docs/ceremony.md`
- [x] 5.2 Validate: `openspec validate ceremony --strict` green
