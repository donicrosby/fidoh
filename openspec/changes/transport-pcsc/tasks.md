# Tasks: transport-pcsc

Spec-authoring phase only — every task produces documents, no code
(config.yaml tasks rules; implementation tasks arrive in a later
change set).

- [x] Read `openspec/config.yaml` invariants + committed sibling
      changes (async-core D3/D4, core-model §8.2, ceremony D2/D3/D7,
      transport-soft) and cite rather than restate them.
- [x] Verify protocol grounding against primary sources: CTAP2.1
      §11.3 (SELECT AID bytes, command frame, 9100/GETRESPONSE),
      §5 NFC user-presence window, ISO 7816-4 SW behavior, ISO
      14443-4 §7.3 WTX, PC/SC return-code values, Yubico fw-5.8
      FIDO-over-CCID documentation URL; correct the brief's
      §11.2.x citations to the actual §11.3.x numbers.
- [x] Author `proposal.md` (Why / What Changes / Impact / Non-goals,
      < 500 words).
- [x] Author `design.md`: Phase C, unification decision with CTAP2.1
      §11.3 citation, shared-vs-exclusive connect decision with
      CCID justification, SELECT-skip policy, blocking-wait table
      with per-wait bounds, alternatives (A1–A5), open questions
      (OQ-1 touch-and-hold, OQ-2 CTAP1 encapsulation frame, OQ-3
      driver WTX variance).
- [x] Author `specs/transport-pcsc/spec.md`: ≥ 1 scenario per
      requirement; every wait scenario names its timeout; error
      mapping table (PC/SC codes + ISO 7816 SW → typed taxonomy).
- [x] Author `docs/transport-pcsc.md`: pcscd/CCID requirements,
      shared-vs-exclusive rationale, fw-5.8+ FIDO-over-CCID note
      with Yubico doc URL, constructed SELECT + getInfo APDU trace
      labeled constructed-vs-captured.
- [x] `openspec validate transport-pcsc --strict` green.
- [ ] Reviewer pass: cross-check citations against config.yaml rules
      and sibling specs (orchestrator review step, per the
      spec-authoring delegation workflow).
- [ ] Owner sign-off on open questions OQ-1 (NFC touch-and-hold
      semantics), OQ-2 (CTAP1/U2F encapsulated frame for a future
      interop change), OQ-3 (reader-driver WTX variance).
