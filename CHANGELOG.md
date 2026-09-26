# Changelog

## 0.1.0 — 2026-09-26

First stable release. Road from `0.1.0-alpha.1` through `0.1.0-beta.1`:

- Core ceremony API: CTAP2 canonical CBOR encoder/decoder with status codes and
  getAssertion/getInfo models; `Transport`/`Device`/`Ceremony` traits with
  `Sleep` and the single-budget `Deadline` (every wait consumes remaining
  handed-in budget); getAssertion orchestration with typed ceremony errors.
- clientPIN support: pinUvAuth acquisition (P2/P1) behind a provider seam with
  typed PIN errors — pinUvAuth proven end-to-end against the soft harness;
  UxDevice PIN plumbing in the reference CLI.
- Hardware transports hardened: Linux hidraw CTAPHID (65-byte report ABI write
  padding, 5ms-bounded read-wait ticks, sysfs path composition against the
  fixture root) and ISO 7816-4 APDU over PC/SC.
- Soft-transport harness: software authenticator for CI with armed clientPIN
  state machine and deterministic harness knobs — no hardware required.
- Conformance vectors: spec-derived plus deterministic constructed sets, with
  provenance tracking and a byte-stable regen-drift CI gate.
- Fuzz targets: CBOR decoder fuzzing with seed corpus and a CI smoke gate.
