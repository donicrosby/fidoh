# error-diagnostics — Tasks

Spec-authoring phase: tasks produce documents, not code. Implementation
arrives in later change-sets.

## 1. Specification

- [ ] 1.1 Author `openspec/changes/error-diagnostics/specs/error-diagnostics/spec.md` covering: single-error-surface consolidation, structured-context fields (device descriptor, phase, elapsed budget), diagnostics requirement for `NoDevice`/channel-open failures, Display/structured-fields contract, no-secrets MUST NOT, no-blocking-I/O in error construction
- [ ] 1.2 Ensure every requirement has ≥1 scenario, including wait-free error-construction scenarios (no timeout behavior needed where no wait exists) and the no-secrets scenario

## 2. Operator documentation

- [ ] 2.1 Author `docs/errors.md` with the full error table: variant, meaning, likely causes, remediation, relevant doc link (docs/transport-hid.md, docs/transport-pcsc.md)
- [ ] 2.2 Include copy-paste udev rule snippets (uaccess and plugdev variants) and pcscd diagnostic commands (`systemctl status pcscd`, `pcsc_scan`) in docs/errors.md, plus the contention-vs-permissions disambiguation guide
- [ ] 2.3 Cross-link docs/errors.md from the error taxonomy section so operators land on it from any typed error

## 3. Validation

- [ ] 3.1 Validate: `openspec validate error-diagnostics --strict` green
