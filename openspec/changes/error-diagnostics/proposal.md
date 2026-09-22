# error-diagnostics — Library Error Surface, Diagnostics, and docs/errors.md

## Why

The ceremony change defines a ten-variant typed error taxonomy
(`NoDevice`, `AmbiguousDevice`, `UserActionTimeout`, `UserCancelled`,
`NoCredentials`, `UpRejected`, `CredentialMismatch`, `Timeout`,
`Transport`, `Ctap`), and the transport specs each map their
platform-specific failures (hidraw errnos, PC/SC return codes, ISO
7816 status words) onto typed causes. What is missing is the
cross-cutting *error surface contract*: a statement that the ceremony
taxonomy is THE single library error surface, that raw OS/PC/SC codes
never escape untyped, that every typed error carries enough structured
context to act on, and that the operator-facing failures
(`NoDevice`, channel-open failures) produce *actionable* remediation
guidance — not just "open failed". Without this change, each crate
would phrase its own diagnostics and there would be no single document
(docs/errors.md) an operator can consult to fix a permission or daemon
problem.

## What Changes

- Specify **error taxonomy consolidation**: the ceremony taxonomy is
  the single error surface of the library. Transports and core MUST map every
  failure into it; a raw OS errno, PC/SC return code, or ISO 7816 status word MUST NOT
  surface to the caller without a typed wrapper (per transport-pcsc's mapping
  table and transport-hid's typed-error rules; CTAP2.1 §8.2 status bytes belong
  to the `Ctap(status)` variant carrying core-model's typed status value.
- Specify the **structured context rule**: every typed error carries
  actionable structured fields — device descriptor where a device is
  implicated (per ceremony's `CandidateDescriptor`: transport kind,
  device path/handle, human-readable metadata, AAGUID when probed),
  the ceremony phase (per async-core D4 `Timeout` naming the phase),
  and elapsed/remaining budget where a deadline is involved.
- Specify the **diagnostics requirement**: `NoDevice` and channel-open
  failures SHOULD carry an actionable remediation string in their
  diagnostic message — hidraw permission failure names the udev
  options (uaccess tag; plugdev group rule) and points at
  docs/transport-hid.md; PC/SC failure names the pcscd running-state
  check and the reader-driver note, pointing at
  docs/transport-pcsc.md. The library provides the diagnostic string;
  rendering (printing, logging, localization) is the caller's job.
- Specify the **Display/structured-fields contract**: every error
  implements `Display` for human consumption and exposes structured
  fields for programmatic handling; callers MUST NOT need to parse
  message text to branch on causes.
- Specify the **no-secrets rule**: error messages MUST NOT contain
  secrets, credential material, or PIN data — ever.
- Author **docs/errors.md**: the operator-facing error table (variant,
  meaning, likely causes, remediation, doc link), copy-paste udev
  rules, and pcscd diagnostic commands.

## Impact

- Affected specs: `error-diagnostics` (new capability).
- Affected code: none — documents only (Phase D, spec-authoring).
- New docs: `docs/errors.md`.
- Depends on: `ceremony` (taxonomy, candidate descriptors, mandatory
  getInfo probe), `async-core` (D4 single-budget timeout model,
  phase-naming `Timeout`), `core-model` (CTAP2.1 §8.2 typed status values),
  `transport-hid` (hidraw permission model), `transport-pcsc` (PC/SC/SW error
  mapping), `docs/transport-hid.md`, `docs/transport-pcsc.md` (remediation grounding).

## Non-goals

- Error-crate or implementation mechanism selection (thiserror/anyhow/etc.) —
  implementation detail, deferred to the implementation change-set (see
  design A3).
- Caller-side rendering of diagnostics beyond the library-provided
  string: printing, coloring, localization, and structured logging are
  the caller's job (cryptile prints it).
- Automatic remediation (installing udev rules, starting pcscd) — the
  library diagnoses; it never mutates system state.
- Retriable-status retry policy (already resolved out of ceremony —
  retry is the caller's re-run, per ceremony OQ-1).
- New error variants beyond the ceremony taxonomy's ten — this change
  consolidates, it does not extend the taxonomy.