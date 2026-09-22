# error-diagnostics — Design

## Phase

Phase D (cross-cutting consolidation / documentation). This change
produces documents only; implementation tasks arrive in later
change-sets per the repo's tasks rules. It builds on the committed
Phase-A/B/C contracts: core-model (CTAP2.1 §8.2 status table),
async-core (traits, D4 single-budget timeout model, phase-naming
`Timeout`, MSRV 1.75, DEFAULT_WAIT_SLICE 30 s, mandatory best-effort
channel release), ceremony (ten-variant error taxonomy, candidate
descriptors, mandatory getInfo probe), transport-hid (CTAPHID per
CTAP2.1 §11.2, hidraw enumeration, udev docs), transport-pcsc (APDU
layer per CTAP2.1 §11.3, 6A82 enumerate-and-skip, PC/SC/SW error
mapping), and transport-soft (error-injection knobs for CI).

## Context

The library's failure surface today is *specified* but *scattered*:
the ceremony spec pins ten typed variants, transport-pcsc pins a full
PC/SC/SW→typed mapping table, transport-hid pins typed hidraw errors, and
core-model pins the CTAP2.1 §8.2 status space. What's missing is a single normative
statement that (a) these compose into ONE error surface, (b) every error
carries actionable context, and (c) the operator-facing failures tell the user
how to fix the problem — with the remediation text grounded in our own
transport docs and public Linux udev/pcsc-lite documentation. This change
writes that contract down and produces docs/errors.md as the operator-facing
companion.

No protocol claims are made in this design; every wire/behavior claim cited
here is grounded in the sibling specs (CTAP2.1 §8.2 status table,
CTAP2.1 §11.2/§11.3 transport specs, PC/SC Part 3 codes) or in public
Linux documentation (udev `uaccess`/`TAG` mechanism per systemd's
`70-uaccess.rules`/`60-fido-id.rules`; pcsc-lite daemon model and
`systemctl status pcscd` / `pcsc_scan` diagnostics).

## Decisions

### D1: One error surface — the ceremony taxonomy

The ten ceremony variants (`NoDevice`, `AmbiguousDevice`,
`UserActionTimeout`, `UserCancelled`, `NoCredentials`, `UpRejected`,
`CredentialMismatch`, `Timeout`, `Transport`, `Ctap`) are THE public
error taxonomy of the library. Transport-layer causes (hidraw errnos,
CTAPHID_ERROR codes, PC/SC return codes, ISO 7816 status words) exist
only as *structured payloads inside* the `Transport` variant (and
inside the per-transport causes carried by `NoDevice` discovery
errors), never as a parallel public hierarchy. A caller that branches
on the ten variants sees everything; a caller that branches deeper
uses the structured cause fields (D2), never string parsing.

This does not add an eleventh variant, does not rename any variant,
and does not restate the status-code mapping — ceremony's §8.2
mapping table and transport-pcsc's PC/SC/SW table stay authoritative.

### D2: Structured context is part of the error value

Every typed error carries the fields a caller (or the diagnostics
text, D3) needs to act:

- **Device descriptor** when a device is implicated: transport kind,
  device path/handle, human-readable metadata, AAGUID when the
  getInfo probe ran (ceremony's `CandidateDescriptor` shape).
- **Phase** naming which ceremony phase failed (async-core D4 already
  requires `Timeout` to name the phase; this change generalizes the
  phase field to `Transport` and `Ctap` errors too).
- **Elapsed / remaining budget** when a deadline is involved: the
  elapsed time and the original budget accompany `Timeout`, so
  "waited 30.2s of 30s budget" is data, not prose.

The exact Rust field layout (struct-per-variant vs. struct +
enum-of-causes) is an implementation detail; the spec pins only the
presence and semantics of the fields.

### D3: Diagnostics are data-producing strings, not magic

`NoDevice` and channel-open failures SHOULD embed an actionable
remediation hint in their diagnostic message (the human-oriented
string the library produces), naming the concrete fix path:

- hidraw permission failure → the udev options (uaccess tag via
  systemd's fido rules; plugdev-style group rule) + docs/transport-hid.md.
- PC/SC failure → the pcscd running-state check
  (`systemctl status pcscd`), reader-driver visibility check
  (`pcsc_scan`), and docs/transport-pcsc.md.

The library PROVIDES the string; the caller (cryptile) renders it.
The library never renders to stderr itself, never colors, never
localizes — those are caller concerns (crate-graph rule: `fidoh-cli-ui`
may depend on core, never the reverse).

Grounding: the udev guidance is documented public behavior of
systemd's `70-uaccess.rules`/`60-fido-id.rules` and the kernel hidraw
model (already written up in docs/transport-hid.md); the pcscd
guidance is documented pcsc-lite behavior (socket activation,
`SCARD_E_NO_SERVICE` when the daemon is down) already written up in
docs/transport-pcsc.md. No new protocol claims.

### D4: Display for humans, fields for programs

Every error type implements `Display` (human sentence including the
remediation hint where D3 applies) AND exposes the structured fields
of D2 as public accessors. The contract: a caller MUST be able to
produce every behavior distinction from fields alone; the Display
string is for operators, logs, and bug reports.

### D5: No secrets in errors — ever

Error values, their Display strings, and their structured fields MUST
NOT contain secrets, credential material, or PIN data. This includes
raw credential IDs beyond a safe truncation, PINs, pinUvAuthToken
material, clientDataHash contents beyond length/prefix, and signature
bytes. The `CredentialMismatch` variant may identify the mismatch
using truncated credential IDs only (ceremony OQ-3(b) already
requires "truncated safely"). This is a hard MUST NOT with a spec
scenario — error paths are the classic secret-leak vector, and
diagnostics strings are exactly what users paste into issue trackers.

## Blocking waits and their timeout bounds

This change introduces no new waits. All waits named by sibling
designs retain their bounds: every wait is bounded by the single
remaining ceremony budget (async-core D4); CTAPHID read slices are
bounded by DEFAULT_WAIT_SLICE (30 s default, caller-overridable);
NFC field polls are sliced at ≤ 1 s. Error construction itself is
non-blocking; building a diagnostic string MUST NOT perform I/O (no
probing udev, no querying pcscd at error-construction time — the
library reports what the failing syscall said, it does not re-diagnose
the system).

## Alternatives Considered

### A1: Opaque error codes with a lookup table — rejected

A compact `u16` error code per failure (à la Windows HRESULTs or
libfido2's `FIDO_ERR_*` integers) keeps binaries small and strings
out of the library, but pushes all remediation onto out-of-band
documentation the operator may never find. The stack invariant
"typed errors everywhere" plus the explicit diagnostics requirement
(actionable remediation text for `NoDevice`/channel-open) is better
served by rich typed values carrying structured context plus a
human string. The cost — message strings in the library — is
accepted and bounded (diagnostics only; no per-cause prose database).

### A2: Caller-side diagnostics (library returns bare codes, cryptile maps them to advice) — rejected

Duplicating the hidraw/udev and pcscd remediation knowledge in every
caller means N copies of the advice drifting apart, and non-cryptile
callers get nothing. The knowledge of WHAT failed and WHY lives in the
transport that saw the errno; the library is the right place to
phrase the hint once. Rendering stays with the caller (D3), so the
separation of concerns is preserved: library = diagnostic content,
caller = presentation.

### A3: Error-crate choice (thiserror vs. snafu vs. hand-rolled) — deferred (implementation detail)

The spec pins behavior (typed variants, structured fields, Display,
no string-parsing, no secrets), not the macro that produces it.
MSRV 1.75 (async-core) and the no-runtime-dependency rule for
`fidoh-core` constrain the choice, but any mainstream option satisfies
them. Defer to the implementation change-set.

### A4: Localized / templated diagnostic strings — rejected for v1

Localization is a presentation-layer concern and would drag a
translation framework into `fidoh-core`. English diagnostic strings
with structured fields let a caller localize from the fields if it
wants to. Revisit only if a concrete downstream needs it.

### A5: Live system re-diagnosis at error time (check udev rules, query pcscd state) — rejected

Re-running system probes inside error construction adds hidden
blocking I/O to a path that must be non-blocking (see timeout bounds),
produces stale or misleading answers (permissions may have changed
mid-ceremony), and expands the OS surface of `fidoh-core`. The error
reports the failing operation's typed cause plus static guidance;
docs/errors.md gives the operator the live commands
(`systemctl status pcscd`, `pcsc_scan`, `getfacl`) to run themselves.

## Open Questions

- OQ-1: Should `AmbiguousDevice` also carry a remediation hint
  (e.g. "pass an explicit SelectionPolicy")? Currently the ten-variant
  diagnostics rule covers `NoDevice` and channel-open failures only;
  `AmbiguousDevice` is arguably operator-facing too. Left to the
  implementation change-set; the spec's SHOULD-scope is deliberately
  narrow.
- OQ-2: Exact truncation rule for credential IDs in `CredentialMismatch`
  diagnostics (byte count vs. hex prefix length). The spec pins
  "truncated" and "never full credential material"; the precise
  display length is presentation detail, deferred.