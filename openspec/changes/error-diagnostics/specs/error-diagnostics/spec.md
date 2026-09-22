# error-diagnostics Specification

Cross-cutting contract for the library's error surface: the ceremony
ten-variant taxonomy is the single public error surface; every typed
error carries structured, actionable context (device descriptor,
phase, elapsed budget); operator-facing failures carry remediation
guidance grounded in docs/transport-hid.md and docs/transport-pcsc.md;
errors implement `Display` for humans and expose structured fields for
programs; and no error ever contains secrets, credential material, or
PIN data. Builds on ceremony's error taxonomy and candidate
descriptors, async-core's D4 single-budget timeout model (phase-naming
`Timeout`), core-model's CTAP2.1 §8.2 typed status values, and the
transport specs' typed-cause mappings (CTAPHID_ERROR per CTAP2.1
§11.2.9.1.6; PC/SC Part 3 codes and ISO 7816-4 status words per
transport-pcsc).

## ADDED Requirements

### Requirement: Single library error surface is the ceremony taxonomy

The library SHALL expose exactly one public error taxonomy: the
ceremony's ten typed variants — `NoDevice`, `AmbiguousDevice`,
`UserActionTimeout`, `UserCancelled`, `NoCredentials`, `UpRejected`,
`CredentialMismatch`, `Timeout`, `Transport`, `Ctap` (ceremony error
taxonomy requirement). Transport and core layers SHALL map every
failure into this surface: a raw OS errno, PC/SC return code (PC/SC
Part 3), ISO 7816-4 status word, or CTAPHID_ERROR code (CTAP2.1
§11.2.9.1.6) MUST NOT surface to the caller without a typed wrapper
carrying it as structured cause data (inside `Transport` or inside the
per-transport causes of `NoDevice`); a CTAP2 status byte MUST surface
only via the typed variants of ceremony's CTAP2.1 §8.2 mapping, with
`Ctap(status)` carrying core-model's typed status value. No failure
SHALL surface as a string, an untyped error, an integer code alone,
or a panic (stack invariant: typed errors everywhere).

#### Scenario: Raw PC/SC code never escapes untyped (CI: transport-pcsc mapping)

- **WHEN** `SCardEstablishContext` fails with SCARD_E_NO_SERVICE
  (0x8010001D) during discovery and no other transport yields a
  candidate
- **THEN** the caller receives `Error::NoDevice` whose per-transport
  cause list contains the pcsc transport kind and a typed `Transport`
  error with the `no-service` cause carrying the raw code as
  structured data — never the bare integer 0x8010001D as the error
  itself

#### Scenario: CTAP status byte surfaces only through the typed mapping (CI: transport-soft status knob)

- **WHEN** the soft token returns 0x30 CTAP2_ERR_NOT_ALLOWED on a
  getNextAssertion continuation
- **THEN** the caller receives `Error::Ctap` carrying core-model's
  typed status value for 0x30, and the raw byte 0x30 appears nowhere
  except inside that typed payload

### Requirement: Every typed error carries actionable structured context

Every typed error SHALL carry, as structured fields accessible without
parsing message text: (a) a device descriptor whenever a device is
implicated — transport kind, the transport's device identifier
(path/handle), human-readable metadata, and the AAGUID when the
mandatory getInfo probe (CTAP2.1 §6.4, ceremony) ran; (b) the ceremony
phase in which the failure occurred (discovery, selection, connect,
probe, getAssertion, user-presence, getNextAssertion — the same phase
vocabulary async-core D4 requires `Timeout` to name); and (c) the
elapsed time and original budget whenever a deadline is involved, so
`Timeout` carries "elapsed vs. budget" as data. Error construction
SHALL be non-blocking: building the error value or its diagnostic
string MUST NOT perform I/O (no udev probing, no pcscd queries, no
device traffic at error time).

#### Scenario: Timeout carries phase and budget as fields (CI: transport-soft require-explicit-poke)

- **WHEN** the soft token is in `require-explicit-poke` UP mode and
  the 30 s ceremony budget expires mid user-presence wait
- **THEN** the `Error::Timeout` value exposes the phase field naming
  user-presence, the elapsed duration, and the 30 s budget as structured fields,
  without the caller parsing the Display string

#### Scenario: Transport error carries the device descriptor

- **WHEN** a hidraw `open()` of `/dev/hidraw3` fails with EACCES
  during connect
- **THEN** the resulting `Transport` error exposes a descriptor with
  transport kind hid, the device identifier `/dev/hidraw3`, and the
  human-readable metadata from enumeration, as structured fields

#### Scenario: Error construction performs no I/O

- **WHEN** any typed error value is constructed or its diagnostic
  string is produced
- **THEN** no syscall, device probe, udev query, or pcscd call occurs —
  the error reports the failing operation's recorded typed cause plus
  static guidance

### Requirement: Diagnostics for NoDevice and channel-open failures

`NoDevice` and channel-open failures (hidraw open, CTAPHID INIT per
CTAP2.1 §11.2, APDU SELECT per CTAP2.1 §11.3.3) SHOULD carry
actionable remediation guidance in their diagnostic message, phrased
against the failing cause: a Linux hidraw permission failure SHALL
name the udev remediation paths — the uaccess tag and the plugdev-style
group rule — and point at docs/transport-hid.md; a PC/SC failure SHALL
name the pcscd running-state check (`systemctl status pcscd`) and the
reader-driver visibility check (`pcsc_scan`), and point at
docs/transport-pcsc.md. The library SHALL provide the diagnostic
string; rendering (printing, coloring, logging, localization) SHALL
be the caller's responsibility — the library never writes to
stdout/stderr itself.

#### Scenario: hidraw permission failure names the udev fix (CI: transport-soft or injected open failure)

- **WHEN** discovery finds one hidraw candidate but connect fails with
  EACCES on `/dev/hidraw3`, and no other transport yields a device
- **THEN** the diagnostic message names the permission failure, names
  both udev options (uaccess tag; plugdev group rule), and references
  docs/transport-hid.md, while the structured cause field still
  carries the typed open-permission cause with the path

#### Scenario: PC/SC no-service failure names the daemon check (CI: transport-pcsc mapping)

- **WHEN** pcscd is not running and discovery produces `NoDevice`
  with the pcsc `no-service` cause
- **THEN** the diagnostic message advises checking the pcscd running
  state (`systemctl status pcscd`) and reader visibility
  (`pcsc_scan`), and references docs/transport-pcsc.md

### Requirement: Display for humans, structured fields for programs

Every error type SHALL implement `Display` producing a human-readable
message (including the remediation guidance of the diagnostics
requirement where applicable) and SHALL expose its structured context
fields (variant, cause, descriptor, phase, budget data) through
programmatic accessors. A caller MUST be able to branch on every
behavioral distinction using fields alone; parsing the `Display`
string to recover the cause, phase, path, or code is a contract
violation.

#### Scenario: Caller branches on fields without string parsing

- **WHEN** a caller receives a `Transport` error from the PC/SC
  transport whose cause is `sharing`
- **THEN** the caller distinguishes the sharing cause from
  `no-service` and `removed` via the cause field alone, and the
  Display string is used only for operator output

### Requirement: Error values and messages MUST NOT contain secrets or credential material

Error values, their `Display` strings, their diagnostic guidance, and
their structured fields MUST NOT contain secrets, credential material,
or PIN data — ever. This prohibition covers: PINs and any PIN-derived
material; pinUvAuthToken values and pinUvAuthParam bytes; full
credential IDs and private key material; signature bytes; and
clientDataHash contents beyond non-sensitive metadata (e.g. its
length). Identifying fields in errors (e.g. `CredentialMismatch`
naming the mismatch per ceremony OQ-3(b)) SHALL use only safely
truncated, non-sensitive identifiers. This holds for every error path
including debug formatting intended for logs and bug reports.

#### Scenario: CredentialMismatch truncates the credential id (CI: transport-soft wrong-credential-id knob)

- **WHEN** the soft token's wrong-credential-id knob (d) is armed and
  the ceremony fails with `CredentialMismatch`
- **THEN** the error's message and fields identify the mismatch using
  a truncated credential id only, and neither the full returned
  credential id nor any allow-list credential id appears in full

#### Scenario: PIN-adjacent failure carries no PIN material

- **WHEN** an authenticator returns 0x33 CTAP2_ERR_PIN_AUTH_INVALID
  and the ceremony maps it to `Error::UpRejected`
- **THEN** neither the error value nor its Display string contains the
  caller-supplied pinUvAuthParam bytes, any pinUvAuthToken material,
  or anything from which a PIN could be derived

### Requirement: docs/errors.md is the operator-facing error reference

The repository SHALL carry `docs/errors.md` documenting every variant
of the taxonomy with: its meaning, likely causes, operator
remediation, and a link to the relevant transport doc
(docs/transport-hid.md or docs/transport-pcsc.md). It SHALL include
copy-paste udev rule snippets for both the uaccess and plugdev
variants (grounded in docs/transport-hid.md's Linux permissions
section), the pcscd diagnostic commands (`systemctl status pcscd`,
`pcsc_scan`), and guidance for distinguishing device contention
(another client holding the authenticator) from missing permissions.
Guidance text in docs/errors.md SHALL be grounded in the transport
docs and public Linux udev/pcsc-lite documentation; where a
remediation claim cannot be so grounded it SHALL be flagged rather
than invented (cleanroom rule).

#### Scenario: Operator resolves a permission failure from docs alone

- **WHEN** an operator hits a hidraw EACCES channel-open failure and
  opens docs/errors.md
- **THEN** they find the `Transport`-permission table row, the
  copy-paste uaccess and plugdev udev rules, the verification commands
  (`ls -l`, `getfacl`), and the link to docs/transport-hid.md —
  sufficient to fix the permission without reading library source

#### Scenario: Operator distinguishes contention from permissions

- **WHEN** an operator sees repeated `Timeout` on connect or a typed
  `sharing` cause and consults docs/errors.md
- **THEN** the document tells them how to tell "another client holds
  the device" (browsers, other tools; ERR_CHANNEL_BUSY / sharing
  violation) apart from "no permission" (EACCES on open), with the
  concrete checks for each
