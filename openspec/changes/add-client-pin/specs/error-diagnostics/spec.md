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
transport-pcsc). Since the add-client-pin change (v2) the ceremony
taxonomy carries the typed PIN failures and the no-secrets rule
explicitly covers PIN material and derived key material.

## MODIFIED Requirements

### Requirement: No secrets in error messages or debug output

Error messages, `Display` impls, `Debug` impls, and diagnostic strings
MUST NOT contain secrets, credential material, PIN data, PIN-derived
material (PIN hashes, shared secrets, pinUvAuthTokens, pinTokens), or
private keys — ever. Since v2 this rule covers every value flowing
through the PIN-provider seam and the pinUvAuth protocols: PIN-related
types render lengths and variant names only; a `Debug` derive on any
type carrying key material is a spec violation. Credential identifiers
keep the truncated-safe hex treatment (first 8 bytes + total length).

#### Scenario: Pin-typed errors render no secret material (CI: transport-soft clientPIN)

- **WHEN** the ceremony fails with `Error::IncorrectPin` after the
  provider supplied a wrong PIN, and the caller formats the error with
  `{:?}` and `{}` and inspects every intermediate `Transport` detail
- **THEN** none of the rendered text contains the PIN bytes, the PIN
  hash, the shared secret, the pinToken, or the encrypted token — only
  the retry count and layer names appear

#### Scenario: Derived material zeroized and absent from memory-exposing output

- **WHEN** an acquisition-flow run completes or fails at any typed
  step and the harness inspects the zeroizing containers' drop behavior
- **THEN** the shared secret and PIN buffers are zeroized on drop, and
  no public `Debug`/`Display` path can print them (length-only
  rendering is enforced by tests)

### Requirement: Single library error surface is the ceremony taxonomy

The library SHALL expose exactly one public error taxonomy: the
ceremony's typed variants — `NoDevice`, `AmbiguousDevice`,
`UserActionTimeout`, `UserCancelled`, `NoCredentials`, `UpRejected`,
`CredentialMismatch`, `Timeout`, `Transport`, `Ctap` (ceremony error
taxonomy requirement), plus, since the add-client-pin change (v2), the
PIN failures `IncorrectPin` (carrying the remaining-retry count when
the authenticator offered it), `PinBlocked`, `PinAuthBlocked`,
`PinNotSet`, `PinRequired`, `PinProviderFailed`, and `PinTooLong`.
Transport and core layers SHALL map every failure into this surface: a
raw OS errno, PC/SC return code (PC/SC Part 3), ISO 7816-4 status word,
or CTAPHID_ERROR code (CTAP2.1 §11.2.9.1.6) MUST NOT surface to the
caller without a typed wrapper carrying it as structured cause data
(inside `Transport` or inside the per-transport causes of `NoDevice`); a
CTAP2 status byte MUST surface only via the typed variants of
ceremony's CTAP2.1 §8.2 mapping, with `Ctap(status)` carrying
core-model's typed status value. No failure SHALL surface as a string,
an untyped error, an integer code alone, or a panic (stack invariant:
typed errors everywhere).

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

#### Scenario: PIN status bytes surface through their dedicated variants (CI: transport-soft clientPIN)

- **WHEN** the soft token answers 0x31, 0x32, 0x34, and 0x35 on
  successive acquisition runs
- **THEN** the caller observes `IncorrectPin`, `PinBlocked`,
  `PinAuthBlocked`, and `PinNotSet` respectively — none of the four
  surfaces as `UpRejected` or `Ctap` — and 0x33/0x36/0x37/0x3C still
  map to `UpRejected` as before

### Requirement: Errors implement std::error::Error under the std feature

On builds with the `std` feature enabled (default-off; `fidoh-core`
itself stays `no_std`), every public error type of the taxonomy
(`CeremonyError`, `Error`, `DecodeError`, `EncodeError`,
`TransportError`) SHALL implement `std::error::Error` in addition to
`Display`, so `Box<dyn std::error::Error>` / `anyhow` consumers can
propagate them without per-crate wrappers. The implementation SHALL be
feature-gated so the default and no_std builds are byte-identical in
surface, and SHALL NOT pull thiserror or any new dependency into the
core crate.

#### Scenario: Anyhow-style consumers propagate typed errors (CI: std-feature test)

- **WHEN** a test with the `std` feature enabled returns a
  `CeremonyError` through `Box<dyn std::error::Error>` and formats it
- **THEN** the boxed error displays exactly as the direct Display text
  and compiles without any new dependency in fidoh-core

#### Scenario: no_std build stays clean

- **WHEN** `fidoh-core` builds with default features (no std)
- **THEN** no `std::error::Error` impl is compiled and the crate
  remains `#![no_std]` with its dependency set unchanged
