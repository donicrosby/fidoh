# fidoh-cli-ui Specification

The reference caller for the fidoh stack: a Linux-first CLI that
enumerates FIDO devices across all transports, probes capabilities,
and runs getAssertion ceremonies through the fidoh-tokio adapter.
Built on async-core's crate-graph reservation (terminal leaf, deps =
core + tokio-adapter + transports), ceremony's orchestration rules
(discovery collect-never-short-circuit, mandatory getInfo probe,
single budget, selection policy), and the typed error taxonomy.

## ADDED Requirements

### Requirement: Device listing aggregates all transports with visible diagnostics

The `list` subcommand SHALL enumerate every compiled-in transport
(hidraw, PC/SC) and print one line per candidate: transport kind,
device identifier (hidraw path / reader name), and FIDO-ness as
reported by enumeration. Per-transport discovery errors and typed
skips (e.g. `skip <reader>: not-fido`) SHALL be printed under a
diagnostics section — never silently dropped, never aborting the
other transports' results (ceremony collect-never-short-circuit).
With zero candidates and zero errors the command SHALL exit
successfully with an explicit "no devices" message; with errors and
zero candidates it SHALL exit non-zero with `Error::NoDevice`'s
per-transport causes rendered.

#### Scenario: Mixed transport listing

- **WHEN** `list` runs on a machine with one FIDO hidraw token, one
  non-FIDO NFC reader, and one unreadable sysfs node
- **THEN** the token is listed, the non-FIDO reader appears as a typed
  skip diagnostic, the unreadable node appears as a per-node
  diagnostic, and the exit code is 0

#### Scenario: No devices at all

- **WHEN** `list` runs with no token attached and no readers present
- **THEN** output states no devices were found and the exit code is 0

### Requirement: The assert subcommand runs the full ceremony with keepalive UX and typed error rendering

The `assert` subcommand SHALL run a complete getAssertion ceremony —
discovery (all transports), mandatory getInfo probe, selection, and
the CTAP2.1 §6.2 exchange — over the fidoh-tokio adapter with a single
caller budget. During the user-presence wait it SHALL print a
"touch your token" prompt on the first UP_NEEDED (0x02) keepalive and
not repeat it per keepalive (display-level dedup); on
KEEPALIVE_CANCEL (0x2D) it SHALL print the typed cancellation; on
budget expiry it SHALL print `Error::Timeout` with the phase the
ceremony crystallization assigns (post-UP_NEEDED expiry names
`UserPresence`). Every error exit SHALL render the typed variant
name, the phase when applicable, and the remediation hint where the
taxonomy carries one — `AmbiguousDevice` MUST print its hint and one
line per candidate. A successful run SHALL print relying-party id,
credential id (hex), user-selected flag when present, and the
authData + signature as hex.

#### Scenario: Touch prompt appears once

- **WHEN** a ceremony waits for user presence and the token emits
  repeated UP_NEEDED keepalives
- **THEN** the touch prompt prints exactly once

#### Scenario: Ambiguous selection renders hint and candidates

- **WHEN** two tokens are attached and the default selection policy
  (Fail) is in effect
- **THEN** the command exits non-zero with `AmbiguousDevice`, its
  remediation hint, and one descriptor line per candidate

#### Scenario: Touch timeout names the phase

- **WHEN** the user never touches and the budget expires after the
  first UP_NEEDED
- **THEN** the rendered error is `Timeout` naming the `UserPresence`
  phase

### Requirement: The crate stays the terminal leaf with tokio entering only via the adapter

`fidoh-cli-ui` SHALL depend on `fidoh-core`, `fidoh-tokio`,
`fidoh-transport-hid`, `fidoh-transport-pcsc`, and (dev/demo only)
`fidoh-transport-soft`, and SHALL NOT be depended on by any workspace
crate (async-core D2). Tokio SHALL enter only through `fidoh-tokio`;
the binary SHALL NOT name tokio directly. Argument parsing SHALL be
hand-rolled (no external arg-parsing crate). A `--demo` mode SHALL run
the same ceremony against the soft token in-process, so the full UX is
exercisable in CI without hardware.

#### Scenario: Manifest dependency audit

- **WHEN** the workspace manifest is audited
- **THEN** no crate depends on `fidoh-cli-ui`, and the only tokio
  edge in the entire workspace still belongs to `fidoh-tokio`

#### Scenario: Demo mode runs the ceremony without hardware

- **WHEN** `assert --demo` runs on a machine with no token attached
- **THEN** the ceremony completes against the soft token with the same
  output shape as a hardware run
