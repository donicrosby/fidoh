# fidoh-cli-ui Specification

## MODIFIED Requirements

### Requirement: The crate stays the terminal leaf with tokio entering only via the adapter

`fidoh-cli-ui` SHALL depend on `fidoh-core`, `fidoh-tokio`,
`fidoh-transport-hid`, `fidoh-transport-pcsc`, and (dev/demo only)
`fidoh-transport-soft`, and SHALL NOT be depended on by any workspace
crate (async-core D2). Tokio SHALL enter only through `fidoh-tokio`;
the binary SHALL NOT name tokio directly. Argument parsing SHALL be
hand-rolled (no external arg-parsing crate). A `--demo` mode SHALL run
the same ceremony against the soft token in-process, so the full UX is
exercisable in CI without hardware. Since the add-client-pin change
(v2), the keepalive-UX `Device` wrapper (`UxDevice`) SHALL live in
`fidoh-core::device` — it is a plain forwarding wrapper with no std or
runtime dependency — and this crate SHALL re-export it for source
compatibility, so non-CLI callers (examples, tests, other binaries)
stop re-implementing the keepalive-UX seam. This crate's own keepalive
UX (`TouchPrompt` dedup) remains the reference sink implementation.

#### Scenario: Manifest dependency audit

- **WHEN** the workspace manifest is audited
- **THEN** no crate depends on `fidoh-cli-ui`, and the only tokio
  edge in the entire workspace still belongs to `fidoh-tokio`

#### Scenario: Demo mode runs the ceremony without hardware

- **WHEN** `--demo` runs against the in-process soft token
- **THEN** the full ceremony completes with the same UX surface as a
  hardware run and no hardware is touched

#### Scenario: UxDevice importable from core by non-CLI callers

- **WHEN** a downstream example (or test) wraps a connected device with
  `fidoh_core::device::UxDevice::new(inner, sink)` and drives a
  ceremony
- **THEN** the sink observes every keepalive exactly as the CLI's
  wrapper delivered them, and the CLI's own re-export resolves to the
  same type
