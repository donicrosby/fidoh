# fidoh-cli-ui — reference caller CLI

## Why

Every crate below it is a library; nothing in the workspace yet
demonstrates the full stack end-to-end from a caller's seat: transport
enumeration across hidraw + PC/SC, the getInfo capability probe, the
getAssertion ceremony with its keepalive/user-presence UX, and the
typed error taxonomy with its remediation hints. async-core D2 reserves
`fidoh-cli-ui` as the terminal leaf (MAY depend on `fidoh-core` and
`fidoh-tokio`; nothing may depend on it); error-diagnostics explicitly
defers diagnostic surfacing to "caller concerns". This change specifies
that reference caller: a small Linux-first binary that turns the
library's typed world into a human-usable token tool — and doubles as
the live-hardware exercise harness for the transport OQ probe queue.

## What Changes

- Add the **`fidoh-cli-ui` binary crate** with three subcommands:
  `list` (enumerate all transports, print candidate descriptors and
  per-transport diagnostics), `info` (mandatory getInfo probe per
  ceremony OQ-2, print versions/AAGUID/options/capabilities), and
  `assert` (full getAssertion ceremony: rpId, optional
  allowCredentials as hex, keepalive-driven "touch your token" prompt,
  assertion result printout).
- Specify **typed-error rendering**: every error path prints the typed
  variant, its phase (async-core D4), and the remediation hint where
  the taxonomy carries one (`AmbiguousDevice` MUST surface its hint;
  discovery diagnostics print per transport, never hidden).
- Specify the **dependency shape**: `fidoh-core` + `fidoh-tokio` +
  transport crates (hid, pcsc) + `fidoh-transport-soft` for a
  `--demo` mode; tokio enters ONLY via `fidoh-tokio` (D2 exclusivity
  extends to binaries); argument parsing is hand-rolled (no clap) to
  keep the dependency leaf narrow.
- Scope: **Linux first** (hidraw + PC/SC are the implemented
  transports), human-readable output only (no JSON output flag in v1),
  no PIN/UV interactive entry in v1 (UV policy = discard, matching
  ceremony defaults), no vendor-specific commands.
