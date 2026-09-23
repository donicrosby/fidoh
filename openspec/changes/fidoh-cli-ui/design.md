# fidoh-cli-ui — Design

The reference caller. Decisions here are orchestrator-level (this spec
was authored before implementation, 2026-09-23, closing the gap that
left fidoh-tokio specless until its code landed).

## Decisions

### D1 — Three subcommands, nothing more in v1

`list`, `info`, `assert`. Everything a token tool minimally does; no
provisioning, no credential management, no vendor commands, no makeCredential
(v1 asserts only — makeCredential is where PIN/UV protocol lives, and
ceremony v1 deliberately stops at getAssertion). `info` exists because
ceremony OQ-2 made the getInfo probe mandatory before assert anyway —
exposing it standalone costs nothing and is the first hardware-day tool.

### D2 — Tokio only via the adapter, binary included

The D2 exclusivity rule ("only fidoh-tokio SHALL name tokio") extends
to binary crates: the CLI uses `fidoh_tokio::TokioSleep` /
`spawn_blocking_slice` and never writes `tokio::` itself. Keeps the
audit trivially greppable and the adapter swappable.

### D3 — Hand-rolled argument parsing

A tool with three subcommands and ~6 flags does not need clap. Keeps
the dependency leaf at workspace crates only (plus tokio behind the
adapter). If the flag surface grows past a screen, revisit — recorded
here, not as an OQ.

### D4 — Keepalive UX dedup at the display layer

The ceremony surfaces every keepalive (core-model/ceremony
crystallizations); the CLI prints the touch prompt on the FIRST
UP_NEEDED only. Device-event fidelity stays in the libraries; pretty
suppression is a caller concern — which is exactly what this crate is.

### D5 — Soft token rides as `--demo`, not a default transport

`fidoh-transport-soft` is compiled in for `assert --demo` so CI can
exercise the full UX hardwareless. The soft token is NOT in `list`/
default discovery: listing a virtual authenticator next to real tokens
invites ceremonies against the wrong device.

### D6 — Exit codes are taxonomy-driven

0 = success (including "no devices" on `list` — an empty room is a
valid answer). Non-zero = typed error path; the renderer prints
variant + phase + hint. No numeric error-code scheme invented — the
typed taxonomy IS the error surface; text is for humans, grep is for
scripts.

## Scope fences (v1)

- Linux only (hidraw + PC/SC are the implemented transports; the CLI
  compiles where its deps compile).
- Human-readable text only; no `--json`.
- No interactive PIN/UV entry: UV policy is discard (ceremony default).
- No makeCredential, no PIN protocol, no vendor-specific commands.
- Windows/macOS transports out of scope until transport crates exist.

## Open questions

- **OQ-1 — assertion output shape for scripting.** v1 prints labeled
  hex blocks. If scripted consumers appear, a stable machine format
  (`--json` or an exit-pipe protocol) is a v2 decision with its own
  spec revision. *Status: open, non-blocking.*
