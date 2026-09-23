# fidoh-cli-ui — Tasks

## 1. Spec authoring

- [x] 1.1 Write proposal.md, specs/fidoh-cli-ui/spec.md, design.md (D1–D6, scope fences, OQ-1)
- [x] 1.2 `openspec validate fidoh-cli-ui --strict`

## 2. Implementation

- [x] 2.1 `crates/fidoh-cli-ui` binary crate: deps per D2/D3/D5 (core, fidoh-tokio, hid, pcsc; soft dev/demo), forbid(unsafe_code), MSRV 1.75
- [x] 2.2 `list` subcommand: all-transport enumeration, typed skip + per-node diagnostics rendering, zero-candidate exits per spec
- [x] 2.3 `info` subcommand: mandatory getInfo probe, versions/AAGUID/options/capabilities printout
- [x] 2.4 `assert` subcommand: full ceremony via adapter, single budget, selection policy incl. AmbiguousDevice hint rendering, keepalive UX dedup, phase-named timeout rendering, hex result printout
- [x] 2.5 `--demo` mode: same ceremony over soft token, no hardware
- [x] 2.6 Typed-error renderer: variant + phase + remediation hint
- [x] 2.7 Tests (scenario-ID): mixed-transport listing, no-devices exit, touch-prompt-once (fake keepalive stream), AmbiguousDevice rendering, UserPresence-phase timeout, demo ceremony end-to-end, manifest audit (no crate depends on cli-ui; tokio only via adapter)
- [x] 2.8 Gates: build; workspace tests all green (276 baseline); clippy `--all-targets --all-features -- -D warnings` zero; fmt --check clean
- [x] 2.9 README status line refresh (implementation no longer "pre-implementation")

Do NOT commit. Leave tree dirty. Report design-silent decisions + spec patch-backs for parent crystallization.
