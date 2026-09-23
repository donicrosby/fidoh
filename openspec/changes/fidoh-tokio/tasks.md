# fidoh-tokio — Tasks

Retroactive spec change: the implementation landed 2026-09-23
(deleg_123d923a) against async-core's named requirements; this change
crystallizes the contract. Spec and code landed together.

## 1. Spec authoring

- [x] 1.1 Write specs/fidoh-tokio/spec.md (4 requirements: Sleep factory, spawn_blocking bridge, tokio exclusivity, MSRV floor)
- [x] 1.2 Write design.md (D1–D6, crystallization notes)
- [x] 1.3 `openspec validate fidoh-tokio --strict`

## 2. Implementation (landed with this change)

- [x] 2.1 `TokioSleep` Sleep impl (Send futures, paused-clock compatible)
- [x] 2.2 `spawn_blocking_slice` grant-before-issue bridge with `SliceGrantArgs`, typed timeout at slice edge, panic folding
- [x] 2.3 Dependency shape: lib = fidoh-core + tokio (rt, time); dev = macros/rt-multi-thread/sync/test-util + fidoh-transport-soft
- [x] 2.4 Tokio floor "1.47" with MSRV rationale in manifest
- [x] 2.5 13 scenario-ID tests + 1 doctest, incl. executor non-stall proof, slice-expiry typed timeout, pre-spawn budget exhaustion, drop-detach, panic folding, full ceremony over soft token, Send-bound spawn proof, device-reuse after dropped ceremony, manifest audit
- [x] 2.6 Gates: build / 276 workspace tests green / clippy `-D warnings` zero / fmt clean
