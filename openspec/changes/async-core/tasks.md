# async-core — Tasks

Spec-authoring phase: tasks produce documents, not code. Implementation
arrives in later change-sets.

## 1. Core trait surface

- [ ] 1.1 Draft `Transport` / `Device` / `Ceremony` / `Sleep` trait reference (signatures, associated types, bounds) in `docs/` from specs/async-core/spec.md
- [ ] 1.2 Confirm object-safety boundaries (`Sleep` object-safe; `Transport`/`Device` generic) against planned call sites
- [x] 1.3 Resolve OQ-1 (MSRV pin) — RESOLVED: MSRV = 1.75, recorded in design.md

## 2. Crate graph

- [ ] 2.1 Document the crate dependency rules (arrows only toward `fidoh-core`) in `docs/architecture.md`
- [ ] 2.2 Author per-crate README stubs describing scope and allowed dependencies (documents only)

## 3. I/O policy

- [ ] 3.1 Record the blocking-syscalls + `spawn_blocking` v1 decision in `docs/architecture.md`, citing design.md D3/A1
- [x] 3.2 Resolve OQ-2 (CTAPHID per-wait slice default) — RESOLVED: 30 s tunable const, recorded in design.md

## 4. Timeout model

- [ ] 4.1 Document the single-budget deadline model and drop-cancellation contract in `docs/architecture.md`
- [x] 4.2 Resolve OQ-3 (channel release on drop-cancel) — RESOLVED: best-effort release is mandatory, spec updated

## 5. Feature flags

- [ ] 5.1 Document the feature matrix (default = soft only; `hid`, `pcsc`, `tokio` opt-in) in `docs/architecture.md`
- [ ] 5.2 Validate: `openspec validate async-core --strict` green
