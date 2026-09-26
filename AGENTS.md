# AGENTS.md — fidoh

CTAP2/FIDO2 client library in Rust. `#![no_std]` + `alloc` core, hardware
transports (HID, CCID/pcsc), tokio adapter, soft-transport test harness.
Consumed by cryptile via git rev pins.

## Non-negotiables

- **NEVER push.** The push remote is deliberately disabled during agent
  waves. Commit to your lane branch only; the orchestrator lands.
- **NEVER commit to `main`.** Lane branches only.
- Never `git add -A` — stage explicit paths only.
- Work only in your assigned worktree. Never cd into or modify the main
  checkout, sibling worktrees, or `/workspace/cryptile*`.

## Gates (all must pass before you report done; capture rc WITHOUT pipes)

```bash
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test --workspace            # default (soft) config
cargo +1.75.0 check --workspace --all-features   # MSRV fence
openspec validate --strict        # when touching openspec/
```

Report each rc verbatim. A gate you didn't run is a gate that failed.

## Hard fences

- **MSRV 1.75.** If a dependency forces higher, STOP and report — do not
  bump the toolchain, do not vendor around it silently.
- **`deny(unsafe_code)` workspace-wide.** No `unsafe` anywhere, no
  exceptions, no `#[allow]`.
- **Runtime cleanliness:** only `fidoh-tokio` may name `tokio`; only
  std-gated modules (opt-in `extern crate std`) may name `std` — the core
  stays `no_std` + `alloc`.
- `zeroize` is exact-pinned (`=1.8.2`) — do not relax or bump it.
- CTAP2.1 spec behavior: cite the spec section in comments/tests when
  implementing or changing protocol semantics (spec-truth over
  implementation-convenience).

## House style

- Conventional commits, optional scope, **em-dash payload**:
  `chore — release 0.1.0`, `feat(fidoh-core) — clientPIN`. A hook enforces
  the format.
- Single-Deadline ceremony budget model: every wait consumes the remaining
  handed-in budget; new blocking paths must take the `Deadline`.
- Benchmarks/vectors/fuzz: don't touch unless your lane is explicitly about
  them; the vectors regen-drift CI gate must stay byte-stable.

## Environment

- Sandbox toolchain is likely NEWER than MSRV — that's why the
  `cargo +1.75.0 check` gate exists. Trust it, not the ambient toolchain.
- Use lane-unique scratch paths (`/tmp/lane-a-*.log`), never generic names —
  sibling agents share this filesystem.
- Avoid parallel `cargo` invocations across worktrees when a sibling is
  mid-gate (file-lock contention). Retry-on-lock is fine; stagger big suites.
- No hardware in this environment: never assume a device is attached. Tests
  use the soft transport / fixtures.
