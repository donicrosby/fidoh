# fidoh

FIDO2 / CTAP2 in Rust. D'oh!

Cleanroom, async, runtime-agnostic CTAP2 client library. Specification-first:
the entire library is derived from the openspec change set under `openspec/`
plus the standards it cites (FIDO CTAP 2.x, W3C WebAuthn, ISO 7816-4, PC/SC).

Status: implemented through the reference caller (`fidoh-cli-ui`): the
spec set of Phase A–D is realized as crates — core model + ceremony,
soft/HID/PC-SC transports, the runtime adapter, and the `fidoh` CLI
(`list` / `info` / `assert`; `assert --demo` runs hardwareless).

Build shapes (async-core spec: soft transport is the default):

```sh
cargo build                            # core + soft transport only — no OS device APIs
cargo build --features hid             # + Linux hidraw transport
cargo build --features pcsc            # + PC/SC transport (needs libpcsclite + pcscd)
cargo build --features hid,pcsc,tokio  # whole graph incl. the runtime adapter
cargo test                             # the CI contract: full ceremony on the soft token
```

See `docs/` and `openspec/` for the living specification.
