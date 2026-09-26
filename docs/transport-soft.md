# transport-soft — the soft-token authenticator (CI harness)

`transport-soft` is an in-process virtual CTAP2 authenticator. It implements
the same `Transport`/`Device` traits as the hardware transports (CTAPHID,
PC/SC), performs no OS I/O, and exists to make the client library testable in
CI without hardware. Governing spec:
`openspec/changes/transport-soft/specs/transport-soft/spec.md`.

All code snippets below are **constructed examples** (written to illustrate
the API shape, not captured from a running system).

## What it implements

| CTAP2 command | Status | Notes |
|---|---|---|
| authenticatorGetInfo | ✅ | Pinned AAGUID = `66 69 64 6F 68 2D 73 6F 66 74 2D 74 6F 6B 65 6E` (`b"fidoh-soft-token"`, 16 ASCII bytes — authoritative value for this crate); versions `FIDO_2_0`, `FIDO_2_1`; options `rk`/`up`/`uv` (CTAP2.1 §6.4) |
| authenticatorMakeCredential | ✅ internal only | Harness method on the concrete type; **not** in the client-facing API (CTAP2.1 §6.1) |
| authenticatorGetAssertion | ✅ | Real ECDSA P-256 signatures over `authenticatorData \|\| clientDataHash` (CTAP2.1 §6.2.2, WebAuthn L2 §6.5.5) |

Attestation is always `none` (WebAuthn L2 §8.7). Out of scope: the
authenticator SET/CHANGE PIN commands (harness `set_pin`/`clear_pin`
provide the PIN state; add-client-pin v2 models the full
authenticatorClientPIN §6.5.5 acquisition side), credential
management, large blobs, hmac-secret.

## CI usage

### Happy-path assertion (constructed example)

```rust
// Constructed example — API names illustrative.
let mut auth = SoftAuthenticator::new(Config::default());       // pinned AAGUID
let device = auth.device();                                     // impl Device

// Mint a resident credential via the INTERNAL harness method.
let cred = auth.make_credential(MakeCredentialArgs {
    rp_id: "example.com".into(),
    user_handle: b"ci-user-1".to_vec(),
    ..Default::default()
})?;

// Run the real client ceremony against the soft transport.
let assertion = client::get_assertion(&device, GetAssertionArgs {
    rp_id: "example.com".into(),
    client_data_hash: sha256(b"..."),   // caller-supplied, per RP boundary
    allow_list: vec![cred.id.clone()],
    deadline: timer.deadline(Duration::from_secs(30)),
}).await?;

assert!(cred.public_key.verify(
    &[assertion.authenticator_data.as_slice(), &client_data_hash].concat(),
    &assertion.signature,
));
```

### Timeout-path test (constructed example)

```rust
auth.knobs().delay_beyond_deadline(true);           // responds after deadline
let err = client::get_assertion(&device, args_with_deadline_ms(100)).await
    .expect_err("must time out");
assert!(matches!(err, Error::Timeout(_)));
// The token's own response is still bounded: deadline + 60 s hard cap.
```

### Explicit-poke UP test (constructed example)

```rust
auth.set_up_mode(UpUvMode::RequireExplicitPoke);
let pending = tokio::spawn(client::get_assertion(/* ... */));
auth.poke_user_presence();                          // harness releases the wait
pending.await??;
```

## Knob table

| Knob | Type | Default | Effect |
|---|---|---|---|
| `up_mode` | `auto-approve` \| `always-fail` \| `require-explicit-poke` | `auto-approve` | Controls UP check and flags bit 0 |
| `uv_mode` | same modes | `auto-approve` | Controls UV check and flags bit 2 |
| `inject_status` | CTAP status code (CTAP2.1 §8.2) | none | Next matching command returns this status |
| `keepalive_sequence` | `[(status_byte, spacing), ...]` | none | Keepalive events emitted before the final response. Spacing is consumed from the caller's `Deadline` budget, not wall-clock: each event consumes its spacing from the remaining budget; exhaustion → typed `Timeout` |
| `delay_beyond_deadline` | bool / duration | off | Final response delayed past caller deadline (hard cap: deadline + 60 s; the overshoot consumes budget the same way) |
| `wrong_credential_id` | bool | off | Assertion signed under a different stored credential ID |
| `initial_sign_count` | u32 | 0 | Starting value of the global signature counter |
| `rng` | `csprng` \| `deterministic(seed)` | build-salted deterministic | Default is injectable and deterministic (seeded from a build-time salt) to keep the crate `no_std` — OS entropy requires the `std` feature. `deterministic(seed)` mode is for committed fixtures; both modes are replaceable via `RngSource` |
| `persistent_knobs` | bool | false | If false, injection knobs reset after firing once |

### clientPIN harness surface (add-client-pin, v2)

Harness-only plumbing (never client API): `set_pin(bytes)` /
`clear_pin()` arm/disarm the PIN secret; `pin_retries()` reads the
retry counter; `power_cycle()` clears the 0x34 latch without touching
the PIN or counter (the stand-in for unplug/replug);
`set_pin_protocols(list)` overrides the advertised
`pinUvAuthProtocols` (default `[2, 1]`); `set_advertise_pin_uv_auth_token(bool)`
hides the `pinUvAuthToken` option ID (models a CTAP2.0 getPinToken-only
token); `client_pin_knobs_mut()` exposes the clientPIN injection knobs:

| clientPIN knob | Type | Default | Effect |
|---|---|---|---|
| `wrong_protocol_echo` | bool | off | The key-agreement register records the OTHER protocol's selector, so the token's KDF/MAC/encrypt diverge from what the client negotiated (exercises the client's protocol-exact verification) |
| `pin_echo_decrypt` | bool | off | The token derives with a different protocol's KDF: pinHashEnc decrypt fails (0x33 PIN_AUTH_INVALID, distinguishable from a wrong PIN's 0x31) even for a correct PIN |

The generic `inject_status` knob fires on authenticatorClientPIN (0x06)
hops exactly as on getAssertion.

## authenticatorData quick reference

Layout per WebAuthn L2 §6.1 (constructed example for an assertion):

```
offset  size  field
0       32    rpIdHash = SHA-256(rpId)
32      1     flags: bit0 UP, bit2 UV, bit6 AT (0 in assertions), bit7 ED (0 in v1)
33      4     signCount, big-endian
```

makeCredential responses additionally set AT and append attested credential
data: 16-byte pinned AAGUID, 2-byte BE credential-ID length, credential ID,
COSE ES256 public key (`{1:2, 3:-7, -1:1, -2:x, -3:y}`, RFC 9052 §7 /
RFC 9053 §7.1).

## Conformance vectors

Test vectors are generated by the soft token itself, then committed:

1. Configure the token with `rng: deterministic(seed)` and a fixed
   `initial_sign_count`.
2. Run a fixed minting script: N credentials across M rpIds, then K
   assertions with fixed clientDataHash values.
3. Export the credential-store snapshot (versioned, serde-serializable) plus
   each response's CBOR bytes.
4. Commit the snapshot + expected outputs under `fixtures/transport-soft/`.

Because key generation and signing are deterministic under the seeded RNG,
re-running the script reproduces the fixtures byte-for-byte; CI asserts this
regeneration is clean. Vectors record: inputs (rpId, userHandle,
clientDataHash), authenticatorData, signature, signCount, and the COSE public
key — each labeled **constructed** (deterministically generated), never
captured from third-party authenticators, per the cleanroom rules.
