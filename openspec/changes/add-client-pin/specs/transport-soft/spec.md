# transport-soft Specification

# transport-soft Specification (delta)

A software CTAP2 authenticator running the same
[`Transport`](#)/[`Device`](#) traits as the hardware transports: the
CI harness for client ceremony code. Since the add-client-pin change
(v2) the token models the authenticator side of the CTAP2.1 §6.5.5
clientPIN flow — PIN state, retry counters, key agreement, and
encrypted pinUvAuthToken issuance — so the full acquisition path is
provable in CI without hardware, under the same error-injection
discipline as the rest of the harness.

## MODIFIED Requirements

### Requirement: authenticatorGetInfo

The soft token's authenticatorGetInfo response SHALL report a pinned
16-byte AAGUID, versions `["FIDO_2_0", "FIDO_2_1"]`, options
`up: true`, `rk: true`, `uv: <uv-capable>` — and, since v2, the
clientPIN feature set under harness configuration: `clientPin: true`
when a clientPIN is modeled, `pinUvAuthToken: true` when the §6.5.5.7.2
subcommand is modeled, `pinUvAuthProtocols: [2, 1]` by default (the
authenticator's decreasing preference order, CTAP2.1 §6.4), with
`forcePINChange` and `minPINLength` available as optional harness
configuration. Defaults keep v1 behavior unchanged: no clientPIN
members unless the harness configures the PIN feature, so every
pre-existing scenario continues to hold byte-for-byte.

#### Scenario: Info advertises the clientPIN feature set when configured

- **WHEN** the soft token is constructed with the clientPIN feature
  configured (PIN set, protocols [2, 1], pinUvAuthToken enabled)
- **THEN** the getInfo response carries option IDs `clientPin: true`,
  `pinUvAuthToken: true`, and `pinUvAuthProtocols: [2, 1]` alongside
  the pinned AAGUID and the v1 members

#### Scenario: Default configuration unchanged from v1

- **WHEN** a soft token is constructed with the default configuration
  and probed
- **THEN** the getInfo response carries NO clientPin or
  pinUvAuthProtocols members — byte-identical to the v1 response shape

## ADDED Requirements

### Requirement: clientPIN state machine

The soft token SHALL model the authenticator side of
authenticatorClientPIN (CTAP2.1 §6.5.5): a PIN secret (stored as
LEFT(SHA-256(PIN), 16), set/cleared through harness-only plumbing —
never client API), a retry counter (default 8, reset to maximum on
successful PIN verification), a consecutive-mismatch counter, a
per-protocol key-agreement register, and a per-protocol pinUvAuthToken
register. It SHALL answer subCommands: getPINRetries (0x01) returning
`pinRetries`; getKeyAgreement (0x02) returning its public keyAgreement
COSE_Key for the requested protocol; getPinToken (0x05) and
getPinUvAuthTokenUsingPinWithPermissions (0x09, honoring the `ga`
permission and permissions rpId) performing, in the CTAP2.1 §6.5.5.7.2
order: protocol support check (unsupported → 0x02
CTAP1_ERR_INVALID_PARAMETER), zero-retry check (0x32
CTAP2_ERR_PIN_BLOCKED), decapsulate the platform key, verify the
protocol-exact pinUvAuthParam MAC, DECREMENT the retry counter,
decrypt pinHashEnc and compare against the stored PIN hash (mismatch →
0x31 CTAP2_ERR_PIN_INVALID with the `pinRetries` member;
three consecutive mismatches → 0x34 CTAP2_ERR_PIN_AUTH_BLOCKED), reset
retries on success, mint a fresh 32-byte token (protocol 2; protocol 1
uses 32 of its allowed 16/32 lengths), and return
`encrypt(sharedSecret, token)`. Key agreement and encryption SHALL use
the SAME RustCrypto primitives as the client (real ECDH, real
AES-256-CBC, real HMAC-SHA-256 with protocol-exact output lengths) —
no stubbed crypto on either side. Cryptographic plumbing (PIN set,
platform keys, shared secrets) stays harness-internal and SHALL NOT
become client API.

#### Scenario: getKeyAgreement returns a real P-256 key per protocol

- **WHEN** the client sends subCommand 0x02 under protocol 1 and again
  under protocol 2
- **THEN** both responses carry decodable keyAgreement COSE_Keys
  ({1: 2, 3: -25, -1: 1, -2, -3}), each encapsulates successfully, and
  the two shared secrets derive independently per protocol KDF

#### Scenario: Wrong PIN decrements the counter once and reports it

- **WHEN** the client sends subCommand 0x09 with a pinHashEnc of the
  wrong PIN against a token whose counter reads 8
- **THEN** the token answers 0x31 with `pinRetries: 7`, the stored
  counter reads 7, and the mismatch counter reads 1

#### Scenario: Correct PIN after failures resets counters and yields a usable token

- **WHEN** a wrong-PIN attempt is followed by a correct-PIN subCommand
  0x09
- **THEN** the token answers 0x00 with the encrypted pinUvAuthToken,
  the retry counter is reset to maximum, and the client's
  getAssertion using the decrypted token succeeds with the UV flag set

#### Scenario: Unsupported protocol echo rejected per spec

- **WHEN** the client sends subCommand 0x02 naming a protocol absent
  from the token's advertised pinUvAuthProtocols
- **THEN** the token answers 0x02 CTAP1_ERR_INVALID_PARAMETER
  (CTAP2.1 §6.5.5.4) and no key-agreement state changes

#### Scenario: Zero retries answers PIN blocked

- **WHEN** the retry counter is 0 and any PIN-bearing subCommand
  arrives
- **THEN** the token answers 0x32 CTAP2_ERR_PIN_BLOCKED without
  touching the key-agreement register

#### Scenario: Three consecutive mismatches answers PIN auth blocked

- **WHEN** three consecutive PIN-bearing subCommands mismatch and a
  fourth arrives with a correct PIN
- **THEN** the third mismatch answers 0x31 (counter 5 from 8) and the
  fourth answers 0x34 CTAP2_ERR_PIN_AUTH_BLOCKED (power-cycle state),
  even though the PIN was correct

### Requirement: clientPIN error injection

The soft token SHALL expose clientPIN-directed injection knobs under
the existing one-shot/persistent discipline: the generic status knob
SHALL fire on authenticatorClientPIN hops exactly as on getAssertion;
a `wrong-protocol` knob SHALL force the token to accept a client
handshake under a protocol it did not advertise (so the CLIENT's
protocol verification — KDF choice and MAC length — is exercised
against a deviant peer); and a `pin-echo-decrypt` knob SHALL make the
token decrypt pinHashEnc with a DIFFERENT key than the correctly
derived shared secret (so the client's own decapsulate/derive path is
proven, not just the token's).

#### Scenario: Status knob fires on a clientPIN hop

- **WHEN** the one-shot status knob is armed with 0x2F and the client
  starts the acquisition flow
- **THEN** the getKeyAgreement hop receives 0x2F and the ceremony maps
  it typed (UserActionTimeout) without any getAssertion exchange

#### Scenario: Deviant protocol peer exercises client verification

- **WHEN** the wrong-protocol knob is armed, the client pins protocol
  1 while the token advertises only protocol 2, and the caller forces
  the handshake through
- **THEN** the client-side flow fails typed citing the protocol
  mismatch (CTAP2.1 §6.5.5) rather than producing a garbage MAC

#### Scenario: Shared-secret mismatch knob proves the client derives independently

- **WHEN** the pin-echo-decrypt knob is armed and the client completes
  the token request
- **THEN** the token's decrypt of pinHashEnc fails (it holds a
  different key), the client observes the authenticator-side 0x31/0x33
  failure typed, and the failure cannot be confused with a wrong PIN
