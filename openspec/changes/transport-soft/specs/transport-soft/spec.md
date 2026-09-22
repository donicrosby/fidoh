# Spec delta: transport-soft

This change ADDS the new capability `transport-soft`: an in-process virtual
CTAP2 authenticator used as the CI harness for the fidoh client library.

Normative references: FIDO CTAP 2.1 (fidoalliance.org), W3C WebAuthn Level 2,
RFC 8152 (CBOR Object Signing and Encryption), RFC 9053 (COSE algorithm
registrations).

## ADDED Requirements

### Requirement: Transport/Device trait parity

The software token SHALL implement the same `Transport` and `Device` traits
defined by the async-core change that hardware transports (CTAPHID, PC/SC)
implement, such that any client ceremony code that runs against a hardware
transport runs unmodified against the software token. It SHALL perform no
operating-system I/O and SHALL NOT depend on any async executor; all waits
SHALL be expressed via the caller-provided timer/sleep factory from
async-core.

#### Scenario: Client ceremony runs against soft token unchanged

- **WHEN** a client ceremony (getInfo probing followed by getAssertion) is
  executed against the software token through the `Device` trait
- **THEN** the ceremony completes using only trait methods, with no
  soft-token-specific code paths in the client

#### Scenario: No executor dependency

- **WHEN** the soft-token crate is compiled in a `no_std`-compatible,
  executor-free configuration
- **THEN** compilation succeeds with no tokio/async-std/smol dependency

### Requirement: authenticatorGetInfo

The software token SHALL implement `authenticatorGetInfo` per CTAP2.1 §6.4
and return a response containing: a pinned AAGUID (a fixed 16-byte value
reserved for the soft token, distinct from any production authenticator),
`versions` containing at least `FIDO_2_0` and `FIDO_2_1`, and an `options`
map with keys `rk`, `up`, and `uv`. The `uv` option value SHALL reflect the
currently configured UV behavior mode; `rk` SHALL be `true` (resident
credentials are stored); `up` SHALL be `true`.

#### Scenario: Default getInfo response

- **WHEN** the client issues authenticatorGetInfo against a default-configured
  soft token
- **THEN** the response contains the pinned AAGUID, versions list including
  exactly `FIDO_2_0` and `FIDO_2_1` (U2F_V2 excluded), and options
  `{rk: true, up: true, uv: <current UV mode capability>}`

#### Scenario: Pinned AAGUID is stable

- **WHEN** two separate soft-token instances are created with default
  configuration and each is queried with authenticatorGetInfo
- **THEN** both return the identical AAGUID value documented in
  docs/transport-soft.md

### Requirement: Internal authenticatorMakeCredential

The software token SHALL implement `authenticatorMakeCredential` per
CTAP2.1 §6.1 as an INTERNAL harness operation only: it SHALL be reachable via
a method on the concrete soft-token type and SHALL NOT be part of the
client-facing `Device`/client API surface. Each invocation SHALL mint a fresh
ES256 (ECDSA P-256) keypair, generate a new credential ID, and persist a
credential source record (WebAuthn L2 §4: type public-key, private key,
rpId, userHandle) in the credential store. The response SHALL include
attested credential data (fmt `none`, WebAuthn L2 §8.7).

#### Scenario: Minting a test credential

- **WHEN** harness code calls the internal makeCredential method with an
  rpId and user handle
- **THEN** a credential source record is stored, and the response contains
  attested credential data embedding the new credential ID and a COSE ES256
  public key

#### Scenario: Not exposed via client API

- **WHEN** the public client API surface is enumerated (traits and public
  functions of the client crate)
- **THEN** no makeCredential entry point exists

### Requirement: authenticatorGetAssertion signatures

The software token SHALL implement `authenticatorGetAssertion` per
CTAP2.1 §6.2 and produce a real ECDSA P-256 signature computed over the byte
concatenation `authenticatorData || clientDataHash` (CTAP2.1 §6.2.2 step 5;
WebAuthn L2 §6.5 "signature" generation). The signature SHALL be ASN.1 DER
encoded and SHALL verify against the public key of the credential source
selected for the assertion.

#### Scenario: Signature verifies

- **WHEN** an assertion is produced for a previously minted credential and a
  caller-supplied 32-byte clientDataHash
- **THEN** the returned signature verifies as a valid ECDSA P-256 signature
  over `authenticatorData || clientDataHash` using the credential's public key

#### Scenario: Unknown credential rejected

- **WHEN** getAssertion is called with an allowList containing only
  credential IDs not present in the store
- **THEN** the token returns `CTAP2_ERR_NO_CREDENTIALS` (0x2E, CTAP2.1 §8.2)

### Requirement: authenticatorData layout

All responses from the software token SHALL construct `authenticatorData`
exactly per WebAuthn L2 §6.5: 32-byte rpIdHash = SHA-256(rpId); one flags
byte with UP = bit 0, UV = bit 2, AT = bit 6, ED = bit 7 (all other bits
zero); a 4-byte big-endian signCount; attested credential data present ONLY
in makeCredential responses (AT set); extension data present only when ED is
set (the soft token emits no extensions in v1, so ED SHALL always be 0).

#### Scenario: Assertion authenticatorData

- **WHEN** an assertion authenticatorData blob is parsed
- **THEN** bytes 0–31 equal SHA-256 of the rpId, bit 0 of the flags byte
  reflects the UP outcome, bit 2 reflects the UV outcome, bit 6 (AT) is 0,
  bit 7 (ED) is 0, and bytes 33–36 are the signCount in big-endian order,
  with no trailing bytes

#### Scenario: makeCredential authenticatorData includes attested credential data

- **WHEN** a makeCredential authenticatorData blob is parsed
- **THEN** flag bit 6 (AT) is set and, immediately after the signCount, the
  attested credential data contains the pinned AAGUID, a 2-byte big-endian
  credential ID length, the credential ID, and the COSE-encoded public key

### Requirement: COSE ES256 public key encoding

Credential source records and attested credential data SHALL encode the
public key as a COSE_Key per RFC 8152 §8 with parameters per RFC 9053 §7.1:
`kty` (1) = 2 (EC2), `alg` (3) = −7 (ES256), `crv` (−1) = 1 (P-256),
`x` (−2) = 32-byte x coordinate, `y` (−3) = 32-byte y coordinate. No other
COSE key parameters SHALL be emitted.

#### Scenario: COSE key round-trips

- **WHEN** the COSE public key from a minted credential is CBOR-decoded
- **THEN** it contains exactly the labels {1: 2, 3: −7, −1: 1, −2: x, −3: y}
  with x and y each 32 bytes, and the key reconstructs the credential's
  P-256 public key

### Requirement: Signature counter

The software token SHALL maintain a global signature counter (per the
authenticator model in CTAP2.1 §6.1.2 and WebAuthn L2 §6.5 signCount
semantics) initialized to a configurable value (default 0) and SHALL
increment it by exactly 1 on each successful makeCredential and each
successful getAssertion.

#### Scenario: Counter increments

- **WHEN** two assertions are produced in sequence
- **THEN** the second assertion's signCount equals the first assertion's
  signCount plus one

### Requirement: UP/UV behavior modes

The software token SHALL support three configurable behavior modes for user
presence (UP) and user verification (UV): `auto-approve` (requirement
satisfied immediately), `always-fail` (command fails with
`CTAP2_ERR_OPERATION_DENIED`, 0x27), and `require-explicit-poke` (command
pends until harness code calls the poke method). The default for both UP and
UV SHALL be `auto-approve`. In `require-explicit-poke` mode the pending wait
SHALL be bounded solely by the caller's ceremony deadline; if the deadline
expires before a poke, the wait SHALL terminate and the command SHALL fail
with a typed timeout. The flags byte SHALL reflect the actual UP/UV outcome
of each command.

#### Scenario: Auto-approve sets flags

- **WHEN** getAssertion runs with UP and UV both in auto-approve mode
- **THEN** the command succeeds and the flags byte has bits 0 (UP) and 2 (UV)
  set

#### Scenario: Always-fail rejects the command

- **WHEN** getAssertion runs with UP in always-fail mode
- **THEN** the command returns `CTAP2_ERR_OPERATION_DENIED` and no signature
  is produced and the signCount does not increment

#### Scenario: Explicit poke completes the ceremony

- **WHEN** getAssertion runs with UP in require-explicit-poke mode and
  harness code calls poke within the ceremony deadline
- **THEN** the command succeeds with the UP flag set

#### Scenario: Poke wait hits the ceremony deadline

- **WHEN** getAssertion runs with UP in require-explicit-poke mode and no
  poke arrives before the caller-provided ceremony deadline expires
- **THEN** the pending wait terminates at the deadline and the command fails
  with a typed timeout error; the wait is bounded by the caller deadline and
  by no other timer

### Requirement: Error injection knobs

The software token SHALL expose configuration knobs that apply to the next
command (or a configured command type): (a) return an arbitrary CTAP status
code (CTAP2.1 §8.2 values) instead of a normal response; (b) emit a
configurable sequence of keepalive events (each carrying a status byte) with
configurable inter-event spacing before the final response; (c) delay the
final response beyond the caller-provided deadline, bounded by a hard cap of
deadline + 60 seconds; (d) return a validly signed assertion for a
credential ID different from the requested one (wrong-credential-id), to
test client-side credential ID verification. Knobs SHALL reset after firing
unless configured as persistent.

#### Scenario: Arbitrary status code injection

- **WHEN** the token is configured to return `CTAP2_ERR_INVALID_CBOR` (0x12)
  for the next getAssertion and the client issues getAssertion
- **THEN** the client observes exactly that status code and maps it to its
  typed error

#### Scenario: Keepalive sequence before response

- **WHEN** the token is configured to emit three keepalive events (status
  `UP_NEEDED`, 0x02) at 50 ms spacing before a successful getAssertion
  response
- **THEN** the client receives exactly three keepalive events at the
  configured spacing followed by the successful response, and the whole
  exchange completes within the caller's ceremony deadline

#### Scenario: Delay beyond deadline triggers client timeout

- **WHEN** the token is configured with a response delay exceeding the
  caller-provided ceremony deadline and the client issues getAssertion
- **THEN** the client-side wait terminates at the deadline with the typed
  timeout error, and the token's own delayed response is delivered no later
  than deadline + 60 s (bounded wait, no unbounded sleep)

#### Scenario: Wrong credential ID response

- **WHEN** the wrong-credential-id knob is armed and the client issues
  getAssertion for a stored credential
- **THEN** the assertion carries a different credential ID than requested
  while remaining a valid signature by the store's credentials, so client
  credential-matching logic is exercised

### Requirement: Credential store

The software token SHALL store credential source records in memory with
lookup by credential ID and enumeration by rpId. It SHALL additionally
support an optional serde-serializable snapshot: the full store (including
private keys) SHALL be exportable to and importable from a versioned
serializable structure so test fixtures can be committed and replayed
deterministically. Snapshots are test-harness artifacts and SHALL NOT be part
of the client-facing API.

#### Scenario: Snapshot round-trip

- **WHEN** a store containing minted credentials is exported to a snapshot,
  imported into a fresh soft-token instance, and an assertion is requested
  for one of the credentials
- **THEN** the fresh instance produces a valid assertion under the same
  credential ID

#### Scenario: Deterministic fixtures

- **WHEN** a snapshot is exported with the deterministic (fixture-only)
  randomness source configured
- **THEN** re-running the same minting sequence produces a byte-identical
  snapshot, enabling committed conformance vectors
