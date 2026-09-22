# async-core Specification

## ADDED Requirements

### Requirement: Transport trait for device discovery and connection

The system SHALL define a `Transport` trait in `fidoh-core` exposing
device enumeration and connection. `Transport` SHALL provide an
`enumerate` operation returning a list of discovered candidate devices
(with identifiers and human-readable metadata) and a `connect`
operation taking a device identifier and a `Sleep` factory, returning a
connected `Device`. Discovery of multiple candidates SHALL NOT trigger
implicit selection; selection policy (`First | Select(fn) | Fail`,
default `Fail`) is applied by the caller, and ambiguity SHALL surface
as a typed `AmbiguousDevice` error listing candidates. `Transport` and
`Device` MAY be generic (non-object-safe) in v1; object safety is
required only for `Sleep`.

#### Scenario: Enumerate devices with zero or more candidates

- **WHEN** a caller invokes `Transport::enumerate` on any transport
  (hid, pcsc, or soft)
- **THEN** the operation returns within the caller-supplied deadline
  and yields either a (possibly empty) list of `DeviceInfo` records or
  a typed error; it never blocks unboundedly, and on deadline expiry it
  returns `Error::Timeout` naming the enumeration phase

#### Scenario: Ambiguous device selection fails loudly

- **WHEN** enumeration yields more than one candidate and the caller's
  selection policy is the default `Fail`
- **THEN** `connect` is never called implicitly and the caller receives
  a typed `AmbiguousDevice` error containing every candidate's
  identifier and metadata

#### Scenario: Connect with deadline

- **WHEN** a caller invokes `Transport::connect` with a valid device id
  and a deadline
- **THEN** the operation either returns a connected `Device` within the
  deadline or returns `Error::Timeout`; a dropped connect future SHALL
  leave the underlying authenticator usable by a subsequent `connect`

### Requirement: Device trait for CTAP command exchange and channel lifecycle

The system SHALL define a `Device` trait in `fidoh-core` exposing:
sending a CTAP command and receiving its response, opening a channel
(CTAPHID INIT negotiation per CTAP2.1 §8.1.4 for HID; APDU SELECT of
the FIDO application per CTAP2.1 §11 for PC/SC), and closing the
device. Every `Device` operation SHALL accept a deadline derived from
the ceremony budget and SHALL return a typed error on failure.
CTAPHID keepalive statuses (0xBB UPNEEDED per CTAP2.1 §8.1.5.1) SHALL
be handled inside the transport and surfaced to the caller as progress
signals, not errors, until the deadline expires.

#### Scenario: Send command and receive response within deadline

- **WHEN** a caller sends a CTAP command (e.g. authenticatorGetInfo,
  CTAP2.1 §8.4) to a connected device with a deadline
- **THEN** the transport returns the parsed response or a typed error
  before the deadline; keepalive waits are bounded by the remaining
  budget and expiry returns `Error::Timeout` naming the command phase

#### Scenario: Channel open negotiation

- **WHEN** a caller opens a channel on an HID transport
- **THEN** the transport performs CTAPHID INIT (CTAP2.1 §8.1.4) within
  the remaining ceremony budget and returns a channel identifier, or
  returns `Error::Timeout` on expiry

#### Scenario: Close releases the device

- **WHEN** a caller closes a device or drops the device future
- **THEN** the channel is released or abandoned per CTAP2.1 §8.1.4
  channel lifetime rules and a subsequent `connect` to the same
  authenticator succeeds (worst case after one INIT re-handshake)

### Requirement: Ceremony trait for orchestration entry

The system SHALL define a `Ceremony` trait in `fidoh-core` as the
single orchestration entry point. A ceremony consumes a connected
`Device`, a `Sleep` factory, and a single deadline budget, and returns
a typed output: for authenticatorGetAssertion (CTAP2.1 §8.2) the raw
assertion (authenticatorData, signature, userHandle, credential id);
for authenticatorGetInfo (CTAP2.1 §8.4) the parsed info structure. The
library SHALL NOT construct `clientDataJSON` or apply origin semantics;
the caller supplies a `clientDataHash` (WebAuthn L2 §6.5 is the RP's
responsibility).

#### Scenario: GetAssertion ceremony completes within budget

- **WHEN** a caller runs a getAssertion ceremony against the soft
  transport with a sufficient budget
- **THEN** the ceremony returns authenticatorData, signature,
  userHandle, and credential id, with every internal wait driven
  through the `Sleep` factory and bounded by the budget

#### Scenario: Ceremony expires during user-presence wait

- **WHEN** the authenticator signals UPNEEDED keepalives (CTAP2.1
  §8.1.5.1) and the budget expires before user presence
- **THEN** the ceremony returns `Error::Timeout` naming the
  user-presence phase, and the device remains usable for a subsequent
  ceremony

### Requirement: Sleep trait as the sole waiting mechanism

The system SHALL define a `Sleep` trait in `fidoh-core` — a
caller-provided factory producing a future that completes after a given
duration. `Sleep` SHALL be object-safe so it can cross crate boundaries
as `&dyn Sleep`. No core or transport crate SHALL invoke
`std::thread::sleep` or any executor-native timer directly; every wait
(sleep, keepalive poll slice, NFC field poll, APDU retry) SHALL go
through `Sleep`. An unbounded wait is a spec violation.

#### Scenario: Runtime adapter supplies Sleep

- **WHEN** a tokio-based caller constructs the `fidoh-tokio` adapter
  and passes its `Sleep` implementation into a ceremony
- **THEN** every timed wait inside the ceremony and transports resolves
  via the caller-supplied factory, and the core crate compiles with no
  tokio dependency

#### Scenario: Deterministic test clock

- **WHEN** the CI harness supplies a fake `Sleep` whose clock advances
  only under test control
- **THEN** ceremony and transport tests complete deterministically with
  zero real-time sleeps

### Requirement: Crate graph with dependencies only toward fidoh-core

The workspace SHALL comprise `fidoh-core` (traits, CTAP model types,
ceremony orchestration; no runtime, no OS dependencies beyond
`alloc`/`core`), `fidoh-transport-hid` (CTAPHID per CTAP2.1 §8.1),
`fidoh-transport-pcsc` (ISO 7816-4 APDU layer shared by FIDO-over-CCID
and NFC/ISO 14443 per CTAP2.1 §11), `fidoh-transport-soft` (in-process
virtual authenticator, the CI harness), `fidoh-tokio` (`Sleep`
implementation plus `spawn_blocking` adapter), and optional
`fidoh-cli-ui`. Dependency arrows SHALL point only toward `fidoh-core`:
transport crates and `fidoh-tokio` depend on `fidoh-core` and never on
each other; `fidoh-cli-ui` MAY depend on `fidoh-core` and `fidoh-tokio`
and SHALL NOT be depended on by any library crate; only `fidoh-tokio`
SHALL name tokio as a dependency.

#### Scenario: Dependency audit

- **WHEN** a dependency-graph audit runs over the workspace
- **THEN** no edge exists between transport crates, no edge exists from
  any transport crate to `fidoh-tokio`, and `fidoh-core`'s dependency
  set contains no runtime or OS-platform crates

#### Scenario: Soft transport builds standalone

- **WHEN** the workspace is built with default features only
- **THEN** the build includes `fidoh-core` and `fidoh-transport-soft`,
  requires no OS device APIs, and the CI harness can run a full
  getAssertion ceremony in-process

### Requirement: Blocking-syscall transport policy with spawn_blocking adapter

Transport crates MAY use blocking syscalls internally (Linux hidraw
`read`/`write`; PC/SC API calls). The `fidoh-tokio` adapter SHALL wrap
blocking transport operations in `spawn_blocking` so async callers are
never blocked on the executor's worker threads. Each blocking operation
SHALL carry a deadline-driven abort path so a detached (dropped-future)
blocking thread exits within the operation's timeout bound: at most the
remaining ceremony budget, with CTAPHID reads re-sliced at a bounded
interval (default 30 s) and NFC field polls sliced at most 1 s. A
fully-async I/O policy (e.g. `async-io`) is explicitly out of scope for
v1.

#### Scenario: Blocking HID read does not stall the executor

- **WHEN** a tokio caller runs a ceremony that reaches a hidraw `read`
  awaiting user presence
- **THEN** the read executes on the blocking pool via `spawn_blocking`,
  executor worker threads remain unblocked, and the wait is bounded by
  the remaining ceremony budget (default 30 s per read slice)

#### Scenario: Dropped future detaches from blocking thread

- **WHEN** a caller drops the ceremony future while a blocking read is
  in flight
- **THEN** the blocking thread exits within its current wait slice
  bounded by the remaining budget (at most the per-slice bound of 30 s
  for HID, 1 s for NFC polls), and a subsequent `connect` to the same
  authenticator succeeds

### Requirement: Single-budget timeout model with safe cancellation

Every ceremony SHALL be driven by one caller-supplied deadline budget
passed at ceremony start; individual hops (INIT, command exchange,
user-presence wait, NFC poll) SHALL consume the remaining budget rather
than independent per-hop timeouts. Expiry at any hop SHALL return a
typed `Error::Timeout` naming the ceremony phase. Cancellation by
dropping any ceremony or device future SHALL be safe: it SHALL NOT
leave shared state poisoned, and the affected authenticator SHALL be
usable by a subsequent ceremony (worst case after one channel
re-handshake per CTAP2.1 §8.1.4).

#### Scenario: Remaining budget propagates across hops

- **WHEN** a ceremony with a 60 s budget spends 5 s on INIT and 10 s on
  authenticatorGetInfo
- **THEN** the subsequent getAssertion hop receives a 45 s remaining
  budget, and expiry returns `Error::Timeout` naming the getAssertion
  phase

#### Scenario: Drop mid-user-presence is safe

- **WHEN** a caller drops the ceremony future while the authenticator
  is emitting UPNEEDED keepalives
- **THEN** no panic or poisoned lock occurs, the transport's in-flight
  wait terminates within its current `Sleep`-driven slice (bounded by
  the remaining budget), and a new ceremony on the same device can
  start cleanly

### Requirement: Feature-flag layout with soft transport as default

The workspace SHALL use a feature layout where default features enable
ONLY the software transport (`default = ["soft"]`). Features `hid`,
`pcsc`, and `tokio` SHALL be opt-in and SHALL enable
`fidoh-transport-hid`, `fidoh-transport-pcsc`, and `fidoh-tokio`
respectively. No feature flag SHALL add a dependency to `fidoh-core`.

#### Scenario: Default build is OS-dependency-free

- **WHEN** the workspace is built with `--no-default-features` implied
  defaults (i.e. plain `cargo build` with default features)
- **THEN** only the soft transport is compiled, no hidraw or PC/SC
  system libraries are required, and the CI ceremony harness runs

#### Scenario: Opt-in hardware features compose

- **WHEN** the workspace is built with `--features hid,pcsc,tokio`
- **THEN** the HID and PC/SC transports and the tokio adapter are
  compiled, each depending only on `fidoh-core`, and `fidoh-core`'s own
  dependency set is unchanged from the default build
