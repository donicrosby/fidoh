# async-core Specification

## MODIFIED Requirements

### Requirement: Transport trait for device discovery and connection

The system SHALL define a `Transport` trait in `fidoh-core` exposing
device enumeration and connection. `Transport` SHALL provide an
`enumerate` operation returning a list of discovered candidate devices
(with identifiers and human-readable metadata) and a `connect`
operation taking a device identifier and a `Sleep` factory, returning a
connected `Device`. Since the add-client-pin change (v2) `Transport`
SHALL also expose a `kind()` operation returning the implementation's
`TransportKind` (`Hid`, `Pcsc`, or `Soft`), with a default answer of
`Soft` so existing external implementations remain source-compatible;
the in-tree hardware transports SHALL override it. Discovery of
multiple candidates SHALL NOT trigger implicit selection; selection
policy (`First | Select(fn) | Fail`, default `Fail`) is applied by the
caller, and ambiguity SHALL surface as a typed `AmbiguousDevice` error
listing candidates. `Transport` and `Device` MAY be generic
(non-object-safe) in v1; object safety is required only for `Sleep`.

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

#### Scenario: Kind reports the transport layer

- **WHEN** a caller invokes `kind()` on each in-tree transport
- **THEN** the HID transport answers `Hid`, the PC/SC transport
  answers `Pcsc`, and the soft transport answers `Soft`; an external
  implementor that does not override the method receives the `Soft`
  default without breaking compilation
