# transport-pcsc Specification

ISO 7816-4 APDU transport over PC/SC (`fidoh-transport-pcsc`): reader
enumeration, FIDO applet selection, CTAP command exchange, NFC
(ISO 14443) field handling, and the typed error mapping from PC/SC
return codes and ISO 7816 status words onto the async-core/ceremony
error taxonomy. One APDU layer serves both FIDO-over-CCID (CTAP 2.x
over ISO 7816 APDUs on the USB CCID interface; Yubico documents this
for YubiKey firmware 5.8+) and NFC (CTAP2.1 §11.3, ISO 14443 with
T=CL). Sharing decisions (async-core D3: PC/SC is a blocking C API
wrapped by `fidoh-tokio`'s `spawn_blocking`), the timeout model
(async-core D4 single budget), and CTAP status-code semantics
(core-model's CTAP2.1 §8.2 table) are owned by the sibling specs and
referenced, not restated.

## ADDED Requirements

### Requirement: Unified APDU layer over CCID and NFC transports

The PC/SC transport SHALL implement ONE APDU-layer engine used
unchanged by both the USB CCID interface (CTAP 2.x over ISO 7816 APDUs
as carried by the PC/SC smart card stack) and the NFC interface
(ISO 14443 with T=CL, CTAP2.1 §11.3: SELECT AID followed by CTAP
command APDUs). Interface selection (CCID vs NFC) SHALL be a property
of the reader/card the PC/SC resource manager reports, not a separate
code path: protocol-relevant behavior (T=CL block handling, field
presence) is layered UNDER the APDU engine and maps onto the same
operations and errors. No transport behavior MAY branch on the
interface type except where this spec states NFC-specific handling.

#### Scenario: Same CTAP exchange code drives CCID and NFC readers

- **WHEN** the APDU-layer engine runs a SELECT + getInfo + getAssertion
  sequence against (a) a YubiKey 5 with firmware ≥ 5.8 over USB CCID
  and (b) the same class of key over an NFC reader (T=CL), each within
  a sufficient ceremony budget
- **THEN** both sequences use the identical APDU framing, SELECT, and
  status-word handling specified by this capability, differing only in
  the NFC-specific behaviors this spec names (field presence, WTX
  handling, 0x9100 status-update loop)

#### Scenario: No interface-specific second implementation

- **WHEN** the transport crate's public surface is reviewed
- **THEN** CCID and NFC appear as connection properties of one
  transport (reader/connection metadata reports the interface), and no
  separate NFC-only or CCID-only command framing exists (CTAP2.1 §11.3
  defines one APDU framing for both)

### Requirement: Reader enumeration and connection via the PC/SC resource manager

The transport SHALL enumerate readers through the PC/SC resource
manager (`SCardListReaders` per PC/SC Core Specification Part 3;
pcsd-lite/pcscd on Linux exposes the resource manager the CCID stack
requires) and SHALL report a `DeviceInfo` per reader with a
connection-capable state. `connect` SHALL open the reader with
`SCardConnect` and a `Sleep` factory per async-core. Sharing mode: for
NFC/T=CL connections the transport SHALL use SHARED mode — exclusive
mode on a contactless reader would lock other hosts' access to the
same reader for the whole ceremony. For CCID/USB the transport SHALL
ALSO connect SHARED by default: the PC/SC resource manager serializes
transactions per reader anyway, and other PC/SC clients (PIV, OATH
applets on the same YubiKey) must not be locked out of the composite
USB device for a ceremony's duration. If the platform returns a
sharing violation on SHARED connect, the transport SHALL retry the
connect (bounded, see the timeout requirement) and SHALL NOT escalate
to EXCLUSIVE automatically; exclusive mode is available to the caller
as an explicit opt-in only.

Card-present detection: the transport SHALL treat a reader as a
candidate only when the resource manager reports a card present and
usable at connect time (`SCARD_STATE_PRESENT`, absent
`SCARD_STATE_MUTE`); a reader whose card disappears between
enumeration and connect yields a typed `Transport` error recorded for
that reader, not a discovery abort (ceremony D2 collect-never-
short-circuit).

#### Scenario: Readers enumerated through SCardListReaders

- **WHEN** a host has pcscd running with two attached readers and the
  caller invokes `Transport::enumerate` with a non-expired budget
- **THEN** enumeration returns one `DeviceInfo` per reader reported by
  `SCardListReaders`, each carrying reader name and connection state,
  within the remaining ceremony budget

#### Scenario: No resource manager running

- **WHEN** pcscd is not running so `SCardEstablishContext`/
  `SCardListReaders` fails (e.g. `SCARD_E_NO_SERVICE`, 0x8010001D)
- **THEN** enumerate returns the typed `Transport` error naming the
  resource-manager cause; discovery collects it per ceremony D2 and
  continues with other transports

#### Scenario: Shared connect used by default on both interfaces

- **WHEN** the transport connects to a CCID/USB YubiKey and to an
  NFC/T=CL reader, in the default configuration
- **THEN** both connections are opened SHARED; the CCID connection
  remains usable concurrently by other PC/SC applications (e.g. an
  OATH applet client on the same key)

#### Scenario: Exclusive mode is explicit caller opt-in

- **WHEN** a caller requests EXCLUSIVE connect mode for a CCID reader
- **THEN** the transport opens the connection exclusive and a sharing
  conflict with another application surfaces as the typed sharing
  error of the error-mapping table; the transport never escalates
  shared→exclusive on its own

#### Scenario: Card vanishes between enumerate and connect

- **WHEN** a reader listed a card at enumerate time but the card is
  absent when `connect` runs, within the remaining budget
- **THEN** connect fails with the typed card-absent `Transport` error
  recorded against that reader, and discovery of other readers
  continues (ceremony D2)

### Requirement: FIDO applet selection and capability gating per CTAP2.1 §11.3.3

Before any other command the transport SHALL send the ISO 7816-4
SELECT (INS 0xA4, P1 0x04) with the FIDO AID `A0000006472F0001`
(rid `A000000647`, pix `2F0001`, CTAP2.1 §11.3.3) and SHALL evaluate
the status word:

- `9000` — applet selected; the response data carries the version
  string per §11.3.3 (`U2F_V2` when CTAP1/U2F is implemented,
  `FIDO_2_0` when only CTAP2 is). A `U2F_V2` answer does NOT settle
  CTAP2 capability: per §11.3.3, CTAP2-aware clients then issue
  authenticatorGetInfo; the mandatory getInfo probe (ceremony D3) is
  that determination, so the transport proceeds.
- `6A82` (file/applet not found, ISO 7816-4) — the card/reader pair
  does not expose the FIDO applet on this interface. The transport
  SHALL report a TYPED skip (device not FIDO-capable on this
  interface, carrying the status word) that discovery records against
  the reader and continues past — per the ceremony's
  collect-never-short-circuit rule this is a per-device negative
  result, not an error that fails enumeration or discovery.
- `6985` (conditions of use not satisfied) — e.g. applet disabled
  (CTAP1/U2F disabled state on some authenticators): TYPED skip with
  the status word, same enumerate-and-skip handling as `6A82`.
- `62xx` warnings — `6283` (selected file invalidated): TYPED skip
  (applet present but unusable, permanent for this power cycle);
  other `62xx` warnings received on SELECT surface as typed
  `Transport` errors with the status word attached (the transport
  does not guess at semantics ISO 7816-4 leaves implementation
  specific).
- Any other status word — typed `Transport` error carrying the raw
  SW, recorded per ceremony D2.

#### Scenario: Non-FIDO card yields typed skip, discovery continues

- **WHEN** SELECT on a reader returns `6A82` (applet not found,
  CTAP2.1 §11.3.3 semantics; ISO 7816-4 file-not-found)
- **THEN** the transport returns a typed not-FIDO-capable skip for
  that reader carrying status word 0x6A82, discovery records it and
  proceeds to other readers, and no discovery-level or ceremony-level
  error results from this reader alone

#### Scenario: Disabled applet conditions map to typed skip

- **WHEN** SELECT returns `6985` (conditions of use not satisfied) or
  `6283` (selected file invalidated)
- **THEN** the transport reports the corresponding typed skip carrying
  the status word, and the reader is excluded from candidates for this
  ceremony without failing discovery

#### Scenario: Successful select on a CTAP1+CTAP2 device proceeds to getInfo

- **WHEN** SELECT returns `9000` with data `U2F_V2` (per §11.3.3 the
  mandated version string when both protocols are implemented)
- **THEN** the transport treats the device as a candidate (CTAP2
  capability undecided), and the subsequent mandatory
  authenticatorGetInfo probe (ceremony D3, CTAP2.1 §6.4/§11.3.3)
  decides CTAP2 capability within the same budget

#### Scenario: Unexpected select status word is typed

- **WHEN** SELECT returns a status word other than 9000, 6A82, 6985,
  or 62xx (e.g. 6D00, instruction not supported)
- **THEN** the transport returns a typed `Transport` error carrying
  the raw status word; discovery collects it per ceremony D2

### Requirement: CTAP command APDU framing per CTAP2.1 §11.3.5

Every CTAP command SHALL be carried in the APDU frame of CTAP2.1
§11.3.5.1: CLA `0x80`, INS `0x10` (NFCCTAP_MSG), P1 `0x00`, P2 `0x00`,
command-data = CTAP command byte || canonical CBOR payload
(core-model, CTAP2.1 §8), Le. Extended length: the spec's
authenticators MUST accept short and extended length (§11.3.5), so the
transport SHALL prefer extended-length encoding when a request exceeds
255 data bytes or a response may exceed 256, and SHALL use short-form
APDU chaining (CLA `0x90` chaining per §11.3.6) only as the
short-length fallback. P1 bit `0x80` (client supports
NFCCTAP_GETRESPONSE, §11.3.7.1) SHALL be set so status-update responses
are legal. The success response (§11.3.5.2) carries SW `9000` with data
= CTAP status byte || response CBOR; the CTAP status byte is mapped
exactly per core-model's CTAP2.1 §8.2 table (this transport never
re-interprets status bytes).

Response chaining: a response SW of `61xx` (more data available) SHALL
be followed by GET RESPONSE (INS `0xC0`, ISO 7816-4) until the full
response is assembled, and `6Cxx` (wrong Le) SHALL be retried once with
Le = xx — both bounded by the same remaining ceremony budget as the
parent exchange.

Status updates: SW `9100` (§11.3.5.2) SHALL trigger the immediate
NFCCTAP_GETRESPONSE (INS `0x11`, §11.3.7.2) loop; each iteration is a
bounded wait under the timeout requirement below.

#### Scenario: getInfo rides the §11.3.5 frame

- **WHEN** the transport sends authenticatorGetInfo (CTAP command byte
  0x04, empty CBOR map payload) to a connected FIDO device
- **THEN** the APDU on the wire is CLA 0x80, INS 0x10, P1 0x00 (with
  bit 0x80 set per §11.3.7.1), P2 0x00, Lc 1, data 0x04, Le 00, and a
  `9000` response is parsed as CTAP status byte || CBOR with the
  status byte mapped via core-model's §8.2 table

#### Scenario: Long request uses extended length

- **WHEN** a getAssertion request with a full allowList encodes to more
  than 255 bytes of command data
- **THEN** the transport emits the command as an extended-length APDU
  (§11.3.5: authenticators MUST support both encodings) rather than
  fragmenting, and falls back to short-APDU chaining (§11.3.6) only if
  the reader rejects extended length with a typed error

#### Scenario: 61xx response chains via GET RESPONSE

- **WHEN** a command response arrives with SW `61 05` (five response
  bytes remain, ISO 7816-4)
- **THEN** the transport issues GET RESPONSE (INS 0xC0) to collect the
  remainder within the same remaining budget, and assembles status
  byte || CBOR before core-model decoding; budget expiry during any
  GET RESPONSE hop is typed `Timeout` naming the exchange phase

#### Scenario: 9100 status update triggers NFCCTAP_GETRESPONSE

- **WHEN** an NFC command returns SW `9100` (status update, §11.3.5.2)
- **THEN** the transport immediately issues NFCCTAP_GETRESPONSE
  (INS 0x11, §11.3.7.2), looping while `9100` recurs, with every loop
  iteration bounded by the remaining ceremony budget and final
  completion on `9000` or an error SW mapped through the error table

### Requirement: NFC field handling and T=CL specifics

On NFC/T=CL connections (ISO 14443): the transport SHALL treat field
loss / card removal at any point of an open ceremony as a typed
`Transport` error carrying the `removed` cause — a ceremony cannot
continue across a lost field, and the error is terminal for that
attempt (the caller re-runs; per async-core the device must be
re-connectable afterwards). Removal detection SHALL be bounded: the
transport polls card presence with per-poll slices of at most 1 s
(async-core resolved blocking-policy decision) so removal surfaces
within one poll slice plus the current APDU exchange.

Time extension: when the reader/card layer reports a waiting-time
extension (ISO 14443-4 §7.3: PICC S(WTX) request answered by the
reader's S(WTX) response, temporary FWT = FWT × WTXM capped at
FWT_MAX), the transport SHALL treat it as progress, not as a response:
it neither errors nor completes the wait. The transport's own wait for
the APDU response stays bounded by the remaining ceremony budget
regardless of how many WTX extensions occur; WTX therefore never
extends the deadline.

User presence on NFC: CTAP2.1 §5 (Terminology, "user gesture") defines
NFC presence as the tap itself — placing the authenticator in the
reader field powers it up, sets the NFC userPresent flag, and starts a
two-minute (120 s) NFC user-presence maximum time limit, after which
presence evidence expires and the key must be re-presented. The
transport therefore SHALL NOT keep a getAssertion wait open
indefinitely for a touch the way HID does: a budget-sufficient
ceremony still cannot outlive the §5 120 s presence window, and a
`up`-required command that finds the window expired surfaces the
authenticator's typed status (e.g. 0x2F user-action timeout via
core-model) rather than waiting. Touch-and-hold vs re-present: the
standard's model is tap-establishes-presence with re-insertion after
expiry; no CTAP2.1 §11 mechanism lets the platform request a
touch-and-hold — see design OQ-1.

#### Scenario: Field loss mid-ceremony is a typed transport error

- **WHEN** the card is removed from the NFC field while a getAssertion
  exchange is in flight
- **THEN** the in-flight wait terminates with a typed `Transport`
  error carrying the removed cause within one presence-poll slice
  (≤ 1 s) of the removal, and the error is terminal for the ceremony
  attempt; a subsequent ceremony re-enumerates and reconnects cleanly
  (async-core cancellation contract)

#### Scenario: WTX extensions do not extend the deadline

- **WHEN** a slow authenticator answers an APDU only after N waiting
  time extensions (ISO 14443-4 §7.3, S(WTX) with WTXM)
- **THEN** the transport observes the extensions as progress, the
  reader performs the S(WTX) handshake, and the transport's response
  wait still expires at the remaining ceremony budget — an unbounded
  chain of WTX extensions results in typed `Timeout`, never in an
  extended deadline

#### Scenario: NFC presence window bounds the UP wait

- **WHEN** a getAssertion over NFC pends for user action and the
  remaining ceremony budget exceeds CTAP2.1 §5's 120 s NFC
  user-presence maximum time limit
- **THEN** the transport's wait is still bounded by the remaining
  budget, and when the authenticator reports the presence window
  expired (e.g. status 0x2F) the typed status mapping (core-model) is
  returned instead of an unbounded wait

#### Scenario: Presence poll slices stay bounded

- **WHEN** the transport polls card presence on a T=CL connection
  between APDU exchanges
- **THEN** each poll slice is at most 1 s and goes through the
  `Sleep` factory (async-core), so removal is observed within one
  slice and no poll loop runs without a budget bound

### Requirement: Every APDU exchange and wait is bounded by the ceremony budget

Every operation of this transport — reader enumeration
(`SCardListReaders`), connect (`SCardConnect`, including any bounded
shared-mode retry), SELECT, each command APDU exchange (including
chaining and GET RESPONSE hops and the 9100/GETRESPONSE loop), each
NFC presence poll slice, and each shared-mode connect retry — SHALL
consume the REMAINING ceremony budget (async-core D4, single budget,
no per-hop timeouts) and SHALL return typed `Timeout` naming the
expired phase when the budget is exhausted at that operation. No
transport wait MAY be unbounded or use a fixed internal timeout larger
than the remaining budget: an unbounded wait is a spec violation
(stack invariant). Blocking PC/SC calls run on the
`fidoh-tokio` blocking pool (async-core D3) with a deadline-driven
abort path so a dropped future's thread exits within the current
slice.

#### Scenario: Budget expiry during connect is typed

- **WHEN** a caller connects with a budget that expires while the
  shared-mode connect retry loop is still contending
- **THEN** connect returns typed `Timeout` naming the connect phase,
  with no further PC/SC calls issued after expiry

#### Scenario: Every exchange hop inherits the remaining budget

- **WHEN** a ceremony spends 5 s on enumerate+connect and 3 s on
  SELECT, leaving 52 s of a 60 s budget, and the subsequent getInfo
  exchange stalls past 52 s
- **THEN** the getInfo hop is cancelled at the budget boundary with
  typed `Timeout` naming the getInfo phase — the transport never
  substitutes its own fixed timeout for the remaining budget

#### Scenario: Blocking call abort path respects the slice

- **WHEN** a caller drops the ceremony future while a blocking
  `SCardTransmit` or presence poll is in flight on the blocking pool
- **THEN** the blocking thread exits within its current wait slice
  (≤ 1 s for NFC polls; ≤ remaining budget for APDU waits), and a
  later connect to the same reader succeeds (async-core D3/D4)

### Requirement: Typed error mapping from PC/SC codes and ISO 7816 status words

The transport SHALL map PC/SC return codes (PC/SC Core Specification
Part 3; values per the Windows/pcsclite shared definitions) and
ISO 7816-4 status words onto the async-core/ceremony typed taxonomy as
follows — no PC/SC code or status word MAY surface untyped, and no
mapping may be invented outside this table:

| Source condition | PC/SC code / SW | Typed result |
|---|---|---|
| Resource manager not running | SCARD_E_NO_SERVICE (0x8010001D) / SCARD_E_SERVICE_STOPPED (0x8010001E) | `Transport` error, `no-service` cause; discovery collects per ceremony D2 |
| No readers attached | SCARD_E_NO_READERS_AVAILABLE (0x8010002E) | typed skip `no-readers` recorded for the pcsc transport (discovery continues) |
| No card in reader at connect/exchange | SCARD_E_NO_SMARTCARD (0x8010000C) | `Transport` error, `absent` cause |
| Card removed mid-operation | SCARD_W_REMOVED_CARD (0x80100069), SCARD_E_NO_SMARTCARD during transmit | `Transport` error, `removed` cause (terminal for the attempt) |
| Another connection holds the reader | SCARD_E_SHARING_VIOLATION (0x8010000B) | `Transport` error, `sharing` cause; triggers the bounded shared-mode retry, then surfaces if it persists |
| Protocol mismatch on connect | SCARD_E_PROTO_MISMATCH (0x8010000F) | `Transport` error, `protocol` cause |
| Card silent / unusable on connect | SCARD_W_UNRESPONSIVE_CARD (0x80100066), SCARD_W_UNPOWERED_CARD (0x80100067) | typed skip `unusable-card` for that reader |
| Card reset under us | SCARD_W_RESET_CARD (0x80100068) | `Transport` error, `reset` cause; retry is the caller's re-run, never implicit |
| Operation deadline exceeded by resource manager | SCARD_E_TIMEOUT (0x8010000A) | `Timeout` naming the phase that was in flight (never retried implicitly) |
| Reader-level failure | SCARD_E_READER_UNAVAILABLE (0x80100017), SCARD_E_NOT_TRANSACTED (0x80100016), SCARD_E_COMM_DATA_LOST (0x8010002F) | `Transport` error, `reader` cause |
| Any other PC/SC code | (all remaining 0x8010xxxx) | `Transport` error, `pcsc(code)` catch-all carrying the raw code |
| SELECT: applet not found | SW 6A82 | typed skip `not-fido` (see applet-selection requirement) |
| SELECT: conditions not satisfied / invalidated applet | SW 6985 / 6283 | typed skip `not-fido` with `condition`/`invalidated` qualifier |
| Success with more data | SW 61xx | GET RESPONSE hop (same budget), not an error |
| Wrong Le | SW 6Cxx | single retry with Le=xx (same budget), else `Transport` error, `le` cause |
| Command not allowed | SW 6986, 6D00 | `Transport` error, `sw` cause carrying the SW |
| Other ISO 7816-4 error SW | (all remaining 6xxx) | `Transport` error, `sw` cause carrying the raw SW |

CTAP status bytes inside a `9000` response are NOT mapped here: they
are core-model's CTAP2.1 §8.2 space and the ceremony's status mapping
owns them.

#### Scenario: No readers is a typed skip, not a crash

- **WHEN** enumerate runs on a host where the resource manager reports
  SCARD_E_NO_READERS_AVAILABLE
- **THEN** the transport yields a typed `no-readers` skip that
  discovery attaches per ceremony D2, and the ceremony's NoDevice
  outcome (if nothing else is found) carries the typed cause

#### Scenario: Removal mid-exchange maps to the removed cause

- **WHEN** an APDU transmit fails with SCARD_W_REMOVED_CARD
- **THEN** the caller receives a typed `Transport` error with the
  `removed` cause, no retry is attempted by the transport, and the
  error text identifies the reader

#### Scenario: Sharing violation retries within budget then surfaces

- **WHEN** SCardConnect returns SCARD_E_SHARING_VIOLATION and the
  contention clears 2 s later, within a sufficient budget
- **THEN** the bounded retry succeeds in shared mode; when contention
  instead outlives the budget the caller receives `Timeout` naming the
  connect phase, and when contention clears but exclusive hold
  persists the caller receives the typed `sharing` cause

#### Scenario: Protocol mismatch is typed

- **WHEN** SCardConnect cannot agree a protocol with the card
  (SCARD_E_PROTO_MISMATCH)
- **THEN** the caller receives a typed `Transport` error with the
  `protocol` cause naming the reader, and no APDU is sent

#### Scenario: Every failure surfaces typed

- **WHEN** any transport operation fails (any PC/SC code, any status
  word, budget expiry)
- **THEN** the result is exactly one typed variant of the taxonomy —
  a `Transport` error with a named cause, a typed skip, or `Timeout`
  naming the phase — never a raw integer, string, or panic
