# transport-hid — CTAPHID over USB HID on Linux

`transport-hid` specifies fidoh's USB HID transport: the CTAPHID
framing and channel protocol (CTAP2.1 §11.2) implemented by
`fidoh-transport-hid` behind the async-core `Transport`/`Device`
traits. Governing spec:
`openspec/changes/transport-hid/specs/transport-hid/spec.md`.

> **Note on section numbers.** Older CTAP 2.0 documents number the USB
> HID transport §8.1; in CTAP 2.1 it is **§11.2**. Citations here use
> the CTAP 2.1 numbering, verified against the published spec text.

All byte-level examples below are **constructed** (hand-assembled to
illustrate the layout; not captured from hardware). Captured traces
from live probes will be added when hardware testing lands and will be
labeled as such.

## Packet layouts (CTAP2.1 §11.2.4)

CTAPHID packets are fixed-size HID reports — 64 bytes for full-speed
devices. The full size is always sent; unused bytes SHOULD be zero.

### Initialization packet (starts every message)

```
byte:  0    1    2    3    4    5    6    7 ... 63
     +----+----+----+----+----+----+----+------------+
     | CID (4 B, big-endian)  |CMD^80| BCNT | DATA   |
     |                        |      | (2 B,| (57 B) |
     |                        |      | BE)  |        |
     +----+----+----+----+----+----+----+------------+
```

| Field | Offset | Size | Meaning |
|---|---|---|---|
| CID | 0–3 | 4 | Channel identifier; `0xFFFFFFFF` = broadcast |
| CMD | 4 | 1 | Command, bit 7 always set (distinguishes init from continuation) |
| BCNT | 5–6 | 2 | Payload length, big-endian (high byte first) |
| DATA | 7–63 | 57 | First payload bytes; zero-padded |

### Continuation packet

```
byte:  0    1    2    3    4    5 ... 63
     +----+----+----+----+----+------------+
     | CID (4 B, big-endian)  |SEQ | DATA  |
     |                        |    | (59 B)|
     +----+----+----+----+----+------------+
```

| Field | Offset | Size | Meaning |
|---|---|---|---|
| CID | 0–3 | 4 | Same channel as the init packet |
| SEQ | 4 | 1 | 0x00..0x7F, ascending, one per continuation packet |
| DATA | 5–63 | 59 | Next payload bytes; final packet zero-padded |

Maximum message payload: `64 − 7 + 128 × (64 − 5) = 7609` bytes
(CTAP2.1 §11.2.4). fidoh rejects longer messages with a typed error
before writing anything.

### Commands used by this transport

| Command | Value | Used for |
|---|---|---|
| CTAPHID_PING | 0x01 | not used in v1 (debug) |
| CTAPHID_MSG | 0x03 | not used in v1 (CTAP1/U2F) |
| CTAPHID_LOCK | 0x04 | **not used in v1** (see spec rationale) |
| CTAPHID_INIT | 0x06 | channel allocation / resync |
| CTAPHID_WINK | 0x08 | only if CAPABILITY_WINK |
| CTAPHID_CBOR | 0x10 | every CTAP2 command exchange |
| CTAPHID_CANCEL | 0x11 | caller cancellation mid-transaction |
| CTAPHID_ERROR | 0x3F | device → host framing errors |
| CTAPHID_KEEPALIVE | 0x3B | device → host progress |

## Channel allocation — worked example (constructed)

Step 1. The host has no channel yet, so it uses the broadcast CID
`0xFFFFFFFF` and generates a fresh 8-byte nonce (v1 implementation:
an incrementing `AtomicU64` counter — §11.2.9.1.3 requires only that
the response echo the request nonce, not that it be unpredictable)
`01 02 03 04 05 06 07 08`.

Step 2. The host writes one init packet (57-byte payload area; the
INIT payload is only 8 bytes, so 49 trailing zeros):

```
FF FF FF FF   86   00 08   01 02 03 04 05 06 07 08   00×49
└─ CID ──┘   └CMD┘  └BCNT┘  └────── nonce ──────┘   └ pad ┘
           0x06|0x80
```

Step 3. The device replies (response BCNT is 17):

```
FF FF FF FF   86   00 11   <nonce 8 B> <new CID 4 B> 02 <ver 3 B> <cap 1 B> 00×39
```

Concretely, if the device allocates channel `0x2A 0x01 0xB6 0x4F`,
reports protocol version 2, device version 1.0.4, capabilities
`0x05` (WINK | CBOR):

```
FF FF FF FF   86   00 11   01 02 03 04 05 06 07 08   2A 01 B6 4F   02   01 00 04   05   00×39
└─ CID ──┘   └CMD┘  └BCNT┘  └─ echoed nonce ────────┘  └─ new CID ─┘  └ver┘ └dev ver┘ └cap┘ └pad┘
```

Step 4. The host compares the echoed nonce to the nonce it sent. Only
on a match does it adopt the new channel ID `0x2A01B64F` for all
subsequent transactions. A mismatch is a typed error — the response
may belong to another contender for the device.

Capabilities byte (CTAP2.1 §11.2.9.1.3): `0x01` WINK, `0x04` CBOR,
`0x08` NMSG ("does not implement CTAPHID_MSG"). fidoh gates WINK and
CBOR on their bits and records NMSG as metadata; v1 never uses
CTAPHID_MSG, so NMSG devices are fully supported for CTAP2.

Re-sending INIT on an already allocated channel (non-broadcast CID) is
the abort-and-resynchronize escape hatch (CTAP2.1 §11.2.5.3): the
device drops the pending transaction and returns to idle.

## Transaction lifecycle: keepalives and cancel

A CTAPHID_CBOR transaction runs: request packets → (keepalives, at
least every 100 ms, CTAP2.1 §11.2.9.1.7) → response packets.

- Keepalive status `0x01` PROCESSING: the device is working.
- Keepalive status `0x02` UPNEEDED: the device is waiting for the user
  to touch. fidoh surfaces each of these to the caller as a **progress
  signal** — they are never errors and never reset the ceremony
  budget.
- Every keepalive wait is bounded by the remaining ceremony budget
  (async-core D4). If the budget expires while waiting for touch, the
  wait ends with the typed `Timeout` naming the user-presence phase
  and the transport sends CTAPHID_CANCEL (`0x11`, BCNT 0) on the
  channel. The device then responds to the *original request* with
  `CTAP2_ERR_KEEPALIVE_CANCEL` (0x2D), which the ceremony layer maps
  to `Error::UserCancelled`. The cancel itself is never answered
  (CTAP2.1 §11.2.9.1.5).
- Reassembly rules on the receive path: SEQ must ascend from 0x00
  (violation → typed invalid-sequence error), packets on other CIDs
  are ignored (they are other clients' traffic), and a stray
  continuation packet with no message in progress is ignored
  (CTAP2.1 §11.2.5.4).

## CTAPHID_ERROR codes (CTAP2.1 §11.2.9.1.6)

| Code | Name | Meaning / fidoh behavior |
|---|---|---|
| 0x01 | ERR_INVALID_CMD | typed error, no retry |
| 0x02 | ERR_INVALID_PAR | typed error, no retry |
| 0x03 | ERR_INVALID_LEN | typed error, no retry |
| 0x04 | ERR_INVALID_SEQ | typed error, then channel resync via INIT |
| 0x05 | ERR_MSG_TIMEOUT | typed error, no retry |
| 0x06 | ERR_CHANNEL_BUSY | bounded retry after a short sleep, within budget |
| 0x0A | ERR_LOCK_REQUIRED | typed error, no retry (fidoh never locks) |
| 0x0B | ERR_INVALID_CHANNEL | typed error, no retry |
| 0x7F | ERR_OTHER | typed error, no retry |

## Linux device discovery and permissions

### Enumeration

fidoh enumerates hidraw nodes (`/dev/hidraw*`) via the kernel's
hidraw class (kernel hidraw doc: udev creates the nodes directly under
`/dev`; applications are advised to locate them via libudev/sysfs).
For each node it reads the device's HID report descriptor from the
sysfs `report_descriptor` attribute and accepts the device only if the
descriptor declares **usage page `0xF1D0`** (FIDO alliance) with
**usage `0x01`** (CTAPHID) — CTAP2.1 §11.2.8.2. There is deliberately
**no VID/PID filter**: any vendor's token matching the usage pair is a
candidate.

### Permissions

Without a udev grant, `/dev/hidraw*` nodes are typically root-owned
and a normal user gets "Permission denied" on open. Two standard
fixes:

**Option A — uaccess tag (recommended on systemd desktops).** The
`uaccess` builtin gives the node an ACL granting the *currently logged
in seat user* access, automatically. systemd ships this for security
tokens already: its `70-uaccess.rules` tags devices via
`ENV{ID_SECURITY_TOKEN}=="?*", TAG+="uaccess"`, and `60-fido-id.rules`
sets `ID_SECURITY_TOKEN` for hidraw devices whose report descriptor
matches the FIDO usage (the `fido_id` helper parses for usage
`0xf1d00001`). On a stock systemd system no custom rule is needed.

To add an explicit rule for a specific device (example — substitute
your device's VID/PID):

```udev
# /etc/udev/rules.d/70-fidoh-uaccess.rules
KERNEL=="hidraw*", ATTRS{idVendor}=="1050", ATTRS{idProduct}=="0407", TAG+="uaccess"
```

**Option B — group rule (servers, headless boxes, non-systemd).** Grant
a unix group read/write on all hidraw nodes and add the service user
to that group:

```udev
# /etc/udev/rules.d/70-fidoh-plugdev.rules
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", MODE="0660", GROUP="plugdev"
```

(On Debian/Ubuntu `plugdev` is conventional; any existing group works —
use `GROUP="fidoh"` with a dedicated group for tighter scoping. This
grants access to *every* hidraw device, which is broader than Option
A.) Reload with `udevadm control --reload && udevadm trigger` and re-
plug the device.

### Diagnostics when open/read/write fails

| Symptom | Typed error | Remediation |
|---|---|---|
| `open("/dev/hidrawN")` → EACCES | typed open-permission error naming the path | apply Option A or B above; verify with `ls -l /dev/hidrawN` and `getfacl /dev/hidrawN` (uaccess shows an ACL entry for your user) |
| `open()` → ENOENT | typed device-not-found error | device unplugged or not a hidraw device; re-run enumeration |
| descriptor read fails during enumeration | node skipped, recorded as diagnostic | other candidates are still returned; check `udevadm info` output for the node |
| `read()` times out repeatedly | typed `Timeout` naming the phase | token may be busy with another client (ERR_CHANNEL_BUSY retries are bounded); check for browsers/other tools holding transactions |
| `write()` fails mid-transaction | typed I/O error | device was unplugged or wedged; reconnect and retry the ceremony |

The typed errors carry the failing path/errno so callers can
distinguish "no permission" from "no device" without string parsing.

### Blocking I/O note (async-core D3)

hidraw `read()` blocks until a report is available (kernel hidraw
doc); there is no executor-native readiness story fidoh can rely on
for arbitrary FIDO devices. Per the async-core blocking-syscall
policy, `fidoh-transport-hid` performs blocking reads/writes.
Blocking waits are sliced HERE (default 30 s,
`fidoh_core::DEFAULT_WAIT_SLICE` re-exported as `WAIT_SLICE`,
caller-overridable) and every slice is checked against the remaining
ceremony budget — the single deadline supplied at ceremony start
(async-core D4). An unbounded wait anywhere in this transport is a
spec violation. The async-side bridge is the slice-level
`fidoh_tokio::spawn_blocking_slice` (one wait slice = one
`tokio::task::spawn_blocking` op, drop-detach semantics), and the
shipped CLI enters through `fidoh_tokio::run`, which drives the
ceremony future on the runtime's own `block_on` — hardware keepalive
waits ride the slice bridge from there. A caller hosting ceremonies
on their own executor should wrap wait slices the same way
(`spawn_blocking_slice`) rather than calling the blocking transport
directly on a worker thread.

## References

- FIDO Client to Authenticator Protocol (CTAP) 2.1, §11.2 USB Human
  Interface Device (USB HID) — fidoalliance.org
- CTAP 2.1 §5 Terminology (user action timeout ≥ 10 s,
  authenticator-chosen), §8 Message Encoding (big-endian rule)
- Linux kernel `Documentation/hid/hidraw.rst` (blocking read/write
  semantics, /dev node creation, ioctl surface)
- Linux kernel HID class sysfs attributes (`report_descriptor`,
  `id/{bustype,vendor,product,version}`)
- systemd udev rules `70-uaccess.rules`, `60-fido-id.rules`, and the
  `fido_id` descriptor parser (usage `0xf1d00001`)
