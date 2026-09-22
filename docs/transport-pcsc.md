# transport-pcsc — the PC/SC APDU transport (FIDO over CCID + NFC)

`transport-pcsc` is fidoh's ISO 7816-4 APDU transport. ONE engine
serves both media: FIDO-over-CCID (CTAP 2.x carried as ISO 7816 APDUs
on the USB CCID interface) and NFC (ISO 14443, T=CL). Governing spec:
`openspec/changes/transport-pcsc/specs/transport-pcsc/spec.md`.

## Requirements on Linux

The transport talks to the PC/SC resource manager; on Linux that is
pcsc-lite:

| Component | Role | Notes |
|---|---|---|
| `pcscd` (pcsc-lite daemon) | PC/SC resource manager | Owns reader access; must be running or `SCardEstablishContext`/`SCardListReaders` fail (`SCARD_E_NO_SERVICE`). Modern pcsc-lite auto-starts via systemd socket activation. |
| CCID reader driver | Talks USB CCID to readers/dongles | The generic CCID driver (`libccid`, ccid.apdu.fr) covers most USB readers; a YubiKey's CCID interface is driven by it. Vendor readers with custom drivers register via the pcsc-lite IFD-handler bundle. |
| `libpcsclite` / PC/SC client API | `SCard*` calls from fidoh | pcsc-lite implements the PC/SC workgroup API (Parts 3 and 10). |
| Kernel layers | USB (CCID) / NFC (ISO 14443) | NFC field handling, T=CL block protocol, and ISO 14443-4 WTX live in the reader + driver layer below PC/SC; fidoh sees only `SCardTransmit`. |

macOS (CryptoTokenKit/PC/SC shim) and Windows (WinSCard) expose the
same PC/SC API surface; v1 development targets Linux pcsc-lite, and
the spec pins only workgroup-defined behavior.

Shared-library vs daemon split note: a missing `pcscd` is a typed
`Transport(no-service)` discovery error — fidoh never tries to start
the daemon itself.

## FIDO over CCID: the YubiKey firmware ≥ 5.8 note

Since YubiKey firmware 5.8, Yubico documents FIDO over CCID: CTAP
2.x commands carried using ISO 7816 APDU messaging over the USB CCID
smart card interface (in addition to the USB HID FIDO interface), so
FIDO operations run through the OS smart card stack (PC/SC) exactly
like traditional smart card applications.

Reference (public documentation, not source code):
https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-fido.html
— section "FIDO over CCID" (YubiKey Technical Manual). The 5.8
firmware capability summary is at
https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-firmware-5.8.html
("FIDO over Chip Card Interface Device (CCID), USB & smart card
SCP11b secure channel").

Consequences for fidoh:

- The same APDU engine serves a fw-5.8 YubiKey over USB (as a CCID
  "card" behind a reader) and the same key over NFC — CTAP2.1 §11.3
  defines the protocol once for ISO 7816/14443 media.
- A fw-5.8 key exposes FIDO alongside PIV/OATH/OpenPGP on the same
  CCID interface; this is the operational reason fidoh connects
  SHARED by default (below).
- Secure channel (SCP11b) is Yubico-documented as NFC-only today and
  is out of fidoh v1 scope.

## Shared vs exclusive connect: rationale

| Connection | Default | Why |
|---|---|---|
| NFC (T=CL) | SHARED (spec-mandated) | An exclusive hold locks other local processes out of the reader for a whole touch-waiting ceremony; the RF field already gives point-to-point exclusivity (ISO 14443). |
| CCID / USB | SHARED (decision, with justification) | A YubiKey is a composite device: PIV/OATH/OpenPGP clients legitimately use other applets concurrently. PC/SC already serializes transactions per reader (Part 3), so exclusivity adds lockout risk for no mutual-exclusion benefit. |
| Either (opt-in) | EXCLUSIVE on explicit request | For callers who need hard exclusion (tests, benchmarking). fidoh never escalates shared→exclusive on its own; sharing violations retry within the budget, then surface typed. |

Failure shape: `SCARD_E_SHARING_VIOLATION` (0x8010000B) during the
retry window is invisible to the caller if contention clears; if it
persists to budget expiry the result is `Timeout` (connect phase); a
persistent exclusive hold after clearing contention surfaces the
typed `sharing` cause. Full table in the spec's error-mapping
requirement.

## Worked example: SELECT + getInfo APDU trace

**Constructed example** — bytes assembled by hand from CTAP2.1 §11.3
and the canonical CBOR rules of §8 to illustrate the wire shape; NOT
captured from hardware. Live captures (cleanroom evidence class 3)
belong in `fixtures/` when hardware CI exists, labeled `captured`.

Scenario: YubiKey 5 (fw ≥ 5.8), USB CCID, pcscd running, device
implements CTAP1+CTAP2, getInfo answers with the minimal CTAP2
capability set. Ceremony budget 30 s; every hop below runs under the
remaining budget.

**1. Connect (SHARED) and SELECT the FIDO applet** (CTAP2.1 §11.3.3;
AID = rid `A000000647` + pix `2F0001`):

```
> 00 A4 04 00 08 A0000006472F0001 00      SELECT, P1=0x04 (by DF name)
< 5532465F5632 9000                       data "U2F_V2" || SW 9000
```

`U2F_V2` is the §11.3.3-mandated version string when CTAP1/U2F and
CTAP2 are both implemented; it does NOT settle CTAP2 capability — the
getInfo probe below does (ceremony D3). Had the applet been absent,
SW would be `6A82` → typed enumerate-and-skip.

**2. authenticatorGetInfo** (CTAP command byte 0x04, empty CBOR map
payload; §11.3.5.1 frame, P1 = 0x80|0x00):

```
> 80 10 80 00 01 04 00                    NFCCTAP_MSG, P1 bit 0x80 set
< 00                                      CTAP status 0x00 (CTAP2_OK)
< A50182684649444F5F325F30684649444F5F325F31
  10...                                    (CBOR continues below)
< 9000                                    SW success
```

Full response data (CTAP status byte + canonical CBOR, 61 bytes):

```
00 A5 01 82 68 4649444F5F325F30 68 4649444F5F325F31
   03 50 0102030405060708090A0B0C0D0E0F10
   04 A3 62 726B F5 62 7570 F5 62 7576 F4
   05 19 03FF
   06 81 01
   9000
```

Decoded: status 0x00; map {1: ["FIDO_2_0","FIDO_2_1"], 3:
h'0102…10' (16-byte AAGUID), 4: {"rk":true,"up":true,"uv":false},
5: 1023 (maxMsgSize), 6: [1] (pinUvAuthProtocols)}; SW 9000. The
CBOR is canonical per CTAP2.1 §8 (sorted numeric keys, minimal
lengths, definite lengths only). The AAGUID shown is a placeholder —
real values are vendor-assigned (see Yubico's AAGUID list, cited from
the technical manual).

**3. If the response had not fit in one short APDU** (getInfo can
exceed 256 bytes with many options), §11.3.6/ISO 7816-4 chaining
applies — status `61 XX`, then GET RESPONSE hops:

```
> 80 C0 00 00 00                          GET RESPONSE (INS 0xC0)
< ...remaining data... 9000
```

or, with the extended-length form (preferred by fidoh when sizes are
known — §11.3.5 requires authenticators to support it):

```
> 80 10 80 00 00 0001 04 0000             extended-length NFCCTAP_MSG
```

**4. Chained request (short-form fallback)**, per §11.3.6, if the
request exceeds 255 bytes and extended length is unavailable — first
chaining block uses CLA 0x90, final block carries Le:

```
> 90 10 00 00 F0 <240 payload bytes>      SW 9000
> 80 10 00 00 <Lc> <rest> 00              SW 9000 + data
```

Every APDU above is bounded by the remaining ceremony budget
(async-core D4); a stall past it returns typed `Timeout` naming the
phase, never an unbounded wait.

## Error quick reference

Condensed from the spec's mapping table (authoritative there):

| Condition | Typed result |
|---|---|
| pcscd not running (0x8010001D/0x8010001E) | `Transport(no-service)`, discovery collects |
| No readers (0x8010002E) | typed skip `no-readers` |
| No card / removed (0x8010000C / 0x80100069) | `Transport(absent)` / `Transport(removed)` |
| Sharing violation (0x8010000B) | bounded retry → `Timeout(connect)` or `Transport(sharing)` |
| Protocol mismatch (0x8010000F) | `Transport(protocol)` |
| SELECT SW 6A82 / 6985 / 6283 | typed skip `not-fido` (+qualifier) |
| SW 61xx / 6Cxx | GET RESPONSE hop / Le retry (same budget) |
| Budget exhausted at any hop | `Timeout` naming the phase |

Debugging on Linux: `pcscd --foreground --debug`, `pcsc-spy`
(pcsc-lite API spy), and `opensc-tool --list-readers` (or
`pcsc_scan` from the pcsc-tools package) to confirm the reader and
card are visible to the resource manager before blaming fidoh.
