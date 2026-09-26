# docs/errors.md — fidoh error reference for operators

Every failure fidoh can report is one of seventeen typed variants (the
ceremony taxonomy; governing spec:
`openspec/changes/ceremony/specs/ceremony/spec.md`, error-surface
contract:
`openspec/changes/error-diagnostics/specs/error-diagnostics/spec.md`;
since the add-client-pin change (v2), the seven PIN-related variants
are specified in
`openspec/changes/add-client-pin/specs/ceremony/spec.md`).
Raw OS errnos, PC/SC codes, and ISO 7816 status words never reach you
bare — they ride inside `Transport` (or inside `NoDevice`'s
per-transport cause list) as typed causes with structured fields you
can branch on programmatically. The table below is the operator view:
what each variant means, what usually causes it, and what to do about
it.

Errors carry a human-readable message (the library's diagnostic
string; your application prints it) plus structured fields you can
branch on: device descriptors (`NoDevice`, `AmbiguousDevice`), the
expired ceremony phase (`Timeout(Phase)`), typed transport causes
(errnos, CTAPHID_ERROR codes, PC/SC causes), and typed status values
(`Ctap(status)`). Not yet in the code: an elapsed-vs-budget data pair
on `Timeout` — it currently names the phase only; that field set is
spec'd in `openspec/changes/error-diagnostics/` and lands with that
change. Error messages never contain secrets, credential material,
or PIN data — safe to paste into bug reports.

## Error table

| Variant | Meaning | Likely causes | Remediation | See |
|---|---|---|---|---|
| `NoDevice` | Discovery found zero usable authenticators; carries each transport's typed discovery error (or an empty list if everything enumerated cleanly and found nothing) | No key plugged in; hidraw permission denied; pcscd not running; no readers; reader holds no FIDO card (SELECT → 6A82 is a typed skip, not a crash) | Re-plug the key; fix hidraw permissions (udev section below); check pcscd state (pcscd section below); for NFC/PC/SC confirm the card is FIDO-capable | [transport-hid.md](transport-hid.md), [transport-pcsc.md](transport-pcsc.md) |
| `AmbiguousDevice` | More than one candidate and the selection policy is the default `Fail`; carries every candidate's descriptor (transport kind, path/handle, metadata, AAGUID if probed) | Two keys plugged in; same key visible over both HID and PC/SC | Unplug the extra key, or pass an explicit `SelectionPolicy` (`First` or `Select(fn)`) — fidoh never silently picks | ceremony spec |
| `UserActionTimeout` | The **authenticator** gave up waiting for the touch (0x2F CTAP2_ERR_USER_ACTION_TIMEOUT) | User didn't touch the key in time | Retry and touch promptly; distinct from `Timeout` (which is the caller's own budget expiring) | ceremony spec (CTAP2.1 §8.2) |
| `UserCancelled` | The pending wait was cancelled (0x2D CTAP2_ERR_KEEPALIVE_CANCEL), including fidoh's own CANCEL after budget expiry | Caller dropped the ceremony; budget expired mid-touch-wait | Usually intentional; safe to retry — the device is left usable | ceremony spec |
| `NoCredentials` | No credential on the authenticator matches the request (0x2E CTAP2_ERR_NO_CREDENTIALS, 0x22 CTAP2_ERR_INVALID_CREDENTIAL) | Wrong key; credential lives on a different authenticator; allowList matches nothing | Use the key the credential was created on; check the allow list | ceremony spec |
| `UpRejected` | User presence/verification refused by the authenticator (0x27 OPERATION_DENIED, 0x3B UP_REQUIRED, and pinUvAuth-adjacent codes 0x33/0x36/0x37/0x3C — 0x34 moved to its own `PinAuthBlocked` variant in v2) | User declined; authenticator requires UV the ceremony can't supply; pinUvAuthParam verification failed on a caller-supplied token | Touch to confirm when prompted; for UV-required RPs supply a pinUvAuthToken (held by the caller, or acquired via a PIN provider — see `PinRequired` below) | ceremony spec, add-client-pin ceremony spec (CTAP2.1 §8.2) |
| `CredentialMismatch` | The returned assertion's credential id is not in the caller's allow list (library-safety check) | Authenticator answered with a foreign credential (should not happen with well-behaved keys); wrong key inserted | Do not accept the assertion; retry with the correct key; the error names the mismatch with a truncated id only | ceremony spec |
| `IncorrectPin { remaining_retries }` | Wrong PIN on the authenticator (0x31 CTAP2_ERR_PIN_INVALID, v2). `remaining_retries` carries the authenticator's pinRetries count when the response offered it (`None` when absent — fidoh spends no extra round-trip fetching it) | The PIN typed into your provider prompt was wrong; the PIN changed on the key | Prompt the user again and re-run the ceremony (fidoh never retries implicitly — each run makes at most one PIN attempt); the count tells you how close to lockout you are | add-client-pin ceremony spec (CTAP2.1 §6.5.5) |
| `PinBlocked` | The PIN retry counter is exhausted (0x32 CTAP2_ERR_PIN_BLOCKED, v2) — every PIN-bearing operation is refused before any comparison, even with the correct PIN | Too many wrong PINs (typically 8); a brute-force attempt on the key | Reset the authenticator (FIDO2 reset wipes its credentials) or power-cycle it per the vendor's recovery procedure; then set a new PIN | add-client-pin ceremony spec (CTAP2.1 §6.5.5.7.2) |
| `PinAuthBlocked` | pinUvAuth blocked after 3 CONSECUTIVE PIN mismatches (0x34 CTAP2_ERR_PIN_AUTH_BLOCKED, v2) — refused until a power cycle, even with the correct PIN; the retry counter is not consumed while latched | Three wrong PINs in a row (an automated retry loop is the usual cause) | Unplug and re-plug the key (power cycle), then retry with the correct PIN — do not loop PIN attempts | add-client-pin ceremony spec (CTAP2.1 §6.5.5.7.2) |
| `PinNotSet` | No PIN is set on the authenticator (0x35 CTAP2_ERR_PIN_NOT_SET, v2) — distinct from a wrong PIN | The key has never had a PIN set (or it was cleared); the ceremony asked it to verify a PIN | Set a PIN on the key first (via your platform's authenticator management, e.g. the browser or `ykman fido access change-pin`); then re-run | add-client-pin ceremony spec (CTAP2.1 §6.5.5) |
| `PinRequired` | The request asked for user verification (`UvPolicy::Preferred`) but the key has no built-in verifier (clientPin-only, like most YubiKeys) and NO PIN provider was supplied (v2 — replaces v1's silent degradation) | The caller forgot to pass a `pin_provider` while the RP demands UV | Supply a PIN provider (a callback that returns the PIN bytes) so fidoh can acquire a pinUvAuthToken; or hold one yourself and pass `pin_uv_auth`; or drop the policy to `Discouraged` if the RP allows | add-client-pin ceremony spec (CTAP2.1 §6.5.5) |
| `PinProviderFailed` | The caller's own PIN provider failed (the user cancelled the prompt, the keystore was locked, …) (v2) — no authenticator round-trip happened after the provider step | User cancelled your UI; your provider errored | Surface it to the user and let them re-run; fidoh made no PIN attempt (the retry counter is untouched) | add-client-pin ceremony spec (PIN-provider seam) |
| `PinTooLong` | The provider returned more than 63 UTF-8 bytes (CTAP2.1 §6.5.5 maximum PIN length, v2) — rejected client-side BEFORE any device traffic | A bug in your provider (or a paste accident); no retry counter or budget was consumed | Fix the provider's input validation; CTAP2 PINs are at most 63 bytes | add-client-pin ceremony spec (CTAP2.1 §6.5.5.5) |
| `Timeout` | The caller's single ceremony budget expired; names the phase (discovery, connect, probe, clientPin — the v2 PIN-acquisition hops, getAssertion, user-presence, getNextAssertion) and carries elapsed-vs-budget | Budget too small; device contention (another client holding the key — see below); user slow to touch; NFC card left the field mid-poll; v2: user took too long in your PIN prompt (the budget keeps running — the next clientPIN hop reports it) | Raise the budget; close other FIDO clients (browsers, other tools); retry. Distinct from `UserActionTimeout` | async-core spec (D4), add-client-pin design D4 |
| `Transport` | I/O or framing failure below the status layer, with a typed cause: hidraw open/read/write errnos, CTAPHID_ERROR codes, PC/SC causes (`no-service`, `no-readers`, `absent`, `removed`, `sharing`, `protocol`, `reset`, `reader`, `timeout`, `pcsc(code)`; ISO 7816 status words appear on typed skips as `not-fido` with the raw SW) | Permission denied (EACCES); device unplugged; card removed; pcscd down; sharing violation; wedged device | Match on the cause field; most rows in the sections below address a specific cause | [transport-hid.md](transport-hid.md), [transport-pcsc.md](transport-pcsc.md) |
| `Ctap(status)` | Any other authenticator status, carrying core-model's typed CTAP2.1 §8.2 status value (e.g. 0x30 NOT_ALLOWED on a continuation) | Authenticator-specific refusal; retriable codes like 0x06 CHANNEL_BUSY (fidoh never retries implicitly — the caller re-runs the ceremony) | Read the typed status; re-run the ceremony for retriable statuses | ceremony spec (CTAP2.1 §8.2) |

## Fixing hidraw permission failures (Linux)

Symptom: `Transport` error from the hid transport whose cause is a
typed open-permission failure naming a `/dev/hidrawN` path (EACCES),
or `NoDevice` carrying that same cause. fidoh's diagnostic message
points here.

The kernel creates `/dev/hidraw*` nodes root-owned; without a udev
grant your user gets "Permission denied" on open. Two standard fixes
(full background in [transport-hid.md](transport-hid.md#permissions)):

### Option A — uaccess tag (recommended on systemd desktops)

On stock systemd, `60-fido-id.rules` + `70-uaccess.rules` already
grant the logged-in seat user access to FIDO hidraw devices — no
custom rule needed. For an explicit per-device rule (substitute your
device's VID/PID):

```udev
# /etc/udev/rules.d/70-fidoh-uaccess.rules
KERNEL=="hidraw*", ATTRS{idVendor}=="1050", ATTRS{idProduct}=="0407", TAG+="uaccess"
```

### Option B — group rule (servers, headless, non-systemd)

```udev
# /etc/udev/rules.d/70-fidoh-plugdev.rules
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", MODE="0660", GROUP="plugdev"
```

Then add the user to the group (`usermod -aG plugdev <user>`;
`plugdev` is the Debian/Ubuntu convention — a dedicated group like
`fidoh` scopes tighter; note this grants access to *every* hidraw
device, broader than Option A).

Apply either with:

```sh
udevadm control --reload && udevadm trigger   # then re-plug the device
```

### Verify

```sh
ls -l /dev/hidrawN        # owner/group/mode
getfacl /dev/hidrawN      # uaccess shows an ACL entry for your user
udevadm info -a /dev/hidrawN
```

## Fixing PC/SC failures (Linux)

The PC/SC transport talks to the pcsc-lite resource manager; fidoh
never starts the daemon itself — a missing daemon is a typed
`Transport(no-service)` error. fidoh's diagnostic message points
here. Checks:

```sh
systemctl status pcscd        # is the resource manager running?
pcsc_scan                     # are readers and cards visible to it? (pcsc-tools package)
```

- `pcscd` down or socket not activating → `Transport(no-service)`
  during discovery (collected into `NoDevice` if nothing else is
  found). Start/enable the daemon (`systemctl start pcscd`; modern
  pcsc-lite uses socket activation).
- `pcsc_scan` shows no readers → driver problem: the generic CCID
  driver (`libccid`) covers most USB readers including a YubiKey's
  CCID interface; vendor readers need their IFD-handler bundle. See
  [transport-pcsc.md](transport-pcsc.md#requirements-on-linux).
- Reader visible but card absent → `Transport(absent)`; card removed
  mid-operation → `Transport(removed)` (terminal for the attempt —
  retry the ceremony).
- SELECT returns 6A82 → the card/reader interface has no FIDO applet;
  fidoh treats this as a typed skip during enumeration, not a crash.

Deeper debugging (from transport-pcsc.md): `pcscd --foreground --debug`,
`pcsc-spy`, `opensc-tool --list-readers`.

## Contention vs. missing permissions — how to tell them apart

These two produce superficially similar "can't use the key" failures
but have different shapes and fixes:

| | Missing permissions | Contention (another client holds the device) |
|---|---|---|
| Error shape | Typed open-permission failure (EACCES) on hidraw `open()`; happens *immediately* at connect | CTAPHID `ERR_CHANNEL_BUSY` (0x06) on HID, or PC/SC `SCARD_E_SHARING_VIOLATION` / repeated read timeouts while another client holds a transaction | 
| When | Instantly, on `open()`/connect | Only when another process (browser, another tool) is mid-transaction; fidoh retries within the budget, then surfaces `Timeout` (connect phase) or a typed `sharing` cause |
| Fix | udev rules above | Close the other FIDO client (browsers hold keys aggressively) and retry — no system change needed |
| Verify | `getfacl /dev/hidrawN` shows no grant for your user | `fuser -v /dev/hidrawN` / check `pcsc_scan` and running browsers; contention clears when the other client exits |

Rule of thumb: **permission errors fail on open and never clear on
their own; contention clears when the other client lets go.**

## Grounding note

All guidance above derives from fidoh's own transport docs
([transport-hid.md](transport-hid.md), [transport-pcsc.md](transport-pcsc.md))
and public Linux documentation (systemd udev `70-uaccess.rules` /
`60-fido-id.rules` and the `uaccess` builtin; pcsc-lite daemon model
and tooling). Nothing here is sourced from other FIDO client
libraries' source code (cleanroom rule).
