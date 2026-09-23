//! The [`Transport`](fidoh_core::Transport) and
//! [`Device`](fidoh_core::Device) trait impls — the thin glue between
//! the CTAPHID state machine and the async-core surface.
//!
//! Design split: all protocol logic lives in `fsm`/`packet`/
//! `descriptor`/`sysfs`; this module maps:
//!
//! - `enumerate` — sysfs walk (design D7: usage-page filter, NO
//!   VID/PID filter), budget-bounded (`Phase::Enumeration`);
//! - `connect` — open the node + INIT allocation, budget-bounded
//!   (`Phase::Connect`), failing typed on a device without
//!   CAPABILITY_CBOR (design D6);
//! - `Device::send` — the keepalive surfacing loop with the
//!   ceremony's phase-renaming rule (UP_NEEDED seen → expiry names
//!   `UserPresence`);
//! - `Device::open_channel` / `close` — INIT re-handshake and the
//!   best-effort release (async-core OQ-3).

use alloc::string::String;
use alloc::vec::Vec;

use fidoh_core::device::{ChannelId, CtapCommand, Device, DeviceEvent};
use fidoh_core::sleep::SleepHandle;
use fidoh_core::time::Phase;
use fidoh_core::transport::{DeviceId, DeviceInfo, Transport};
use fidoh_core::{Deadline, Error};

use crate::consts::{CAPABILITY_WINK, CMD_CBOR, CMD_PING, CMD_WINK, STATUS_UPNEEDED};
use crate::error::{Capability, FramingError, HidError};
use crate::fd::{open_node, RawFd};
use crate::fsm::{cbor_payload, Frame, Fsm, FsmError, TransactionOutcome};

/// Default per-read wait slice: re-exported from fidoh-core so the
/// crate surfaces one knob (async-core OQ-2 resolution: a tunable
/// named constant, not a scattered literal).
pub use fidoh_core::DEFAULT_WAIT_SLICE as WAIT_SLICE;

/// The Linux hidraw CTAPHID transport.
///
/// Cloneable (`Send + Sync`); every [`Transport::connect`] opens its
/// own device node and allocates its own channel, matching the
/// kernel's multi-client hidraw model (CTAP2.1 §11.2.3).
#[derive(Clone, Default)]
pub struct HidTransport {
    /// Override for the sysfs root (fixture trees in tests; `None` =
    /// the real `/sys`).
    sysfs_root: Option<String>,
}

impl HidTransport {
    /// The production transport.
    pub fn new() -> Self {
        Self::default()
    }

    /// A transport reading sysfs under `root` instead of `/sys`
    /// (integration tests against fixture trees).
    pub fn rooted(root: &str) -> Self {
        Self {
            sysfs_root: Some(String::from(root)),
        }
    }
}

impl Transport for HidTransport {
    type Device = HidDevice;

    async fn enumerate(
        &self,
        deadline: &Deadline,
        _sleep: SleepHandle<'_>,
    ) -> Result<Vec<DeviceInfo>, Error> {
        // The sysfs walk is nonblocking file I/O (design §Blocking
        // waits, row 8); the budget check here is the bound. A scan
        // found before expiry is not delivered after it.
        if deadline.remaining().is_zero() {
            return Err(Error::Timeout(Phase::Enumeration));
        }
        let reader = match &self.sysfs_root {
            None => crate::sysfs_fs::FsSysfs::system(),
            Some(root) => crate::sysfs_fs::FsSysfs::rooted(root),
        };
        let (candidates, _diagnostics) = crate::sysfs::walk(&reader, "/sys/class/hidraw");
        // Per-node failures were already degraded to diagnostics inside
        // `walk` (spec scenario "Unreadable report descriptor degrades,
        // not fails"); candidates are returned regardless. Diagnostics
        // are observable via `enumerate_with_diag` for callers that
        // want them; the plain trait surface keeps the async-core
        // signature.
        Ok(candidates
            .into_iter()
            .map(|entry| DeviceInfo {
                id: DeviceId::new(entry.dev_path.clone()),
                // No product string before INIT (hidraw exposes none);
                // the uevent HID_NAME is the best human-readable
                // metadata (async-core DeviceInfo doc).
                name: entry.hid_name.clone().unwrap_or(entry.name),
                aaguid: None,
            })
            .collect())
    }

    async fn connect(
        &self,
        id: &DeviceId,
        deadline: &Deadline,
        sleep: SleepHandle<'_>,
    ) -> Result<Self::Device, Error> {
        // Open the node the DeviceId names (the enumeration's
        // /dev/hidrawN path). open failure carries the path + cause.
        let raw = open_node(id.as_str()).map_err(HidError::into_core)?;
        let mut fsm = Fsm::new(raw);
        let info = fsm
            .allocate(deadline, sleep)
            .await
            .map_err(FsmError::into_core)?;
        // Capability gate at connect time (design D6): no CBOR bit →
        // the device cannot serve CTAP2 at all.
        if !info.capabilities.cbor() {
            return Err(HidError::NoCbor.into_core());
        }
        Ok(HidDevice {
            fsm,
            channel: ChannelId(info.cid),
            capabilities: info.capabilities,
        })
    }
}

/// A connected CTAPHID device handle: one hidraw fd + one allocated
/// channel. Generic over the fd layer so the fake-fd tests drive the
/// trait impls without hardware; the production alias is
/// `HidDevice<crate::fd::HidRawFile>` (the `Transport` associated
/// type).
pub struct HidDevice<F: RawFd = crate::fd::HidRawFile> {
    fsm: Fsm<F>,
    channel: ChannelId,
    capabilities: Capability,
}

impl<F: RawFd> HidDevice<F> {
    /// Wrap an already-handshaken FSM (tests drive the Device layer
    /// against a fake fd; production code goes through
    /// `HidTransport::connect`).
    pub fn from_fsm(fsm: Fsm<F>, channel: ChannelId, capabilities: Capability) -> Self {
        Self {
            fsm,
            channel,
            capabilities,
        }
    }

    /// The allocated channel (CTAP2.1 §11.2.3).
    pub fn channel(&self) -> ChannelId {
        self.channel
    }

    /// The INIT capabilities byte, parsed (§11.2.9.1.3).
    pub fn capabilities(&self) -> Capability {
        self.capabilities
    }

    /// Run one CTAPHID_CBOR exchange, surfacing keepalives and
    /// applying the phase-renaming rule (once UP_NEEDED was seen the
    /// observable wait IS user presence, so expiry names
    /// `UserPresence` — mirroring the ceremony's rename).
    async fn exchange(
        &mut self,
        payload: &[u8],
        base_phase: Phase,
        deadline: &Deadline,
        sleep: SleepHandle<'_>,
    ) -> Result<DeviceEvent, Error> {
        let mut seen_up = false;
        // One transaction: busy retries live INSIDE `Fsm::transaction`
        // (§11.2.9.1.6); a keepalive never ends a transaction
        // (§11.2.9.1.7), so this hop resolves in a single pass.
        {
            let phase = if seen_up {
                Phase::UserPresence
            } else {
                base_phase
            };
            let outcome = self
                .fsm
                .transaction(CMD_CBOR, payload, phase, deadline, sleep, |status| {
                    if status == STATUS_UPNEEDED {
                        seen_up = true;
                    }
                })
                .await;
            match outcome {
                Ok(TransactionOutcome::Done(Frame::Cbor(response))) => {
                    // CTAP response payload: status byte first
                    // (§11.2.9.1.2 message layout); body is the rest.
                    let (status, body) = match response.split_first() {
                        Some((s, rest)) => (*s, rest.to_vec()),
                        // An empty CBOR payload is a protocol violation;
                        // model it as an unknown status rather than
                        // guessing success.
                        None => (fidoh_core::StatusCode::Other.to_u8(), Vec::new()),
                    };
                    Ok(DeviceEvent::Response { status, body })
                }
                Ok(TransactionOutcome::Done(_)) => {
                    // Wrong frame type for CBOR: ERR_INVALID_CMD class.
                    Err(HidError::Framing(FramingError::UnexpectedCommand {
                        got: 0,
                        expected: CMD_CBOR,
                    })
                    .into_core())
                }
                Ok(TransactionOutcome::DeviceError(code)) => {
                    Err(HidError::Device(code).into_core())
                }
                Err(e) => {
                    // Budget expiry (and every other terminal error)
                    // cancels the pending transaction best-effort on
                    // the way out (async-core OQ-3); a swallowed error
                    // never masks the typed outcome.
                    let _ = self.fsm.send_cancel();
                    Err(e.into_core())
                }
            }
        }
    }

    /// CTAPHID_WINK (§11.2.9.2.1), gated on CAPABILITY_WINK
    /// (§11.2.9.1.3): refused typed without writing when not
    /// advertised (spec scenario "Wink refused when not advertised").
    pub async fn wink(&mut self, deadline: &Deadline, sleep: SleepHandle<'_>) -> Result<(), Error> {
        if self.capabilities.0 & CAPABILITY_WINK == 0 {
            return Err(HidError::UnsupportedOperation {
                required: Capability(CAPABILITY_WINK),
            }
            .into_core());
        }
        let phase = Phase::CommandExchange;
        match self
            .fsm
            .transaction(CMD_WINK, &[], phase, deadline, sleep, |_| {})
            .await
        {
            Ok(TransactionOutcome::Done(Frame::Wink)) => Ok(()),
            Ok(TransactionOutcome::Done(_)) => {
                Err(Error::Transport(fidoh_core::TransportError::new(
                    "hid",
                    String::from("wink answered with a non-wink frame"),
                )))
            }
            Ok(TransactionOutcome::DeviceError(code)) => Err(HidError::Device(code).into_core()),
            Err(e) => Err(e.into_core()),
        }
    }

    /// CTAPHID_PING (§11.2.9.1.1) — not a v1 ceremony command; the
    /// hardware probe suite uses it as an echo sanity check. Verifies
    /// the echo (§11.2.9.1.1: the data sent is returned).
    pub async fn ping(
        &mut self,
        payload: &[u8],
        deadline: &Deadline,
        sleep: SleepHandle<'_>,
    ) -> Result<Vec<u8>, Error> {
        let phase = Phase::CommandExchange;
        match self
            .fsm
            .transaction(CMD_PING, payload, phase, deadline, sleep, |_| {})
            .await
        {
            Ok(TransactionOutcome::Done(Frame::Ping(echo))) => {
                if echo != payload {
                    return Err(HidError::Framing(FramingError::PingEchoMismatch).into_core());
                }
                Ok(echo)
            }
            Ok(TransactionOutcome::Done(_)) => {
                Err(Error::Transport(fidoh_core::TransportError::new(
                    "hid",
                    String::from("ping answered with a non-ping frame"),
                )))
            }
            Ok(TransactionOutcome::DeviceError(code)) => Err(HidError::Device(code).into_core()),
            Err(e) => Err(e.into_core()),
        }
    }

    /// The channel's INIT-resync escape hatch (§11.2.5.3), exposed for
    /// error recovery by callers owning a longer-lived connection.
    pub async fn resync(
        &mut self,
        deadline: &Deadline,
        sleep: SleepHandle<'_>,
    ) -> Result<ChannelId, Error> {
        let info = self
            .fsm
            .resync(deadline, sleep)
            .await
            .map_err(FsmError::into_core)?;
        self.channel = ChannelId(info.cid);
        self.capabilities = info.capabilities;
        if !info.capabilities.cbor() {
            return Err(HidError::NoCbor.into_core());
        }
        Ok(self.channel)
    }
}

// `F: Send` because the `Device` trait's futures are `Send` by
// design (async-core A4); the fd they own (std `File`) moves with the
// future between executor threads.
impl<F: RawFd + Send> Device for HidDevice<F> {
    async fn send(
        &mut self,
        cmd: &CtapCommand,
        deadline: &Deadline,
        sleep: SleepHandle<'_>,
    ) -> Result<DeviceEvent, Error> {
        // CBOR gate (design D6): checked before every CTAP2 command.
        self.fsm.ensure_cbor_ready().map_err(FsmError::into_core)?;
        let payload = match cmd {
            // authenticatorGetInfo: command byte 0x04, no body
            // (CTAP2.1 §6.4).
            CtapCommand::GetInfo => cbor_payload(0x04, &[]),
            CtapCommand::GetAssertion(request) => {
                // authenticatorGetAssertion: command byte 0x02 with the
                // §6.2 request as body.
                let body = request.encode().map_err(|e| {
                    Error::Transport(fidoh_core::TransportError::new(
                        "hid",
                        alloc::format!("getAssertion request encode: {e}"),
                    ))
                })?;
                cbor_payload(0x02, &body)
            }
        };
        // Oversized outgoing messages are rejected INSIDE
        // transaction→encode_message before any packet is written
        // (spec scenario "Oversized message rejected before
        // transmission").
        let base = match cmd {
            CtapCommand::GetInfo => Phase::GetInfo,
            CtapCommand::GetAssertion(_) => Phase::GetAssertion,
        };
        self.exchange(&payload, base, deadline, sleep).await
    }

    async fn open_channel(
        &mut self,
        deadline: &Deadline,
        sleep: SleepHandle<'_>,
    ) -> Result<ChannelId, Error> {
        // INIT on the allocated cid = §11.2.5.3 resync (also the
        // re-handshake path after errors; never allocated → it is the
        // initial allocation).
        self.resync(deadline, sleep).await
    }

    async fn close(mut self) -> Result<(), Error> {
        // Mandatory best-effort release (async-core OQ-3, resolved):
        // CANCEL drops any pending transaction on the device (ignored
        // when none is outstanding, §11.2.9.1.5). The attempt is
        // real I/O with no new budget — if it fails, the error is
        // reported here but swallowable: the channel state resets on
        // the next connect's INIT (§11.2.5.3) either way. This close
        // path performs no waiting, so no Sleep is needed.
        self.fsm.send_cancel().map_err(HidError::into_core)?;
        Ok(())
    }
}
