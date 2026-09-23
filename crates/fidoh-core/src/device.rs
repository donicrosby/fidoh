//! The [`Device`] trait: CTAP command exchange and channel lifecycle
//! (async-core spec: "Device trait for CTAP command exchange and
//! channel lifecycle").
//!
//! A `Device` is a connected authenticator handle from
//! [`Transport::connect`](crate::transport::Transport::connect). Every
//! operation takes the ceremony budget by shared reference and a
//! [`Sleep`](crate::sleep::Sleep) factory; keepalive statuses surface
//! as [`Progress`] values, not errors, until the deadline expires
//! (async-core spec: keepalives "handled inside the transport and
//! surfaced to the caller as progress signals, not errors, until the
//! deadline expires").
//!
//! Cancellation contract (async-core spec, OQ-3): dropping any device
//! future is safe — no poisoned state; a device dropped mid-operation
//! makes a best-effort release attempt, and a subsequent `connect` to
//! the same authenticator succeeds (worst case after one INIT
//! re-handshake, CTAP2.1 §8.1.4).

use core::future::Future;

use crate::error::Error;
use crate::sleep::SleepHandle;
use crate::time::{Deadline, Phase};

use alloc::vec::Vec;

/// A connected CTAP device handle.
///
/// Implemented by the per-transport device types (the `Device`
/// associated type of a `Transport`). RPITIT + `Send` futures per
/// design A4: bounds are visible at the trait so `fidoh-tokio`'s
/// `spawn_blocking` glue can rely on them.
pub trait Device {
    /// Send a CTAP command and await its response, bounded by the
    /// remaining budget.
    ///
    /// Keepalive waits are bounded by the remaining budget; expiry
    /// returns
    /// [`Error::Timeout(Phase::CommandExchange)`](crate::error::Error)
    /// (async-core spec: "the transport returns the parsed response or
    /// a typed error before the deadline; keepalive waits are bounded
    /// by the remaining budget and expiry returns `Error::Timeout`
    /// naming the command phase").
    ///
    /// Dropping the returned future mid-wait is safe: the in-flight
    /// wait terminates within its current
    /// [`Sleep`](crate::sleep::Sleep)-driven slice (async-core spec:
    /// "Drop mid-user-presence is safe"), and the device remains
    /// usable for a subsequent operation.
    fn send(
        &mut self,
        cmd: &CtapCommand,
        deadline: &Deadline,
        sleep: SleepHandle,
    ) -> impl Future<Output = Result<DeviceEvent, Error>> + Send;

    /// Open a channel on the transport (CTAPHID INIT negotiation per
    /// CTAP2.1 §8.1.4 for HID; APDU SELECT of the FIDO application per
    /// CTAP2.1 §11 for PC/SC), bounded by the remaining budget.
    ///
    /// Returns the negotiated channel identifier, or
    /// [`Error::Timeout(Phase::ChannelOpen)`](crate::error::Error) on
    /// expiry.
    fn open_channel(
        &mut self,
        deadline: &Deadline,
        sleep: SleepHandle,
    ) -> impl Future<Output = Result<ChannelId, Error>> + Send;

    /// Close the device, making a best-effort attempt to release the
    /// channel (CTAP2.1 §8.1.4 channel lifetime rules).
    ///
    /// The release attempt is mandatory (design OQ-3, resolved): if
    /// the release itself fails or the budget has already expired, the
    /// error is reported but swallowable — the channel release is
    /// still attempted.
    ///
    /// Dropping the device instead of calling `close` triggers the
    /// same best-effort release via [`Drop`] where the transport can
    /// do so without blocking (e.g. marking the channel for release);
    /// the awaitable close path is this method.
    fn close(self) -> impl Future<Output = Result<(), Error>> + Send;
}

/// A CTAP command in transit to a device.
///
/// v1 carries the two commands in scope (async-core spec: "for
/// authenticatorGetAssertion (CTAP2.1 §8.2) the raw assertion...; for
/// authenticatorGetInfo (CTAP2.1 §8.4) the parsed info structure") by
/// reference to the core-model request structures; the wire encoding
/// is delegated to those models (`get_assertion::GetAssertionRequest`,
/// `get_info` has no request payload beyond the leading command byte).
#[derive(Clone, Debug)]
pub enum CtapCommand {
    /// authenticatorGetInfo (CTAP2.1 §8.4 / §6.4). No request
    /// payload.
    GetInfo,
    /// authenticatorGetAssertion (CTAP2.1 §8.2 / §6.2) with the
    /// caller-validated request model.
    GetAssertion(crate::get_assertion::GetAssertionRequest),
}

impl CtapCommand {
    /// The phase this command's exchange belongs to, for typed
    /// timeouts.
    pub fn phase(&self) -> Phase {
        match self {
            Self::GetInfo => Phase::GetInfo,
            Self::GetAssertion(_) => Phase::GetAssertion,
        }
    }
}

/// What a [`Device::send`] resolved to.
///
/// Progress values (keepalive) are distinct from the terminal
/// response: keepalives are surfaced as progress signals, not errors,
/// per async-core spec. A caller loops on `send`-style awaits only via
/// this event stream — the transport performs the keepalive slicing
/// internally and reports each status as it arrives.
#[derive(Clone, Debug, PartialEq)]
pub enum DeviceEvent {
    /// CTAPHID keepalive status surfaced as progress (CTAP2.1
    /// §11.2.9.1.7: status byte 0x02 UPNEEDED in frames carrying cmd
    /// 0x3B); not an error, delivered so callers can update UI.
    Keepalive {
        /// The raw keepalive status byte (0x01 processing, 0x02
        /// UPNEEDED per CTAP2.1 §11.2.9.1.7).
        status: u8,
    },
    /// The terminal response payload: the CTAP2 status byte plus the
    /// response body for successful commands (CBOR payload; empty for
    /// authenticatorGetInfo per §8.4 response layout).
    Response {
        /// CTAP2 status byte (CTAP2.1 §8.2); 0x00 on success.
        status: u8,
        /// Response body bytes (CBOR payload for success; empty for
        /// non-zero status).
        body: Vec<u8>,
    },
}

/// The channel identifier negotiated at
/// [`Device::open_channel`](Device::open_channel) (CTAPHID CID per
/// CTAP2.1 §8.1.4; PC/SC has a logical per-connection channel).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChannelId(pub u32);
