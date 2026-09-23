//! The [`Ceremony`] trait: the single orchestration entry point
//! (async-core spec: "Ceremony trait for orchestration entry").
//!
//! A ceremony consumes a connected [`Device`], a [`Sleep`] factory, and
//! a single [`Deadline`] budget, and returns a typed output — the raw
//! getAssertion payload (CTAP2.1 §8.2) or the parsed getInfo structure
//! (CTAP2.1 §8.4). The library NEVER constructs `clientDataJSON` or
//! applies origin semantics: the caller supplies the
//! `clientDataHash` (WebAuthn L2 §6.5 is the RP's responsibility).
//!
//! Concrete ceremonies (the getAssertion runbook: getInfo probe →
//! exchange → keepalive drain) land with the ceremony change; this
//! module fixes the trait seam they implement.

use core::future::Future;

use crate::device::{CtapCommand, Device};
use crate::error::Error;
use crate::sleep::SleepHandle;
use crate::time::Deadline;

/// A ceremony: the orchestration entry over a connected device.
///
/// Generic in `D: Device` and RPITIT-`Send` per design D1/A4 — the
/// ceremony hot path stays monomorphized and alloc-free beyond the
/// response payload itself.
pub trait Ceremony {
    /// The typed ceremony output: the raw assertion for getAssertion
    /// (authenticatorData, signature, userHandle, credential id per
    /// CTAP2.1 §8.2) or the parsed info structure for getInfo
    /// (CTAP2.1 §8.4).
    type Output;

    /// Run the ceremony against `device`, bounded by the single
    /// caller-supplied `deadline` budget, with every wait driven
    /// through `sleep` (async-core spec: "a ceremony consumes a
    /// connected `Device`, a `Sleep` factory, and a single deadline
    /// budget").
    ///
    /// Expiry at any hop returns
    /// [`Error::Timeout(Phase)`](crate::error::Error) naming the phase
    /// (async-core spec: single-budget timeout model). Dropping the
    /// returned future mid-run is safe per the cancellation contract:
    /// no poisoned state, the device remains usable for a subsequent
    /// ceremony (worst case after one channel re-handshake, CTAP2.1
    /// §8.1.4).
    ///
    /// `D: Send + 'static` is required so the run can be hosted by a
    /// `spawn_blocking`-style adapter (design D3): the device handle and
    /// its in-flight futures cross onto the blocking pool.
    fn run<D: Device + Send + 'static>(
        self,
        device: D,
        deadline: &Deadline,
        sleep: SleepHandle,
    ) -> impl Future<Output = Result<Self::Output, Error>> + Send;
}

/// A no-op ceremony: echoes one command exchange through the device.
///
/// Proof-of-seam for the trait (async-core spec: trait compile tests
/// "proving the seams exist... driving a trivial exchange through
/// them"): it shows a `Ceremony` driving a generic `D: Device` through
/// `send` with the budget + sleep plumbing exactly as the real
/// ceremonies will. Not a real ceremony — real orchestration logic is
/// the ceremony change's scope.
#[derive(Clone, Copy, Debug, Default)]
pub struct EchoCeremony;

impl Ceremony for EchoCeremony {
    type Output = crate::device::DeviceEvent;

    async fn run<D: Device + Send + 'static>(
        self,
        mut device: D,
        deadline: &Deadline,
        sleep: SleepHandle<'_>,
    ) -> Result<Self::Output, Error> {
        device.send(&CtapCommand::GetInfo, deadline, sleep).await
    }
}
