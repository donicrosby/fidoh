//! Transport discovery, device selection, and the [`Transport`] trait
//! (async-core spec: "Transport trait for device discovery and
//! connection").
//!
//! Discovery NEVER triggers implicit selection (stack invariant:
//! "Explicit, deterministic device selection"): callers pick a device
//! with a [`SelectionPolicy`], and the default policy is `Fail` with a
//! typed [`Error::AmbiguousDevice`](crate::error::Error) listing every
//! candidate.
//!
//! `Transport` is associated-type + RPITIT by design (design D1/A3):
//! monomorphized at call sites, NOT object-safe in v1. Only
//! [`Sleep`](crate::sleep::Sleep) crosses as `dyn`.

use alloc::string::String;
use alloc::vec::Vec;
use core::future::Future;

use crate::device::Device;
use crate::error::Error;
use crate::sleep::SleepHandle;

/// Opaque transport-specific device identifier.
///
/// A displayable token (hidraw path, PC/SC reader name, soft-token
/// slot) usable with [`Transport::connect`]. Comparison is by value;
/// equality of two ids means "same underlying device per this
/// transport".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceId(pub(crate) String);

impl DeviceId {
    /// Wrap a transport-specific id string.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The identifier string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Human-readable metadata for a discovered device (async-core spec:
/// "`enumerate` ... returning a list of discovered candidate devices
/// (with identifiers and human-readable metadata)").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    /// Transport-specific device identifier for [`Transport::connect`].
    pub id: DeviceId,
    /// Human-readable name, e.g. product string or reader name.
    pub name: String,
    /// AAGUID if the transport can supply it without opening the
    /// device (hidraw exposes none before INIT; some transports may).
    pub aaguid: Option<[u8; 16]>,
}

impl DeviceInfo {
    /// The candidate descriptor for this device, as carried by
    /// `Error::AmbiguousDevice`.
    pub fn descriptor(&self) -> CandidateDescriptor {
        CandidateDescriptor {
            id: self.id.clone(),
            name: self.name.clone(),
            aaguid: self.aaguid,
        }
    }
}

/// A candidate device, as listed by
/// [`Error::AmbiguousDevice`](crate::error::Error) — every candidate's
/// identifier and metadata (async-core spec: "a typed `AmbiguousDevice`
/// error containing every candidate's identifier and metadata").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateDescriptor {
    /// Transport-specific device identifier.
    pub id: DeviceId,
    /// Human-readable metadata.
    pub name: String,
    /// AAGUID when known without opening the device.
    pub aaguid: Option<[u8; 16]>,
}

impl core::fmt::Display for CandidateDescriptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?} ({})", self.id, self.name)
    }
}

/// Explicit device selection policy (stack invariant: "Caller provides
/// a selection policy (`First | Select(fn) | Fail`); default is Fail
/// with a typed `AmbiguousDevice` error listing candidates").
///
/// Constructed via the variants; `Select` wraps a caller predicate
/// that returns `Some(descriptor)` for the chosen candidate. The
/// policy is applied by the CALLER (or by the later ceremony crate
/// logic); this type carries the choice.
#[derive(Default)]
pub enum SelectionPolicy {
    /// Take the first enumerated candidate (deterministic transport
    /// order).
    First,
    /// Let the caller pick among all candidates; returning `None`
    /// declines every candidate and yields
    /// [`Error::UnknownDevice`](crate::error::Error) for the selected
    /// absent device.
    Select(fn(&[CandidateDescriptor]) -> Option<CandidateDescriptor>),
    /// Fail with `Error::AmbiguousDevice` when more than one candidate
    /// exists (the default).
    #[default]
    Fail,
}

impl core::fmt::Display for SelectionPolicy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::First => f.write_str("first"),
            Self::Select(_) => f.write_str("select(fn)"),
            Self::Fail => f.write_str("fail"),
        }
    }
}

/// Apply a selection policy to an enumerated candidate list.
///
/// Returns:
/// - `Ok(Some(descriptor))` — a device was selected;
/// - `Ok(None)` — zero candidates, nothing to select;
/// - `Err(Error::AmbiguousDevice(_))` — multiple candidates under the
///   default `Fail` policy, carrying every candidate.
///
/// `Select` requires exactly the selected descriptor to still be in
/// the list (it is re-validated so a stale pointer cannot slip
/// through). This function is the ONLY place implicit selection could
/// happen, and it never picks silently: the policy is explicit at the
/// call site.
pub fn apply_selection(
    policy: &SelectionPolicy,
    candidates: &[CandidateDescriptor],
) -> Result<Option<CandidateDescriptor>, Error> {
    match policy {
        SelectionPolicy::First => match candidates {
            [] => Ok(None),
            [first, ..] => Ok(Some(first.clone())),
        },
        SelectionPolicy::Select(f) => match f(candidates) {
            Some(picked) => {
                if candidates.contains(&picked) {
                    Ok(Some(picked))
                } else {
                    // A pick outside the enumerated set is an invalid
                    // selection; surface it as an unknown device rather
                    // than silently proceeding.
                    Err(Error::UnknownDevice(picked.id))
                }
            }
            None => Ok(None),
        },
        // Default: refuse to pick among multiple candidates; a single
        // candidate under `Fail` is unambiguous and proceeds.
        SelectionPolicy::Fail => match candidates {
            [] => Ok(None),
            [only] => Ok(Some(only.clone())),
            many => Err(Error::AmbiguousDevice(many.to_vec())),
        },
    }
}

/// A transport: device enumeration and connection (async-core spec:
/// "Transport trait for device discovery and connection").
///
/// Implemented by the transport crates (`fidoh-transport-hid`,
/// `fidoh-transport-pcsc`, `fidoh-transport-soft`) and generic at
/// ceremony call sites (design D1: associated-type + RPITIT, not
/// object-safe in v1).
///
/// Both operations are deadline-bounded by the single ceremony budget:
/// they receive the budget by shared reference and
/// [`consume`](crate::time::Deadline::consume_slice) their wait slices
/// from it. Expiry surfaces as
/// [`Error::Timeout(Phase::Enumeration)`](crate::error::Error) /
/// [`Error::Timeout(Phase::Connect)`](crate::error::Error).
pub trait Transport {
    /// The connected-device type this transport hands back.
    type Device: Device;

    /// Enumerate candidate devices.
    ///
    /// Returns within the caller-supplied deadline (async-core spec:
    /// "returns within the caller-supplied deadline and yields either
    /// a (possibly empty) list of `DeviceInfo` records or a typed
    /// error; it never blocks unboundedly").
    fn enumerate(
        &self,
        deadline: &crate::time::Deadline,
        sleep: SleepHandle,
    ) -> impl Future<Output = Result<Vec<DeviceInfo>, Error>> + Send;

    /// Connect to the device with the given identifier, bounded by the
    /// remaining budget.
    ///
    /// Dropping the returned future before completion must leave the
    /// underlying authenticator usable by a subsequent `connect`
    /// (async-core spec: "a dropped connect future SHALL leave the
    /// underlying authenticator usable by a subsequent `connect`").
    fn connect(
        &self,
        id: &DeviceId,
        deadline: &crate::time::Deadline,
        sleep: SleepHandle,
    ) -> impl Future<Output = Result<Self::Device, Error>> + Send;
}

/// The transport kind, for diagnostics carrying per-transport detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransportKind {
    /// CTAPHID over USB HID (CTAP2.1 §8.1) — `fidoh-transport-hid`.
    Hid,
    /// ISO 7816-4 APDU over CCID or NFC (CTAP2.1 §11) —
    /// `fidoh-transport-pcsc`.
    Pcsc,
    /// In-process software token (the CI harness) —
    /// `fidoh-transport-soft`.
    Soft,
}

impl core::fmt::Display for TransportKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Hid => f.write_str("hid"),
            Self::Pcsc => f.write_str("pcsc"),
            Self::Soft => f.write_str("soft"),
        }
    }
}
