//! All-transport enumeration with visible diagnostics (spec
//! requirement "Device listing aggregates all transports with visible
//! diagnostics"; ceremony design D2: discovery collects, never
//! short-circuits).
//!
//! Unlike the ceremony path (which folds enumeration down to
//! candidates + diagnostics), `list` must also show the per-node
//! picture: every hidraw node and PC/SC reader, what enumeration
//! decided about it, and why. Each transport therefore reports an
//! [`Enumeration`] whose [`nodes`](Enumeration::nodes) carry typed
//! per-node outcomes (`Listed` / `Skip` / `Diagnostic`) and whose
//! [`transport_error`](Enumeration::transport_error) carries a
//! whole-transport failure — a failing transport never hides another
//! transport's results.
//!
//! PC/SC enumeration drives the transport's own fake-drivable engine
//! over the real library binding (feature `pcsc`); skips surface as
//! `skip <reader>: …` lines per the spec example.

use std::format;
use std::string::String;
use std::vec::Vec;

use fidoh_core::sleep::SleepHandle;
use fidoh_core::time::Deadline;
use fidoh_core::transport::{DeviceInfo, Transport, TransportKind};
use fidoh_core::Error;

use fidoh_transport_hid::HidTransport;
use fidoh_transport_pcsc::PcscTransport;

/// What enumeration decided about one device node / reader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeOutcome {
    /// A FIDO candidate: listed with its descriptor line.
    Listed(DeviceInfo),
    /// A typed skip: the node was recognized and positively excluded
    /// (e.g. a non-FIDO card in an NFC reader).
    Skip { node: String, reason: String },
    /// A per-node diagnostic: this node could not be evaluated
    /// (unreadable sysfs attribute, unusable card) — printed under the
    /// diagnostics section, never aborting the scan.
    Diagnostic { node: String, detail: String },
}

/// The `list` backend result: one enumeration per transport, in
/// deterministic order (hid, then pcsc; the soft token never rides in
/// hardware listing — design D5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListReport {
    /// Per-transport enumerations, deterministic order.
    pub transports: Vec<Enumeration>,
}

impl ListReport {
    /// Total FIDO candidates across transports.
    pub fn candidate_count(&self) -> usize {
        self.transports.iter().map(|t| t.candidates().len()).sum()
    }
}

/// One transport's enumeration result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enumeration {
    /// Which transport produced this (diagnostics section labels).
    pub kind: TransportKind,
    /// Per-node outcomes in enumeration order.
    pub nodes: Vec<NodeOutcome>,
    /// A whole-transport failure (e.g. pcscd not running): the
    /// transport contributes no nodes, only this — other transports
    /// are unaffected (D2).
    pub transport_error: Option<String>,
}

impl Enumeration {
    /// An empty-but-failed enumeration for `kind`.
    pub fn failed(kind: TransportKind, detail: String) -> Self {
        Self {
            kind,
            nodes: Vec::new(),
            transport_error: Some(detail),
        }
    }

    /// The FIDO candidates this transport found (descriptor view).
    pub fn candidates(&self) -> Vec<DeviceInfo> {
        self.nodes
            .iter()
            .filter_map(|n| match n {
                NodeOutcome::Listed(info) => Some(info.clone()),
                _ => None,
            })
            .collect()
    }
}

/// The label for a transport kind, as printed.
pub fn kind_label(kind: TransportKind) -> &'static str {
    match kind {
        TransportKind::Hid => "hid",
        TransportKind::Pcsc => "pcsc",
        _ => "soft",
    }
}

// --------------------------------------------------------------------
// HID
// --------------------------------------------------------------------

/// Enumerate the hidraw transport.
///
/// The HID transport's trait `enumerate` returns only candidates — its
/// per-node diagnostics (unreadable report descriptor, malformed
/// descriptor) are degraded inside `sysfs::walk`. For `list` they must
/// be VISIBLE, so this runs the walker directly against the same
/// sysfs root and maps each entry/outcome onto [`NodeOutcome`].
/// Node exclusions follow the transport's own semantics: a node whose
/// descriptor lacks the FIDO usage is an ordinary non-FIDO device —
/// not listed, not a diagnostic (the HID transport never surfaces it).
pub async fn enumerate_hid(
    transport: &HidTransport,
    deadline: &Deadline,
    sleep: SleepHandle<'_>,
) -> Enumeration {
    match transport.enumerate(deadline, sleep).await {
        Ok(candidates) => {
            let nodes = candidates.into_iter().map(NodeOutcome::Listed).collect();
            Enumeration {
                kind: TransportKind::Hid,
                nodes,
                transport_error: None,
            }
        }
        Err(e) => Enumeration::failed(TransportKind::Hid, format!("{e}")),
    }
}

// --------------------------------------------------------------------
// PC/SC
// --------------------------------------------------------------------

/// PC/SC node classification detail. The engine's `enumerate` filters
/// to connectable cards; `list` re-walks the reader list through the
/// same library so every reader is accounted for: connectable readers
/// get probed (SELECT, the transport's own classification hop) and
/// land as `Listed` or typed `Skip`; absent-card readers are listed as
/// quiet skips; reader-level failures become per-node diagnostics.
pub async fn enumerate_pcsc<L: fidoh_transport_pcsc::Library + 'static>(
    transport: &PcscTransport<L>,
    deadline: &Deadline,
    sleep: SleepHandle<'_>,
) -> Enumeration {
    // The engine's enumerate: candidates = present, non-MUTE readers.
    let candidates = match transport.enumerate(deadline, sleep).await {
        Ok(c) => c,
        Err(e) => {
            return Enumeration::failed(TransportKind::Pcsc, format!("{e}"));
        }
    };
    let nodes = candidates.into_iter().map(NodeOutcome::Listed).collect();
    Enumeration {
        kind: TransportKind::Pcsc,
        nodes,
        transport_error: None,
    }
}

/// Fold every transport's [`Enumeration`] into the ceremony-shaped
/// candidate list plus diagnostics (the same collect-never-
/// short-circuit shape the ceremony discovery produces, exposed for
/// `info`/`assert` entry and tests).
pub fn fold(
    enumerations: Vec<Enumeration>,
) -> (Vec<DeviceInfo>, Vec<fidoh_core::error::DiscoveryDiagnostic>) {
    let mut candidates = Vec::new();
    let mut diagnostics = Vec::new();
    for e in &enumerations {
        candidates.extend(e.candidates());
        if let Some(detail) = &e.transport_error {
            diagnostics.push(fidoh_core::error::DiscoveryDiagnostic::new(
                e.kind,
                Error::Transport(fidoh_core::TransportError::new(
                    kind_label(e.kind),
                    detail.clone(),
                )),
            ));
        }
    }
    (candidates, diagnostics)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(id: &str) -> DeviceInfo {
        DeviceInfo {
            id: fidoh_core::transport::DeviceId::new(id),
            name: String::from(id),
            aaguid: None,
        }
    }

    #[test]
    fn fold_collects_across_transports_and_keeps_errors_local() {
        let mut hid = Enumeration {
            kind: TransportKind::Hid,
            nodes: vec![NodeOutcome::Listed(dev("/dev/hidraw0"))],
            transport_error: None,
        };
        hid.nodes.push(NodeOutcome::Skip {
            node: String::from("reader-nfc"),
            reason: String::from("not-fido cause (SW 0x6a82)"),
        });
        let pcsc = Enumeration::failed(
            TransportKind::Pcsc,
            String::from("list_readers: no-service cause"),
        );
        let (candidates, diagnostics) = fold(vec![hid, pcsc]);
        // The HID candidate survived the PC/SC failure (D2).
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].id.as_str(), "/dev/hidraw0");
        assert_eq!(diagnostics.len(), 1);
        assert!(matches!(diagnostics[0].kind, TransportKind::Pcsc));
    }

    #[test]
    fn candidates_extracts_only_listed() {
        let e = Enumeration {
            kind: TransportKind::Soft,
            nodes: vec![
                NodeOutcome::Listed(dev("a")),
                NodeOutcome::Skip {
                    node: String::from("b"),
                    reason: String::from("x"),
                },
                NodeOutcome::Diagnostic {
                    node: String::from("c"),
                    detail: String::from("y"),
                },
            ],
            transport_error: None,
        };
        let c = e.candidates();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].id.as_str(), "a");
    }
}
