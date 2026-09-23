//! Rendering: turning the typed world into the human surface (design
//! D6: exit codes are taxonomy-driven — 0 success including "no
//! devices" on `list`, non-zero typed error path; text is for humans,
//! grep is for scripts).
//!
//! Every error exit renders
//!
//! ```text
//! error: <typed variant>[ naming <phase> phase]
//! hint:  <remediation, where the taxonomy carries one>
//! ```
//!
//! `AmbiguousDevice` additionally prints one descriptor line per
//! candidate (spec scenario "Ambiguous selection renders hint and
//! candidates"). The renderer is pure (bytes in → lines out) so tests
//! assert on strings without spawning anything.

use std::format;
use std::string::String;
use std::vec::Vec;

use fidoh_core::error::CeremonyError;
use fidoh_core::time::Phase;
use fidoh_core::transport::CandidateDescriptor;

/// "error:" / "hint:" line labels (grep anchors for scripts).
pub const ERROR_TAG: &str = "error:";
pub const HINT_TAG: &str = "hint:";

/// A renderer output line, split so tests can assert tag/subject
/// separately from formatting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    /// The whole line, exactly as printed.
    pub text: String,
}

/// The typed-variant name of a ceremony error (the taxonomy IS the
/// error surface, design D6 — no numeric codes invented).
pub fn variant_name(err: &CeremonyError) -> &'static str {
    match err {
        CeremonyError::NoDevice(_) => "NoDevice",
        CeremonyError::AmbiguousDevice(_) => "AmbiguousDevice",
        CeremonyError::UserActionTimeout => "UserActionTimeout",
        CeremonyError::UserCancelled => "UserCancelled",
        CeremonyError::NoCredentials => "NoCredentials",
        CeremonyError::UpRejected => "UpRejected",
        CeremonyError::Timeout(_) => "Timeout",
        CeremonyError::Transport(_) => "Transport",
        CeremonyError::Ctap(_) => "Ctap",
        CeremonyError::CredentialMismatch { .. } => "CredentialMismatch",
    }
}

/// The phase a `Timeout` names, if this error is a timeout.
pub fn timeout_phase(err: &CeremonyError) -> Option<Phase> {
    match err {
        CeremonyError::Timeout(phase) => Some(*phase),
        _ => None,
    }
}

/// The remediation hint carried by the taxonomy for this error, if any
/// (spec: "the remediation hint where the taxonomy carries one").
pub fn remediation_hint(err: &CeremonyError) -> Option<String> {
    match err {
        CeremonyError::AmbiguousDevice(_) => Some(String::from(
            "pick one device explicitly: --first, or disconnect all but one token",
        )),
        CeremonyError::NoDevice(_) => Some(String::from(
            "attach a token (or check pcscd is running for readers); `fidoh list` shows why each transport found nothing",
        )),
        CeremonyError::UserActionTimeout => Some(String::from(
            "the token gave up waiting — retry and touch it promptly",
        )),
        CeremonyError::UserCancelled => Some(String::from(
            "the pending operation was cancelled (another client or the token itself) — retry",
        )),
        CeremonyError::NoCredentials => Some(String::from(
            "no credential for this rpId on the token — register first, or pass --allow with an id it holds",
        )),
        CeremonyError::UpRejected => Some(String::from(
            "the token refused presence/verification (pin/uv policies are out of scope for this tool) — retry the touch",
        )),
        CeremonyError::Timeout(_) => Some(String::from(
            "raise --budget if the ceremony genuinely needs longer",
        )),
        CeremonyError::Transport(_) => Some(String::from(
            "`fidoh list` shows per-transport diagnostics for the failing layer",
        )),
        CeremonyError::Ctap(_) => None,
        CeremonyError::CredentialMismatch { .. } => Some(String::from(
            "the token returned a credential outside the allow list — verify the --allow ids",
        )),
    }
}

/// The candidate descriptor lines for an `AmbiguousDevice` payload
/// (one per candidate, in discovery order).
pub fn candidate_lines(candidates: &[CandidateDescriptor]) -> Vec<String> {
    candidates
        .iter()
        .map(|c| format!("  candidate: {c}"))
        .collect()
}

/// Render a ceremony error into its full multi-line form: variant
/// (+phase), per-candidate lines where carried, hint where carried.
pub fn error_lines(err: &CeremonyError) -> Vec<String> {
    let mut out = Vec::new();
    let variant = variant_name(err);
    let head = match timeout_phase(err) {
        Some(phase) => format!("{ERROR_TAG} {variant} naming the {phase} phase"),
        None => format!("{ERROR_TAG} {variant}"),
    };
    out.push(head);
    // Context lines the payload carries.
    match err {
        CeremonyError::AmbiguousDevice(candidates) => {
            out.extend(candidate_lines(candidates));
        }
        CeremonyError::NoDevice(diag) => {
            for d in diag {
                out.push(format!("  {}: {}", d.kind, d.cause));
            }
        }
        CeremonyError::CredentialMismatch { returned, allowed } => {
            out.push(format!("  returned: {}", HexBrief(returned),));
            out.push(format!("  allowed:  {}", HexIdList(allowed)));
        }
        _ => {}
    }
    if let Some(hint) = remediation_hint(err) {
        out.push(format!("{HINT_TAG} {hint}"));
    }
    out
}

/// First-4-byte truncated-safe hex (matches the core's truncation
/// discipline for CredentialMismatch context).
struct HexBrief<'a>(&'a [u8]);

impl core::fmt::Display for HexBrief<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:02x}", self.0.first().copied().unwrap_or(0))?;
        if self.0.len() > 1 {
            write!(f, "{:02x}", self.0[1])?;
        }
        write!(f, "…({} bytes)", self.0.len())
    }
}

struct HexIdList<'a>(&'a [Vec<u8>]);

impl core::fmt::Display for HexIdList<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for (i, id) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{}", HexBrief(id))?;
        }
        Ok(())
    }
}

/// The hex block for a successful assertion (spec: "print relying-party
/// id, credential id (hex), user-selected flag when present, and the
/// authData + signature as hex").
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use fidoh_core::error::{DiscoveryDiagnostic, Error, TransportError};
    use fidoh_core::transport::{DeviceId, TransportKind};

    fn candidate(id: &str, name: &str) -> CandidateDescriptor {
        CandidateDescriptor {
            id: DeviceId::new(id),
            name: String::from(name),
            aaguid: None,
        }
    }

    #[test]
    fn ambiguous_renders_hint_and_one_line_per_candidate() {
        let err = CeremonyError::AmbiguousDevice(vec![
            candidate("/dev/hidraw0", "YubiKey"),
            candidate("reader-b", "NFC reader"),
        ]);
        assert_eq!(variant_name(&err), "AmbiguousDevice");
        let lines = error_lines(&err);
        assert_eq!(lines[0], "error: AmbiguousDevice");
        assert!(lines
            .iter()
            .any(|l| l.contains("candidate: ") && l.contains("/dev/hidraw0")));
        assert!(lines
            .iter()
            .any(|l| l.contains("candidate: ") && l.contains("reader-b")));
        assert!(lines.iter().any(|l| l.starts_with("hint: ")));
    }

    #[test]
    fn timeout_renders_phase_name() {
        let err = CeremonyError::Timeout(Phase::UserPresence);
        assert_eq!(variant_name(&err), "Timeout");
        let lines = error_lines(&err);
        assert_eq!(lines[0], "error: Timeout naming the user-presence phase");
        assert!(lines.iter().any(|l| l.starts_with("hint: ")));
    }

    #[test]
    fn no_device_renders_per_transport_causes() {
        let err = CeremonyError::NoDevice(vec![
            DiscoveryDiagnostic::new(
                TransportKind::Hid,
                Error::Transport(TransportError::new(
                    "hid",
                    String::from("open /dev/hidraw0: boom"),
                )),
            ),
            DiscoveryDiagnostic::new(
                TransportKind::Pcsc,
                Error::Transport(TransportError::new(
                    "pcsc",
                    String::from("list: no-service cause"),
                )),
            ),
        ]);
        let lines = error_lines(&err);
        assert_eq!(lines[0], "error: NoDevice");
        assert!(lines
            .iter()
            .any(|l| l.contains("hid: ") && l.contains("boom")));
        assert!(lines
            .iter()
            .any(|l| l.contains("pcsc: ") && l.contains("no-service")));
    }

    #[test]
    fn ctap_carries_no_hint() {
        let err = CeremonyError::Ctap(fidoh_core::StatusCode::ChannelBusy);
        assert_eq!(variant_name(&err), "Ctap");
        assert!(remediation_hint(&err).is_none());
        assert!(error_lines(&err).iter().all(|l| !l.starts_with("hint:")));
    }

    #[test]
    fn hex_encoding() {
        assert_eq!(hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex(&[]), "");
    }
}
