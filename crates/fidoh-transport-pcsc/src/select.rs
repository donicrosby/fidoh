//! FIDO AID selection (CTAP2.1 §11.3.3) and its typed outcome.
//!
//! §11.3.3: "A client SHALL send a Select to the authenticator before
//! any other command", using AID = rid `A000000647` + pix `2F0001`
//! (byte-verified against the spec text; see design D3). The SELECT
//! response's status word classifies the reader:
//!
//! - `9000` → candidate (version string does NOT settle CTAP2
//!   capability — the mandatory getInfo probe, ceremony D3, decides);
//! - `6A82` / `6985` / `6283` → typed per-device skips
//!   (enumerate-and-skip, ceremony D2 collect-never-short-circuit);
//! - anything else → typed `Transport` errors carrying the raw SW.

use alloc::string::String;
use alloc::vec::Vec;

use fidoh_core::{Error, Phase, TransportError};

use crate::sw::StatusWord;

/// The FIDO authenticator AID: `A0000006472F0001` (CTAP2.1 §11.3.3;
/// rid `A000000647` — FIDO Alliance, pix `2F0001` — FIDO applet).
pub const FIDO_AID: [u8; 8] = [0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];

/// The version string §11.3.3 mandates when CTAP1/U2F is implemented
/// (`U2F_V2`); its presence does NOT decide CTAP2 capability.
pub const U2F_V2: &[u8] = b"U2F_V2";
/// The version string for CTAP2-only implementations (§11.3.3).
pub const FIDO_2_0: &[u8] = b"FIDO_2_0";

/// Encode the SELECT AID command APDU for the FIDO applet
/// (ISO 7816-4 SELECT by DF name: INS 0xA4, P1 0x04, P2 0x00, data =
/// AID, Le 256-short so the full version string returns).
///
/// Pure: returns the exact wire bytes
/// `00 A4 04 00 08 A0000006472F0001 00` when the transport uses the
/// short form (the form shown in docs/transport-pcsc.md's trace).
pub fn select_fido_aid() -> Vec<u8> {
    crate::apdu::case4(0x00, 0xA4, 0x04, 0x00, &FIDO_AID, 256, false).bytes
}

/// The typed outcome of the §11.3.3 SELECT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectOutcome {
    /// `9000` — applet selected; this reader/card is a candidate.
    /// Carries the version string from the response data when present.
    Selected {
        /// Version string per §11.3.3 (`U2F_V2` / `FIDO_2_0`); None
        /// when the response carried no data (non-conformant but
        /// tolerated: capability settles at the getInfo probe).
        version: Option<Vec<u8>>,
    },
    /// `6A82` — not FIDO-capable on this interface: typed skip.
    NotFido,
    /// `6985` — conditions of use not satisfied (e.g. applet
    /// disabled): typed skip with the `condition` qualifier.
    ConditionSkip,
    /// `6283` — selected file invalidated (applet present but
    /// unusable this power cycle): typed skip with the `invalidated`
    /// qualifier.
    InvalidatedSkip,
}

impl SelectOutcome {
    /// Whether this outcome leaves the reader as a ceremony candidate.
    pub fn is_candidate(self) -> bool {
        matches!(self, Self::Selected { .. })
    }
}

/// Evaluate a SELECT response (data || SW) into the typed outcome.
///
/// Pure: takes the raw response bytes of one SCardTransmit.
pub fn evaluate_select(response: &[u8]) -> Result<SelectOutcome, Error> {
    if response.len() < 2 {
        return Err(select_error(
            &StatusWord::Other([0x00, 0x00]),
            String::from("SELECT response shorter than a status word"),
        ));
    }
    let (data, sw) = response.split_at(response.len() - 2);
    let word = StatusWord::from_pair(sw[0], sw[1]);
    match word {
        StatusWord::Ok => Ok(SelectOutcome::Selected {
            version: if data.is_empty() {
                None
            } else {
                Some(data.to_vec())
            },
        }),
        StatusWord::NotFound => Ok(SelectOutcome::NotFido),
        StatusWord::ConditionsNotSatisfied => Ok(SelectOutcome::ConditionSkip),
        StatusWord::FileInvalidated => Ok(SelectOutcome::InvalidatedSkip),
        other => Err(select_error(
            &other,
            alloc::format!("unexpected SELECT status word: {other}"),
        )),
    }
}

fn select_error(word: &StatusWord, detail: String) -> Error {
    Error::Transport(TransportError::new(
        "pcsc",
        alloc::format!(
            "FIDO applet selection ({}, {} phase): {detail}",
            word,
            Phase::ChannelOpen
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn aid_bytes_match_ctap2_1_11_3_3() {
        // rid A000000647 + pix 2F0001 (design D3: byte-verified).
        assert_eq!(FIDO_AID, [0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]);
        let select = select_fido_aid();
        assert_eq!(
            select,
            vec![
                0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01, 0x00
            ]
        );
    }

    #[test]
    fn u2f_v2_select_is_a_candidate() {
        let mut response = U2F_V2.to_vec();
        response.extend_from_slice(&[0x90, 0x00]);
        let outcome = evaluate_select(&response).unwrap();
        assert_eq!(
            outcome,
            SelectOutcome::Selected {
                version: Some(U2F_V2.to_vec())
            }
        );
        assert!(outcome.is_candidate());
    }

    #[test]
    fn skips_are_typed_per_device_negatives() {
        assert_eq!(evaluate_select(&[0x6A, 0x82]), Ok(SelectOutcome::NotFido));
        assert!(!SelectOutcome::NotFido.is_candidate());
        assert_eq!(
            evaluate_select(&[0x69, 0x85]),
            Ok(SelectOutcome::ConditionSkip)
        );
        assert_eq!(
            evaluate_select(&[0x62, 0x83]),
            Ok(SelectOutcome::InvalidatedSkip)
        );
    }

    #[test]
    fn unexpected_select_sw_is_a_typed_transport_error() {
        let err = evaluate_select(&[0x6F, 0x00]).unwrap_err();
        match err {
            Error::Transport(e) => {
                assert!(e.detail.contains("6F00"), "detail: {}", e.detail);
            }
            other => panic!("expected Transport error, got {other:?}"),
        }
        // Other 62xx warnings are errors too (never guessed semantics).
        assert!(evaluate_select(&[0x62, 0x81]).is_err());
    }

    #[test]
    fn empty_response_is_typed() {
        assert!(evaluate_select(&[]).is_err());
        assert!(evaluate_select(&[0x90]).is_err());
    }
}
