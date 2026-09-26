//! CTAP-over-APDU framing (CTAP2.1 §11.3.5) and response assembly
//! (§11.3.5.2, §11.3.7.2, ISO 7816-4 GET RESPONSE / Le retry).
//!
//! Transmit path (§11.3.5.1): CLA 0x80, INS 0x10 (NFCCTAP_MSG),
//! P1 0x00 with bit 0x80 set (client supports NFCCTAP_GETRESPONSE,
//! §11.3.7.1 — status updates are legal only under this declaration),
//! P2 0x00, command-data = CTAP command byte || canonical CBOR
//! (CTAP2.1 §8, encoded by fidoh-core's models), Le. Extended length
//! is preferred once the command data exceeds 255 bytes; short-form
//! chaining (CLA 0x90, §11.3.6) is the fallback.
//!
//! Receive path (§11.3.5.2): SW 9000 → data = CTAP status byte ||
//! response CBOR (the status byte is mapped by core-model's §8.2
//! table — this transport never re-interprets it); SW 9100 →
//! NFCCTAP_GETRESPONSE (INS 0x11, §11.3.7.2) loop; SW 61xx → GET
//! RESPONSE (INS 0xC0) hops; SW 6Cxx → single retry with the
//! corrected Le.

use alloc::string::String;
use alloc::vec::Vec;

use fidoh_core::{Error, Phase, TransportError};

use crate::sw::StatusWord;

/// CLA for NFCCTAP commands (CTAP2.1 §11.3.5.1).
pub const CLA_CTAP: u8 = 0x80;
/// CLA for non-final short-form chaining blocks (§11.3.6).
pub const CLA_CHAIN: u8 = 0x90;
/// INS 0x10 — NFCCTAP_MSG (§11.3.5.1; carries every CTAP command).
pub const INS_MSG: u8 = 0x10;
/// INS 0x11 — NFCCTAP_GETRESPONSE (§11.3.7.2).
pub const INS_GETRESPONSE: u8 = 0x11;
/// INS 0xC0 — GET RESPONSE (ISO 7816-4; drains `61xx` chains).
pub const INS_GET_RESPONSE: u8 = 0xC0;
/// P1 bit declaring the client supports NFCCTAP_GETRESPONSE
/// (§11.3.7.1); OR'd into P1 0x00 of every NFCCTAP_MSG.
pub const P1_GETRESPONSE_SUPPORTED: u8 = 0x80;

/// CTAP command bytes in v1 scope (CTAP2.1 §6: GET_INFO §6.4 = 0x04,
/// GET_ASSERTION §6.2 = 0x02).
pub mod command_byte {
    /// authenticatorGetInfo (CTAP2.1 §6.4).
    pub const GET_INFO: u8 = 0x04;
    /// authenticatorGetAssertion (CTAP2.1 §6.2).
    pub const GET_ASSERTION: u8 = 0x02;
    /// authenticatorClientPIN (CTAP2.1 §6.5.5; add-client-pin).
    pub const CLIENT_PIN: u8 = 0x06;
}

/// Short-form Le encoding: `0x00` = "up to 256 response bytes"
/// (ISO 7816-4).
pub const SHORT_LE: usize = 256;

/// One command APDU ready to transmit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NextApdu(pub Vec<u8>);

impl NextApdu {
    /// The wire bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn from_command(command: crate::apdu::ApduCommand) -> Self {
        Self(command.bytes)
    }
}

/// Encode the §11.3.5.1 command frame for a CTAP exchange.
///
/// Extended length when the command data exceeds 255 bytes (§11.3.5:
/// authenticators MUST support short AND extended length; the spec's
/// "Long request uses extended length" scenario forbids fragmenting
/// in that case).
pub fn framed(command: u8, payload: &[u8]) -> NextApdu {
    let extended = payload.len() + 1 > 255;
    NextApdu(command_frame(command, payload, SHORT_LE, extended))
}

/// The §11.3.6 short-form chaining fallback: fragment a request whose
/// command data exceeds 255 bytes into CLA-0x90-chained blocks; only
/// the final block carries Le. Used when a reader rejects extended
/// length (spec: "falls back to short-APDU chaining (§11.3.6) only if
/// the reader rejects extended length").
pub fn framed_chained(command: u8, payload: &[u8]) -> Vec<NextApdu> {
    let mut data = Vec::with_capacity(payload.len() + 1);
    data.push(command);
    data.extend_from_slice(payload);
    crate::apdu::chain_short(CLA_CTAP, &data, 255, |cla, chunk, last| {
        if last {
            crate::apdu::case4(
                cla,
                INS_MSG,
                P1_GETRESPONSE_SUPPORTED,
                0x00,
                chunk,
                SHORT_LE,
                false,
            )
        } else {
            crate::apdu::case3(cla, INS_MSG, P1_GETRESPONSE_SUPPORTED, 0x00, chunk, false)
        }
    })
    .into_iter()
    .map(NextApdu::from_command)
    .collect()
}

fn command_frame(command: u8, payload: &[u8], le: usize, extended: bool) -> Vec<u8> {
    let mut data = Vec::with_capacity(payload.len() + 1);
    data.push(command);
    data.extend_from_slice(payload);
    crate::apdu::case4(
        CLA_CTAP,
        INS_MSG,
        P1_GETRESPONSE_SUPPORTED,
        0x00,
        &data,
        le,
        extended,
    )
    .bytes
}

/// The encoded NFCCTAP_GETRESPONSE APDU (§11.3.7.2: INS 0x11,
/// P1 = P2 = 0x00, no data, Le 00).
fn getresponse_apdu() -> NextApdu {
    NextApdu(crate::apdu::case2(CLA_CTAP, INS_GETRESPONSE, 0x00, 0x00, SHORT_LE, false).bytes)
}

/// The encoded GET RESPONSE APDU for an `61xx` remainder of `n`
/// bytes (INS 0xC0, ISO 7816-4; Le = n, `0x00`/256 when n = 0).
fn get_response_apdu(n: u8) -> NextApdu {
    NextApdu(crate::apdu::case2(CLA_CTAP, INS_GET_RESPONSE, 0x00, 0x00, n as usize, false).bytes)
}

/// The state machine for ONE CTAP command exchange (§11.3.5.2 receive
/// procedure): feed each transmitted response in, get either the next
/// APDU to send or the assembled terminal CTAP response.
///
/// Pure bookkeeping — it never waits. Every hop it produces is a
/// budget-bounded transmit at the engine layer (spec: chaining hops,
/// GET RESPONSE iterations, and the 9100/GETRESPONSE loop each
/// consume the remaining budget).
#[derive(Debug)]
pub struct Exchange {
    /// Command data (command byte || payload), kept for the one-shot
    /// `6Cxx` Le retry.
    command_data: Vec<u8>,
    /// Assembled response data across `61xx` hops.
    collected: Vec<u8>,
    /// Whether the §11.3.7.2 status-update loop is active.
    status_update: bool,
    /// Whether the single `6Cxx` Le retry (error table) was used.
    le_retried: bool,
    /// Runaway guard for non-conformant cards that would keep the
    /// chain/loop alive forever (stack invariant: no unbounded loops;
    /// real chains terminate on `9000` far earlier, and the budget
    /// bounds each hop besides).
    hops_left: u8,
    /// The phase a timeout at this exchange names (the command's).
    phase: Phase,
}

/// Bounded hop count for chains and the status-update loop.
pub const MAX_HOPS: u8 = 64;

/// One state-machine step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Transmit these bytes next (GET RESPONSE, GETRESPONSE poll, or
    /// Le retry).
    Send(NextApdu),
    /// The exchange resolved to a terminal CTAP response.
    Done(CtapResponse),
}

impl Exchange {
    /// Begin an exchange for CTAP `command` with its CBOR `payload`.
    /// The first fed response is the answer to [`framed`]'s APDU.
    pub fn new(command: u8, payload: &[u8], phase: Phase) -> Self {
        let mut command_data = Vec::with_capacity(payload.len() + 1);
        command_data.push(command);
        command_data.extend_from_slice(payload);
        Self {
            command_data,
            collected: Vec::new(),
            status_update: false,
            le_retried: false,
            hops_left: MAX_HOPS,
            phase,
        }
    }

    /// Whether the §11.3.7.2 status-update loop is active.
    pub fn in_status_update(&self) -> bool {
        self.status_update
    }

    /// Feed one transmitted response (data || SW) in.
    pub fn step(&mut self, response: &[u8]) -> Result<Step, Error> {
        let parsed = Response::parse(response)?;
        match parsed.sw {
            StatusWord::Ok => {
                let mut data = core::mem::take(&mut self.collected);
                data.extend_from_slice(&parsed.data);
                Ok(Step::Done(CtapResponse::assemble(data, self.phase)?))
            }
            StatusWord::MoreData(n) => {
                self.guard_hop()?;
                self.collected.extend_from_slice(&parsed.data);
                Ok(Step::Send(get_response_apdu(n)))
            }
            StatusWord::WrongLe(correct) => {
                // Single retry with Le = xx (error table: "single
                // retry with Le=xx (same budget), else `Transport`
                // error, `le` cause").
                if self.le_retried {
                    return Err(exchange_error(
                        self.phase,
                        alloc::format!(
                            "second 6C{:02X} after the Le retry: response does not converge",
                            correct
                        ),
                    ));
                }
                self.le_retried = true;
                // Extended length only when the command data needs it;
                // a corrected Le of 0 is the short "up to 256" form.
                let extended = self.command_data.len() > 255;
                Ok(Step::Send(NextApdu(command_frame(
                    self.command_data[0],
                    &self.command_data[1..],
                    correct as usize,
                    extended,
                ))))
            }
            StatusWord::StatusUpdate => {
                // §11.3.5.2/§11.3.7.2: SW 9100 — processing continues,
                // poll NFCCTAP_GETRESPONSE immediately; loop while it
                // recurs, complete on 9000.
                self.status_update = true;
                self.guard_hop()?;
                Ok(Step::Send(getresponse_apdu()))
            }
            StatusWord::Warn(_)
            | StatusWord::NotFound
            | StatusWord::ConditionsNotSatisfied
            | StatusWord::FileInvalidated
            | StatusWord::NotAllowed
            | StatusWord::NotAllowed6D00
            | StatusWord::Other(_) => Err(exchange_error(
                self.phase,
                alloc::format!("CTAP exchange failed: {}", parsed.sw),
            )),
        }
    }

    fn guard_hop(&mut self) -> Result<(), Error> {
        if self.hops_left == 0 {
            return Err(exchange_error(
                self.phase,
                String::from("unbounded response chain (runaway guard exhausted)"),
            ));
        }
        self.hops_left -= 1;
        Ok(())
    }
}

/// A parsed APDU response: the SW plus whatever data preceded it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// Response data (everything before the trailing SW).
    pub data: Vec<u8>,
    /// The typed status word.
    pub sw: StatusWord,
}

impl Response {
    /// Parse one transmit result (data || SW).
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 2 {
            return Err(exchange_error(
                Phase::CommandExchange,
                String::from("APDU response shorter than a status word"),
            ));
        }
        let (data, sw) = bytes.split_at(bytes.len() - 2);
        Ok(Self {
            data: data.to_vec(),
            sw: StatusWord::from_pair(sw[0], sw[1]),
        })
    }
}

/// The assembled CTAP response (§11.3.5.2): CTAP status byte || CBOR.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CtapResponse {
    /// The CTAP2 status byte (CTAP2.1 §8.2; decoded by core-model —
    /// this transport never re-interprets it).
    pub status: u8,
    /// The response CBOR body (empty for non-zero status).
    pub body: Vec<u8>,
}

impl CtapResponse {
    /// Split assembled data into status byte || body. Zero-length
    /// data is a typed error: a `9000` SW with no CTAP status byte
    /// cannot be a CTAP response (§11.3.5.2 response shape).
    pub fn assemble(data: Vec<u8>, phase: Phase) -> Result<Self, Error> {
        let Some((status, body)) = data.split_first() else {
            return Err(exchange_error(
                phase,
                String::from("SW 9000 response carried no CTAP status byte"),
            ));
        };
        Ok(Self {
            status: *status,
            body: body.to_vec(),
        })
    }
}

fn exchange_error(phase: Phase, detail: String) -> Error {
    Error::Transport(TransportError::new(
        "pcsc",
        alloc::format!("APDU exchange ({phase} phase): {detail}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn getinfo_frame_matches_spec_scenario() {
        // Spec scenario "getInfo rides the §11.3.5 frame": CLA 0x80,
        // INS 0x10, P1 0x00 (with bit 0x80 set per §11.3.7.1), P2
        // 0x00, Lc 1, data 0x04, Le 00.
        let apdu = framed(command_byte::GET_INFO, &[]);
        assert_eq!(apdu.as_bytes(), &[0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00]);
    }

    #[test]
    fn long_request_uses_extended_length_not_fragmentation() {
        // Spec scenario "Long request uses extended length": > 255
        // command-data bytes ⇒ extended APDU, not fragmentation.
        let payload = vec![0x42; 300];
        let apdu = framed(command_byte::GET_ASSERTION, &payload);
        let bytes = apdu.as_bytes();
        assert_eq!(&bytes[..4], &[0x80, 0x10, 0x80, 0x00]);
        assert_eq!(bytes[4], 0x00, "extended-length delimiter");
        assert_eq!(&bytes[5..7], &[0x01, 0x2D], "Lc = 301 big-endian");
        assert_eq!(bytes.len(), 7 + 301 + 2);
        assert_eq!(&bytes[7 + 301..], &[0x01, 0x00], "Le = 256 extended");
    }

    #[test]
    fn short_requests_stay_short() {
        let payload = vec![0x7F; 254];
        let apdu = framed(command_byte::GET_ASSERTION, &payload);
        let bytes = apdu.as_bytes();
        assert_eq!(bytes[4], 255, "short Lc = 255");
        assert_eq!(bytes.len(), 5 + 255 + 1, "short Lc + data + one Le");
    }

    #[test]
    fn chained_fallback_fragments_with_cla_90() {
        let payload = vec![0x55; 600];
        let blocks = framed_chained(command_byte::GET_ASSERTION, &payload);
        assert_eq!(blocks.len(), 3, "1 + 600 bytes split 255/255/91");
        assert_eq!(blocks[0].as_bytes()[0], CLA_CHAIN);
        assert_eq!(blocks[1].as_bytes()[0], CLA_CHAIN);
        assert_eq!(blocks[2].as_bytes()[0], CLA_CTAP, "final block: real CLA");
        assert_eq!(blocks[0].as_bytes().len(), 5 + 255);
        assert_eq!(blocks[1].as_bytes().len(), 5 + 255);
        assert_eq!(blocks[2].as_bytes().len(), 5 + 91 + 1, "final block has Le");
    }

    #[test]
    fn done_response_splits_status_and_body() {
        let mut ex = Exchange::new(command_byte::GET_INFO, &[], Phase::GetInfo);
        match ex.step(&[0x00, 0xA1, 0x02, 0x03, 0x90, 0x00]).unwrap() {
            Step::Done(ctap) => {
                assert_eq!(ctap.status, 0x00);
                assert_eq!(ctap.body, vec![0xA1, 0x02, 0x03]);
            }
            other => panic!("expected Done, got {other:?}"),
        }
    }

    #[test]
    fn more_data_chains_via_get_response() {
        // Spec scenario "61xx response chains via GET RESPONSE":
        // SW 61 05 → GET RESPONSE (INS 0xC0) within the same budget.
        let mut ex = Exchange::new(command_byte::GET_INFO, &[], Phase::GetInfo);
        match ex.step(&[0x61, 0x05]).unwrap() {
            Step::Send(next) => {
                assert_eq!(next.as_bytes(), &[0x80, 0xC0, 0x00, 0x00, 0x05]);
            }
            other => panic!("expected Send, got {other:?}"),
        }
        match ex.step(&[0x00, 0xAA, 0x90, 0x00]).unwrap() {
            Step::Done(ctap) => {
                assert_eq!(ctap.status, 0x00);
                assert_eq!(ctap.body, vec![0xAA]);
            }
            other => panic!("expected Done, got {other:?}"),
        }
    }

    #[test]
    fn multi_hop_chain_accumulates_in_order() {
        let mut ex = Exchange::new(command_byte::GET_INFO, &[], Phase::GetInfo);
        assert!(matches!(
            ex.step(&[0x11, 0x22, 0x61, 0x01]).unwrap(),
            Step::Send(_)
        ));
        match ex.step(&[0x33, 0x90, 0x00]).unwrap() {
            Step::Done(ctap) => {
                assert_eq!(ctap.status, 0x11);
                assert_eq!(ctap.body, vec![0x22, 0x33]);
            }
            other => panic!("expected Done, got {other:?}"),
        }
    }

    #[test]
    fn wrong_le_retries_once_with_corrected_le() {
        let mut ex = Exchange::new(command_byte::GET_INFO, &[], Phase::GetInfo);
        match ex.step(&[0x6C, 0x40]).unwrap() {
            Step::Send(next) => {
                // Original command re-sent with Le = 0x40.
                assert_eq!(next.as_bytes(), &[0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x40]);
            }
            other => panic!("expected Send, got {other:?}"),
        }
        match ex.step(&[0x00, 0x99, 0x90, 0x00]).unwrap() {
            Step::Done(ctap) => {
                assert_eq!(ctap.status, 0x00);
                assert_eq!(ctap.body, vec![0x99]);
            }
            other => panic!("expected Done, got {other:?}"),
        }
    }

    #[test]
    fn second_wrong_le_is_a_typed_le_error() {
        let mut ex = Exchange::new(command_byte::GET_INFO, &[], Phase::GetInfo);
        assert!(matches!(ex.step(&[0x6C, 0x40]).unwrap(), Step::Send(_)));
        let err = ex.step(&[0x6C, 0x10]).unwrap_err();
        match err {
            Error::Transport(e) => assert!(e.detail.contains("second 6C10"), "{}", e.detail),
            other => panic!("expected Transport error, got {other:?}"),
        }
    }

    #[test]
    fn status_update_loop_polls_ins_11_until_9000() {
        // Spec scenario "9100 status update triggers
        // NFCCTAP_GETRESPONSE": loop while 9100 recurs, complete on
        // 9000, every iteration bounded (guard + budget at engine).
        let mut ex = Exchange::new(command_byte::GET_ASSERTION, &[0x01], Phase::GetAssertion);
        match ex.step(&[0x91, 0x00]).unwrap() {
            Step::Send(next) => {
                assert!(ex.in_status_update());
                assert_eq!(
                    next.as_bytes(),
                    &[0x80, 0x11, 0x00, 0x00, 0x00],
                    "INS 0x11, P1=P2=0x00, Le 00"
                );
            }
            other => panic!("expected Send, got {other:?}"),
        }
        // Recurring 9100 on the poll → poll again.
        match ex.step(&[0x91, 0x00]).unwrap() {
            Step::Send(next) => assert_eq!(next.as_bytes(), &[0x80, 0x11, 0x00, 0x00, 0x00]),
            other => panic!("expected Send, got {other:?}"),
        }
        // 9000 resolves with status || CBOR.
        match ex.step(&[0x00, 0xAB, 0x90, 0x00]).unwrap() {
            Step::Done(ctap) => {
                assert_eq!(ctap.status, 0x00);
                assert_eq!(ctap.body, vec![0xAB]);
            }
            other => panic!("expected Done, got {other:?}"),
        }
    }

    #[test]
    fn error_sws_map_typed_with_sw_in_text() {
        for (sw, needle) in [
            (&[0x69u8, 0x86u8][..], "6986"),
            (&[0x6Du8, 0x00u8][..], "command not allowed"),
            (&[0x6Au8, 0x82u8][..], "6A82"),
            (&[0x69u8, 0x85u8][..], "6985"),
            (&[0x62u8, 0x83u8][..], "6283"),
            (&[0x62u8, 0x81u8][..], "6281"),
        ] {
            let mut ex = Exchange::new(command_byte::GET_INFO, &[], Phase::GetInfo);
            let err = ex.step(sw).unwrap_err();
            match err {
                Error::Transport(e) => assert!(e.detail.contains(needle), "{}", e.detail),
                other => panic!("expected Transport error, got {other:?}"),
            }
        }
    }

    #[test]
    fn missing_status_byte_is_typed() {
        let mut ex = Exchange::new(command_byte::GET_INFO, &[], Phase::GetInfo);
        let err = ex.step(&[0x90, 0x00]).unwrap_err();
        match err {
            Error::Transport(e) => assert!(e.detail.contains("no CTAP status byte")),
            other => panic!("expected Transport error, got {other:?}"),
        }
    }

    #[test]
    fn short_response_is_typed() {
        let mut ex = Exchange::new(command_byte::GET_INFO, &[], Phase::GetInfo);
        assert!(ex.step(&[0x90]).is_err());
        assert!(ex.step(&[]).is_err());
    }

    #[test]
    fn runaway_guard_bounds_the_chain() {
        let mut ex = Exchange::new(command_byte::GET_INFO, &[], Phase::GetInfo);
        for _ in 0..MAX_HOPS {
            assert!(matches!(ex.step(&[0x61, 0x01]).unwrap(), Step::Send(_)));
        }
        let err = ex.step(&[0x61, 0x01]).unwrap_err();
        match err {
            Error::Transport(e) => assert!(e.detail.contains("runaway guard")),
            other => panic!("expected Transport error, got {other:?}"),
        }
    }
}
