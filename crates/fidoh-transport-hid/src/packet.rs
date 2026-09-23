//! CTAPHID packet encode/decode — the pure wire layer (CTAP2.1
//! §11.2.4). No I/O, no time, no device: bytes in, packets out.
//!
//! Design D1: a strict encode / strict decode pair.
//!
//! Encode builds init + continuation packets exactly per §11.2.4 (CID,
//! CMD|0x80, BCNT big-endian, SEQ ascending from 0x00, zero padding to
//! 64 bytes). Decode enforces SEQ expectation, BCNT plausibility
//! against the 7609-byte ceiling, and per-frame payload capacities
//! with typed errors.

use alloc::vec::Vec;

use crate::consts::{
    CMD_TYPE_BIT, CONT_HEADER, CONT_PAYLOAD, INIT_HEADER, INIT_PAYLOAD, MAX_MESSAGE_SIZE,
    REPORT_SIZE,
};
use crate::error::FramingError;

/// One encoded packet: always a full [`REPORT_SIZE`] report (§11.2.4:
/// "Packets shall always be sent as full 64 bytes").
pub type Packet = [u8; REPORT_SIZE];

/// Offset of the payload area in an initialization packet (§11.2.4
/// offset table).
pub const INIT_HEADER_OFF: usize = 7;

/// Offset of the payload area in a continuation packet (§11.2.4).
pub const CONT_HEADER_OFF: usize = 5;

/// Encode a complete outgoing message: initialization packet plus
/// continuation packets (SEQ 0x00 ascending, final packet zero-padded
/// to 64 bytes; §11.2.4).
///
/// `payload` is the full message payload — for CTAPHID_CBOR the CTAP2
/// command byte followed by the encoded request body (§11.2.9.1.2);
/// for CTAPHID_INIT the 8-byte nonce.
///
/// Rejects payloads beyond [`MAX_MESSAGE_SIZE`] before emitting any
/// packet (spec scenario "Oversized message rejected before
/// transmission").
pub fn encode_message(cid: u32, cmd: u8, payload: &[u8]) -> Result<Vec<Packet>, FramingError> {
    if payload.len() > MAX_MESSAGE_SIZE {
        return Err(FramingError::MessageTooLong { len: payload.len() });
    }
    let mut packets = Vec::with_capacity(packet_count(payload.len()));
    // Initialization packet: CID(4) CMD(1) BCNT(2) + first ≤57 payload
    // bytes, zero-padded (§11.2.4 offset table).
    let mut init = [0u8; REPORT_SIZE];
    init[0..4].copy_from_slice(&cid.to_be_bytes());
    init[4] = cmd | CMD_TYPE_BIT;
    let bcnt = u16::try_from(payload.len())
        .map_err(|_| FramingError::MessageTooLong { len: payload.len() })?;
    init[5..7].copy_from_slice(&bcnt.to_be_bytes());
    let first = payload.len().min(INIT_PAYLOAD);
    init[INIT_HEADER..INIT_HEADER + first].copy_from_slice(&payload[..first]);
    packets.push(init);
    // Continuation packets: CID(4) SEQ(1) + next ≤59 payload bytes.
    let mut rest = &payload[first..];
    let mut seq = 0u8;
    while !rest.is_empty() {
        let take = rest.len().min(CONT_PAYLOAD);
        let mut cont = [0u8; REPORT_SIZE];
        cont[0..4].copy_from_slice(&cid.to_be_bytes());
        cont[4] = seq;
        cont[CONT_HEADER..CONT_HEADER + take].copy_from_slice(&rest[..take]);
        packets.push(cont);
        rest = &rest[take..];
        seq += 1; // ≤128 packets by the MAX_MESSAGE_SIZE ceiling.
    }
    Ok(packets)
}

/// Number of 64-byte packets a payload of `len` bytes needs (§11.2.4
/// split rule). A zero-length payload is one packet.
pub fn packet_count(len: usize) -> usize {
    if len <= INIT_PAYLOAD {
        1
    } else {
        1 + (len - INIT_PAYLOAD).div_ceil(CONT_PAYLOAD)
    }
}

/// The kind of frame an inbound packet is (bit 7 of byte 4, §11.2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InboundKind {
    /// An initialization packet (bit 7 set): command + BCNT.
    Init,
    /// A continuation packet (bit 7 clear): SEQ + payload.
    Continuation,
}

/// Classify an inbound 64-byte report (§11.2.4: "The command byte has
/// always the highest bit set to distinguish it from a continuation
/// packet").
pub fn classify(report: &[u8]) -> Result<InboundKind, FramingError> {
    if report.len() < REPORT_SIZE {
        return Err(FramingError::ShortReport { got: report.len() });
    }
    if report[4] & CMD_TYPE_BIT != 0 {
        Ok(InboundKind::Init)
    } else {
        Ok(InboundKind::Continuation)
    }
}

/// The header fields of an inbound initialization packet (§11.2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitHeader {
    /// Channel the packet arrived on.
    pub cid: u32,
    /// Command byte with bit 7 stripped (0x06 INIT, 0x10 CBOR, 0x3B
    /// KEEPALIVE, 0x3F ERROR, …).
    pub cmd: u8,
    /// Announced total payload length (big-endian bytes 5–6).
    pub bcnt: usize,
}

/// Parse an inbound initialization packet header (§11.2.4).
pub fn parse_init_header(report: &[u8]) -> Result<InitHeader, FramingError> {
    if report.len() < REPORT_SIZE {
        return Err(FramingError::ShortReport { got: report.len() });
    }
    let cid = u32::from_be_bytes([report[0], report[1], report[2], report[3]]);
    let cmd = report[4] & !CMD_TYPE_BIT;
    let bcnt = u16::from_be_bytes([report[5], report[6]]) as usize;
    Ok(InitHeader { cid, cmd, bcnt })
}

/// Parse an inbound continuation packet header (§11.2.4): (cid, seq).
pub fn parse_cont_header(report: &[u8]) -> Result<(u32, u8), FramingError> {
    if report.len() < REPORT_SIZE {
        return Err(FramingError::ShortReport { got: report.len() });
    }
    let cid = u32::from_be_bytes([report[0], report[1], report[2], report[3]]);
    Ok((cid, report[4]))
}

/// The payload of a single-packet frame (INIT request/response,
/// KEEPALIVE, ERROR, single-packet CBOR): everything after the header,
/// truncated to BCNT (§11.2.4).
pub fn payload_of(report: &[u8], hdr: InitHeader) -> Result<Vec<u8>, FramingError> {
    if report.len() < REPORT_SIZE {
        return Err(FramingError::ShortReport { got: report.len() });
    }
    Ok(report[INIT_HEADER..]
        .iter()
        .take(hdr.bcnt)
        .copied()
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::MAX_MESSAGE_SIZE;
    use alloc::vec;

    const BROADCAST: u32 = 0xFFFF_FFFF;

    // Spec scenario: "Single-packet message" — ≤57-byte payload is one
    // init packet, bit 7 set, BCNT = payload length, trailing bytes
    // zeroed.
    #[test]
    fn single_packet_message_encode() {
        // The docs/transport-hid.md constructed INIT example.
        let packets =
            encode_message(BROADCAST, 0x06, &[1, 2, 3, 4, 5, 6, 7, 8]).expect("8-byte payload");
        assert_eq!(packets.len(), 1);
        let p = &packets[0];
        assert_eq!(p.len(), 64);
        assert_eq!(&p[0..4], &[0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(p[4], 0x86);
        assert_eq!(&p[5..7], &[0x00, 0x08]);
        assert_eq!(&p[7..15], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(p[15..].iter().all(|&b| b == 0));
    }

    // Spec scenario: "Multi-packet message uses ascending sequence
    // numbers" — init carries 57 bytes, continuations 59 each, SEQ
    // 0x00 ascending, final packet zero-padded.
    #[test]
    fn multi_packet_message_ascending_seq() {
        // 57 + 59 + 10 = 126-byte payload → 3 packets.
        let payload: Vec<u8> = (0u8..=125).collect();
        let packets = encode_message(0x0102_0304, 0x90, &payload).expect("126-byte payload");
        assert_eq!(packets.len(), 3);
        // Init packet: first 57 bytes.
        assert_eq!(packets[0][4], 0x90 | 0x80);
        assert_eq!(&packets[0][5..7], &[0x00, 126]);
        assert_eq!(&packets[0][7..64], &payload[..57]);
        // Continuation SEQ 0: bytes 57..116.
        assert_eq!(packets[1][0..4], 0x0102_0304u32.to_be_bytes());
        assert_eq!(packets[1][4], 0x00);
        assert_eq!(&packets[1][5..64], &payload[57..116]);
        // Continuation SEQ 1: bytes 116..126, zero-padded.
        assert_eq!(packets[2][4], 0x01);
        assert_eq!(&packets[2][5..15], &payload[116..126]);
        assert!(packets[2][15..].iter().all(|&b| b == 0));
    }

    // Spec scenario: "Oversized message rejected before transmission"
    // — 7610 bytes fails typed; 7609 (the §11.2.4 maximum) succeeds.
    #[test]
    fn oversized_message_rejected_before_transmission() {
        assert_eq!(
            encode_message(1, 0x90, &vec![0u8; MAX_MESSAGE_SIZE + 1]),
            Err(FramingError::MessageTooLong {
                len: MAX_MESSAGE_SIZE + 1
            })
        );
        // Exactly the maximum encodes: 1 + 128 packets, final SEQ
        // 0x7F.
        let max = encode_message(1, 0x90, &vec![0u8; MAX_MESSAGE_SIZE]).expect("7609 is the max");
        assert_eq!(max.len(), 129);
        assert_eq!(max[128][4], 127);
    }

    #[test]
    fn packet_count_matches_split_rule() {
        assert_eq!(packet_count(0), 1);
        assert_eq!(packet_count(57), 1);
        assert_eq!(packet_count(58), 2);
        assert_eq!(packet_count(116), 2);
        assert_eq!(packet_count(117), 3);
        assert_eq!(packet_count(MAX_MESSAGE_SIZE), 129);
    }

    // Round trip: encode then walk the decode helpers; BCNT and
    // payload reassemble to the input.
    #[test]
    fn encode_decode_round_trip() {
        let payload: Vec<u8> = (0..200).map(|i| (i % 251) as u8).collect();
        let packets = encode_message(0x0BAD_C0DE, 0x90, &payload).expect("under maximum");
        let hdr = parse_init_header(&packets[0]).expect("init header");
        assert_eq!(hdr.cid, 0x0BAD_C0DE);
        assert_eq!(hdr.cmd, 0x10);
        assert_eq!(hdr.bcnt, payload.len());
        let mut got = Vec::new();
        got.extend_from_slice(&packets[0][7..]);
        for (i, p) in packets.iter().enumerate().skip(1) {
            assert_eq!(classify(p), Ok(InboundKind::Continuation));
            let (cid, seq) = parse_cont_header(p).expect("cont header");
            assert_eq!(cid, 0x0BAD_C0DE);
            assert_eq!(seq, (i - 1) as u8);
            got.extend_from_slice(&p[5..]);
        }
        got.truncate(hdr.bcnt);
        assert_eq!(got, payload);
    }

    #[test]
    fn classify_and_headers() {
        let mut init = [0u8; 64];
        init[4] = 0x86;
        assert_eq!(classify(&init), Ok(InboundKind::Init));
        assert_eq!(parse_init_header(&init).expect("hdr").cmd, 0x06);
        let mut cont = [0u8; 64];
        cont[4] = 0x02; // bit 7 clear
        assert_eq!(classify(&cont), Ok(InboundKind::Continuation));
        // Short reports are typed, never a panic.
        assert_eq!(
            classify(&[0u8; 63]),
            Err(FramingError::ShortReport { got: 63 })
        );
        assert_eq!(
            parse_init_header(&[0u8; 10]),
            Err(FramingError::ShortReport { got: 10 })
        );
    }

    // A payload between 58 and 116 needs one continuation; BCNT is
    // announced in full by the init packet.
    #[test]
    fn two_packet_boundary() {
        let payload = vec![7u8; 58];
        let packets = encode_message(1, 0x90, &payload).expect("fits");
        assert_eq!(packets.len(), 2);
        assert_eq!(&packets[0][5..7], &[0x00, 58]);
        assert_eq!(packets[1][4], 0);
        assert_eq!(packets[1][5], 7);
        assert!(packets[1][6..].iter().all(|&b| b == 0));
    }

    // payload_of truncates to BCNT (keepalive status extraction).
    #[test]
    fn payload_of_truncates_to_bcnt() {
        let mut report = [0u8; 64];
        report[0..4].copy_from_slice(&1u32.to_be_bytes());
        report[4] = 0x3B | 0x80; // KEEPALIVE
        report[5..7].copy_from_slice(&1u16.to_be_bytes());
        report[7] = 0x02; // UPNEEDED
        let hdr = parse_init_header(&report).expect("hdr");
        assert_eq!(payload_of(&report, hdr), Ok(vec![0x02]));
    }
}
