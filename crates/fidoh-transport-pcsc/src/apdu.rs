//! APDU command encoding (ISO 7816-4): short form, extended length,
//! and short-form command chaining — pure, no library context.
//!
//! Encoding forms per ISO 7816-4 §5.1 (and CTAP2.1 §11.3.5, whose
//! authenticators MUST accept short and extended length):
//!
//! - **short** — CLA INS P1 P2 [`00` Lc data] Le, Lc/Le ≤ 255;
//! - **extended** — CLA INS P1 P2 `00` LL{2} Lc data LL{2} Le, for
//!   Lc/Le up to 65 535; preferred by this transport whenever a
//!   request exceeds 255 data bytes or a large response is expected
//!   (spec: "Long request uses extended length");
//! - **chained (short-form fallback)** — all blocks but the last use
//!   CLA `0x90` (§11.3.6 CTAP chaining / ISO 7816-4 class-bit 4);
//!   only the final block carries Le.

use alloc::vec::Vec;

/// A completely formed command APDU (one wire message to transmit).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApduCommand {
    /// Wire bytes.
    pub bytes: Vec<u8>,
}

impl ApduCommand {
    /// The wire bytes to transmit.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Case 1: header only (no data, no response expected beyond SW).
///
/// (Present for completeness of the ISO 7816-4 case table; the CTAP
/// layer itself uses case 2/3/4.)
pub fn case1(cla: u8, ins: u8, p1: u8, p2: u8) -> ApduCommand {
    ApduCommand {
        bytes: alloc::vec![cla, ins, p1, p2],
    }
}

/// Case 2: no command data, `le` response bytes expected.
///
/// Short form uses a single Le byte (`0x00` encodes "up to 256");
/// extended form uses two bytes.
pub fn case2(cla: u8, ins: u8, p1: u8, p2: u8, le: usize, extended: bool) -> ApduCommand {
    let mut bytes = Vec::with_capacity(if extended { 9 } else { 5 });
    bytes.extend_from_slice(&[cla, ins, p1, p2]);
    if extended {
        bytes.push(0x00);
        bytes.extend_from_slice(&(le as u16).to_be_bytes());
    } else {
        bytes.push(short_le(le));
    }
    ApduCommand { bytes }
}

/// Case 3: command data, no response data expected.
///
/// Short form caps at 255 data bytes (longer requests must use the
/// extended form or chaining); extended form carries a 2-byte Lc.
pub fn case3(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], extended: bool) -> ApduCommand {
    let mut bytes = Vec::with_capacity(data.len() + 7);
    bytes.extend_from_slice(&[cla, ins, p1, p2]);
    if extended {
        bytes.push(0x00);
        bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
    } else {
        bytes.push(data.len() as u8);
    }
    bytes.extend_from_slice(data);
    ApduCommand { bytes }
}

/// Case 4: command data and response bytes expected.
///
/// Short form caps at 255 data bytes; extended form carries 2-byte
/// Lc/Le fields (with the mandatory `00` after P2 delimiting them).
pub fn case4(
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
    le: usize,
    extended: bool,
) -> ApduCommand {
    let mut bytes = Vec::with_capacity(data.len() + 10);
    bytes.extend_from_slice(&[cla, ins, p1, p2]);
    if extended {
        bytes.push(0x00);
        bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
        bytes.extend_from_slice(data);
        bytes.extend_from_slice(&(le as u16).to_be_bytes());
    } else {
        bytes.push(data.len() as u8);
        bytes.extend_from_slice(data);
        bytes.push(short_le(le));
    }
    ApduCommand { bytes }
}

/// Whether a command data payload fits the short form (≤ 255 bytes).
pub fn fits_short(data_len: usize) -> bool {
    data_len <= 255
}

/// Whether a request needs extended-length encoding: more than 255
/// data bytes, or a response expectation beyond 256 bytes.
pub fn needs_extended(data_len: usize, expected_le: usize) -> bool {
    data_len > 255 || expected_le > 256
}

/// Fragment `data` into chained APDU blocks (short-form chaining,
/// CLA `0x90` on every block but the last — CTAP2.1 §11.3.6 fallback).
///
/// `build` assembles one block from (cla, data-chunk, is-last). The
/// max block payload is 255 bytes (`chunk_size` must be 1..=255).
/// Only the final block carries Le, per §11.3.6.
pub fn chain_short<F>(cla: u8, data: &[u8], chunk_size: usize, mut build: F) -> Vec<ApduCommand>
where
    F: FnMut(u8, &[u8], bool) -> ApduCommand,
{
    debug_assert!((1..=255).contains(&chunk_size));
    let mut blocks = Vec::new();
    if data.is_empty() {
        blocks.push(build(cla, data, true));
        return blocks;
    }
    let mut rest = data;
    while !rest.is_empty() {
        let end = rest.len().min(chunk_size);
        let (chunk, tail) = rest.split_at(end);
        let is_last = tail.is_empty();
        let block_cla = if is_last { cla } else { 0x90 };
        blocks.push(build(block_cla, chunk, is_last));
        rest = tail;
    }
    blocks
}

/// Le byte for the short form: `0x00` means "up to 256" (ISO 7816-4);
/// any other value is the exact expected count.
fn short_le(le: usize) -> u8 {
    if le == 0 || le == 256 {
        0x00
    } else {
        le as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn case2_short_uses_one_le_byte() {
        let apdu = case2(0x80, 0xC0, 0x00, 0x00, 0, false);
        assert_eq!(apdu.bytes, vec![0x80, 0xC0, 0x00, 0x00, 0x00]);
        let apdu = case2(0x00, 0xA4, 0x04, 0x00, 0x100, false);
        assert_eq!(apdu.bytes, vec![0x00, 0xA4, 0x04, 0x00, 0x00]);
    }

    #[test]
    fn case2_extended_uses_two_le_bytes() {
        let apdu = case2(0x80, 0xC0, 0x00, 0x00, 0x100, true);
        assert_eq!(apdu.bytes, vec![0x80, 0xC0, 0x00, 0x00, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn case3_short_and_extended() {
        let apdu = case3(0x00, 0xA4, 0x04, 0x00, &[1, 2, 3], false);
        assert_eq!(apdu.bytes, vec![0x00, 0xA4, 0x04, 0x00, 0x03, 1, 2, 3]);
        let big = vec![0xAB; 300];
        let apdu = case3(0x80, 0x10, 0x00, 0x00, &big, true);
        assert_eq!(
            &apdu.bytes[..7],
            &[0x80, 0x10, 0x00, 0x00, 0x00, 0x01, 0x2C]
        );
        assert_eq!(apdu.bytes.len(), 7 + 300);
    }

    #[test]
    fn case4_matches_the_docs_getinfo_frame() {
        // docs/transport-pcsc.md constructed trace: getInfo rides the
        // §11.3.5 frame with P1 0x80, Lc 1, data 0x04, Le 00.
        let apdu = case4(0x80, 0x10, 0x80, 0x00, &[0x04], 256, false);
        assert_eq!(apdu.bytes, vec![0x80, 0x10, 0x80, 0x00, 0x01, 0x04, 0x00]);
    }

    #[test]
    fn case4_extended_layout() {
        let data = vec![0xCD; 260];
        let apdu = case4(0x80, 0x10, 0x00, 0x00, &data, 0x1000, true);
        assert_eq!(
            &apdu.bytes[..7],
            &[0x80, 0x10, 0x00, 0x00, 0x00, 0x01, 0x04]
        );
        // 0x0104 = 260
        assert_eq!(&apdu.bytes[5..7], &[0x01, 0x04]);
        assert_eq!(&apdu.bytes[7 + 260..], &[0x10, 0x00]);
    }

    #[test]
    fn chaining_fragments_at_255() {
        let data = vec![0x11; 600];
        let blocks = chain_short(0x80, &data, 255, |cla, chunk, last| {
            if last {
                case4(cla, 0x10, 0x00, 0x00, chunk, 256, false)
            } else {
                case3(cla, 0x10, 0x00, 0x00, chunk, false)
            }
        });
        assert_eq!(blocks.len(), 3);
        // Chaining blocks: 0x90 on all but the last.
        assert_eq!(blocks[0].bytes[0], 0x90);
        assert_eq!(blocks[1].bytes[0], 0x90);
        assert_eq!(blocks[2].bytes[0], 0x80);
        assert_eq!(blocks[0].bytes.len(), 5 + 255);
        assert_eq!(blocks[1].bytes.len(), 5 + 255);
        assert_eq!(blocks[2].bytes.len(), 5 + 90 + 1);
    }

    #[test]
    fn needs_extended_boundaries() {
        assert!(!needs_extended(255, 256));
        assert!(needs_extended(256, 256));
        assert!(needs_extended(0, 257));
    }
}
