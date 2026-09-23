//! HID report-descriptor usage extraction — the pure parser behind
//! enumeration (design D7 / OQ-4).
//!
//! Reads the kernel-exposed binary `report_descriptor` sysfs attribute
//! bytes and decides whether the device declares the FIDO usage page
//! 0xF1D0 with usage 0x01 (CTAPHID), per CTAP2.1 §11.2.8.2: "A unique
//! Usage Page is defined (0xF1D0) for the FIDO alliance and under this
//! realm, a CTAPHID Usage is defined as well (0x01). During CTAPHID
//! device discovery, all HID devices present in the system are
//! examined and devices that match this usage pages and usage are then
//! considered to be CTAPHID devices."
//!
//! Parsing follows the USB HID 1.11 spec §6.2.2 (Report Descriptor:
//! main/global/local items; short items carry a 2-bit size and 2-bit
//! type in the prefix, 0–4 payload bytes; long items — prefix
//! 0xFE — are skipped). Usage items inherit the Usage Page active when
//! they were declared (HID 1.11 §6.2.2.7); 32-bit usage payloads with
//! nonzero high bits embed the page inline (extended usage). The
//! parser tracks the Global-item stack (Push/Pop) so nested
//! collections are matched correctly.
//!
//! No `unsafe`, no ioctl: the bytes come from sysfs, not HIDIOCGRDESC
//! (crate-level `forbid(unsafe_code)`).

use alloc::vec::Vec;

use crate::error::FramingError;

/// The FIDO Alliance usage page (CTAP2.1 §11.2.8.2).
pub const FIDO_USAGE_PAGE: u16 = 0xF1D0;

/// The CTAPHID usage within the FIDO page (CTAP2.1 §11.2.8.2).
pub const CTAPHID_USAGE: u16 = 0x0001;

/// Short-item type field values (HID 1.11 §6.2.2.1).
mod item_type {
    /// Main items (Input/Output/Feature/Collection/End Collection).
    pub const MAIN: u8 = 0x0;
    /// Global items (Usage Page, Report Size/Count, Push/Pop, …).
    pub const GLOBAL: u8 = 0x1;
    /// Local items (Usage, Usage Minimum/Maximum, …).
    pub const LOCAL: u8 = 0x2;
}

/// The Global-item fields this parser tracks (HID 1.11 §6.2.2.4):
/// the active usage page, and report size/count for output sizing.
#[derive(Clone, Copy, Debug, Default)]
struct Globals {
    /// The active usage page (0 = none declared yet).
    page: u32,
    /// `Report Size` (bits per report field).
    report_size: u32,
    /// `Report Count` (fields per report).
    report_count: u32,
}

/// Outcome of scanning one descriptor for the FIDO usage pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FidoMatch {
    /// Usage page 0xF1D0 was declared anywhere in the descriptor.
    pub page: bool,
    /// Usage 0x01 was declared while the FIDO page was active (or as
    /// an extended 32-bit usage embedding the page).
    pub usage: bool,
    /// The parsed output-report size in bytes (Report Size × Report
    /// Count ÷ 8 at the first Output main item), when determinable.
    /// Drives CTAPHID OUT-report sizing (design OQ: the probe suite
    /// compares this against the actual 64-byte report).
    pub output_report_size: Option<usize>,
}

impl FidoMatch {
    /// Whether the descriptor identifies a CTAPHID device (§11.2.8.2).
    pub fn is_fido(self) -> bool {
        self.page && self.usage
    }
}

/// Scan a full report descriptor for the FIDO usage pair (§11.2.8.2).
///
/// Malformed item structure (truncated payload, sizes past the end,
/// cut-off long items) returns a typed error rather than a guess: an
/// unreadable or nonsensical descriptor must not silently admit or
/// reject a device (spec scenario "Unreadable report descriptor
/// degrades, not fails" — callers degrade per-node failures to
/// diagnostics).
pub fn find_fido_usage(descriptor: &[u8]) -> Result<FidoMatch, FramingError> {
    let mut globals = Globals::default();
    let mut stack: Vec<Globals> = Vec::new();
    let mut page_declared = false;
    let mut usage_matched = false;
    let mut output_report_size: Option<usize> = None;

    let mut i = 0usize;
    while i < descriptor.len() {
        let prefix = descriptor[i];
        i += 1;
        if prefix == 0xFE {
            // Long item: next byte is the long-item tag, then a 1-byte
            // length (HID 1.11 §6.2.2.3). Skip the data.
            if i + 2 > descriptor.len() {
                return Err(FramingError::ShortReport {
                    got: descriptor.len(),
                });
            }
            let len = descriptor[i + 1] as usize;
            i += 2 + len;
            if i > descriptor.len() {
                return Err(FramingError::ShortReport {
                    got: descriptor.len(),
                });
            }
            continue;
        }
        // Short item: bits 0–1 size code, bits 2–3 type, bits 4–7 tag
        // (HID 1.11 §6.2.2.1).
        let size: usize = match prefix & 0b11 {
            0 => 0,
            1 => 1,
            2 => 2,
            _ => 4, // two-bit code 3 = 4 bytes
        };
        let ty = (prefix >> 2) & 0b11;
        let tag = (prefix >> 4) & 0b1111;
        if i + size > descriptor.len() {
            return Err(FramingError::ShortReport {
                got: descriptor.len(),
            });
        }
        let raw = &descriptor[i..i + size];
        i += size;
        // Unsigned little-endian payload. (HID 1.11 §6.2.2.2: values
        // may be signed two's-complement; usage pages/usages are
        // always treated unsigned, and bit-31-set 4-byte usages are
        // extended usages — see `split_usage`.)
        let unsigned: u32 = match size {
            0 => 0,
            1 => u32::from(raw[0]),
            2 => u32::from(u16::from_le_bytes([raw[0], raw[1]])),
            _ => u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
        };
        // Global item tags (HID 1.11 §6.2.2.7 — the WELL-KNOWN
        // prefixes: Usage Page (Generic Desktop) = 05 01, i.e. tag 0,
        // type Global): Usage Page 0x0, Push 0xA, Pop 0xB, Report
        // Size 0x7, Report Count 0x9.
        match (ty, tag) {
            // Global, Usage Page (HID 1.11 §6.2.2.7, tag 0).
            (item_type::GLOBAL, 0x00) => {
                globals.page = unsigned;
                if unsigned == u32::from(FIDO_USAGE_PAGE) {
                    page_declared = true;
                }
            }
            // Global, Push 0x0A — snapshot globals.
            (item_type::GLOBAL, 0x0A) => stack.push(globals),

            // Global, Pop 0x0B — restore globals.
            (item_type::GLOBAL, 0x0B) => {
                if let Some(g) = stack.pop() {
                    globals = g;
                }
            }
            // Global, Report Size 0x7 (prefix 0x75 size 1).
            (item_type::GLOBAL, 0x07) => globals.report_size = unsigned,
            // Global, Report Count 0x9 (prefix 0x95 size 1).
            (item_type::GLOBAL, 0x09) => globals.report_count = unsigned,
            // Local, Usage 0x00 (HID 1.11 §6.2.2.7).
            (item_type::LOCAL, 0x00) => {
                let (usage_page, usage) = match split_usage(unsigned, globals.page) {
                    Some(pair) => pair,
                    None => (globals.page, unsigned),
                };
                if usage_page == u32::from(FIDO_USAGE_PAGE) && usage == u32::from(CTAPHID_USAGE) {
                    usage_matched = true;
                    // An extended usage carries its page inline; that
                    // IS the page declaration.
                    page_declared = true;
                }
            }
            // Main, Output 0x09: the output report's total size from
            // the globals in effect (first one wins — a second Output
            // item under a different report ID is its own report).
            (item_type::MAIN, 0x09)
                if output_report_size.is_none()
                    && globals.report_size > 0
                    && globals.report_count > 0 =>
            {
                output_report_size = Some(
                    (globals.report_size as usize).saturating_mul(globals.report_count as usize)
                        / 8,
                );
            }
            // All other items (Input, Feature, Collection, End
            // Collection, Logical/Physical Minimum-Maximum, Usage
            // Minimum/Maximum, …) carry no usage-page/usage evidence
            // for this parser.
            _ => {}
        }
    }
    Ok(FidoMatch {
        page: page_declared,
        usage: usage_matched,
        output_report_size,
    })
}

/// Resolve a Usage item payload against the active page: 32-bit
/// values with nonzero high bits carry the page inline (extended
/// usage, HID 1.11 §6.2.2.7); smaller values are page-relative and
/// resolve against `active_page`.
fn split_usage(unsigned: u32, active_page: u32) -> Option<(u32, u32)> {
    if unsigned & 0xFFFF_0000 != 0 {
        Some((unsigned >> 16, unsigned & 0xFFFF))
    } else {
        Some((active_page, unsigned))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    /// Build a short item (HID 1.11 §6.2.2.1).
    fn item(tag: u8, ty: u8, payload: &[u8]) -> Vec<u8> {
        let size_code = match payload.len() {
            0 => 0u8,
            1 => 1,
            2 => 2,
            3 | 4 => 3,
            _ => panic!("payload too large for a short item"),
        };
        let mut out = vec![(tag << 4) | (ty << 2) | size_code];
        out.extend_from_slice(payload);
        out
    }

    fn usage_page(p: u16) -> Vec<u8> {
        // Real encoding: Usage Page (0xF1D0) = 06 D0 F1 (tag 0, Global,
        // size 2); HID 1.11 §6.2.2.7.
        item(0x00, item_type::GLOBAL, &p.to_le_bytes())
    }

    fn usage(u: u16) -> Vec<u8> {
        item(0x00, item_type::LOCAL, &u.to_le_bytes())
    }

    fn collection_open_close() -> Vec<u8> {
        // Collection 0xA1 0x01 (Application), End Collection 0xC0.
        vec![0xA1, 0x01, 0xC0]
    }

    /// The CTAP2.1 §11.2.8.2 reference-report-descriptor shape for a
    /// CTAPHID device (usage page + usage + collection with 64-byte
    /// input/output reports), synthesized from the spec's structure.
    fn fido_descriptor() -> Vec<u8> {
        let mut d = usage_page(FIDO_USAGE_PAGE);
        d.extend(usage(CTAPHID_USAGE));
        d.extend(collection_open_close());
        // Input: 64 bytes (Report Size 8 × Count 64).
        d.extend(item(0x07, item_type::GLOBAL, &[8]));
        d.extend(item(0x09, item_type::GLOBAL, &[64]));
        d.extend(item(0x08, item_type::MAIN, &[2])); // Data,Var,Abs
                                                     // Output: 64 bytes.
        d.extend(item(0x09, item_type::MAIN, &[2]));
        d.extend(collection_open_close());
        d
    }

    fn keyboard_descriptor() -> Vec<u8> {
        // Generic Desktop page 0x01, usage 0x06 (keyboard).
        let mut d = usage_page(0x01);
        d.extend(usage(0x06));
        d.extend(collection_open_close());
        d
    }

    // Spec scenario: "FIDO usage match is enumerated regardless of
    // vendor" — the FIDO-usage descriptor matches, the keyboard's does
    // not; nothing in the parser sees VID/PID.
    #[test]
    fn fido_usage_matches_keyboard_does_not() {
        let fido = find_fido_usage(&fido_descriptor()).expect("parse fido");
        assert!(fido.is_fido(), "{fido:?}");
        assert_eq!(fido.output_report_size, Some(64));
        let kb = find_fido_usage(&keyboard_descriptor()).expect("parse keyboard");
        assert!(!kb.is_fido(), "{kb:?}");
    }

    // Usage declared BEFORE the page switch resolves against the
    // earlier page, not the later one — a keyboard whose usages
    // precede an unrelated page must not match.
    #[test]
    fn usage_before_page_switch_does_not_match() {
        let mut d = usage(0x06); // usage 6, no page yet (page = 0)
        d.extend(usage_page(0x01)); // page arrives after the usage
        d.extend(collection_open_close());
        let m = find_fido_usage(&d).expect("parse");
        assert!(!m.is_fido(), "{m:?}");
    }

    // Extended usage (nonzero high 16 bits) embeds the page inline
    // (HID 1.11 §6.2.2.7): matches even without a Usage Page item.
    #[test]
    fn extended_usage_32bit_matches() {
        let mut d = item(0x00, item_type::LOCAL, &0xF1D0_0001u32.to_le_bytes());
        d.extend(collection_open_close());
        let m = find_fido_usage(&d).expect("parse");
        assert!(m.is_fido(), "{m:?}");
    }

    // Multi-usage descriptors: the FIDO pair among other usages still
    // matches; a device declaring the page but never usage 0x01 (a
    // hypothetical other FIDO-page user) must NOT match.
    #[test]
    fn multi_usage_and_page_without_usage() {
        let mut d = usage_page(FIDO_USAGE_PAGE);
        d.extend(usage(0x20)); // some other FIDO-page usage
        d.extend(usage(CTAPHID_USAGE));
        d.extend(usage(0x21));
        d.extend(collection_open_close());
        assert!(find_fido_usage(&d).expect("parse").is_fido());

        let mut d = usage_page(FIDO_USAGE_PAGE);
        d.extend(usage(0x30));
        d.extend(collection_open_close());
        let m = find_fido_usage(&d).expect("parse");
        assert!(
            !m.is_fido(),
            "page without usage 0x01 must not match: {m:?}"
        );
    }

    // Malformed: truncated payload / cut-off items are typed errors,
    // never silent acceptance (an unreadable descriptor must not admit
    // a device as a candidate).
    #[test]
    fn malformed_descriptors_are_typed_errors() {
        // A 2-byte-size usage item with the payload cut off.
        let mut d = usage_page(FIDO_USAGE_PAGE);
        d.extend(vec![0x02]); // prefix claims 2 payload bytes, none follow
        assert!(find_fido_usage(&d).is_err());
        // A long-item header cut off mid-length.
        assert!(find_fido_usage(&[0xFE, 0xFE]).is_err());
        // Long item claiming more data than the buffer holds.
        assert!(find_fido_usage(&[0xFE, 0xFE, 0x20, 0xAA, 0xBB]).is_err());
        // Empty descriptor: parses trivially, no match.
        assert_eq!(
            find_fido_usage(&[]).expect("empty"),
            FidoMatch {
                page: false,
                usage: false,
                output_report_size: None,
            }
        );
    }

    // Push/Pop restores the active page (HID 1.11 §6.2.2.4).
    #[test]
    fn push_pop_restores_page() {
        let mut d = usage_page(FIDO_USAGE_PAGE);
        d.extend(item(0x0A, item_type::GLOBAL, &[])); // Push
        d.extend(usage_page(0x01)); // switch away
        d.extend(item(0x0B, item_type::GLOBAL, &[])); // Pop
        d.extend(usage(CTAPHID_USAGE));
        d.extend(collection_open_close());
        assert!(find_fido_usage(&d).expect("parse").is_fido());
    }

    // Output-report size extraction drives SET_REPORT sizing (first
    // output item wins).
    #[test]
    fn output_report_size_first_item_wins() {
        let mut d = usage_page(FIDO_USAGE_PAGE);
        d.extend(usage(CTAPHID_USAGE));
        d.extend(collection_open_close());
        d.extend(item(0x07, item_type::GLOBAL, &[8]));
        d.extend(item(0x09, item_type::GLOBAL, &[64]));
        d.extend(item(0x09, item_type::MAIN, &[2])); // Output 64 B
        d.extend(item(0x09, item_type::GLOBAL, &[16]));
        d.extend(item(0x09, item_type::MAIN, &[2])); // Output 32 B (ignored)
        let m = find_fido_usage(&d).expect("parse");
        assert_eq!(m.output_report_size, Some(64));
    }
}
