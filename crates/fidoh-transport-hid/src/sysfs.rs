//! sysfs tree model and walker — the pure enumeration source (design
//! D7).
//!
//! The kernel exposes hidraw devices through sysfs:
//!
//! - `/sys/class/hidraw/hidrawN` — class links; `dev` carries the
//!   `major:minor` pair matching the `/dev/hidrawN` node (kernel
//!   hidraw doc: udev creates the /dev nodes; applications locate
//!   devices via sysfs instead of guessing node names);
//! - `/sys/class/hidraw/hidrawN/device/uevent` — `HID_ID=` and
//!   `HID_NAME=` lines for the parent HID device (kernel drivers/hid
//!   hid-core.c);
//! - `/sys/class/hidraw/hidrawN/device/report_descriptor` — the
//!   binary HID report descriptor (bin attribute).
//!
//! `HidRawSysfs` is a read-only TREE MODEL (pure data, fully testable
//! against a fixture tree); `walk` is the scanner that builds it with
//! a caller-supplied file reader so tests drive it without /sys. The
//! fd layer (fd.rs) supplies the real reader.
//!
//! Missing directories yield empty enumeration; unreadable descriptors
//! degrade that node to a diagnostic (spec scenario "Unreadable report
//! descriptor degrades, not fails") — never a panic, never a total
//! failure.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::descriptor::{self, FidoMatch};
use crate::error::HidError;

/// The `dev` attribute value: decimal `major:minor` (kernel hidraw
/// class_show / hidraw doc).
pub(crate) fn parse_dev(text: &str) -> Option<(u32, u32)> {
    let (major, minor) = text.trim().split_once(':')?;
    Some((major.trim().parse().ok()?, minor.trim().parse().ok()?))
}

/// One `HID_ID=0003:0000240A:00001101` line (bustype:vendor:product,
/// hex, kernel hid-core.c uevent format).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HidId {
    /// Bus type (3 = USB per linux/hid.h BUS_USB).
    pub bustype: u16,
    /// USB vendor id (diagnostics only — enumeration NEVER filters on
    /// it, spec requirement: no VID/PID filter).
    pub vendor: u16,
    /// USB product id (diagnostics only).
    pub product: u16,
}

/// Parse a `HID_ID=0003:0000240A:00001101` value.
pub(crate) fn parse_hid_id(value: &str) -> Option<HidId> {
    let mut parts = value.trim().split(':');
    let bustype = u16::from_str_radix(parts.next()?.trim(), 16).ok()?;
    let vendor = u16::from_str_radix(parts.next()?.trim(), 16).ok()?;
    let product = u16::from_str_radix(parts.next()?.trim(), 16).ok()?;
    Some(HidId {
        bustype,
        vendor,
        product,
    })
}

/// Parse the `uevent` file content into (HID_ID, HID_NAME). Missing
/// lines are `None` — name/id are diagnostics, never match criteria.
pub(crate) fn parse_uevent(text: &str) -> (Option<HidId>, Option<String>) {
    let mut id = None;
    let mut name = None;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("HID_ID=") {
            id = parse_hid_id(v);
        } else if let Some(v) = line.strip_prefix("HID_NAME=") {
            name = Some(v.trim_end().to_string());
        }
    }
    (id, name)
}

/// One enumerated hidraw candidate's sysfs record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HidRawEntry {
    /// Node name, e.g. `hidraw0`.
    pub name: String,
    /// The device node path (`/dev/hidrawN`) for the fd layer.
    pub dev_path: String,
    /// `major:minor` from the `dev` attribute (ties the sysfs entry to
    /// the /dev node).
    pub dev: Option<(u32, u32)>,
    /// Parent HID device identity from uevent (diagnostics).
    pub hid_id: Option<HidId>,
    /// Parent HID device name from uevent (diagnostics / DeviceInfo
    /// name before the INIT handshake — hidraw exposes no product
    /// string before INIT, async-core `DeviceInfo::aaguid` note).
    pub hid_name: Option<String>,
    /// The report descriptor bytes as read (kept for probes).
    pub report_descriptor: Vec<u8>,
    /// Parser verdict: does the descriptor declare FIDO page + usage?
    pub fido: FidoMatch,
}

/// Read result abstraction so `walk` is testable without /sys (and
/// so the integration tests can drive enumeration against fixture
/// trees).
pub trait SysfsRead {
    /// Read a whole file; `Err` on missing/unreadable (ENOENT, EACCES,
    /// …).
    fn read(&self, path: &str) -> Result<Vec<u8>, HidError>;
    /// List directory entries; `Err` on missing/unreadable.
    fn read_dir(&self, path: &str) -> Result<Vec<String>, HidError>;
}

/// Scan a sysfs hidraw class directory and return the FIDO-matching
/// entries plus per-node diagnostics for skipped ones.
///
/// `class_dir` is normally `/sys/class/hidraw`; tests pass a fixture
/// root. Ordering is the directory's natural (ascending-name) order so
/// enumeration is deterministic (async-core: transport order).
///
/// Per the spec scenarios:
/// - a node whose descriptor fails to read or parse is skipped and
///   recorded as a diagnostic; the scan continues;
/// - nodes whose descriptor parses but lacks the FIDO usage are
///   simply not candidates (no diagnostic — an ordinary keyboard is
///   not an error);
/// - a missing class directory (no hidraw devices at all) is an EMPTY
///   enumeration, not an error (spec: "Missing dirs/nodes → empty
///   enumeration or typed error, never panic").
pub(crate) fn walk(reader: &dyn SysfsRead, class_dir: &str) -> (Vec<HidRawEntry>, Vec<HidError>) {
    let mut candidates = Vec::new();
    let mut diagnostics = Vec::new();
    let names = match reader.read_dir(class_dir) {
        Ok(names) => names,
        Err(_) => return (candidates, diagnostics), // empty enumeration
    };
    let mut names = names;
    // Sort numerically by node index (hidraw0 < hidraw2 < hidraw10):
    // readdir order is arbitrary; the async-core contract wants a
    // deterministic transport order.
    names.sort_by_key(|n| {
        n.strip_prefix("hidraw")
            .and_then(|r| r.parse::<u32>().ok())
            .unwrap_or(u32::MAX)
    });
    for name in names {
        // hidrawN: exactly `hidraw` followed by decimal digits (the
        // kernel's node naming); anything else in the class dir is
        // ignored.
        let rest = name.strip_prefix("hidraw");
        match rest {
            Some(r) if !r.is_empty() && r.bytes().all(|b| b.is_ascii_digit()) => {}
            _ => continue,
        }
        let base = format!("{class_dir}/{name}");
        // dev attribute: optional (diagnostic only).
        let dev = reader
            .read(&format!("{base}/dev"))
            .ok()
            .and_then(|b| String::from_utf8(b).ok().and_then(|s| parse_dev(&s)));
        // uevent: optional (name/id are diagnostics).
        let (hid_id, hid_name) = reader
            .read(&format!("{base}/device/uevent"))
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .map(|s| parse_uevent(&s))
            .unwrap_or((None, None));
        // report_descriptor: REQUIRED for candidacy. Unreadable →
        // skip the node with a diagnostic (spec scenario).
        let descriptor_bytes = match reader.read(&format!("{base}/device/report_descriptor")) {
            Ok(bytes) => bytes,
            Err(e) => {
                diagnostics.push(e);
                continue;
            }
        };
        // Malformed descriptor: same degradation path.
        let fido = match descriptor::find_fido_usage(&descriptor_bytes) {
            Ok(m) => m,
            Err(e) => {
                diagnostics.push(e.into());
                continue;
            }
        };
        if !fido.is_fido() {
            continue; // ordinary HID device, not an error
        }
        candidates.push(HidRawEntry {
            dev_path: format!("/dev/{name}"),
            name,
            dev,
            hid_id,
            hid_name,
            report_descriptor: descriptor_bytes,
            fido,
        });
    }
    (candidates, diagnostics)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    /// In-memory sysfs fixture: map of path → bytes.
    struct Fixture {
        files: BTreeMap<String, Vec<u8>>,
        dirs: BTreeMap<String, Vec<String>>,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                files: BTreeMap::new(),
                dirs: BTreeMap::new(),
            }
        }

        fn file(&mut self, path: &str, bytes: &[u8]) {
            self.files.insert(String::from(path), bytes.to_vec());
        }

        fn dir(&mut self, path: &str, entries: &[&str]) {
            self.dirs.insert(
                String::from(path),
                entries.iter().map(|s| String::from(*s)).collect(),
            );
        }
    }

    impl SysfsRead for Fixture {
        fn read(&self, path: &str) -> Result<Vec<u8>, HidError> {
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| HidError::io(path, "read", "No such file or directory (os error 2)"))
        }

        fn read_dir(&self, path: &str) -> Result<Vec<String>, HidError> {
            self.dirs.get(path).cloned().ok_or_else(|| {
                HidError::io(path, "read_dir", "No such file or directory (os error 2)")
            })
        }
    }

    fn fido_descriptor_bytes() -> Vec<u8> {
        // The same shape descriptor.rs's tests build: page + usage +
        // collection. (Constructed fixture; not captured hardware.)
        let mut d = vec![0x06, 0xD0, 0xF1]; // Usage Page 0xF1D0
        d.extend([0x09, 0x01]); // Usage 0x01 (Local tag 0, size 1)
        d.extend([0xA1, 0x01]); // Collection (Application)
        d.extend([0x75, 0x08, 0x95, 0x40]); // Report Size 8, Count 64
        d.extend([0x81, 0x02]); // Input
        d.extend([0x91, 0x02]); // Output
        d.push(0xC0); // End Collection
        d
    }

    fn keyboard_descriptor_bytes() -> Vec<u8> {
        let mut d = vec![0x05, 0x01]; // Usage Page 0x01 (Generic Desktop)
        d.extend([0x09, 0x06]); // Usage 0x06 (Keyboard)
        d.extend([0xA1, 0x01, 0xC0]);
        d
    }

    /// Build a fixture with one FIDO hidraw (hidraw0) and one keyboard
    /// hidraw (hidraw1).
    fn two_node_fixture() -> Fixture {
        let mut f = Fixture::new();
        f.dir("/sys/class/hidraw", &["hidraw0", "hidraw1"]);
        f.file("/sys/class/hidraw/hidraw0/dev", b"244:0\n");
        f.file(
            "/sys/class/hidraw/hidraw0/device/uevent",
            b"DRIVER=hid-generic\nHID_ID=0003:00001050:00000407\nHID_NAME=Yubico YubiKey\n",
        );
        f.file(
            "/sys/class/hidraw/hidraw0/device/report_descriptor",
            &fido_descriptor_bytes(),
        );
        f.file("/sys/class/hidraw/hidraw1/dev", b"244:1\n");
        f.file(
            "/sys/class/hidraw/hidraw1/device/uevent",
            b"DRIVER=hid-generic\nHID_ID=0003:000004D9:00001234\nHID_NAME=Keyboard\n",
        );
        f.file(
            "/sys/class/hidraw/hidraw1/device/report_descriptor",
            &keyboard_descriptor_bytes(),
        );
        f
    }

    // The fixture descriptor bytes themselves parse as FIDO (guards
    // fixture drift from the parser).
    #[test]
    fn fixture_descriptor_bytes_parse_as_fido() {
        let m = crate::descriptor::find_fido_usage(&fido_descriptor_bytes())
            .expect("fixture descriptor parses");
        assert!(m.is_fido(), "fixture parse: {m:?}");
        assert_eq!(m.output_report_size, Some(64));
    }

    // Spec scenario: "FIDO usage match is enumerated regardless of
    // vendor" — exactly the FIDO-usage node comes back; the keyboard
    // node is not a candidate and not a diagnostic.
    #[test]
    fn fido_node_enumerated_keyboard_skipped() {
        let f = two_node_fixture();
        let (candidates, diagnostics) = walk(&f, "/sys/class/hidraw");
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert_eq!(candidates.len(), 1, "candidates: {candidates:?}");
        let c = &candidates[0];
        assert_eq!(c.name, "hidraw0");
        assert_eq!(c.dev_path, "/dev/hidraw0");
        assert_eq!(c.dev, Some((244, 0)));
        assert_eq!(
            c.hid_id,
            Some(HidId {
                bustype: 3,
                vendor: 0x1050,
                product: 0x0407,
            })
        );
        assert_eq!(c.hid_name.as_deref(), Some("Yubico YubiKey"));
        assert!(c.fido.is_fido());
    }

    // Missing class dir → empty enumeration, no diagnostics, no panic
    // ("Missing dirs/nodes → empty enumeration").
    #[test]
    fn missing_class_dir_is_empty_enumeration() {
        let f = Fixture::new();
        let (candidates, diagnostics) = walk(&f, "/sys/class/hidraw");
        assert!(candidates.is_empty());
        assert!(diagnostics.is_empty());
    }

    // Spec scenario: "Unreadable report descriptor degrades, not
    // fails" — the bad node is skipped with a diagnostic; the other
    // candidate still comes back.
    #[test]
    fn unreadable_descriptor_degrades_to_diagnostic() {
        let mut f = two_node_fixture();
        f.dir("/sys/class/hidraw", &["hidraw0", "hidraw1", "hidraw2"]);
        f.file("/sys/class/hidraw/hidraw2/dev", b"244:2\n");
        // hidraw2 has a uevent but NO report_descriptor file (EACCES /
        // ENOENT race with unplug).
        f.file(
            "/sys/class/hidraw/hidraw2/device/uevent",
            b"HID_ID=0003:00001050:00000407\nHID_NAME=Gone Soon\n",
        );
        let (candidates, diagnostics) = walk(&f, "/sys/class/hidraw");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].name, "hidraw0");
        assert_eq!(diagnostics.len(), 1);
        assert!(matches!(&diagnostics[0], HidError::Io { path, .. } if path.contains("hidraw2")));
    }

    // A MALFORMED descriptor also degrades with a diagnostic rather
    // than panicking or admitting the node.
    #[test]
    fn malformed_descriptor_degrades_to_diagnostic() {
        let mut f = two_node_fixture();
        f.file(
            "/sys/class/hidraw/hidraw1/device/report_descriptor",
            &[0x06, 0xD0], // Usage Page claiming 2 bytes, payload cut
        );
        let (candidates, diagnostics) = walk(&f, "/sys/class/hidraw");
        assert_eq!(candidates.len(), 1);
        assert_eq!(diagnostics.len(), 1);
        assert!(matches!(diagnostics[0], HidError::Framing(_)));
    }

    // Enumeration order is deterministic ascending node name.
    #[test]
    fn enumeration_order_is_deterministic() {
        let mut f = Fixture::new();
        f.dir("/sys/class/hidraw", &["hidraw10", "hidraw2", "hidraw0"]);
        for n in ["hidraw0", "hidraw2", "hidraw10"] {
            f.file(
                &format!("/sys/class/hidraw/{n}/device/report_descriptor"),
                &fido_descriptor_bytes(),
            );
        }
        let (candidates, _) = walk(&f, "/sys/class/hidraw");
        let names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
        // Numeric order (hidraw2 < hidraw10), NOT shell-lexicographic.
        assert_eq!(names, vec!["hidraw0", "hidraw2", "hidraw10"]);
    }

    // Non-hidraw entries are ignored.
    #[test]
    fn non_hidraw_entries_ignored() {
        let mut f = Fixture::new();
        f.dir("/sys/class/hidraw", &["hidraw0", "README", "usb1"]);
        f.file(
            "/sys/class/hidraw/hidraw0/device/report_descriptor",
            &fido_descriptor_bytes(),
        );
        let (candidates, diagnostics) = walk(&f, "/sys/class/hidraw");
        assert_eq!(candidates.len(), 1);
        assert!(diagnostics.is_empty());
    }

    // uevent/dev parsers.
    #[test]
    fn dev_and_uevent_parsers() {
        assert_eq!(parse_dev("244:0\n"), Some((244, 0)));
        assert_eq!(parse_dev(" 1:2 "), Some((1, 2)));
        assert_eq!(parse_dev("nonsense"), None);
        assert_eq!(parse_dev(""), None);
        assert_eq!(
            parse_hid_id("0003:0000240A:00001101"),
            Some(HidId {
                bustype: 3,
                vendor: 0x240A,
                product: 0x1101,
            })
        );
        assert_eq!(parse_hid_id("x:1:2"), None);
        let (id, name) = parse_uevent(
            "DRIVER=hid-generic\nHID_ID=0003:00001050:00000407\nHID_NAME=Yubico YubiKey OTP\n",
        );
        assert_eq!(
            id,
            Some(HidId {
                bustype: 3,
                vendor: 0x1050,
                product: 0x0407,
            })
        );
        assert_eq!(name.as_deref(), Some("Yubico YubiKey OTP"));
        // Absent lines are None, not errors.
        let (id, name) = parse_uevent("DRIVER=hid-generic\n");
        assert_eq!(id, None);
        assert_eq!(name, None);
    }
}
