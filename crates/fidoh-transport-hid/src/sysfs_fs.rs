//! The real sysfs reader: std::fs backed [`SysfsRead`] implementation
//! used by enumeration. Split from `sysfs.rs` so the tree model and
//! walker stay pure; this module is the only std::fs contact point
//! besides `fd.rs`.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::HidError;
use crate::sysfs::SysfsRead;

/// Reads real filesystem paths under a root (normally `/sys`).
pub(crate) struct FsSysfs {
    /// Root prepended to every path (tests can point it at a fixture
    /// tree; production uses `/sys`).
    root: String,
}

impl FsSysfs {
    /// The production reader rooted at `/sys`.
    pub(crate) fn system() -> Self {
        Self {
            root: String::from("/sys"),
        }
    }

    /// A reader rooted elsewhere (fixture trees in integration tests).
    /// `root` REPLACES the leading `/sys` of every path (e.g.
    /// `rooted("/tmp/fx")` maps `/sys/class/hidraw` to
    /// `/tmp/fx/class/hidraw`); the production root `"/sys"` composes
    /// back to the unchanged absolute path.
    pub(crate) fn rooted(root: &str) -> Self {
        Self {
            root: String::from(root),
        }
    }

    fn full(&self, path: &str) -> String {
        // `root` replaces the leading `/sys` of the absolute sysfs path
        // (regression: composing the root in front of an already
        // absolute `/sys/...` path produced `/sys/sys/...`, which made
        // every real enumeration silently empty — the missing-dir
        // degradation path, by spec, reports nothing).
        let rel = path.strip_prefix("/sys").unwrap_or(path);
        alloc::format!("{}{}", self.root, rel)
    }
}

impl SysfsRead for FsSysfs {
    fn read(&self, path: &str) -> Result<Vec<u8>, HidError> {
        std::fs::read(self.full(path))
            .map_err(|e| HidError::io(path, "read", alloc::format!("{e}")))
    }

    fn read_dir(&self, path: &str) -> Result<Vec<String>, HidError> {
        let mut out: Vec<String> = Vec::new();
        // A directory entry racing an unplug mid-iteration is skipped,
        // not fatal.
        for entry in std::fs::read_dir(self.full(path))
            .map_err(|e| HidError::io(path, "read_dir", alloc::format!("{e}")))?
            .flatten()
        {
            out.push(entry.file_name().to_string_lossy().into_owned());
        }
        Ok(out)
    }
}

/// Enumerate FIDO hidraw candidates on the real system: walk
/// `/sys/class/hidraw` (design D7), returning matching entries and
/// per-node diagnostics.
#[allow(dead_code)]
pub(crate) fn enumerate_system() -> (Vec<crate::sysfs::HidRawEntry>, Vec<HidError>) {
    crate::sysfs::walk(&FsSysfs::system(), "/sys/class/hidraw")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// The FIDO-matching descriptor shape (same bytes the sysfs unit
    /// fixtures use): Usage Page 0xF1D0, Usage 0x01, collection with
    /// 64-byte reports.
    fn fido_descriptor_bytes() -> Vec<u8> {
        let mut d = vec![0x06, 0xD0, 0xF1];
        d.extend([
            0x09, 0x01, 0xA1, 0x01, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0x91, 0x02, 0xC0,
        ]);
        d
    }

    // REGRESSION (OQ-4 hardware-day finding): FsSysfs must compose with
    // walk's absolute class_dir so the PRODUCTION reader sees the real
    // `/sys/class/hidraw` — composing the root verbatim in front of the
    // absolute path produced `/sys/sys/...`, silently empty on every
    // real machine while all fixture tests stayed green.
    #[test]
    fn fs_sysfs_system_composes_to_real_sys_class() {
        // Arrange the same shape under a fake root, but ask through the
        // PRODUCTION root and walk's PRODUCTION absolute class_dir.
        let tmp = std::env::temp_dir().join(format!("fidoh-sysfs-fs-{}", std::process::id()));
        let class = tmp.join("class/hidraw");
        fs::create_dir_all(&class).expect("mk class");
        fs::create_dir_all(class.join("hidraw0/device")).expect("mk node");
        fs::write(class.join("hidraw0/dev"), b"244:0\n").expect("dev");
        fs::write(
            class.join("hidraw0/device/uevent"),
            b"DRIVER=hid-generic\nHID_ID=0003:00001050:00000406\nHID_NAME=Yubico YubiKey FIDO+CCID\n",
        )
        .expect("uevent");
        fs::write(
            class.join("hidraw0/device/report_descriptor"),
            fido_descriptor_bytes(),
        )
        .expect("desc");

        let reader = FsSysfs::rooted(tmp.to_str().expect("utf8 tmp"));
        let (candidates, diagnostics) = crate::sysfs::walk(&reader, "/sys/class/hidraw");

        assert!(
            diagnostics.is_empty(),
            "fixture tree must be fully readable: {diagnostics:?}"
        );
        assert_eq!(candidates.len(), 1, "candidates: {candidates:?}");
        assert_eq!(candidates[0].name, "hidraw0");
        assert_eq!(candidates[0].dev_path, "/dev/hidraw0");

        fs::remove_dir_all(&tmp).ok();
    }

    // The production root composes back to the untouched absolute path:
    // `FsSysfs::system()` + walk's `/sys/class/hidraw` must read the
    // REAL `/sys/class/hidraw` (a real machine always has the class
    // dir; empty enumeration here means the composition is broken
    // again).
    #[test]
    fn fs_sysfs_production_root_reads_real_class_dir() {
        let reader = FsSysfs::system();
        // Some CI runners have no HID at all; the assertion only means
        // something on machines that do (any dev box with a keyboard).
        let Ok(names) = reader.read_dir("/sys/class/hidraw") else {
            return; // genuinely no hidraw class here — nothing to pin
        };
        assert!(
            names.iter().any(|n| n.starts_with("hidraw")),
            "/sys/class/hidraw lists but composition is broken (empty/garbled listing): {names:?}"
        );
    }
}
