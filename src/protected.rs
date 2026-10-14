//! Registry of devices that must never be written: the disks holding the running
//! system and the dfnix live medium. dfnix writes it once at boot to
//! `/run/dfnix/protected.json`, before any evidence is handled, and every tool
//! checks candidates against it in addition to its own live system detection.
//!
//! Entries are identified by WWN or serial where the device reports one, so a
//! protected disk stays protected when it re-enumerates under another kernel name,
//! and a different disk that takes over the old name is not mistaken for it. A
//! queried node is found in the device tree by path and by device number, so
//! aliases (`/dev/dm-N`, `/dev/disk/by-*`) resolve to the same entry.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::host;
use crate::lsblk::{self, DeviceIdentity, FlatDevice, LIVE_LABEL};
use crate::sysfs::{self, DevNum};
use crate::Refusal;

pub const DEFAULT_PATH: &str = "/run/dfnix/protected.json";
pub const SCHEMA: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// The medium dfnix booted from (label DFNIX_LIVE)
    LiveMedium,
    /// A disk holding /, /boot, /nix, swap or another system mount
    SystemDisk,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedDevice {
    pub role: Role,
    pub identity: DeviceIdentity,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registry {
    pub schema: u32,
    pub generated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_id: Option<String>,
    pub devices: Vec<ProtectedDevice>,
}

/// Registry location; `DFNIX_PROTECTED_FILE` overrides it for tests.
pub fn path() -> PathBuf {
    std::env::var_os("DFNIX_PROTECTED_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PATH))
}

impl Registry {
    /// Whole disks (and optical media) that hold the running system.
    pub fn build(flat: &[FlatDevice]) -> Self {
        let devices = flat
            .iter()
            .filter(|f| f.level == 0 && f.is_system)
            .map(|f| {
                let reasons = lsblk::system_reasons(&f.device);
                let live = reasons.iter().any(|r| r.contains(LIVE_LABEL));
                ProtectedDevice {
                    role: if live {
                        Role::LiveMedium
                    } else {
                        Role::SystemDisk
                    },
                    identity: f.device.identity(),
                    reasons,
                }
            })
            .collect();
        Registry {
            schema: SCHEMA,
            generated_at: host::rfc3339_utc(host::unix_now()),
            boot_id: host::boot_id(),
            devices,
        }
    }

    /// `None` when no registry has been written (e.g. outside dfnix).
    pub fn load(path: &Path) -> Result<Option<Self>> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let reg: Registry = serde_json::from_slice(&bytes).with_context(|| {
                    format!("Corrupt protected-device registry {}", path.display())
                })?;
                anyhow::ensure!(
                    reg.schema == SCHEMA,
                    "Unsupported protected-device registry schema {} in {}",
                    reg.schema,
                    path.display()
                );
                Ok(Some(reg))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("Cannot read {}", path.display())),
        }
    }

    /// Write via a temporary file and rename, so readers never see a partial registry.
    pub fn write_atomic(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("Cannot create {}", dir.display()))?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)
            .with_context(|| format!("Cannot write {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("Cannot replace {}", path.display()))
    }

    /// The registry entry protecting `path` or the whole disk(s) it sits on.
    /// A block device node is also matched by its device number, so `/dev/dm-3`
    /// or a `/dev/disk/by-id` link finds what lsblk lists under another name.
    pub fn protecting(&self, flat: &[FlatDevice], path: &str) -> Option<&ProtectedDevice> {
        self.protecting_dev(flat, path, sysfs::dev_num_of_path(Path::new(path)))
    }

    /// [`protecting`](Self::protecting) with the device number of the node at
    /// `path` given by the caller (`None`: match by path only).
    pub fn protecting_dev(
        &self,
        flat: &[FlatDevice],
        path: &str,
        dev: Option<DevNum>,
    ) -> Option<&ProtectedDevice> {
        let hits = lsblk::lookup(flat, path, dev);
        let candidates: Vec<DeviceIdentity> = lsblk::roots_of(flat, &hits)
            .into_iter()
            .chain(hits.iter().copied())
            .map(|f| f.device.lsblk_identity())
            .collect();
        self.devices
            .iter()
            .find(|p| candidates.iter().any(|c| p.identity.same_device(c)))
    }
}

/// Check `device_path` against the registry at the default location. A missing
/// registry is not an error: the tool's own system detection still applies.
/// Refused with a [`Refusal`]: a device the registry protects or that sits on a
/// protected disk, and a block device lsblk does not list, since neither the
/// registry nor system detection can vouch for it (fail closed).
pub fn check(flat: &[FlatDevice], device_path: &str) -> Result<()> {
    let registry = Registry::load(&path())?;
    check_against(
        registry.as_ref(),
        flat,
        device_path,
        sysfs::dev_num_of_path(Path::new(device_path)),
    )
}

/// Core of [`check`], separated from the host for tests. `dev` is the device
/// number of `device_path` when it is a block device node.
pub fn check_against(
    registry: Option<&Registry>,
    flat: &[FlatDevice],
    device_path: &str,
    dev: Option<DevNum>,
) -> Result<()> {
    if let Some((major, minor)) = dev {
        if lsblk::lookup(flat, device_path, dev).is_empty() {
            return Err(Refusal(format!(
                "ABORT: {device_path} (block device {major}:{minor}) is not listed by lsblk; refusing: it cannot be checked against the system disks and the dfnix registry"
            ))
            .into());
        }
    }
    if let Some(reg) = registry {
        if let Some(p) = reg.protecting_dev(flat, device_path, dev) {
            return Err(Refusal(format!(
                "ABORT: {} is protected by the dfnix registry ({:?} {}): {}",
                device_path,
                p.role,
                p.identity
                    .serial
                    .as_deref()
                    .or(p.identity.wwn.as_deref())
                    .unwrap_or(&p.identity.kernel_name),
                p.reasons.join("; ")
            ))
            .into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsblk::tests::{lab, LAB};

    #[test]
    fn registry_holds_system_disk_and_live_medium() {
        let reg = Registry::build(&lab());
        let names: Vec<_> = reg
            .devices
            .iter()
            .map(|d| (d.identity.kernel_name.as_str(), d.role))
            .collect();
        assert_eq!(
            names,
            [("nvme0n1", Role::SystemDisk), ("sr0", Role::LiveMedium)]
        );
        assert_eq!(reg.devices[0].identity.serial.as_deref(), Some("S6Z0NJ0W"));
    }

    #[test]
    fn protects_partitions_and_stacked_devices_of_registered_disks() {
        let flat = lab();
        let reg = Registry::build(&flat);
        // Matching by path only: the host's /dev must not decide a test
        for p in [
            "/dev/nvme0n1",
            "/dev/nvme0n1p1",
            "/dev/mapper/cryptroot",
            "/dev/sr0",
        ] {
            assert!(reg.protecting_dev(&flat, p, None).is_some(), "{p}");
        }
        for p in ["/dev/sdb", "/dev/sdb1", "/dev/sde1"] {
            assert!(reg.protecting_dev(&flat, p, None).is_none(), "{p}");
        }
        // Not a device node: matched by path
        let file = std::env::temp_dir().join(format!("dfcore_not_a_dev_{}", std::process::id()));
        std::fs::write(&file, b"x").unwrap();
        assert!(reg.protecting(&flat, &file.to_string_lossy()).is_none());
        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn device_mapper_and_alias_nodes_match_by_device_number() {
        let flat = lab();
        let reg = Registry::build(&flat);
        // canonicalize(/dev/mapper/cryptroot) is /dev/dm-0, which lsblk does not list
        assert!(reg.protecting_dev(&flat, "/dev/dm-0", None).is_none());
        let p = reg
            .protecting_dev(&flat, "/dev/dm-0", Some((254, 0)))
            .unwrap();
        assert_eq!(
            (p.identity.kernel_name.as_str(), p.role),
            ("nvme0n1", Role::SystemDisk)
        );
        let p = reg
            .protecting_dev(&flat, "/dev/disk/by-id/ata-ZM001", Some((11, 0)))
            .unwrap();
        assert_eq!(p.role, Role::LiveMedium);
        // An evidence disk reached through an alias stays unprotected
        assert!(reg
            .protecting_dev(&flat, "/dev/disk/by-id/ata-WDC_WD-EVID001", Some((8, 16)))
            .is_none());

        let e = check_against(Some(&reg), &flat, "/dev/dm-0", Some((254, 0))).unwrap_err();
        assert!(crate::is_refusal(&e), "{e:#}");
        assert!(
            e.to_string().contains("protected by the dfnix registry"),
            "{e}"
        );
    }

    #[test]
    fn a_block_device_lsblk_does_not_list_is_refused() {
        let flat = lab();
        let reg = Registry::build(&flat);
        for registry in [Some(&reg), None] {
            let e = check_against(registry, &flat, "/dev/sdz", Some((8, 200))).unwrap_err();
            assert!(crate::is_refusal(&e), "{e:#}");
            assert!(
                e.to_string().contains("not listed by lsblk; refusing"),
                "{e}"
            );
            // Listed, unprotected devices pass, by path or by number
            check_against(registry, &flat, "/dev/sdb1", Some((8, 17))).unwrap();
            check_against(registry, &flat, "/dev/disk/by-label/EVID", Some((8, 17))).unwrap();
            // Image files are not block devices and not this check's business
            check_against(registry, &flat, "/cases/disk.raw", None).unwrap();
        }
        // Without a registry only the fail-closed rule applies
        check_against(None, &flat, "/dev/nvme0n1", Some((259, 0))).unwrap();
    }

    #[test]
    fn a_replugged_protected_disk_stays_protected() {
        let flat = lab();
        let mut reg = Registry::build(&flat);
        reg.devices[1].identity.diskseq = Some(4);
        // The live medium came back as sr1 with a new device and sequence number
        let replugged = LAB
            .replace("\"sr0\"", "\"sr1\"")
            .replace("/dev/sr0", "/dev/sr1")
            .replace("\"11:0\"", "\"11:1\"");
        let flat = lsblk::parse(replugged.as_bytes()).unwrap();
        let e = check_against(Some(&reg), &flat, "/dev/sr1", Some((11, 1))).unwrap_err();
        assert!(crate::is_refusal(&e), "{e:#}");
        assert!(e.to_string().contains("LiveMedium"), "{e}");
    }

    #[test]
    fn protection_follows_the_disk_not_the_kernel_name() {
        let reg = Registry::build(&lab());
        // After a hotplug shuffle the system disk is sdx and an evidence disk got nvme0n1
        let swapped = LAB
            .replace("\"nvme0n1\"", "\"tmpname\"")
            .replace(
                "\"name\":\"sdb\",\"path\":\"/dev/sdb\"",
                "\"name\":\"nvme0n1\",\"path\":\"/dev/nvme0n1\"",
            )
            .replace(
                "\"name\":\"tmpname\",\"path\":\"/dev/nvme0n1\"",
                "\"name\":\"sdx\",\"path\":\"/dev/sdx\"",
            );
        // Unmount everything: only the registry knows which disk is the system disk
        let unmounted = swapped
            .replace("[\"/boot\"]", "[null]")
            .replace("[\"/nix/store\",\"/\"]", "[null]")
            .replace("\"DFNIX_LIVE\"", "null");
        let flat = lsblk::parse(unmounted.as_bytes()).unwrap();
        assert!(flat.iter().all(|f| !f.is_system));
        assert!(reg.protecting_dev(&flat, "/dev/sdx", None).is_some());
        assert!(reg.protecting_dev(&flat, "/dev/nvme0n1", None).is_none());
    }

    #[test]
    fn write_load_and_check() {
        let dir = std::env::temp_dir().join(format!("dfcore_registry_{}", std::process::id()));
        let file = dir.join("protected.json");
        let flat = lab();
        Registry::build(&flat).write_atomic(&file).unwrap();
        let loaded = Registry::load(&file).unwrap().unwrap();
        assert_eq!(loaded.devices.len(), 2);
        assert!(Registry::load(&dir.join("absent.json")).unwrap().is_none());
        std::fs::write(&file, b"{not json").unwrap();
        assert!(Registry::load(&file).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
