//! Registry of devices that must never be written: the disks holding the running
//! system and the dfnix live medium. dfnix writes it once at boot to
//! `/run/dfnix/protected.json`, before any evidence is handled, and every tool
//! checks candidates against it in addition to its own live system detection.
//!
//! Entries are identified by WWN or serial where the device reports one, so a
//! protected disk stays protected when it re-enumerates under another kernel name,
//! and a different disk that takes over the old name is not mistaken for it.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::host;
use crate::lsblk::{self, DeviceIdentity, FlatDevice, LIVE_LABEL};
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
    pub fn protecting(&self, flat: &[FlatDevice], path: &str) -> Option<&ProtectedDevice> {
        let mut candidates: Vec<DeviceIdentity> = lsblk::roots(flat, path)
            .into_iter()
            .map(|r| r.device.identity())
            .collect();
        if let Some(own) = flat.iter().find(|f| f.device.dev_path() == path) {
            candidates.push(own.device.identity());
        }
        self.devices
            .iter()
            .find(|p| candidates.iter().any(|c| p.identity.same_device(c)))
    }
}

/// Check `path` against the registry at the default location. A missing
/// registry is not an error: the tool's own system detection still applies.
/// A protected device is refused with a [`Refusal`].
pub fn check(flat: &[FlatDevice], device_path: &str) -> Result<()> {
    let registry_path = path();
    if let Some(reg) = Registry::load(&registry_path)? {
        if let Some(p) = reg.protecting(flat, device_path) {
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
        for p in [
            "/dev/nvme0n1",
            "/dev/nvme0n1p1",
            "/dev/mapper/cryptroot",
            "/dev/sr0",
        ] {
            assert!(reg.protecting(&flat, p).is_some(), "{p}");
        }
        for p in ["/dev/sdb", "/dev/sdb1", "/dev/sde1"] {
            assert!(reg.protecting(&flat, p).is_none(), "{p}");
        }
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
        assert!(reg.protecting(&flat, "/dev/sdx").is_some());
        assert!(reg.protecting(&flat, "/dev/nvme0n1").is_none());
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
