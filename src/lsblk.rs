//! Block device tree as reported by `lsblk -J`, flattened with each entry's chain of
//! enclosing devices, and the rule for what belongs to the running system.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::process::Command;

use crate::sysfs::{self, BlockTopology, DevNum};

pub const LSBLK_COLUMNS: &str =
    "NAME,PATH,MAJ:MIN,SIZE,RO,TYPE,FSTYPE,LABEL,MOUNTPOINTS,MODEL,SERIAL,WWN";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlockDevice {
    pub name: String,
    pub path: Option<String>,
    #[serde(rename = "maj:min")]
    pub maj_min: Option<String>,
    pub size: Option<String>,
    pub ro: Option<bool>,
    #[serde(rename = "type")]
    pub dev_type: Option<String>,
    pub fstype: Option<String>,
    pub label: Option<String>,
    pub mountpoints: Option<Vec<Option<String>>>,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub wwn: Option<String>,
    pub children: Option<Vec<BlockDevice>>,
}

impl BlockDevice {
    pub fn dev_path(&self) -> String {
        self.path
            .clone()
            .unwrap_or_else(|| format!("/dev/{}", self.name))
    }

    pub fn mounts(&self) -> impl Iterator<Item = &str> {
        self.mountpoints
            .iter()
            .flatten()
            .flatten()
            .map(|s| s.as_str())
    }

    pub fn is_type(&self, t: &str) -> bool {
        self.dev_type.as_deref() == Some(t)
    }

    /// Device number from the `MAJ:MIN` column.
    pub fn dev_num(&self) -> Option<DevNum> {
        sysfs::parse_dev_num(self.maj_min.as_deref()?)
    }

    /// Identity as lsblk reports it, with the disk sequence number from sysfs.
    pub fn identity(&self) -> DeviceIdentity {
        self.identity_in(&BlockTopology::default())
    }

    /// [`identity`](Self::identity) with sysfs read from `topo`.
    pub fn identity_in(&self, topo: &BlockTopology) -> DeviceIdentity {
        let mut id = self.lsblk_identity();
        id.diskseq = self.sysfs_name(topo).and_then(|k| topo.diskseq(&k));
        id
    }

    /// What lsblk reports, without looking at sysfs.
    pub(crate) fn lsblk_identity(&self) -> DeviceIdentity {
        let clean = |v: &Option<String>| {
            v.as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        DeviceIdentity {
            path: self.dev_path(),
            kernel_name: self.name.clone(),
            maj_min: clean(&self.maj_min),
            serial: clean(&self.serial),
            wwn: clean(&self.wwn),
            model: clean(&self.model),
            size: clean(&self.size),
            diskseq: None,
        }
    }

    /// Kernel name in sysfs. lsblk's NAME is the mapper name for device-mapper
    /// devices (`cryptroot`, not `dm-0`), so the device number decides.
    fn sysfs_name(&self, topo: &BlockTopology) -> Option<String> {
        match self.dev_num() {
            Some(dev) if topo.dev_of(&self.name) == Some(dev) => Some(self.name.clone()),
            Some(dev) => topo.name_of(dev),
            None => Some(self.name.clone()),
        }
    }
}

/// How a device is identified in the registry and in audit records. Serial and
/// WWN survive re-enumeration; kernel name and major:minor do not. `diskseq` is
/// new for every attachment, even of the same disk on the same node.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub path: String,
    pub kernel_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maj_min: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wwn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diskseq: Option<u64>,
}

impl DeviceIdentity {
    /// Same physical device: by WWN or serial when either side has one, otherwise
    /// by kernel name and major:minor.
    pub fn same_device(&self, other: &DeviceIdentity) -> bool {
        if let (Some(a), Some(b)) = (&self.wwn, &other.wwn) {
            return a.eq_ignore_ascii_case(b);
        }
        match (&self.serial, &other.serial) {
            (Some(a), Some(b)) => a == b,
            (Some(_), None) | (None, Some(_)) => false,
            (None, None) => {
                self.kernel_name == other.kernel_name
                    && self.maj_min.is_some()
                    && self.maj_min == other.maj_min
            }
        }
    }

    /// Same device in the same attachment: the same physical device, still
    /// behind the same major:minor and, where both sides know it, the same disk
    /// sequence number. False when a disk was swapped in on the node between two
    /// looks at it, even one that reports no serial. [`same_device`] stays true
    /// for a re-plugged disk; that is what protection follows.
    ///
    /// [`same_device`]: Self::same_device
    pub fn same_attachment(&self, other: &DeviceIdentity) -> bool {
        let seq_matches = match (self.diskseq, other.diskseq) {
            (Some(a), Some(b)) => a == b,
            _ => true,
        };
        self.maj_min.is_some()
            && self.maj_min == other.maj_min
            && seq_matches
            && self.same_device(other)
    }
}

#[derive(Debug, Deserialize)]
struct LsblkOutput {
    blockdevices: Vec<BlockDevice>,
}

#[derive(Debug, Clone)]
pub struct FlatDevice {
    pub device: BlockDevice,
    pub level: usize,
    pub is_system: bool,
    /// Paths of the enclosing devices, outermost (whole disk) first.
    /// lsblk lists a holder (dm, md) under every device it spans, so such a
    /// device appears once per parent, each time with a different chain.
    pub ancestors: Vec<String>,
}

impl FlatDevice {
    /// Path of the whole disk this entry sits on (itself for a whole disk).
    pub fn root_path(&self) -> String {
        self.ancestors
            .first()
            .cloned()
            .unwrap_or_else(|| self.device.dev_path())
    }
}

/// Mountpoints that belong to the running system. Desktop automounts below
/// /run/media and /run/user do not.
pub fn is_mount_system(m: &str) -> bool {
    if m.starts_with("/run/media/") || m.starts_with("/run/user/") {
        return false;
    }
    m == "/"
        || m.starts_with("/boot")
        || m.starts_with("/nix")
        || m.starts_with("/iso")
        || m.starts_with("/sysroot")
        || m.starts_with("/run")
        || m == "[SWAP]"
}

pub fn is_evidence_mount(m: &str) -> bool {
    m.starts_with("/media/evidence")
}

pub const LIVE_LABEL: &str = "DFNIX_LIVE";

/// Why a device or anything stacked on it belongs to the running system.
pub fn system_reasons(dev: &BlockDevice) -> Vec<String> {
    let mut reasons = Vec::new();
    collect_reasons(dev, &mut reasons);
    reasons
}

fn collect_reasons(dev: &BlockDevice, reasons: &mut Vec<String>) {
    if dev.label.as_deref() == Some(LIVE_LABEL) {
        reasons.push(format!("{} has label {}", dev.dev_path(), LIVE_LABEL));
    }
    for m in dev.mounts().filter(|m| is_mount_system(m)) {
        reasons.push(format!("{} mounted at {}", dev.dev_path(), m));
    }
    for c in dev.children.iter().flatten() {
        collect_reasons(c, reasons);
    }
}

pub fn is_system_device(dev: &BlockDevice) -> bool {
    !system_reasons(dev).is_empty()
}

pub fn parse(json: &[u8]) -> Result<Vec<FlatDevice>> {
    let parsed: LsblkOutput = serde_json::from_slice(json).context("Failed to parse lsblk JSON")?;
    let mut flat = Vec::new();

    fn recurse(
        dev: &BlockDevice,
        ancestors: &mut Vec<String>,
        parent_is_sys: bool,
        flat: &mut Vec<FlatDevice>,
    ) {
        let is_sys = parent_is_sys || is_system_device(dev);
        flat.push(FlatDevice {
            device: dev.clone(),
            level: ancestors.len(),
            is_system: is_sys,
            ancestors: ancestors.clone(),
        });
        ancestors.push(dev.dev_path());
        for c in dev.children.iter().flatten() {
            recurse(c, ancestors, is_sys, flat);
        }
        ancestors.pop();
    }

    for dev in &parsed.blockdevices {
        recurse(dev, &mut Vec::new(), false, &mut flat);
    }
    Ok(flat)
}

/// Run `lsblk` on this host and parse its tree.
pub fn scan() -> Result<Vec<FlatDevice>> {
    let out = Command::new("lsblk")
        .args(["-J", "-o", LSBLK_COLUMNS])
        .output()
        .context("Failed to run lsblk")?;
    if !out.status.success() {
        bail!(
            "lsblk failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    parse(&out.stdout)
}

/// Every entry nested anywhere below `path`.
pub fn descendants<'a>(
    flat: &'a [FlatDevice],
    path: &str,
) -> impl Iterator<Item = &'a FlatDevice> + 'a {
    let path = path.to_string();
    flat.iter().filter(move |f| f.ancestors.contains(&path))
}

/// Every entry that is the device at `path`: listed under that path or, given
/// the device number of the node at `path`, with that `MAJ:MIN`. The number
/// finds a device reached through another name, such as `/dev/dm-3` for what
/// lsblk lists as `/dev/mapper/cryptroot`, or a `/dev/disk/by-id` link.
pub fn lookup<'a>(flat: &'a [FlatDevice], path: &str, dev: Option<DevNum>) -> Vec<&'a FlatDevice> {
    flat.iter()
        .filter(|f| f.device.dev_path() == path || (dev.is_some() && f.device.dev_num() == dev))
        .collect()
}

/// The whole-disk entries (level 0) every entry for `path` sits on.
pub fn roots<'a>(flat: &'a [FlatDevice], path: &str) -> Vec<&'a FlatDevice> {
    roots_of(flat, &lookup(flat, path, None))
}

/// The whole-disk entries (level 0) the given entries sit on.
pub fn roots_of<'a>(flat: &'a [FlatDevice], entries: &[&FlatDevice]) -> Vec<&'a FlatDevice> {
    let mut roots: Vec<&FlatDevice> = Vec::new();
    for hit in entries {
        let root = hit.root_path();
        if let Some(r) = flat
            .iter()
            .find(|f| f.level == 0 && f.device.dev_path() == root)
        {
            if !roots.iter().any(|x| x.device.dev_path() == root) {
                roots.push(r);
            }
        }
    }
    roots
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::sysfs::tests::FakeSys;

    pub const LAB: &str = r#"{"blockdevices":[
      {"name":"nvme0n1","path":"/dev/nvme0n1","maj:min":"259:0","type":"disk","serial":"S6Z0NJ0W","wwn":"eui.0025384b21406566","model":"Samsung SSD 990","mountpoints":[null],"children":[
        {"name":"nvme0n1p1","path":"/dev/nvme0n1p1","maj:min":"259:1","type":"part","fstype":"vfat","mountpoints":["/boot"]},
        {"name":"nvme0n1p2","path":"/dev/nvme0n1p2","maj:min":"259:2","type":"part","fstype":"crypto_LUKS","mountpoints":[null],"children":[
          {"name":"cryptroot","path":"/dev/mapper/cryptroot","maj:min":"254:0","type":"crypt","fstype":"ext4","mountpoints":["/nix/store","/"]}]}]},
      {"name":"sr0","path":"/dev/sr0","maj:min":"11:0","type":"rom","fstype":"iso9660","label":"DFNIX_LIVE","serial":"ZM001","mountpoints":[null]},
      {"name":"sdb","path":"/dev/sdb","maj:min":"8:16","type":"disk","serial":"WD-EVID001","model":"WDC","mountpoints":[null],"children":[
        {"name":"sdb1","path":"/dev/sdb1","maj:min":"8:17","type":"part","fstype":"ntfs","mountpoints":["/media/evidence/sdb1"]}]},
      {"name":"sde","path":"/dev/sde","maj:min":"8:64","type":"disk","serial":"  ","mountpoints":[null],"children":[
        {"name":"sde1","path":"/dev/sde1","maj:min":"8:65","type":"part","fstype":"vfat","mountpoints":["/run/media/nixos/STICK"]}]}
    ]}"#;

    pub fn lab() -> Vec<FlatDevice> {
        parse(LAB.as_bytes()).unwrap()
    }

    #[test]
    fn system_status_covers_the_whole_disk_and_stacked_devices() {
        let flat = lab();
        let sys: Vec<_> = flat
            .iter()
            .filter(|f| f.is_system)
            .map(|f| f.device.name.as_str())
            .collect();
        assert_eq!(
            sys,
            ["nvme0n1", "nvme0n1p1", "nvme0n1p2", "cryptroot", "sr0"]
        );
        let reasons = system_reasons(&flat[0].device);
        assert!(reasons.iter().any(|r| r.contains("/boot")), "{reasons:?}");
        assert!(
            reasons.iter().any(|r| r.contains("mounted at /")),
            "{reasons:?}"
        );
    }

    #[test]
    fn mount_classification() {
        for m in [
            "/",
            "/boot/efi",
            "/nix/store",
            "/iso",
            "/run/initramfs",
            "[SWAP]",
        ] {
            assert!(is_mount_system(m), "{m}");
        }
        for m in [
            "/run/media/nixos/X",
            "/run/user/1000",
            "/media/target/sdc1",
            "/mnt",
        ] {
            assert!(!is_mount_system(m), "{m}");
        }
        assert!(is_evidence_mount("/media/evidence/sdb1"));
    }

    #[test]
    fn tree_navigation() {
        let flat = lab();
        let crypt = flat.iter().find(|f| f.device.name == "cryptroot").unwrap();
        assert_eq!(crypt.ancestors, ["/dev/nvme0n1", "/dev/nvme0n1p2"]);
        assert_eq!(crypt.root_path(), "/dev/nvme0n1");
        let below: Vec<_> = descendants(&flat, "/dev/nvme0n1p2")
            .map(|f| f.device.name.as_str())
            .collect();
        assert_eq!(below, ["cryptroot"]);
        let roots = roots(&flat, "/dev/mapper/cryptroot");
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].device.name, "nvme0n1");
    }

    #[test]
    fn lookup_by_path_or_device_number() {
        let flat = lab();
        let names =
            |v: Vec<&FlatDevice>| v.iter().map(|f| f.device.name.clone()).collect::<Vec<_>>();
        assert_eq!(
            names(lookup(&flat, "/dev/mapper/cryptroot", None)),
            ["cryptroot"]
        );
        // The kernel name of the same node is not listed by lsblk
        assert!(lookup(&flat, "/dev/dm-0", None).is_empty());
        let hits = lookup(&flat, "/dev/dm-0", Some((254, 0)));
        assert_eq!(names(hits.clone()), ["cryptroot"]);
        assert_eq!(names(roots_of(&flat, &hits)), ["nvme0n1"]);
        assert!(lookup(&flat, "/dev/sdz", Some((8, 200))).is_empty());
        assert_eq!(flat[0].device.dev_num(), Some((259, 0)));
    }

    #[test]
    fn identity_matching() {
        let flat = lab();
        let nvme = flat[0].device.lsblk_identity();
        assert_eq!(nvme.serial.as_deref(), Some("S6Z0NJ0W"));
        // Same disk re-enumerated under another name and number
        let moved = DeviceIdentity {
            path: "/dev/nvme1n1".into(),
            kernel_name: "nvme1n1".into(),
            maj_min: Some("259:5".into()),
            ..nvme.clone()
        };
        assert!(nvme.same_device(&moved));
        // Another disk that took over the old name
        let other = DeviceIdentity {
            serial: Some("OTHER".into()),
            wwn: None,
            ..nvme.clone()
        };
        assert!(!nvme.same_device(&other));
        // Blank serials are not identities; fall back to name + major:minor
        let sde = flat
            .iter()
            .find(|f| f.device.name == "sde")
            .unwrap()
            .device
            .lsblk_identity();
        assert_eq!(sde.serial, None);
        assert!(sde.same_device(&sde.clone()));
        let renamed = DeviceIdentity {
            maj_min: Some("8:80".into()),
            ..sde.clone()
        };
        assert!(!sde.same_device(&renamed));
    }

    #[test]
    fn identity_takes_the_disk_sequence_number_from_sysfs() {
        let s = FakeSys::new("lsblk_identity");
        s.add("block/nvme0n1", "nvme0n1", "259:0", false, &[]);
        s.add("block/nvme0n1/nvme0n1p2", "nvme0n1p2", "259:2", true, &[]);
        s.add("virtual/block/dm-0", "dm-0", "254:0", false, &["nvme0n1p2"]);
        s.set("block/nvme0n1", "diskseq", "3");
        s.set("virtual/block/dm-0", "diskseq", "9");
        // A stale entry with lsblk's name but another device number
        s.add("block/sdb", "sdb", "8:99", false, &[]);
        s.set("block/sdb", "diskseq", "77");
        let topo = s.topo();
        let flat = lab();
        let seq = |name: &str| {
            flat.iter()
                .find(|f| f.device.name == name)
                .unwrap()
                .device
                .identity_in(&topo)
                .diskseq
        };
        assert_eq!(seq("nvme0n1"), Some(3));
        assert_eq!(seq("nvme0n1p2"), Some(3));
        // lsblk names dm-0 "cryptroot"; found by major:minor
        assert_eq!(seq("cryptroot"), Some(9));
        assert_eq!(seq("sdb"), None);
        assert_eq!(seq("sde"), None);
    }

    #[test]
    fn disk_sequence_number_is_optional_in_json() {
        let id = lab()[0].device.lsblk_identity();
        let json = serde_json::to_string(&id).unwrap();
        assert!(!json.contains("diskseq"), "{json}");
        let old: DeviceIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(old.diskseq, None);
        let with = DeviceIdentity {
            diskseq: Some(7),
            ..id
        };
        let back: DeviceIdentity =
            serde_json::from_str(&serde_json::to_string(&with).unwrap()).unwrap();
        assert_eq!(back, with);
    }

    #[test]
    fn same_attachment_detects_a_disk_swapped_on_the_same_node() {
        let flat = lab();
        let id = |name: &str| {
            flat.iter()
                .find(|f| f.device.name == name)
                .unwrap()
                .device
                .lsblk_identity()
        };
        let selected = DeviceIdentity {
            diskseq: Some(12),
            ..id("sdb")
        };
        assert_eq!(selected.kernel_name, "sdb");
        assert!(selected.same_attachment(&selected.clone()));
        // Re-plugged: same disk, new attachment; still the same device
        let replugged = DeviceIdentity {
            diskseq: Some(13),
            ..selected.clone()
        };
        assert!(selected.same_device(&replugged));
        assert!(!selected.same_attachment(&replugged));
        // Another disk took over /dev/sdb and 8:16
        let swapped = DeviceIdentity {
            serial: Some("WD-OTHER".into()),
            ..selected.clone()
        };
        assert!(!selected.same_attachment(&swapped));
        // Same disk, but now behind another device number
        let moved = DeviceIdentity {
            maj_min: Some("8:32".into()),
            ..selected.clone()
        };
        assert!(!selected.same_attachment(&moved));
        // An unknown sequence number on one side leaves the other checks
        let unknown = DeviceIdentity {
            diskseq: None,
            ..selected.clone()
        };
        assert!(selected.same_attachment(&unknown));
        // Without major:minor nothing ties the two to one attachment
        let bare = DeviceIdentity {
            maj_min: None,
            ..selected.clone()
        };
        assert!(!bare.same_attachment(&bare.clone()));
        // No serial: a different sequence number is the only tell
        let sde = DeviceIdentity {
            diskseq: Some(30),
            ..id("sde")
        };
        assert_eq!(
            (sde.kernel_name.as_str(), sde.serial.as_deref()),
            ("sde", None)
        );
        let other_stick = DeviceIdentity {
            diskseq: Some(31),
            ..sde.clone()
        };
        assert!(sde.same_device(&other_stick));
        assert!(!sde.same_attachment(&other_stick));
    }
}
