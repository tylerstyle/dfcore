//! Which physical disks a block device, or the filesystem holding a path, is
//! ultimately stored on: partitions resolve to their disk, device-mapper and md
//! devices to the disks behind their `slaves`, loop devices to the disk holding
//! their backing file. Filesystems with anonymous device numbers (btrfs, overlay)
//! are resolved through `/proc/self/mountinfo`.

use anyhow::Result;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::Refusal;

/// A block device as the kernel numbers it.
pub type DevNum = (u32, u32);

/// Read-only view of `/sys/class/block`, rooted elsewhere in tests.
pub struct BlockTopology {
    class_block: PathBuf,
}

impl Default for BlockTopology {
    fn default() -> Self {
        Self::new("/sys/class/block")
    }
}

impl BlockTopology {
    pub fn new(class_block: impl Into<PathBuf>) -> Self {
        Self {
            class_block: class_block.into(),
        }
    }

    /// Kernel name (sda, sda1, dm-0, loop3, ...) of a device number.
    pub fn name_of(&self, dev: DevNum) -> Option<String> {
        let want = format!("{}:{}", dev.0, dev.1);
        fs::read_dir(&self.class_block)
            .ok()?
            .flatten()
            .find(|e| {
                fs::read_to_string(e.path().join("dev"))
                    .map(|s| s.trim() == want)
                    .unwrap_or(false)
            })
            .map(|e| e.file_name().to_string_lossy().into_owned())
    }

    /// Whole physical disks a device ultimately stores its data on: a partition
    /// maps to its disk, device-mapper/md devices to the disks behind their
    /// `slaves`, and loop devices to the disks holding their backing file.
    pub fn backing_disks(&self, name: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        self.collect_backing(name, 0, &mut out);
        out
    }

    fn collect_backing(&self, name: &str, depth: usize, out: &mut BTreeSet<String>) {
        if depth > 16 {
            // Unexpectedly deep stack: keep the device itself so it still counts
            out.insert(name.to_string());
            return;
        }
        let node = self.class_block.join(name);

        let slaves: Vec<String> = fs::read_dir(node.join("slaves"))
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        if !slaves.is_empty() {
            for s in slaves {
                self.collect_backing(&s, depth + 1, out);
            }
            return;
        }

        if let Ok(backing) = fs::read_to_string(node.join("loop").join("backing_file")) {
            if let Some(dev) = backing_device_of_path(Path::new(backing.trim())) {
                if let Some(parent) = self.name_of(dev) {
                    self.collect_backing(&parent, depth + 1, out);
                    return;
                }
            }
        }

        if node.join("partition").exists() {
            // /sys/class/block/sdb1 -> .../block/sdb/sdb1
            if let Some(disk) = fs::canonicalize(&node).ok().and_then(|p| {
                p.parent()
                    .and_then(|d| d.file_name())
                    .map(|f| f.to_string_lossy().into_owned())
            }) {
                out.insert(disk);
                return;
            }
        }

        out.insert(name.to_string());
    }
}

/// One line of /proc/self/mountinfo, reduced to what we need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    pub mount_point: PathBuf,
    pub dev: DevNum,
    pub source: String,
}

fn unescape_mountinfo(s: &str) -> String {
    // Spaces, tabs, newlines and backslashes are written as \ooo octal escapes
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 4 <= bytes.len() {
            let oct = &bytes[i + 1..i + 4];
            if oct.iter().all(|b| (b'0'..=b'7').contains(b)) {
                out.push(
                    oct.iter()
                        .fold(0u8, |acc, b| acc.wrapping_mul(8).wrapping_add(b - b'0')),
                );
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_mountinfo(content: &str) -> Vec<MountEntry> {
    content
        .lines()
        .filter_map(|line| {
            let (pre, post) = line.split_once(" - ")?;
            let pre: Vec<&str> = pre.split(' ').collect();
            let post: Vec<&str> = post.split(' ').collect();
            let (maj, min) = pre.get(2)?.split_once(':')?;
            Some(MountEntry {
                mount_point: PathBuf::from(unescape_mountinfo(pre.get(4)?)),
                dev: (maj.parse().ok()?, min.parse().ok()?),
                source: unescape_mountinfo(post.get(1)?),
            })
        })
        .collect()
}

/// The mount that contains `path` (longest matching mount point, last one wins
/// for stacked mounts).
pub fn mount_containing<'a>(mounts: &'a [MountEntry], path: &Path) -> Option<&'a MountEntry> {
    mounts
        .iter()
        .filter(|m| path.starts_with(&m.mount_point))
        .max_by_key(|m| m.mount_point.components().count())
}

#[cfg(unix)]
fn dev_split(dev: u64) -> DevNum {
    (
        libc::major(dev as libc::dev_t) as u32,
        libc::minor(dev as libc::dev_t) as u32,
    )
}

/// Block device holding the filesystem that stores `path`, if it is on one.
#[cfg(unix)]
pub fn backing_device_of_path(path: &Path) -> Option<DevNum> {
    use std::os::unix::fs::MetadataExt;
    let canonical = fs::canonicalize(path).ok()?;
    let st_dev = dev_split(fs::metadata(&canonical).ok()?.dev());
    if st_dev.0 != 0 {
        return Some(st_dev);
    }
    // Btrfs, overlayfs and network/virtual filesystems report an anonymous
    // device; the mount source names the real one when there is one
    let mounts = parse_mountinfo(&fs::read_to_string("/proc/self/mountinfo").ok()?);
    let m = mount_containing(&mounts, &canonical)?;
    if m.source.starts_with("/dev/") {
        source_device(Path::new(&m.source))
    } else {
        None
    }
}

#[cfg(not(unix))]
pub fn backing_device_of_path(_path: &Path) -> Option<DevNum> {
    None
}

/// Device number of a block device node, or `None` for anything else.
#[cfg(unix)]
pub fn source_device(path: &Path) -> Option<DevNum> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let meta = fs::metadata(path).ok()?;
    if meta.file_type().is_block_device() {
        Some(dev_split(meta.rdev()))
    } else {
        None
    }
}

#[cfg(not(unix))]
pub fn source_device(_path: &Path) -> Option<DevNum> {
    None
}

/// Core of the destination-on-source check, separated from the host for tests.
/// Every refusal, including a device that cannot be resolved, is a [`Refusal`].
pub fn check_disjoint(
    topo: &BlockTopology,
    source: DevNum,
    source_label: &str,
    dest: Option<DevNum>,
    dest_label: &str,
) -> Result<()> {
    let Some(dest) = dest else {
        // tmpfs, network shares, FUSE: not stored on any local block device
        return Ok(());
    };
    if dest == source {
        return Err(Refusal(format!(
            "Critical Safety Error: destination {} is stored on the source device {} itself!",
            dest_label, source_label
        ))
        .into());
    }
    // Fail closed: a device sysfs does not know cannot be shown to be disjoint
    let src_name = topo.name_of(source).ok_or_else(|| {
        Refusal(format!(
            "Cannot resolve source {} in sysfs; refusing to acquire",
            source_label
        ))
    })?;
    let dst_name = topo.name_of(dest).ok_or_else(|| {
        Refusal(format!(
            "Cannot resolve the device holding {} ({}:{}) in sysfs; refusing to acquire",
            dest_label, dest.0, dest.1
        ))
    })?;
    let src_disks = topo.backing_disks(&src_name);
    let dst_disks = topo.backing_disks(&dst_name);
    let shared: Vec<_> = src_disks.intersection(&dst_disks).cloned().collect();
    if shared.is_empty() {
        Ok(())
    } else {
        Err(Refusal(format!(
            "Critical Safety Error: destination {} is on {} which shares physical disk {} with source {} ({}). Choose an output directory on a separate target drive.",
            dest_label,
            dst_name,
            shared.join(", "),
            source_label,
            src_name
        ))
        .into())
    }
}

/// Refuse when the output directory lives on the same physical disk (any
/// partition, or any LVM/RAID/crypt/loop stack on it) as a block-device source.
/// Regular-file sources are not block devices and are not checked here.
pub fn ensure_destination_not_on_source(source_path: &str, output_dir: &Path) -> Result<()> {
    let Some(source) = source_device(Path::new(source_path)) else {
        return Ok(());
    };
    let dest = backing_device_of_path(output_dir);
    check_disjoint(
        &BlockTopology::default(),
        source,
        source_path,
        dest,
        &output_dir.display().to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct FakeSys {
        root: PathBuf,
    }

    impl FakeSys {
        fn new(tag: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "dfcore_fake_sysfs_{}_{}",
                tag,
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(root.join("class/block")).unwrap();
            fs::create_dir_all(root.join("devices")).unwrap();
            Self { root }
        }

        fn topo(&self) -> BlockTopology {
            BlockTopology::new(self.root.join("class/block"))
        }

        fn add(&self, real: &str, name: &str, dev: &str, partition: bool, slaves: &[&str]) {
            let dir = self.root.join("devices").join(real);
            fs::create_dir_all(dir.join("slaves")).unwrap();
            fs::write(dir.join("dev"), format!("{}\n", dev)).unwrap();
            if partition {
                fs::write(dir.join("partition"), "1\n").unwrap();
            }
            for s in slaves {
                fs::write(dir.join("slaves").join(s), "").unwrap();
            }
            symlink(&dir, self.root.join("class/block").join(name)).unwrap();
        }

        /// sda (system) + sdb (evidence: sdb1, sdb2, LVM dm-0 on sdb2) +
        /// sdc (target: sdc1, dm-1 crypt on sdc1) + md0 over sdb1 and sdc1
        fn lab(tag: &str) -> Self {
            let s = Self::new(tag);
            s.add("block/sda", "sda", "8:0", false, &[]);
            s.add("block/sda/sda1", "sda1", "8:1", true, &[]);
            s.add("block/sdb", "sdb", "8:16", false, &[]);
            s.add("block/sdb/sdb1", "sdb1", "8:17", true, &[]);
            s.add("block/sdb/sdb2", "sdb2", "8:18", true, &[]);
            s.add("virtual/block/dm-0", "dm-0", "254:0", false, &["sdb2"]);
            s.add("block/sdc", "sdc", "8:32", false, &[]);
            s.add("block/sdc/sdc1", "sdc1", "8:33", true, &[]);
            s.add("virtual/block/dm-1", "dm-1", "254:1", false, &["sdc1"]);
            s.add("virtual/block/md0", "md0", "9:0", false, &["sdb1", "sdc1"]);
            s
        }
    }

    impl Drop for FakeSys {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn backing_disks_resolve_partitions_and_stacks() {
        let s = FakeSys::lab("resolve");
        let t = s.topo();
        let set = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<BTreeSet<_>>();
        assert_eq!(t.backing_disks("sdb"), set(&["sdb"]));
        assert_eq!(t.backing_disks("sdb1"), set(&["sdb"]));
        assert_eq!(t.backing_disks("dm-0"), set(&["sdb"]));
        assert_eq!(t.backing_disks("dm-1"), set(&["sdc"]));
        assert_eq!(t.backing_disks("md0"), set(&["sdb", "sdc"]));
        assert_eq!(t.name_of((8, 33)).as_deref(), Some("sdc1"));
        assert_eq!(t.name_of((8, 99)), None);
    }

    #[test]
    fn destination_on_other_disk_is_allowed() {
        let s = FakeSys::lab("allowed");
        assert!(check_disjoint(
            &s.topo(),
            (8, 16),
            "/dev/sdb",
            Some((8, 33)),
            "/media/target"
        )
        .is_ok());
        assert!(check_disjoint(
            &s.topo(),
            (8, 16),
            "/dev/sdb",
            Some((254, 1)),
            "/media/target"
        )
        .is_ok());
        assert!(check_disjoint(&s.topo(), (8, 17), "/dev/sdb1", None, "/tmp").is_ok());
    }

    #[test]
    fn destination_on_source_tree_is_refused() {
        let s = FakeSys::lab("refused");
        let t = s.topo();
        let refused = |src: DevNum, label: &str, dest: DevNum| {
            let e = check_disjoint(&t, src, label, Some(dest), "/mnt/x").unwrap_err();
            assert!(crate::is_refusal(&e), "{e:#}");
            e.to_string()
        };
        // Whole disk source, image written to one of its partitions
        let e = refused((8, 16), "/dev/sdb", (8, 17));
        assert!(e.contains("Critical Safety Error"), "{e}");
        assert!(e.contains("shares physical disk sdb"), "{e}");
        // Partition source, image on a sibling partition
        refused((8, 17), "/dev/sdb1", (8, 18));
        // Image on an LVM volume living on the source disk
        refused((8, 16), "/dev/sdb", (254, 0));
        // Image on a RAID array that has a member on the source disk
        refused((8, 16), "/dev/sdb", (9, 0));
        // Source is the array, image on a disk that is one of its members
        refused((9, 0), "/dev/md0", (8, 33));
        // Same device outright
        let e = refused((8, 17), "/dev/sdb1", (8, 17));
        assert!(e.contains("Critical Safety Error"), "{e}");
    }

    #[test]
    fn unresolvable_source_or_destination_device_is_refused() {
        let s = FakeSys::lab("unresolved");
        for (src, dest) in [((8, 16), (8, 200)), ((8, 200), (8, 33))] {
            let e = check_disjoint(&s.topo(), src, "/dev/sdb", Some(dest), "/mnt/x").unwrap_err();
            assert!(crate::is_refusal(&e), "{e:#}");
            assert!(e.to_string().contains("Cannot resolve"), "{e}");
        }
    }

    #[test]
    fn mountinfo_parsing_and_lookup() {
        let info = "\
22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw
40 22 0:35 / /media/target rw,relatime shared:20 - btrfs /dev/sdc1 rw,space_cache=v2
41 40 0:36 / /media/target/sub\\040dir rw - tmpfs tmpfs rw
";
        let mounts = parse_mountinfo(info);
        assert_eq!(mounts.len(), 3);
        assert_eq!(mounts[1].dev, (0, 35));
        assert_eq!(mounts[1].source, "/dev/sdc1");
        assert_eq!(
            mounts[2].mount_point,
            PathBuf::from("/media/target/sub dir")
        );

        let m = mount_containing(&mounts, Path::new("/media/target/case1")).unwrap();
        assert_eq!(m.source, "/dev/sdc1");
        let m = mount_containing(&mounts, Path::new("/media/target/sub dir/x")).unwrap();
        assert_eq!(m.source, "tmpfs");
        // Prefix match is by path component, not by string
        let m = mount_containing(&mounts, Path::new("/media/targetX")).unwrap();
        assert_eq!(m.mount_point, PathBuf::from("/"));
    }
}
