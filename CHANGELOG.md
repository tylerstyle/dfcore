# Changelog

## 0.2.0

### Breaking

- `audit::export` returns `ExportInfo { jsonl, head, state }` (was `ChainState`)
  and writes `audit-<boot_id>.jsonl` / `audit-<boot_id>.head` instead of
  `audit.jsonl` / `audit.head`.
- `DeviceIdentity` has a new field `diskseq: Option<u64>`; struct literals need
  it or `..Default::default()`. JSON without it still deserializes.
- `protected::check` refuses a block device that lsblk does not list, with or
  without a registry.

### Added

- `dfcore::Refusal` and `dfcore::is_refusal`: every policy refusal
  (`sysfs::check_disjoint`, `sysfs::ensure_destination_not_on_source`,
  `protected::check`) carries a `Refusal` in its error chain, so tools tell a
  refusal from an I/O or parse failure without matching message text.
- `DeviceIdentity::same_attachment`: same device, same major:minor and, where
  known, same disk sequence number; detects a disk swapped in on the same node.
  `BlockDevice::identity()` fills `diskseq` from sysfs (partitions report their
  disk's; device-mapper devices are found by major:minor).
- `sysfs::dev_num_of_path`, `kname_of`, `diskseq`, `holders`, `read_only`,
  `parse_dev_num`, `existing_ancestor`, and `BlockTopology::{dev_of, diskseq,
  holders, read_only}` for a sysfs rooted elsewhere.
- `Registry::protecting_dev`, `protected::check_against`, `lsblk::lookup`,
  `lsblk::roots_of`, `BlockDevice::dev_num`, `BlockDevice::identity_in`,
  `audit::export_for_boot`.

### Fixed

- Registry matching by device number: `/dev/dm-N` (what `/dev/mapper/x`
  canonicalizes to) and `/dev/disk/by-*` links on a protected disk were not
  recognised because lsblk lists them under another path.
- Audit export never destroys an earlier boot's chain: within a boot a copy is
  replaced only by a longer state of the same log, anything else goes to
  `audit-<boot_id>-<n>.jsonl`. Writes are atomic (temporary file, fsync,
  rename, directory fsync).
- Records of a log redirected with `DFNIX_AUDIT_LOG` (test suites) are no longer
  mirrored into the host's journal unless `DFNIX_AUDIT_JOURNAL=1`;
  `DFNIX_AUDIT_JOURNAL=0` disables the mirror.
- `ensure_destination_not_on_source` checks an output directory that does not
  exist yet at its nearest existing ancestor instead of letting it pass.
- `audit::verify` reads under a shared lock, so a concurrent append cannot show
  up as a torn last line.

## 0.1.0

- Device tree from lsblk with system-device detection, physical-disk topology
  from sysfs, protected-device registry, hash-chained audit log.
