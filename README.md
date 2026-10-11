# dfcore

Shared forensic safety core for the [dfnix](https://github.com/tylerstyle/dfnix) tools
(`dfdisk`, `dfmount`, `dfnet`). One implementation of the rules that decide which
devices may be touched, and one tamper-evident record of what was done.

## Modules

- **`lsblk`**: block device tree from `lsblk -J` (with `MAJ:MIN`, serial and WWN),
  flattened with each entry's chain of enclosing devices. A device belongs to the
  running system if it or anything stacked on it is mounted at `/`, `/boot`, `/nix`,
  `/iso`, `/sysroot`, `/run/…` (desktop automounts excepted) or as swap, or carries
  the `DFNIX_LIVE` label; partitions and holders inherit that status.
- **`sysfs`**: the physical disks a device, or the filesystem holding a path, is
  stored on (partitions, device-mapper/md `slaves`, loop backing files, mountinfo for
  btrfs/overlay). Used to refuse writing an image onto the disk being acquired.
- **`protected`**: registry of system disks and the live medium, written at boot to
  `/run/dfnix/protected.json` by `dfcore-protect`. Entries match by WWN or serial, so
  protection follows the disk across re-enumeration, not the kernel name.
- **`audit`**: append-only JSONL log (`/run/dfnix/audit.jsonl`), one record per tool
  action with time, boot ID, host, kernel, dfnix revision, tool version, uid, argv,
  device identity, outcome and details. Each record holds the SHA-256 of its
  predecessor and of its own canonical encoding; appends are serialized with `flock`
  and mirrored to the systemd journal (`SYSLOG_IDENTIFIER=dfnix-audit`).
- **`release`**: `DFNIX_REVISION` from `/etc/dfnix-release`.

## Tamper evidence and its limit

`dfcore-audit verify` detects any modified, deleted, inserted or reordered record.
Removing records from the *end* of the log leaves a valid shorter chain, so tools
write the chain head into their reports and manifests; compare a report's head with
the log to show that nothing recorded before it was removed. A hash chain is not a
signature: someone able to rewrite the whole file and every report can rebuild it.

```bash
dfcore-protect --print                 # (re)write /run/dfnix/protected.json
dfcore-audit verify                    # OK: 42 records, head 3f…
dfcore-audit export /media/target/case01
```

Paths can be redirected with `DFNIX_PROTECTED_FILE`, `DFNIX_AUDIT_LOG` and
`DFNIX_RELEASE_FILE`.

## License

MIT OR Apache-2.0
