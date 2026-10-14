//! Append-only, tamper-evident audit log: one JSON record per line, each carrying
//! the SHA-256 of its predecessor (`prev`) and of itself (`hash`).
//!
//! Editing, deleting, inserting or reordering any record breaks the chain and is
//! reported by [`verify`]. Cutting records off the *end* cannot be detected from
//! the file alone, so tools also write the current chain head (`hash` of the last
//! record) into their reports and manifests: an anchor outside the log.
//!
//! The hash covers a canonical encoding (object keys sorted, no whitespace) of the
//! record without its `hash` field, so it does not depend on field order.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::host;
use crate::lsblk::DeviceIdentity;
use crate::release;

pub const DEFAULT_PATH: &str = "/run/dfnix/audit.jsonl";
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Log location; `DFNIX_AUDIT_LOG` overrides it (tests, or a log on the case drive).
/// Records of a redirected log are not mirrored into the journal unless
/// `DFNIX_AUDIT_JOURNAL=1`.
pub fn path() -> PathBuf {
    std::env::var_os("DFNIX_AUDIT_LOG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PATH))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Ok,
    Refused,
    Error,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub seq: u64,
    pub ts: String,
    pub boot_id: Option<String>,
    pub host: Option<String>,
    pub kernel: Option<String>,
    pub system_revision: Option<String>,
    pub tool: String,
    pub tool_version: String,
    pub uid: u32,
    pub argv: Vec<String>,
    pub action: String,
    pub outcome: Outcome,
    pub message: Option<String>,
    pub device: Option<DeviceIdentity>,
    pub details: Value,
    pub prev: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

/// What a tool did; the log adds sequence, time, host facts and the chain.
#[derive(Debug, Clone)]
pub struct Event {
    pub tool: String,
    pub tool_version: String,
    pub action: String,
    pub outcome: Outcome,
    pub message: Option<String>,
    pub device: Option<DeviceIdentity>,
    pub details: Map<String, Value>,
    /// Command-line flags whose values are secrets and must not reach the log
    pub redact: Vec<String>,
}

pub const REDACTED: &str = "<redacted>";

/// The command line with the values of `flags` replaced, in all forms clap
/// accepts: `--flag value`, `--flag=value` and, for short flags, `-fvalue`.
pub fn redact_args(args: impl IntoIterator<Item = String>, flags: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut hide_next = false;
    for arg in args {
        if hide_next {
            out.push(REDACTED.to_string());
            hide_next = false;
            continue;
        }
        let mut replaced = None;
        for flag in flags {
            if arg == *flag {
                hide_next = true;
            } else if arg.starts_with(&format!("{flag}=")) {
                replaced = Some(format!("{flag}={REDACTED}"));
            } else if flag.len() == 2
                && !flag.starts_with("--")
                && arg.starts_with(flag.as_str())
                && !arg.starts_with("--")
            {
                replaced = Some(format!("{flag}{REDACTED}"));
            }
        }
        out.push(replaced.unwrap_or(arg));
    }
    out
}

impl Event {
    pub fn new(tool: &str, tool_version: &str, action: &str) -> Self {
        Event {
            tool: tool.into(),
            tool_version: tool_version.into(),
            action: action.into(),
            outcome: Outcome::Ok,
            message: None,
            device: None,
            details: Map::new(),
            redact: Vec::new(),
        }
    }

    /// Hide the values of these command-line flags in the recorded argv.
    pub fn redact(mut self, flags: &[&str]) -> Self {
        self.redact.extend(flags.iter().map(|f| f.to_string()));
        self
    }

    pub fn device(mut self, identity: DeviceIdentity) -> Self {
        self.device = Some(identity);
        self
    }

    pub fn detail(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    pub fn outcome(mut self, outcome: Outcome, message: Option<String>) -> Self {
        self.outcome = outcome;
        self.message = message;
        self
    }

    /// Set outcome and message from a result: `Ok`, or `Error` with its text.
    pub fn result<T>(self, result: &Result<T>) -> Self {
        match result {
            Ok(_) => self.outcome(Outcome::Ok, None),
            Err(e) => self.outcome(Outcome::Error, Some(format!("{e:#}"))),
        }
    }
}

/// Canonical JSON: object keys sorted, no insignificant whitespace.
pub fn canonical(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let fields: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", Value::String(k.clone()), canonical(&map[k])))
                .collect();
            format!("{{{}}}", fields.join(","))
        }
        Value::Array(items) => {
            format!(
                "[{}]",
                items.iter().map(canonical).collect::<Vec<_>>().join(",")
            )
        }
        other => other.to_string(),
    }
}

/// Hash of a record: SHA-256 over the canonical encoding without `hash`.
pub fn record_hash(record: &Value) -> Result<String> {
    let mut body = record
        .as_object()
        .ok_or_else(|| anyhow!("audit record is not a JSON object"))?
        .clone();
    body.remove("hash");
    Ok(format!(
        "{:x}",
        Sha256::digest(canonical(&Value::Object(body)).as_bytes())
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainState {
    pub records: u64,
    /// Hash of the last record, or [`GENESIS`] for an empty log
    pub head: String,
}

/// Check every record's hash, sequence number and link to its predecessor.
pub fn verify_str(content: &str) -> Result<ChainState> {
    let mut prev = GENESIS.to_string();
    let mut records = 0u64;
    for (idx, line) in content.lines().enumerate() {
        let lineno = idx + 1;
        if line.trim().is_empty() {
            bail!("line {lineno}: empty line inside the audit log");
        }
        let value: Value =
            serde_json::from_str(line).with_context(|| format!("line {lineno}: not valid JSON"))?;
        let stored = value["hash"]
            .as_str()
            .ok_or_else(|| anyhow!("line {lineno}: record has no hash"))?;
        let computed = record_hash(&value)?;
        if stored != computed {
            bail!("line {lineno}: record was modified (hash {stored} != content {computed})");
        }
        if value["prev"].as_str() != Some(prev.as_str()) {
            bail!("line {lineno}: chain broken (prev does not match the preceding record's hash)");
        }
        if value["seq"].as_u64() != Some(records) {
            bail!(
                "line {lineno}: sequence number {} where {} was expected",
                value["seq"],
                records
            );
        }
        prev = computed;
        records += 1;
    }
    Ok(ChainState {
        records,
        head: prev,
    })
}

fn verify_bytes(content: &[u8]) -> Result<ChainState> {
    verify_str(std::str::from_utf8(content).context("audit log is not valid UTF-8")?)
}

/// Verify the log at `path`; a missing log is an empty chain.
pub fn verify(path: &Path) -> Result<ChainState> {
    verify_bytes(&read_log(path)?)
}

/// The log's bytes, read under a shared lock so that an append in progress is
/// wholly in or wholly out. A missing log reads as empty. The lock is best
/// effort: a filesystem that cannot lock still gets read, and a torn last
/// line would fail verification rather than pass.
fn read_log(path: &Path) -> Result<Vec<u8>> {
    use std::os::unix::io::AsRawFd;
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("Cannot read {}", path.display())),
    };
    // SAFETY: flock on a file descriptor we own; released when `file` is dropped
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) };
    let mut content = Vec::new();
    file.read_to_end(&mut content)
        .with_context(|| format!("Cannot read {}", path.display()))?;
    Ok(content)
}

/// Append one event to the log at `path`, holding an exclusive lock so concurrent
/// tools cannot interleave or fork the chain. Returns the stored record.
pub fn append_to(path: &Path, event: Event) -> Result<Record> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("Cannot create {}", dir.display()))?;
    }
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("Cannot open audit log {}", path.display()))?;
    // SAFETY: flock on a file descriptor we own; released when `file` is dropped
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error()).context("Cannot lock audit log");
    }

    let mut content = String::new();
    file.seek(SeekFrom::Start(0))?;
    file.read_to_string(&mut content)?;
    // Never extend a chain that no longer verifies: the break must stay visible
    let state = verify_str(&content).with_context(|| {
        format!(
            "Audit log {} failed verification; not appending",
            path.display()
        )
    })?;

    let mut record = Record {
        seq: state.records,
        ts: host::rfc3339_utc(host::unix_now()),
        boot_id: host::boot_id(),
        host: host::hostname(),
        kernel: host::kernel_release(),
        system_revision: release::system_revision(),
        tool: event.tool,
        tool_version: event.tool_version,
        uid: host::uid(),
        argv: redact_args(std::env::args(), &event.redact),
        action: event.action,
        outcome: event.outcome,
        message: event.message,
        device: event.device,
        details: Value::Object(event.details),
        prev: state.head,
        hash: None,
    };
    record.hash = Some(record_hash(&serde_json::to_value(&record)?)?);
    let line = serde_json::to_string(&record)?;
    file.write_all(format!("{line}\n").as_bytes())?;
    file.sync_all().context("Cannot sync audit log")?;
    if journal_mirror(
        path,
        std::env::var_os("DFNIX_AUDIT_LOG").as_deref(),
        std::env::var_os("DFNIX_AUDIT_JOURNAL").as_deref(),
    ) {
        send_to_journal(&record, &line);
    }
    Ok(record)
}

/// Append to the default log.
pub fn append(event: Event) -> Result<Record> {
    append_to(&path(), event)
}

/// Whether an append to `log` is mirrored into the systemd journal, given the
/// values of `DFNIX_AUDIT_LOG` and `DFNIX_AUDIT_JOURNAL`.
///
/// The journal belongs to the host. A log redirected with `DFNIX_AUDIT_LOG`, or
/// appended to at any other path than the system log, is a test or scratch log
/// whose records must not show up among the host's own (test suites of the
/// tools did exactly that). So only the system log is mirrored by default;
/// `DFNIX_AUDIT_JOURNAL=1` mirrors any log and `DFNIX_AUDIT_JOURNAL=0` none.
fn journal_mirror(log: &Path, audit_log_env: Option<&OsStr>, journal_env: Option<&OsStr>) -> bool {
    match journal_env.and_then(OsStr::to_str) {
        Some("0") => false,
        Some("1") => true,
        _ => audit_log_env.is_none() && log == Path::new(DEFAULT_PATH),
    }
}

/// Mirror a record into the systemd journal (native protocol). Best effort: the
/// file is the authoritative log.
fn send_to_journal(record: &Record, line: &str) {
    use std::os::unix::net::UnixDatagram;
    let message = format!(
        "MESSAGE=dfnix audit #{} {} {} {:?}\nSYSLOG_IDENTIFIER=dfnix-audit\nPRIORITY=6\nDFNIX_AUDIT_SEQ={}\nDFNIX_AUDIT_HASH={}\nDFNIX_AUDIT_RECORD={}\n",
        record.seq,
        record.tool,
        record.action,
        record.outcome,
        record.seq,
        record.hash.as_deref().unwrap_or(""),
        line
    );
    if let Ok(sock) = UnixDatagram::unbound() {
        let _ = sock.send_to(message.as_bytes(), "/run/systemd/journal/socket");
    }
}

/// Boot ID in export file names when the kernel does not report one.
pub const UNKNOWN_BOOT: &str = "unknown-boot";

/// Highest `<n>` in `audit-<boot_id>-<n>.jsonl` that [`export`] tries.
const MAX_EXPORTS: u32 = 9999;

/// Where [`export`] put the copy of the log and its head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportInfo {
    pub jsonl: PathBuf,
    pub head: PathBuf,
    pub state: ChainState,
}

/// Copy the log into a case directory as `audit-<boot_id>.jsonl`, with its head
/// in `audit-<boot_id>.head`, so the case directory carries its own anchor.
///
/// The log under /run starts afresh at every boot of the live system, so each
/// boot gets its own file and a later boot never replaces an earlier boot's
/// chain. Within a boot the log only grows: an existing copy whose bytes are a
/// prefix of the log is replaced by the longer one. Any other file is left
/// alone and the copy goes to the next free `audit-<boot_id>-<n>.jsonl`.
/// Files are written under a temporary name, synced and renamed into place.
/// Names hold no ':' and nothing is linked, for exFAT, FAT and NTFS case drives.
pub fn export(log: &Path, dir: &Path) -> Result<ExportInfo> {
    let boot_id = host::boot_id().unwrap_or_else(|| UNKNOWN_BOOT.to_string());
    export_for_boot(log, dir, &boot_id)
}

/// [`export`] under the given boot ID.
pub fn export_for_boot(log: &Path, dir: &Path, boot_id: &str) -> Result<ExportInfo> {
    let content = read_log(log)?;
    let state = verify_bytes(&content).with_context(|| {
        format!(
            "Audit log {} failed verification; not exporting",
            log.display()
        )
    })?;
    std::fs::create_dir_all(dir).with_context(|| format!("Cannot create {}", dir.display()))?;
    // Exports into one directory take turns choosing a name and writing
    let _lock = lock_dir(dir);
    let stem = export_stem(dir, &file_name_safe(boot_id), &content)?;
    let jsonl = dir.join(format!("{stem}.jsonl"));
    let head = dir.join(format!("{stem}.head"));
    // Same permissions as the log itself; the head is no secret
    write_atomic(&jsonl, &content, 0o600)?;
    write_atomic(
        &head,
        format!("{}  records={}\n", state.head, state.records).as_bytes(),
        0o644,
    )?;
    Ok(ExportInfo { jsonl, head, state })
}

/// ASCII letters, digits, '-' and '_' kept, anything else replaced by '_'.
fn file_name_safe(s: &str) -> String {
    let safe: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if safe.is_empty() {
        UNKNOWN_BOOT.to_string()
    } else {
        safe
    }
}

/// The first of `audit-<boot>`, `audit-<boot>-2`, … whose `.jsonl` is absent or
/// an earlier state of `content` (a prefix of it). A `.head` whose `.jsonl` is
/// gone still takes the name: an existing file is only ever replaced by a
/// superset of itself.
fn export_stem(dir: &Path, boot: &str, content: &[u8]) -> Result<String> {
    for n in 1..=MAX_EXPORTS {
        let stem = if n == 1 {
            format!("audit-{boot}")
        } else {
            format!("audit-{boot}-{n}")
        };
        let jsonl = dir.join(format!("{stem}.jsonl"));
        match std::fs::read(&jsonl) {
            Ok(existing) if content.starts_with(&existing) => return Ok(stem),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let head = dir.join(format!("{stem}.head"));
                if std::fs::symlink_metadata(head).is_err() {
                    return Ok(stem);
                }
            }
            Err(e) => return Err(e).with_context(|| format!("Cannot read {}", jsonl.display())),
        }
    }
    bail!(
        "No free audit export name for boot {boot} in {}",
        dir.display()
    )
}

/// Hold an exclusive lock on a directory until the returned handle is dropped.
/// Best effort: some filesystems cannot lock, and exporting must still work.
fn lock_dir(dir: &Path) -> Option<std::fs::File> {
    use std::os::unix::io::AsRawFd;
    let handle = std::fs::File::open(dir).ok()?;
    // SAFETY: flock on a file descriptor we own; released when `handle` is dropped
    (unsafe { libc::flock(handle.as_raw_fd(), libc::LOCK_EX) } == 0).then_some(handle)
}

/// Replace `path` by a temporary file in the same directory that is written,
/// synced and renamed over it, then sync the directory: readers and a power
/// cut see the old file or the new one, never a mix.
fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .ok_or_else(|| anyhow!("{} has no file name", path.display()))?;
    let tmp = dir.join(format!(
        ".{}.{}-{}.tmp",
        name.to_string_lossy(),
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let written = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("Cannot write {}", path.display()));
    }
    sync_dir(dir)
}

fn sync_dir(dir: &Path) -> Result<()> {
    match std::fs::File::open(dir).and_then(|d| d.sync_all()) {
        Ok(()) => Ok(()),
        // Some FUSE and network filesystems cannot sync a directory
        Err(e)
            if matches!(
                e.raw_os_error(),
                Some(libc::EINVAL | libc::ENOTSUP | libc::ENOSYS)
            ) =>
        {
            Ok(())
        }
        Err(e) => Err(e).with_context(|| format!("Cannot sync {}", dir.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_log(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("dfcore_audit_{}_{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("audit.jsonl")
    }

    fn sample(i: u64) -> Event {
        Event::new("dfmount", "0.1.1", "evidence_mount")
            .device(DeviceIdentity {
                path: "/dev/sdb1".into(),
                kernel_name: "sdb1".into(),
                serial: Some("WD-EVID001".into()),
                ..Default::default()
            })
            .detail("ro_before", true)
            .detail("index", i)
    }

    #[test]
    fn canonical_encoding_ignores_key_order() {
        let a: Value =
            serde_json::from_str(r#"{"b":1,"a":{"y":[1,{"d":2,"c":3}],"x":"é"}}"#).unwrap();
        let b: Value =
            serde_json::from_str(r#"{"a":{"x":"é","y":[1,{"c":3,"d":2}]},"b":1}"#).unwrap();
        assert_eq!(canonical(&a), canonical(&b));
        assert_eq!(
            canonical(&a),
            r#"{"a":{"x":"é","y":[1,{"c":3,"d":2}]},"b":1}"#
        );
    }

    #[test]
    fn appended_records_form_a_verifiable_chain() {
        let log = temp_log("chain");
        let mut last = None;
        for i in 0..5 {
            let rec = append_to(&log, sample(i)).unwrap();
            assert_eq!(rec.seq, i);
            assert_eq!(
                rec.prev,
                last.clone().unwrap_or_else(|| GENESIS.to_string())
            );
            last = rec.hash.clone();
        }
        let state = verify(&log).unwrap();
        assert_eq!(state.records, 5);
        assert_eq!(Some(state.head), last);
        let _ = std::fs::remove_dir_all(log.parent().unwrap());
    }

    fn tampered(tag: &str, edit: impl Fn(Vec<String>) -> Vec<String>) -> String {
        let log = temp_log(tag);
        for i in 0..4 {
            append_to(&log, sample(i)).unwrap();
        }
        let lines: Vec<String> = std::fs::read_to_string(&log)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        let edited = edit(lines).join("\n") + "\n";
        let _ = std::fs::remove_dir_all(log.parent().unwrap());
        verify_str(&edited).unwrap_err().to_string()
    }

    #[test]
    fn modification_deletion_insertion_and_reordering_are_detected() {
        let e = tampered("modify", |mut l| {
            l[1] = l[1].replace("\"ro_before\":true", "\"ro_before\":false");
            l
        });
        assert!(e.contains("line 2") && e.contains("modified"), "{e}");

        let e = tampered("delete", |mut l| {
            l.remove(1);
            l
        });
        assert!(e.contains("line 2") && e.contains("chain broken"), "{e}");

        let e = tampered("reorder", |mut l| {
            l.swap(1, 2);
            l
        });
        assert!(e.contains("line 2"), "{e}");

        // A forged record with a correct self-hash still breaks the link
        let e = tampered("insert", |mut l| {
            let mut forged: Value = serde_json::from_str(&l[1]).unwrap();
            forged["prev"] = Value::String(GENESIS.into());
            let h = record_hash(&forged).unwrap();
            forged["hash"] = Value::String(h);
            l.insert(1, forged.to_string());
            l
        });
        assert!(e.contains("line 2") && e.contains("chain broken"), "{e}");
    }

    #[test]
    fn refuses_to_extend_a_broken_chain() {
        let log = temp_log("broken");
        append_to(&log, sample(0)).unwrap();
        append_to(&log, sample(1)).unwrap();
        let content = std::fs::read_to_string(&log)
            .unwrap()
            .replace("WD-EVID001", "FORGED");
        std::fs::write(&log, content).unwrap();
        let e = append_to(&log, sample(2)).unwrap_err();
        assert!(format!("{e:#}").contains("failed verification"), "{e:#}");
        let _ = std::fs::remove_dir_all(log.parent().unwrap());
    }

    #[test]
    fn concurrent_appends_keep_one_chain() {
        let log = temp_log("concurrent");
        let handles: Vec<_> = (0..8)
            .map(|t| {
                let log = log.clone();
                std::thread::spawn(move || {
                    for i in 0..10 {
                        append_to(&log, sample(t * 100 + i)).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(verify(&log).unwrap().records, 80);
        let _ = std::fs::remove_dir_all(log.parent().unwrap());
    }

    #[test]
    fn records_carry_context_and_outcome() {
        let log = temp_log("context");
        let failed: Result<()> = Err(anyhow!("blockdev --setro failed"));
        let rec = append_to(&log, sample(0).result(&failed)).unwrap();
        assert_eq!(rec.outcome, Outcome::Error);
        assert_eq!(rec.message.as_deref(), Some("blockdev --setro failed"));
        assert!(rec.ts.ends_with('Z'));
        assert_eq!(rec.details["ro_before"], Value::Bool(true));
        assert!(!rec.argv.is_empty());
        let _ = std::fs::remove_dir_all(log.parent().unwrap());
    }

    fn files_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap()
    }

    #[test]
    fn export_keeps_one_copy_per_boot_and_grows_it_within_the_boot() {
        let log = temp_log("export_boots");
        let case = log.parent().unwrap().join("case");
        append_to(&log, sample(0)).unwrap();
        append_to(&log, sample(1)).unwrap();

        let first = export_for_boot(&log, &case, "boot-a").unwrap();
        assert_eq!(first.jsonl, case.join("audit-boot-a.jsonl"));
        assert_eq!(first.head, case.join("audit-boot-a.head"));
        assert_eq!(first.state.records, 2);
        assert_eq!(read(&first.jsonl), read(&log));
        assert_eq!(
            read(&first.head),
            format!("{}  records=2\n", first.state.head)
        );

        // Later in the same boot: the same file, now with every record
        append_to(&log, sample(2)).unwrap();
        let again = export_for_boot(&log, &case, "boot-a").unwrap();
        assert_eq!(again.jsonl, first.jsonl);
        assert_eq!(again.state.records, 3);
        assert_eq!(read(&again.jsonl), read(&log));
        let boot_a = read(&again.jsonl);

        // After a reboot the live log starts again from genesis
        std::fs::remove_file(&log).unwrap();
        append_to(&log, sample(9)).unwrap();
        let next_boot = export_for_boot(&log, &case, "boot-b").unwrap();
        assert_eq!(next_boot.jsonl, case.join("audit-boot-b.jsonl"));
        assert_eq!(next_boot.state.records, 1);
        assert_eq!(read(&case.join("audit-boot-a.jsonl")), boot_a);
        assert_eq!(
            files_in(&case),
            [
                "audit-boot-a.head",
                "audit-boot-a.jsonl",
                "audit-boot-b.head",
                "audit-boot-b.jsonl"
            ]
        );
        assert_eq!(
            verify(&case.join("audit-boot-a.jsonl")).unwrap(),
            again.state
        );
        let _ = std::fs::remove_dir_all(log.parent().unwrap());
    }

    #[test]
    fn export_never_overwrites_a_copy_that_is_not_an_earlier_state_of_the_log() {
        let log = temp_log("export_numbered");
        let base = log.parent().unwrap().to_path_buf();
        let case = base.join("case");
        append_to(&log, sample(0)).unwrap();
        append_to(&log, sample(1)).unwrap();
        let original = export_for_boot(&log, &case, "b").unwrap();
        let kept = read(&original.jsonl);
        // Files of dfcore 0.1 and of other tools stay untouched
        std::fs::write(case.join("audit.jsonl"), "legacy\n").unwrap();
        std::fs::write(case.join("audit.head"), "legacy\n").unwrap();

        // Another chain under the same boot ID (log restarted or replaced)
        let other = base.join("other.jsonl");
        append_to(&other, sample(5)).unwrap();
        let second = export_for_boot(&other, &case, "b").unwrap();
        assert_eq!(second.jsonl, case.join("audit-b-2.jsonl"));
        assert_eq!(second.head, case.join("audit-b-2.head"));
        assert_eq!(read(&original.jsonl), kept);

        // That chain grows: its own copy is replaced, not the first one
        append_to(&other, sample(6)).unwrap();
        let grown = export_for_boot(&other, &case, "b").unwrap();
        assert_eq!(grown.jsonl, second.jsonl);
        assert_eq!(grown.state.records, 2);

        // The first chain grows too: back to its own file
        append_to(&log, sample(2)).unwrap();
        assert_eq!(
            export_for_boot(&log, &case, "b").unwrap().jsonl,
            original.jsonl
        );

        // A third chain takes the next free number
        let third = base.join("third.jsonl");
        append_to(&third, sample(7)).unwrap();
        assert_eq!(
            export_for_boot(&third, &case, "b").unwrap().jsonl,
            case.join("audit-b-3.jsonl")
        );

        // A head left without its log keeps its name too
        std::fs::write(case.join("audit-c.head"), "kept\n").unwrap();
        let orphan = export_for_boot(&log, &case, "c").unwrap();
        assert_eq!(orphan.jsonl, case.join("audit-c-2.jsonl"));
        assert_eq!(read(&case.join("audit-c.head")), "kept\n");

        assert_eq!(read(&case.join("audit.jsonl")), "legacy\n");
        assert_eq!(read(&case.join("audit.head")), "legacy\n");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn export_writes_through_temporary_files_and_leaves_none_behind() {
        let log = temp_log("export_atomic");
        let base = log.parent().unwrap().to_path_buf();
        let case = base.join("case");
        for i in 0..3 {
            append_to(&log, sample(i)).unwrap();
        }
        // Concurrent exports of one log into one directory
        let handles: Vec<_> = (0..6)
            .map(|_| {
                let (log, case) = (log.clone(), case.clone());
                std::thread::spawn(move || export_for_boot(&log, &case, "b").unwrap())
            })
            .collect();
        for h in handles {
            assert_eq!(h.join().unwrap().jsonl, case.join("audit-b.jsonl"));
        }
        assert_eq!(files_in(&case), ["audit-b.head", "audit-b.jsonl"]);
        assert_eq!(read(&case.join("audit-b.jsonl")), read(&log));

        // A failed write leaves the target as it was and no temporary file
        let target = case.join("audit-b.jsonl");
        let blocked = case.join("blocked");
        std::fs::create_dir_all(blocked.join("not-empty")).unwrap();
        assert!(write_atomic(&blocked, b"new", 0o600).is_err());
        assert!(blocked.join("not-empty").is_dir());
        assert_eq!(
            files_in(&case),
            ["audit-b.head", "audit-b.jsonl", "blocked"]
        );
        write_atomic(&target, b"replaced\n", 0o600).unwrap();
        assert_eq!(read(&target), "replaced\n");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn export_names_files_by_the_running_boot() {
        let log = temp_log("export_boot_id");
        let case = log.parent().unwrap().join("case");
        append_to(&log, sample(0)).unwrap();
        let info = export(&log, &case).unwrap();
        let boot = host::boot_id().unwrap_or_else(|| UNKNOWN_BOOT.into());
        assert_eq!(
            info.jsonl,
            case.join(format!("audit-{}.jsonl", file_name_safe(&boot)))
        );
        // Boot IDs only ever become portable file names
        assert_eq!(file_name_safe("0b9f-4c:1/x y"), "0b9f-4c_1_x_y");
        assert_eq!(file_name_safe(""), UNKNOWN_BOOT);
        let odd = export_for_boot(&log, &case, "a:b/../c").unwrap();
        assert_eq!(odd.jsonl, case.join("audit-a_b____c.jsonl"));
        let _ = std::fs::remove_dir_all(log.parent().unwrap());
    }

    #[test]
    fn export_of_a_missing_or_broken_log() {
        let log = temp_log("export_missing");
        let case = log.parent().unwrap().join("case");
        // Nothing logged yet: an empty copy anchored at genesis
        let empty = export_for_boot(&log, &case, "b").unwrap();
        assert_eq!(empty.state.records, 0);
        assert_eq!(read(&empty.jsonl), "");
        assert!(read(&empty.head).starts_with(GENESIS));
        // An empty copy is an earlier state of every log
        append_to(&log, sample(0)).unwrap();
        let filled = export_for_boot(&log, &case, "b").unwrap();
        assert_eq!(filled.jsonl, empty.jsonl);
        assert_eq!(filled.state.records, 1);

        // A log that fails verification is not exported anywhere
        let content = read(&log).replace("WD-EVID001", "FORGED");
        std::fs::write(&log, content).unwrap();
        let elsewhere = log.parent().unwrap().join("case2");
        let e = export_for_boot(&log, &elsewhere, "b").unwrap_err();
        assert!(format!("{e:#}").contains("failed verification"), "{e:#}");
        assert!(!elsewhere.exists());
        let _ = std::fs::remove_dir_all(log.parent().unwrap());
    }

    #[test]
    fn secrets_in_argv_are_redacted_in_every_form() {
        let flags = vec!["--password".to_string(), "-p".to_string()];
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            redact_args(
                args(&[
                    "dfnet",
                    "hotspot",
                    "start",
                    "--password",
                    "s3cret",
                    "--ssid",
                    "AP"
                ]),
                &flags
            ),
            args(&[
                "dfnet",
                "hotspot",
                "start",
                "--password",
                REDACTED,
                "--ssid",
                "AP"
            ])
        );
        assert_eq!(
            redact_args(
                args(&["dfnet", "--password=s3cret", "-ps3cret", "-p", "s3cret"]),
                &flags
            ),
            args(&[
                "dfnet",
                "--password=<redacted>",
                "-p<redacted>",
                "-p",
                REDACTED
            ])
        );
        // Unrelated flags and values are kept
        assert_eq!(
            redact_args(args(&["dfnet", "--port", "9999", "--passive"]), &flags),
            args(&["dfnet", "--port", "9999", "--passive"])
        );
    }

    #[test]
    fn only_the_system_log_is_mirrored_into_the_journal_by_default() {
        let system = Path::new(DEFAULT_PATH);
        let scratch = Path::new("/tmp/dfdisk-test/audit.jsonl");
        let env = |v: &'static str| Some(OsStr::new(v));
        assert!(journal_mirror(system, None, None));
        // Redirected by DFNIX_AUDIT_LOG (test suites), or another path
        assert!(!journal_mirror(
            scratch,
            env("/tmp/dfdisk-test/audit.jsonl"),
            None
        ));
        assert!(!journal_mirror(system, env(DEFAULT_PATH), None));
        assert!(!journal_mirror(scratch, None, None));
        // DFNIX_AUDIT_JOURNAL=1 forces the mirror, =0 disables it always
        assert!(journal_mirror(scratch, env("/tmp/x"), env("1")));
        assert!(journal_mirror(scratch, None, env("1")));
        assert!(!journal_mirror(system, None, env("0")));
        assert!(!journal_mirror(scratch, env("/tmp/x"), env("0")));
        // Anything else leaves the default
        assert!(journal_mirror(system, None, env("yes")));
        assert!(!journal_mirror(scratch, env("/tmp/x"), env("")));
    }

    #[test]
    fn empty_or_missing_log_is_genesis() {
        assert_eq!(verify_str("").unwrap().head, GENESIS);
        assert_eq!(
            verify(Path::new("/nonexistent/dfcore/audit.jsonl"))
                .unwrap()
                .records,
            0
        );
        assert!(verify_str("\n").is_err());
    }
}
