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
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::host;
use crate::lsblk::DeviceIdentity;
use crate::release;

pub const DEFAULT_PATH: &str = "/run/dfnix/audit.jsonl";
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Log location; `DFNIX_AUDIT_LOG` overrides it (tests, or a log on the case drive).
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
        }
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

pub fn verify(path: &Path) -> Result<ChainState> {
    match std::fs::read_to_string(path) {
        Ok(content) => verify_str(&content),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ChainState {
            records: 0,
            head: GENESIS.into(),
        }),
        Err(e) => Err(e).with_context(|| format!("Cannot read {}", path.display())),
    }
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
        argv: std::env::args().collect(),
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
    send_to_journal(&record, &line);
    Ok(record)
}

/// Append to the default log.
pub fn append(event: Event) -> Result<Record> {
    append_to(&path(), event)
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

/// Copy the log next to case files and record its head, so the case directory
/// carries its own anchor.
pub fn export(log: &Path, dir: &Path) -> Result<ChainState> {
    let state = verify(log)?;
    std::fs::create_dir_all(dir)?;
    if log.exists() {
        std::fs::copy(log, dir.join("audit.jsonl"))?;
    }
    std::fs::write(
        dir.join("audit.head"),
        format!("{}  records={}\n", state.head, state.records),
    )?;
    Ok(state)
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
        let out = log.parent().unwrap().join("case");
        let state = export(&log, &out).unwrap();
        assert_eq!(state.records, 1);
        assert!(std::fs::read_to_string(out.join("audit.head"))
            .unwrap()
            .starts_with(&state.head));
        let _ = std::fs::remove_dir_all(log.parent().unwrap());
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
