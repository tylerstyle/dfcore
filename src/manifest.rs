//! One record format for every logical acquisition: files from a mount, mail,
//! cloud services, databases, received streams.
//!
//! A collection directory holds
//!
//! - `manifest.json`: who, what, why and how (case, source, method, scope,
//!   clocks) plus totals. Written as `incomplete` before anything is acquired
//!   and replaced atomically when the collection finishes.
//! - `items.jsonl`: one [`Item`] per line, appended as each item is decided,
//!   including the items the scope left out and the ones that failed.
//! - `footprint.jsonl`: one [`FootprintEntry`] per action the source could see
//!   (connections, TLS, authentication, commands, queries).
//! - `items.csv`: the items as a court annex, generated when the collection
//!   finishes.
//! - the acquired data, laid out by the tool, and the audit-log copy.
//!
//! Integrity runs from the data to the audit log: every item carries its
//! SHA-256, the finished manifest carries the SHA-256 of `items.jsonl`,
//! `footprint.jsonl` and `items.csv`, and the `<action>_finished` audit record
//! carries the SHA-256 of `manifest.json`. The `<action>_started` record is
//! written before any data and its hash is the manifest's `audit_anchor`.

use crate::{audit, host};
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    path::{Component, Path, PathBuf},
};

pub const FORMAT: &str = "dfnix-manifest/1";
pub const MANIFEST: &str = "manifest.json";
pub const ITEMS: &str = "items.jsonl";
pub const FOOTPRINT: &str = "footprint.jsonl";
pub const CSV: &str = "items.csv";

/// Appended lines between two syncs of `items.jsonl` / `footprint.jsonl`
const SYNC_EVERY: u64 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Started and not finished: running, interrupted or crashed
    Incomplete,
    /// Every in-scope item was acquired
    Complete,
    /// Finished, but items failed or the tool reported errors
    CompleteWithErrors,
    /// Stopped on purpose or by a fatal error before the scope was covered
    Aborted,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Case {
    pub case_number: String,
    pub evidence_number: String,
    pub examiner: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// What was acquired from.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Source {
    /// e.g. `filesystem`, `smb`, `imap`, `graph`, `cloud`, `database`, `stream`
    pub kind: String,
    /// Path, URL, server and account, ...
    pub locator: String,
    /// What identifies the source beyond its locator: device identity, TLS
    /// certificate fingerprint, server version, tenant ID, ...
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub identity: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub details: Value,
}

/// How it was acquired.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Method {
    pub tool: String,
    pub tool_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_revision: Option<String>,
    /// Command line with secrets already redacted
    pub argv: Vec<String>,
    /// The read-only means the tool relied on, e.g. `IMAP EXAMINE`,
    /// `BODY.PEEK[]`, `read-only bind mount`, `COPY_ONLY backup`
    #[serde(default)]
    pub read_only_primitives: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// What items whose time is unknown count as when the scope has a time window.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownTime {
    #[default]
    Exclude,
    Include,
}

/// The legal and technical limits of an acquisition (ScopeSpec). The examiner
/// and the order decide it; the tools apply it before transferring any bytes
/// and record every item it leaves out.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    /// Reference to the order or legal basis (file number, decision, date)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_basis: Option<String>,
    /// Accounts in scope; empty: every account the source offers
    #[serde(default)]
    pub accounts: Vec<String>,
    /// Patterns on the source path: `*` and `?` stay within one `/`-separated
    /// segment, `**` spans segments. Empty: every path.
    #[serde(default)]
    pub include: Vec<String>,
    /// Patterns that leave a path out even when it matches `include`
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Window start, inclusive (RFC 3339, kept as entered)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    /// Window end, exclusive (RFC 3339, kept as entered)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    /// Which time of an item the window applies to (`mtime`, `INTERNALDATE`, ...)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_basis: Option<String>,
    #[serde(default)]
    pub unknown_time: UnknownTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// An item as the scope sees it, before any of its bytes are transferred.
#[derive(Debug, Clone, Copy, Default)]
pub struct Candidate<'a> {
    pub path: &'a str,
    pub account: Option<&'a str>,
    /// The item's time named by [`Scope::time_basis`], ns since the Unix epoch
    pub time_ns: Option<i128>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    InScope,
    /// Why the item is left out; goes into [`Item::reason`]
    OutOfScope(String),
}

/// A [`Scope`] with parsed window and checked patterns.
#[derive(Debug, Clone)]
pub struct ScopeRules {
    scope: Scope,
    not_before: Option<i128>,
    not_after: Option<i128>,
}

impl Scope {
    /// Check the scope and prepare it for [`ScopeRules::decide`].
    pub fn rules(&self) -> Result<ScopeRules> {
        for p in self.include.iter().chain(&self.exclude) {
            ensure!(!p.is_empty(), "scope: empty path pattern");
        }
        ensure!(
            !self.accounts.iter().any(String::is_empty),
            "scope: empty account"
        );
        let parse = |name: &str, v: &Option<String>| -> Result<Option<i128>> {
            v.as_deref()
                .map(|s| host::parse_rfc3339(s).with_context(|| format!("scope: {name}")))
                .transpose()
        };
        let not_before = parse("not_before", &self.not_before)?;
        let not_after = parse("not_after", &self.not_after)?;
        if let (Some(a), Some(b)) = (not_before, not_after) {
            ensure!(a < b, "scope: not_before must be earlier than not_after");
        }
        if not_before.is_some() || not_after.is_some() {
            ensure!(
                self.time_basis.is_some(),
                "scope: a time window needs time_basis (which time of an item it applies to)"
            );
        }
        Ok(ScopeRules {
            scope: self.clone(),
            not_before,
            not_after,
        })
    }
}

impl ScopeRules {
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    pub fn has_window(&self) -> bool {
        self.not_before.is_some() || self.not_after.is_some()
    }

    pub fn decide(&self, c: &Candidate) -> Decision {
        let s = &self.scope;
        if let Some(account) = c.account {
            if !s.accounts.is_empty() && !s.accounts.iter().any(|a| a == account) {
                return Decision::OutOfScope(format!("account {account} is not in scope"));
            }
        }
        if let Some(p) = s.exclude.iter().find(|p| glob_match(p, c.path)) {
            return Decision::OutOfScope(format!("excluded by {p}"));
        }
        if !s.include.is_empty() && !s.include.iter().any(|p| glob_match(p, c.path)) {
            return Decision::OutOfScope("matches no include pattern".into());
        }
        if self.has_window() {
            let basis = s.time_basis.as_deref().unwrap_or("time");
            match c.time_ns {
                None if s.unknown_time == UnknownTime::Exclude => {
                    return Decision::OutOfScope(format!("{basis} unknown"));
                }
                None => {}
                Some(t) => {
                    if self.not_before.is_some_and(|nb| t < nb) {
                        return Decision::OutOfScope(format!("{basis} before the time window"));
                    }
                    if self.not_after.is_some_and(|na| t >= na) {
                        return Decision::OutOfScope(format!("{basis} after the time window"));
                    }
                }
            }
        }
        Decision::InScope
    }
}

/// Match a whole `/`-separated path against a pattern: `?` is one character and
/// `*` any run of characters within a segment, `**` any run including `/`, and
/// `**/` also matches nothing (`a/**/b` matches `a/b`). Case-sensitive.
pub fn glob_match(pattern: &str, path: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let s: Vec<char> = path.chars().collect();
    let (n, m) = (p.len(), s.len());
    // dp[i][j]: p[i..] matches s[j..]
    let mut dp = vec![vec![false; m + 1]; n + 1];
    dp[n][m] = true;
    for i in (0..n).rev() {
        let double = p[i] == '*' && p.get(i + 1) == Some(&'*');
        if double && p.get(i + 2) == Some(&'/') {
            // `**/`: zero or more whole segments, i.e. nothing or a run of
            // characters that ends with '/'
            let rest = i + 3;
            let mut ends_at_slash = false; // some s[k] == '/' (k >= j) with dp[rest][k + 1]
            for j in (0..=m).rev() {
                if j < m && s[j] == '/' && dp[rest][j + 1] {
                    ends_at_slash = true;
                }
                dp[i][j] = dp[rest][j] || ends_at_slash;
            }
            continue;
        }
        for j in (0..=m).rev() {
            dp[i][j] = match p[i] {
                // `**` elsewhere: any run of characters, '/' included
                '*' if double => dp[i + 2][j] || (j < m && dp[i][j + 1]),
                '*' => dp[i + 1][j] || (j < m && s[j] != '/' && dp[i][j + 1]),
                '?' => j < m && s[j] != '/' && dp[i + 1][j + 1],
                c => j < m && s[j] == c && dp[i + 1][j + 1],
            };
        }
    }
    dp[0][0]
}

/// The examiner's reference time, entered from a trusted clock.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReferenceTime {
    /// As entered, RFC 3339
    pub value: String,
    /// Where it came from (radio clock, phone, GPS, ...)
    pub how: String,
    /// The dfnix clock when it was entered
    pub local: String,
    /// `value` minus `local`, in seconds: add it to dfnix times
    pub offset_seconds: f64,
}

/// The source's own clock, read during the acquisition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceClock {
    /// As the source reported it, RFC 3339
    pub value: String,
    /// How it was read (`IMAP Date header`, `SELECT now()`, `SMB2 negotiate`, ...)
    pub how: String,
    /// The dfnix clock when it was read
    pub local: String,
    /// `value` minus `local`, in seconds
    pub offset_seconds: f64,
}

impl ReferenceTime {
    /// `value` read off a trusted clock at the dfnix time `local_ns`.
    pub fn new(value: &str, how: &str, local_ns: i128) -> Result<Self> {
        let v = host::parse_rfc3339(value).context("reference time")?;
        Ok(Self {
            value: value.to_string(),
            how: how.to_string(),
            local: host::rfc3339_utc_ns(local_ns),
            offset_seconds: (v - local_ns) as f64 / 1e9,
        })
    }
}

impl SourceClock {
    /// `value` reported by the source at the dfnix time `local_ns`.
    pub fn new(value: &str, how: &str, local_ns: i128) -> Result<Self> {
        let v = host::parse_rfc3339(value).context("source clock")?;
        Ok(Self {
            value: value.to_string(),
            how: how.to_string(),
            local: host::rfc3339_utc_ns(local_ns),
            offset_seconds: (v - local_ns) as f64 / 1e9,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Clocks {
    /// dfnix clock, set by [`Collection::create`]
    #[serde(default)]
    pub started: String,
    /// dfnix clock, set by [`Collection::finish`]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<ReferenceTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceClock>,
}

/// Everything about a collection that is known before it starts.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Header {
    /// Audit action stem: `<action>_started`, `_resumed`, `_finished`
    pub action: String,
    pub case: Case,
    pub source: Source,
    pub method: Method,
    pub scope: Scope,
    #[serde(default)]
    pub clocks: Clocks,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemStatus {
    /// Bytes stored and hashed
    Acquired,
    /// Left out by the scope; nothing transferred
    OutOfScope,
    /// In scope, but reading or storing it failed
    Error,
    /// In scope, but not acquirable by design (socket, device node, ...)
    Skipped,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Hashes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub md5: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
}

/// An item's times on the source, RFC 3339 with nanoseconds where known.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Times {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accessed: Option<String>,
    /// Inode / MFT record change
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<String>,
    /// Creation (birth)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub birth: Option<String>,
}

/// A hash the source itself reports (QuickXorHash, Drive MD5, S3 ETag, ...)
/// and whether it matched the acquired bytes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceHash {
    pub algorithm: String,
    pub value: String,
    pub matches: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Item {
    /// Assigned by [`Collection::add`]
    #[serde(default)]
    pub seq: u64,
    pub status: ItemStatus,
    /// Path on the source (`/`-separated), mailbox/UID, object key, ...
    pub path: String,
    /// What the item is when it is not a file with content: `directory`,
    /// `symlink`, `special`, `message`, `object`, ... (absent: a file)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// Where the bytes are, relative to the collection directory: a file, or
    /// the container that holds them
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored_as: Option<String>,
    /// The entry inside the container `stored_as` (e.g. a ZIP member name)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default)]
    pub hashes: Hashes,
    #[serde(default)]
    pub times: Times,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_hash: Option<SourceHash>,
    /// Kind-specific: mode, owner, xattrs, ACL, symlink target, IMAP UID and
    /// flags, Graph message ID, ...
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
    /// Why it was left out, skipped or failed
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Item {
    pub fn new(status: ItemStatus, path: impl Into<String>) -> Self {
        Self {
            seq: 0,
            status,
            path: path.into(),
            kind: None,
            account: None,
            stored_as: None,
            member: None,
            size: None,
            hashes: Hashes::default(),
            times: Times::default(),
            source_hash: None,
            metadata: Value::Null,
            reason: None,
        }
    }

    /// An item the scope left out, with the scope's reason.
    pub fn out_of_scope(path: impl Into<String>, reason: impl Into<String>) -> Self {
        let mut item = Self::new(ItemStatus::OutOfScope, path);
        item.reason = Some(reason.into());
        item
    }
}

/// One action on the source that the source could see or log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FootprintEntry {
    /// dfnix clock; set by [`Collection::footprint`] when empty
    #[serde(default)]
    pub ts: String,
    /// `connect`, `tls`, `auth`, `command`, `query`, `write`, ...
    pub kind: String,
    /// Never secrets: the authentication method, not the password
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub detail: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_sent: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_received: Option<u64>,
}

impl FootprintEntry {
    pub fn new(kind: &str, detail: Value) -> Self {
        Self {
            ts: String::new(),
            kind: kind.to_string(),
            detail,
            bytes_sent: None,
            bytes_received: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Totals {
    pub acquired: u64,
    /// Out-of-scope items listed in items.jsonl
    pub out_of_scope: u64,
    /// Out-of-scope items counted without being listed (so that names outside
    /// the scope are not recorded), by reason
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub unlisted_out_of_scope: std::collections::BTreeMap<String, u64>,
    pub errors: u64,
    pub skipped: u64,
    /// Bytes of the acquired items
    pub bytes: u64,
    pub footprint_entries: u64,
    /// SHA-256 of the record files, set when the collection finishes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub footprint_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csv_sha256: Option<String>,
}

impl Totals {
    fn count(&mut self, item: &Item) {
        match item.status {
            ItemStatus::Acquired => {
                self.acquired += 1;
                self.bytes += item.size.unwrap_or(0);
            }
            ItemStatus::OutOfScope => self.out_of_scope += 1,
            ItemStatus::Error => self.errors += 1,
            ItemStatus::Skipped => self.skipped += 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub format: String,
    pub status: Status,
    #[serde(flatten)]
    pub header: Header,
    pub totals: Totals,
    /// Hash of the `<action>_started` audit record
    pub audit_anchor: Option<String>,
    /// Hashes of the `<action>_resumed` audit records
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit_resumed: Vec<String>,
    #[serde(default)]
    pub errors: Vec<String>,
    /// Problems that do not touch the evidence (an audit record not written)
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// How a collection ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Completion {
    /// The scope was worked through; item errors make it `complete_with_errors`
    Done { errors: Vec<String> },
    /// Stopped before the scope was covered
    Aborted { reason: String },
}

/// An open collection directory.
pub struct Collection {
    dir: PathBuf,
    audit_log: PathBuf,
    rules: ScopeRules,
    manifest: Manifest,
    items: File,
    footprint: File,
    next_seq: u64,
    unsynced: u64,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 of a file, streamed.
pub fn sha256_file(path: &Path) -> Result<String> {
    let mut f = File::open(path).with_context(|| format!("Cannot open {}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f
            .read(&mut buf)
            .with_context(|| format!("Cannot read {}", path.display()))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A path relative to the collection directory that cannot leave it.
fn check_relative(path: &str) -> Result<()> {
    let p = Path::new(path);
    ensure!(
        !path.is_empty()
            && p.components()
                .all(|c| matches!(c, Component::Normal(_) | Component::CurDir)),
        "stored_as must be a relative path inside the collection: {path:?}"
    );
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("json.tmp");
    let mut f = File::create(&tmp).with_context(|| format!("Cannot create {}", tmp.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path).with_context(|| format!("Cannot replace {}", path.display()))?;
    if let Some(dir) = path.parent() {
        // Persist the rename itself; not every filesystem can sync a directory
        let _ = File::open(dir).and_then(|d| d.sync_all());
    }
    Ok(())
}

fn open_append(path: &Path) -> Result<File> {
    OpenOptions::new()
        .append(true)
        .open(path)
        .with_context(|| format!("Cannot open {}", path.display()))
}

/// Stream the records of a JSONL file to `f`. Only a crash during an append
/// leaves a last line without its newline (the "torn" line); such a line is
/// skipped, and cut off if `cut` is set. Any other unreadable line is an error.
/// Returns whether a torn line was found.
fn scan_jsonl<T: serde::de::DeserializeOwned>(
    path: &Path,
    cut: bool,
    mut f: impl FnMut(T) -> Result<()>,
) -> Result<bool> {
    let file = OpenOptions::new()
        .read(true)
        .write(cut)
        .open(path)
        .with_context(|| format!("Cannot open {}", path.display()))?;
    let mut reader = BufReader::new(&file);
    let mut good: u64 = 0;
    let mut line = Vec::new();
    for n in 1.. {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            return Ok(false);
        }
        if !line.ends_with(b"\n") {
            if cut {
                file.set_len(good)?;
                file.sync_all()?;
            }
            return Ok(true);
        }
        let record = serde_json::from_slice::<T>(&line)
            .with_context(|| format!("{}: line {n} is not a valid record", path.display()))?;
        f(record)?;
        good += line.len() as u64;
    }
    unreachable!("the line counter cannot overflow")
}

/// Call `f` for every item of a collection, in order (e.g. to skip what a
/// resumed collection already has). A torn last line is ignored.
pub fn for_each_item(dir: &Path, f: impl FnMut(Item) -> Result<()>) -> Result<()> {
    scan_jsonl(&dir.join(ITEMS), false, f).map(|_| ())
}

/// Hold an exclusive lock on the open record file while the collection is
/// open, so two processes cannot append to one collection. A filesystem that
/// cannot lock gets a warning instead.
fn lock(file: &File, dir: &Path, warnings: &mut Vec<String>) -> Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: flock on a descriptor this function borrows; no memory involved
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock {
            bail!("{} is open in another process", dir.display());
        }
        warnings.push(format!(
            "could not lock {}: {err}",
            dir.join(ITEMS).display()
        ));
    }
    Ok(())
}

/// What [`Collection::finish`] produced.
#[derive(Debug, Clone)]
pub struct Finished {
    pub manifest: Manifest,
    /// Hash of the `<action>_finished` audit record
    pub audit_record: Option<String>,
    /// The copy of the audit log in the collection directory
    pub audit_export: Option<audit::ExportInfo>,
    /// Problems after the manifest became final: the finish record or the
    /// audit-log copy could not be written. The evidence is unaffected, and
    /// [`verify`] reports the missing record.
    pub warnings: Vec<String>,
}

impl Collection {
    /// Start a collection in `dir` (created if missing). Refuses a directory
    /// that already holds a manifest, and an invalid scope. Writes the
    /// `incomplete` manifest and the `<action>_started` audit record before
    /// anything is acquired.
    pub fn create(dir: &Path, header: Header) -> Result<Self> {
        Self::create_with_log(dir, header, &audit::path())
    }

    /// [`create`](Self::create) with an explicit audit log.
    pub fn create_with_log(dir: &Path, mut header: Header, audit_log: &Path) -> Result<Self> {
        ensure!(!header.action.is_empty(), "manifest: action is empty");
        ensure!(!header.method.tool.is_empty(), "manifest: tool is empty");
        let rules = header.scope.rules()?;
        std::fs::create_dir_all(dir).with_context(|| format!("Cannot create {}", dir.display()))?;
        let manifest_path = dir.join(MANIFEST);
        ensure!(
            !manifest_path.exists(),
            "{} already holds a collection; resume it or choose another directory",
            dir.display()
        );
        // create_new: two tools racing for the same directory cannot both win
        let mut files = Vec::new();
        for name in [ITEMS, FOOTPRINT] {
            let path = dir.join(name);
            files.push(
                OpenOptions::new()
                    .append(true)
                    .create_new(true)
                    .open(&path)
                    .with_context(|| format!("Cannot create {}", path.display()))?,
            );
        }
        let footprint = files.pop().expect("two files");
        let items = files.pop().expect("two files");
        let mut warnings = Vec::new();
        lock(&items, dir, &mut warnings)?;
        header.clocks.started = host::rfc3339_utc_ns(host::unix_now_ns());
        let mut manifest = Manifest {
            format: FORMAT.to_string(),
            status: Status::Incomplete,
            header,
            totals: Totals::default(),
            audit_anchor: None,
            audit_resumed: Vec::new(),
            errors: Vec::new(),
            warnings,
        };
        let event = audit_event(&manifest, "started")
            .detail("directory", dir.to_string_lossy().to_string())
            .detail("scope", serde_json::to_value(&manifest.header.scope)?);
        match audit::append_to(audit_log, event) {
            Ok(rec) => manifest.audit_anchor = rec.hash,
            Err(e) => manifest
                .warnings
                .push(format!("audit record not written: {e:#}")),
        }
        write_atomic(&manifest_path, &serde_json::to_vec_pretty(&manifest)?)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            audit_log: audit_log.to_path_buf(),
            rules,
            manifest,
            items,
            footprint,
            next_seq: 1,
            unsynced: 0,
        })
    }

    /// Reopen an `incomplete` collection after an interruption. A torn last
    /// record line is cut off and noted. The items already recorded are read
    /// with [`for_each_item`]. Unlisted out-of-scope counts start again from
    /// zero: the tool decides every candidate again and counts it again.
    pub fn resume(dir: &Path) -> Result<Self> {
        Self::resume_with_log(dir, &audit::path())
    }

    /// [`resume`](Self::resume) with an explicit audit log.
    pub fn resume_with_log(dir: &Path, audit_log: &Path) -> Result<Self> {
        let manifest_path = dir.join(MANIFEST);
        let mut manifest: Manifest = serde_json::from_slice(
            &std::fs::read(&manifest_path)
                .with_context(|| format!("Cannot read {}", manifest_path.display()))?,
        )
        .with_context(|| format!("Cannot parse {}", manifest_path.display()))?;
        ensure!(
            manifest.format == FORMAT,
            "unknown manifest format {}",
            manifest.format
        );
        ensure!(
            manifest.status == Status::Incomplete,
            "{} is {:?}; only an incomplete collection can be resumed",
            dir.display(),
            manifest.status
        );
        let rules = manifest.header.scope.rules()?;
        let items = open_append(&dir.join(ITEMS))?;
        lock(&items, dir, &mut manifest.warnings)?;
        let mut totals = Totals::default();
        let (mut count, mut last_seq) = (0u64, 0u64);
        let torn_items = scan_jsonl(&dir.join(ITEMS), true, |item: Item| {
            totals.count(&item);
            count += 1;
            last_seq = item.seq;
            Ok(())
        })?;
        let torn_fp = scan_jsonl(&dir.join(FOOTPRINT), true, |_: FootprintEntry| {
            totals.footprint_entries += 1;
            Ok(())
        })?;
        for (torn, name) in [(torn_items, ITEMS), (torn_fp, FOOTPRINT)] {
            if torn {
                manifest
                    .warnings
                    .push(format!("cut off a torn last line of {name} when resuming"));
            }
        }
        manifest.totals = totals;
        let event = audit_event(&manifest, "resumed")
            .detail("directory", dir.to_string_lossy().to_string())
            .detail("items", count);
        match audit::append_to(audit_log, event) {
            Ok(rec) => manifest.audit_resumed.extend(rec.hash),
            Err(e) => manifest
                .warnings
                .push(format!("audit record not written: {e:#}")),
        }
        write_atomic(&manifest_path, &serde_json::to_vec_pretty(&manifest)?)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            audit_log: audit_log.to_path_buf(),
            rules,
            manifest,
            items,
            footprint: open_append(&dir.join(FOOTPRINT))?,
            next_seq: last_seq + 1,
            unsynced: 0,
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn scope(&self) -> &ScopeRules {
        &self.rules
    }

    /// Count an item the scope leaves out without listing it: nothing about it
    /// but the reason reaches the record.
    pub fn count_out_of_scope(&mut self, reason: &str) {
        *self
            .manifest
            .totals
            .unlisted_out_of_scope
            .entry(reason.to_string())
            .or_default() += 1;
    }

    /// Record what identifies the source once it is known, e.g. after
    /// connecting: TLS certificates, server greeting and capabilities.
    pub fn set_source_identity(&mut self, identity: Value) {
        self.manifest.header.source.identity = identity;
    }

    /// Record the source's clock once it is known (after connecting).
    pub fn set_source_clock(&mut self, clock: SourceClock) {
        self.manifest.header.clocks.source = Some(clock);
    }

    /// Record a problem that is not tied to one item.
    pub fn error(&mut self, message: impl Into<String>) {
        self.manifest.errors.push(message.into());
    }

    fn maybe_sync(&mut self) -> Result<()> {
        self.unsynced += 1;
        if self.unsynced >= SYNC_EVERY {
            self.items.sync_data()?;
            self.footprint.sync_data()?;
            self.unsynced = 0;
        }
        Ok(())
    }

    /// Append an item. An acquired file (no `kind`, or `kind` `file`) and any
    /// item with stored content needs a size and a SHA-256; `stored_as` must
    /// stay inside the collection. Returns the item's number.
    pub fn add(&mut self, mut item: Item) -> Result<u64> {
        // Directories, symlinks and the like are acquired as metadata only
        let content =
            matches!(item.kind.as_deref(), None | Some("file")) || item.stored_as.is_some();
        if item.status == ItemStatus::Acquired && content {
            ensure!(
                item.size.is_some(),
                "acquired item without size: {}",
                item.path
            );
            ensure!(
                item.hashes.sha256.as_deref().is_some_and(is_sha256_hex),
                "acquired item without a lowercase hex SHA-256: {}",
                item.path
            );
        }
        if let Some(stored) = &item.stored_as {
            check_relative(stored)?;
        }
        item.seq = self.next_seq;
        let mut line = serde_json::to_vec(&item)?;
        line.push(b'\n');
        self.items
            .write_all(&line)
            .with_context(|| format!("Cannot append to {}", self.dir.join(ITEMS).display()))?;
        self.next_seq += 1;
        self.manifest.totals.count(&item);
        self.maybe_sync()?;
        Ok(item.seq)
    }

    /// Append a footprint entry, stamped with the dfnix clock if it has no time.
    pub fn footprint(&mut self, mut entry: FootprintEntry) -> Result<()> {
        if entry.ts.is_empty() {
            entry.ts = host::rfc3339_utc_ns(host::unix_now_ns());
        }
        let mut line = serde_json::to_vec(&entry)?;
        line.push(b'\n');
        self.footprint
            .write_all(&line)
            .with_context(|| format!("Cannot append to {}", self.dir.join(FOOTPRINT).display()))?;
        self.manifest.totals.footprint_entries += 1;
        self.maybe_sync()
    }

    /// Close the collection: sync the records, write `items.csv`, hash the
    /// record files into the final manifest, log `<action>_finished` with the
    /// manifest's SHA-256 and copy the audit log into the directory. Fails only
    /// if the records cannot be written; audit problems become warnings.
    pub fn finish(mut self, completion: Completion) -> Result<Finished> {
        self.items.sync_all()?;
        self.footprint.sync_all()?;
        let m = &mut self.manifest;
        m.status = match completion {
            Completion::Aborted { reason } => {
                m.errors.push(reason);
                Status::Aborted
            }
            Completion::Done { errors } => {
                m.errors.extend(errors);
                if m.totals.errors > 0 || !m.errors.is_empty() {
                    Status::CompleteWithErrors
                } else {
                    Status::Complete
                }
            }
        };
        let csv_path = self.dir.join(CSV);
        write_csv(&self.dir.join(ITEMS), &csv_path)?;
        m.totals.items_sha256 = Some(sha256_file(&self.dir.join(ITEMS))?);
        m.totals.footprint_sha256 = Some(sha256_file(&self.dir.join(FOOTPRINT))?);
        m.totals.csv_sha256 = Some(sha256_file(&csv_path)?);
        m.header.clocks.finished = Some(host::rfc3339_utc_ns(host::unix_now_ns()));
        // The manifest is final once its hash is in the finish record, so
        // problems from here on go to the caller
        let bytes = serde_json::to_vec_pretty(&*m)?;
        write_atomic(&self.dir.join(MANIFEST), &bytes)?;
        let outcome = match m.status {
            Status::Aborted => audit::Outcome::Error,
            _ => audit::Outcome::Ok,
        };
        let event = audit_event(m, "finished")
            .outcome(outcome, None)
            .detail("directory", self.dir.to_string_lossy().to_string())
            .detail("status", serde_json::to_value(m.status)?)
            .detail("manifest_sha256", sha256_hex(&bytes))
            .detail("acquired", m.totals.acquired)
            .detail("out_of_scope", m.totals.out_of_scope)
            .detail("errors", m.totals.errors)
            .detail("bytes", m.totals.bytes);
        let mut warnings = Vec::new();
        let audit_record = match audit::append_to(&self.audit_log, event) {
            Ok(rec) => rec.hash,
            Err(e) => {
                warnings.push(format!("audit record not written: {e:#}"));
                None
            }
        };
        let audit_export = match audit::export(&self.audit_log, &self.dir) {
            Ok(info) => Some(info),
            Err(e) => {
                warnings.push(format!("audit log not copied into the collection: {e:#}"));
                None
            }
        };
        Ok(Finished {
            manifest: self.manifest,
            audit_record,
            audit_export,
            warnings,
        })
    }
}

fn audit_event(m: &Manifest, stage: &str) -> audit::Event {
    audit::Event::new(
        &m.header.method.tool,
        &m.header.method.tool_version,
        &format!("{}_{stage}", m.header.action),
    )
    .detail("case_number", m.header.case.case_number.clone())
    .detail("evidence_number", m.header.case.evidence_number.clone())
    .detail("source_kind", m.header.source.kind.clone())
    .detail("source", m.header.source.locator.clone())
}

const CSV_COLUMNS: [&str; 15] = [
    "seq",
    "status",
    "account",
    "path",
    "stored_as",
    "size",
    "sha256",
    "md5",
    "sha1",
    "modified",
    "accessed",
    "changed",
    "birth",
    "source_hash",
    "reason",
];

/// One CSV cell (RFC 4180). A cell starting with `=`, `+`, `-`, `@`, tab or CR
/// gets a leading `'`, so a spreadsheet shows it instead of evaluating it as
/// a formula; items.jsonl keeps the exact value.
fn csv_cell(value: &str) -> String {
    let guarded = if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{value}")
    } else {
        value.to_string()
    };
    if guarded.contains([',', '"', '\n', '\r'])
        || guarded.starts_with(' ')
        || guarded.ends_with(' ')
    {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

/// `items.csv` from `items.jsonl`: RFC 4180, CRLF, UTF-8 with BOM (spreadsheets
/// otherwise misread non-ASCII names).
fn write_csv(items: &Path, csv: &Path) -> Result<()> {
    let mut out = std::io::BufWriter::new(
        File::create(csv).with_context(|| format!("Cannot create {}", csv.display()))?,
    );
    out.write_all("\u{feff}".as_bytes())?;
    out.write_all(CSV_COLUMNS.join(",").as_bytes())?;
    out.write_all(b"\r\n")?;
    let dir = items.parent().unwrap_or(Path::new("."));
    for_each_item(dir, |item| {
        let status = serde_json::to_value(item.status)?;
        let opt = |v: &Option<String>| v.clone().unwrap_or_default();
        let cells = [
            item.seq.to_string(),
            status.as_str().unwrap_or_default().to_string(),
            opt(&item.account),
            item.path.clone(),
            opt(&item.stored_as),
            item.size.map(|s| s.to_string()).unwrap_or_default(),
            opt(&item.hashes.sha256),
            opt(&item.hashes.md5),
            opt(&item.hashes.sha1),
            opt(&item.times.modified),
            opt(&item.times.accessed),
            opt(&item.times.changed),
            opt(&item.times.birth),
            item.source_hash
                .as_ref()
                .map(|h| {
                    format!(
                        "{}:{} ({})",
                        h.algorithm,
                        h.value,
                        if h.matches { "matches" } else { "MISMATCH" }
                    )
                })
                .unwrap_or_default(),
            opt(&item.reason),
        ];
        let row: Vec<String> = cells.iter().map(|c| csv_cell(c)).collect();
        out.write_all(row.join(",").as_bytes())?;
        out.write_all(b"\r\n")?;
        Ok(())
    })?;
    let file = out.into_inner().map_err(|e| e.into_error())?;
    file.sync_all()?;
    Ok(())
}

/// Result of [`verify`].
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct VerifyReport {
    pub status: Option<Status>,
    /// Acquired items whose stored file was re-hashed and matched
    pub items_ok: u64,
    /// Acquired items with content this check cannot reach (inside a
    /// container, or not stored); metadata-only items are not counted
    pub items_unchecked: u64,
    pub items_mismatch: Vec<String>,
    pub items_missing: Vec<String>,
    pub audit_anchor_found: bool,
    pub audit_finish_found: bool,
    pub problems: Vec<String>,
}

impl VerifyReport {
    /// Everything that could be checked matched.
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
            && self.items_mismatch.is_empty()
            && self.items_missing.is_empty()
            && self.audit_anchor_found
            && self.audit_finish_found
    }
}

/// Check a finished collection: the record files against the manifest, every
/// stored item against its size and SHA-256, and the audit-log copies in the
/// directory for the start record and a finish record that names this
/// manifest's SHA-256.
pub fn verify(dir: &Path) -> Result<VerifyReport> {
    let mut r = VerifyReport::default();
    let manifest_bytes = std::fs::read(dir.join(MANIFEST))
        .with_context(|| format!("Cannot read {}", dir.join(MANIFEST).display()))?;
    let m: Manifest = serde_json::from_slice(&manifest_bytes)
        .with_context(|| format!("Cannot parse {}", dir.join(MANIFEST).display()))?;
    ensure!(m.format == FORMAT, "unknown manifest format {}", m.format);
    r.status = Some(m.status);
    if m.status == Status::Incomplete {
        r.problems.push("the collection never finished".into());
    }
    for (name, expected) in [
        (ITEMS, &m.totals.items_sha256),
        (FOOTPRINT, &m.totals.footprint_sha256),
        (CSV, &m.totals.csv_sha256),
    ] {
        match expected {
            None => r
                .problems
                .push(format!("the manifest has no hash of {name}")),
            Some(want) => match sha256_file(&dir.join(name)) {
                Ok(got) if &got == want => {}
                Ok(got) => r
                    .problems
                    .push(format!("{name}: SHA-256 {got}, manifest says {want}")),
                Err(e) => r.problems.push(format!("{name}: {e:#}")),
            },
        }
    }
    let mut totals = Totals::default();
    for_each_item(dir, |item| {
        totals.count(&item);
        if item.status != ItemStatus::Acquired {
            return Ok(());
        }
        // Metadata only, or inside a container the tool itself verifies
        let Some(stored) = item.stored_as.as_ref().filter(|_| item.member.is_none()) else {
            if item.stored_as.is_some() || item.size.is_some() {
                r.items_unchecked += 1;
            }
            return Ok(());
        };
        if check_relative(stored).is_err() {
            r.problems.push(format!(
                "item {}: stored_as leaves the collection",
                item.seq
            ));
            return Ok(());
        }
        let path = dir.join(stored);
        if !path.is_file() {
            r.items_missing.push(stored.clone());
            return Ok(());
        }
        let size_ok = std::fs::metadata(&path).map(|md| Some(md.len()) == item.size)?;
        let hash_ok = sha256_file(&path)? == item.hashes.sha256.clone().unwrap_or_default();
        if size_ok && hash_ok {
            r.items_ok += 1;
        } else {
            r.items_mismatch.push(stored.clone());
        }
        Ok(())
    })?;
    for (what, got, want) in [
        ("acquired", totals.acquired, m.totals.acquired),
        ("out_of_scope", totals.out_of_scope, m.totals.out_of_scope),
        ("errors", totals.errors, m.totals.errors),
        ("bytes", totals.bytes, m.totals.bytes),
    ] {
        if got != want {
            r.problems.push(format!(
                "totals.{what}: items.jsonl gives {got}, manifest says {want}"
            ));
        }
    }
    let manifest_sha = sha256_hex(&manifest_bytes);
    let finished = format!("{}_finished", m.header.action);
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if !(name.starts_with("audit-") && name.ends_with(".jsonl")) {
            continue;
        }
        let content = std::fs::read_to_string(&path)?;
        if let Err(e) = audit::verify_str(&content) {
            r.problems.push(format!("{name}: {e:#}"));
            continue;
        }
        for line in content.lines().filter(|l| !l.is_empty()) {
            let rec: audit::Record = serde_json::from_str(line)?;
            if rec.hash.is_some() && rec.hash == m.audit_anchor {
                r.audit_anchor_found = true;
            }
            if rec.action == finished
                && rec.details.get("manifest_sha256").and_then(Value::as_str) == Some(&manifest_sha)
            {
                r.audit_finish_found = true;
            }
        }
    }
    Ok(r)
}

#[cfg(test)]
mod tests;
