use super::*;
use serde_json::json;

/// A fresh scratch directory with a collection directory and an audit log.
fn scratch(tag: &str) -> (PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!("dfcore_manifest_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    (root.join("collection"), root.join("audit.jsonl"))
}

fn header() -> Header {
    Header {
        action: "logical_collection".into(),
        case: Case {
            case_number: "CASE-2026-001".into(),
            evidence_number: "EV-03".into(),
            examiner: "examiner".into(),
            ..Case::default()
        },
        source: Source {
            kind: "filesystem".into(),
            locator: "/media/evidence/sdb1".into(),
            ..Source::default()
        },
        method: Method {
            tool: "dfcollect".into(),
            tool_version: "0.1.0".into(),
            argv: vec!["dfcollect".into(), "files".into()],
            read_only_primitives: vec!["read-only mount".into()],
            ..Method::default()
        },
        scope: Scope::default(),
        clocks: Clocks::default(),
    }
}

/// Store `data` under `data/<name>` and return the acquired item for it.
fn acquired(dir: &Path, name: &str, data: &[u8]) -> Item {
    let stored = format!("data/{name}");
    let path = dir.join(&stored);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, data).unwrap();
    let mut item = Item::new(ItemStatus::Acquired, format!("/{name}"));
    item.stored_as = Some(stored);
    item.size = Some(data.len() as u64);
    item.hashes.sha256 = Some(sha256_hex(data));
    item.times.modified = Some(host::rfc3339_utc_ns(1_700_000_000_123_456_789));
    item
}

fn audit_records(log: &Path) -> Vec<audit::Record> {
    std::fs::read_to_string(log)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn glob_patterns() {
    let cases = [
        ("*.txt", "a.txt", true),
        ("*.txt", "dir/a.txt", false),
        ("**/*.txt", "a.txt", true),
        ("**/*.txt", "dir/sub/a.txt", true),
        ("INBOX/**", "INBOX/Sent/1", true),
        ("INBOX/**", "INBOXES/1", false),
        ("a/**/b", "a/b", true),
        ("a/**/b", "a/x/y/b", true),
        ("a/**/b", "a/xb", false),
        ("a/**/b", "a/x/yb", false),
        ("**/b", "xb", false),
        ("**/b", "x/b", true),
        ("a/**", "a/", true),
        ("a/**", "a", false),
        ("**.txt", "x/y.txt", true),
        ("a?c", "abc", true),
        ("a?c", "a/c", false),
        ("/home/*/Mail/**", "/home/anna/Mail/inbox/cur/1", true),
        ("/home/*/Mail/**", "/home/anna/x/Mail/inbox", false),
        ("exact", "exact", true),
        ("exact", "Exact", false),
        ("Pr\u{fc}f*", "Pr\u{fc}fbericht.pdf", true),
        ("**", "", true),
        ("*", "", true),
        ("?", "", false),
    ];
    for (pattern, path, want) in cases {
        assert_eq!(glob_match(pattern, path), want, "{pattern} vs {path}");
    }
}

#[test]
fn scope_decides_by_account_path_and_time() {
    let scope = Scope {
        legal_basis: Some("AG Musterstadt 12 Gs 34/26".into()),
        accounts: vec!["anna@example.org".into()],
        include: vec!["INBOX/**".into(), "Sent/**".into()],
        exclude: vec!["INBOX/Spam/**".into()],
        not_before: Some("2026-01-01T00:00:00Z".into()),
        not_after: Some("2026-07-01T00:00:00+02:00".into()),
        time_basis: Some("INTERNALDATE".into()),
        ..Scope::default()
    };
    let rules = scope.rules().unwrap();
    let t = |s: &str| Some(host::parse_rfc3339(s).unwrap());
    let decide = |path, account, time_ns| {
        rules.decide(&Candidate {
            path,
            account,
            time_ns,
        })
    };
    let anna = Some("anna@example.org");
    assert_eq!(
        decide("INBOX/1", anna, t("2026-03-01T10:00:00Z")),
        Decision::InScope
    );
    // Window start is inclusive, the end exclusive (2026-06-30T22:00:00Z)
    assert_eq!(
        decide("INBOX/1", anna, t("2026-01-01T00:00:00Z")),
        Decision::InScope
    );
    assert_eq!(
        decide("INBOX/1", anna, t("2026-06-30T21:59:59.999999999Z")),
        Decision::InScope
    );
    assert_eq!(
        decide("INBOX/1", anna, t("2026-06-30T22:00:00Z")),
        Decision::OutOfScope("INTERNALDATE after the time window".into())
    );
    assert_eq!(
        decide("INBOX/1", anna, t("2025-12-31T23:59:59Z")),
        Decision::OutOfScope("INTERNALDATE before the time window".into())
    );
    assert_eq!(
        decide(
            "INBOX/1",
            Some("bob@example.org"),
            t("2026-03-01T10:00:00Z")
        ),
        Decision::OutOfScope("account bob@example.org is not in scope".into())
    );
    assert_eq!(
        decide("INBOX/Spam/7", anna, t("2026-03-01T10:00:00Z")),
        Decision::OutOfScope("excluded by INBOX/Spam/**".into())
    );
    assert_eq!(
        decide("Drafts/2", anna, t("2026-03-01T10:00:00Z")),
        Decision::OutOfScope("matches no include pattern".into())
    );
    assert_eq!(
        decide("INBOX/1", anna, None),
        Decision::OutOfScope("INTERNALDATE unknown".into())
    );
    let lenient = Scope {
        unknown_time: UnknownTime::Include,
        ..scope.clone()
    };
    assert_eq!(
        lenient.rules().unwrap().decide(&Candidate {
            path: "INBOX/1",
            account: anna,
            time_ns: None
        }),
        Decision::InScope
    );
}

#[test]
fn empty_scope_takes_everything() {
    let rules = Scope::default().rules().unwrap();
    assert!(!rules.has_window());
    let c = Candidate {
        path: "/any/path",
        account: Some("x"),
        time_ns: None,
    };
    assert_eq!(rules.decide(&c), Decision::InScope);
}

#[test]
fn invalid_scopes_are_refused() {
    let window = |nb: &str, na: &str, basis: Option<&str>| Scope {
        not_before: Some(nb.into()),
        not_after: Some(na.into()),
        time_basis: basis.map(String::from),
        ..Scope::default()
    };
    for (scope, needle) in [
        (
            window("2026-01-01", "2026-02-01T00:00:00Z", Some("mtime")),
            "not_before",
        ),
        (
            window(
                "2026-02-01T00:00:00Z",
                "2026-01-01T00:00:00Z",
                Some("mtime"),
            ),
            "earlier",
        ),
        (
            window("2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z", None),
            "time_basis",
        ),
        (
            Scope {
                include: vec![String::new()],
                ..Scope::default()
            },
            "empty path pattern",
        ),
    ] {
        let err = format!("{:#}", scope.rules().unwrap_err());
        assert!(err.contains(needle), "{err}");
    }
    // A misspelt field in a scope file is an error, not a silently wider scope
    let typo = r#"{"includes": ["INBOX/**"]}"#;
    assert!(serde_json::from_str::<Scope>(typo).is_err());
}

#[test]
fn collection_records_items_and_verifies() {
    let (dir, log) = scratch("roundtrip");
    let mut h = header();
    h.clocks.reference = Some(
        ReferenceTime::new(
            "2026-10-16T12:00:05Z",
            "radio clock",
            1_792_152_000 * 1_000_000_000,
        )
        .unwrap(),
    );
    let mut c = Collection::create_with_log(&dir, h, &log).unwrap();
    assert_eq!(c.manifest().status, Status::Incomplete);
    let on_disk: Manifest =
        serde_json::from_slice(&std::fs::read(dir.join(MANIFEST)).unwrap()).unwrap();
    assert_eq!(on_disk.status, Status::Incomplete);
    assert!(on_disk.audit_anchor.is_some());
    assert_eq!(
        c.manifest()
            .header
            .clocks
            .reference
            .as_ref()
            .unwrap()
            .offset_seconds,
        5.0
    );

    c.footprint(FootprintEntry::new(
        "connect",
        json!({"remote": "198.51.100.7:993"}),
    ))
    .unwrap();
    c.set_source_clock(
        SourceClock::new(
            "2026-10-16T12:00:00Z",
            "IMAP Date",
            1_792_152_003 * 1_000_000_000,
        )
        .unwrap(),
    );
    assert_eq!(c.add(acquired(&dir, "a.txt", b"alpha")).unwrap(), 1);
    // A name a spreadsheet would run as a formula, with a comma and a quote
    let mut tricky = acquired(&dir, "b.txt", b"beta");
    tricky.path = "=HYPERLINK(\"x\"),1".into();
    assert_eq!(c.add(tricky).unwrap(), 2);
    assert_eq!(
        c.add(Item::out_of_scope("/c.txt", "matches no include pattern"))
            .unwrap(),
        3
    );
    let finished = c.finish(Completion::Done { errors: vec![] }).unwrap();
    assert!(finished.warnings.is_empty(), "{:?}", finished.warnings);
    assert!(finished.audit_export.is_some());
    let manifest = finished.manifest;

    assert_eq!(manifest.status, Status::Complete);
    assert_eq!(manifest.totals.acquired, 2);
    assert_eq!(manifest.totals.out_of_scope, 1);
    assert_eq!(manifest.totals.bytes, 9);
    assert_eq!(manifest.totals.footprint_entries, 1);
    assert_eq!(
        manifest
            .header
            .clocks
            .source
            .as_ref()
            .unwrap()
            .offset_seconds,
        -3.0
    );
    assert!(manifest.header.clocks.finished.is_some());

    // The finish record names the manifest as written
    let records = audit_records(&log);
    let actions: Vec<&str> = records.iter().map(|r| r.action.as_str()).collect();
    assert_eq!(
        actions,
        ["logical_collection_started", "logical_collection_finished"]
    );
    assert_eq!(records[0].hash, manifest.audit_anchor);
    assert_eq!(records[0].tool, "dfcollect");
    assert_eq!(records[1].outcome, audit::Outcome::Ok);
    assert_eq!(
        records[1].details["manifest_sha256"],
        sha256_file(&dir.join(MANIFEST)).unwrap()
    );

    let csv = std::fs::read_to_string(dir.join(CSV)).unwrap();
    assert!(csv.starts_with("\u{feff}seq,status,account,path,"), "{csv}");
    assert!(
        csv.contains("\r\n2,acquired,,\"'=HYPERLINK(\"\"x\"\"),1\",data/b.txt,4,"),
        "{csv}"
    );
    assert!(csv.contains("3,out_of_scope,,/c.txt,"), "{csv}");

    let report = verify(&dir).unwrap();
    assert!(report.ok(), "{report:?}");
    assert_eq!(report.items_ok, 2);
    assert_eq!(report.items_unchecked, 0);
    assert_eq!(report.status, Some(Status::Complete));
}

#[test]
fn verify_detects_changed_and_missing_data_and_records() {
    let (dir, log) = scratch("tamper");
    let mut c = Collection::create_with_log(&dir, header(), &log).unwrap();
    c.add(acquired(&dir, "a.txt", b"alpha")).unwrap();
    c.add(acquired(&dir, "b.txt", b"beta")).unwrap();
    c.finish(Completion::Done { errors: vec![] }).unwrap();
    assert!(verify(&dir).unwrap().ok());

    std::fs::write(dir.join("data/a.txt"), b"alphA").unwrap();
    std::fs::remove_file(dir.join("data/b.txt")).unwrap();
    let r = verify(&dir).unwrap();
    assert_eq!(r.items_mismatch, ["data/a.txt"]);
    assert_eq!(r.items_missing, ["data/b.txt"]);
    assert!(!r.ok());

    // Editing a record breaks its hash in the manifest
    let items = std::fs::read_to_string(dir.join(ITEMS)).unwrap();
    let edited = items.replacen("\"seq\":1", "\"seq\":7", 1);
    std::fs::write(dir.join(ITEMS), edited).unwrap();
    let r = verify(&dir).unwrap();
    assert!(
        r.problems
            .iter()
            .any(|p| p.starts_with("items.jsonl: SHA-256")),
        "{r:?}"
    );

    // A rewritten manifest no longer matches the finish record in the audit log
    let m = std::fs::read_to_string(dir.join(MANIFEST)).unwrap();
    std::fs::write(dir.join(MANIFEST), m.replace("EV-03", "EV-04")).unwrap();
    let r = verify(&dir).unwrap();
    assert!(r.audit_anchor_found);
    assert!(!r.audit_finish_found);
}

#[test]
fn errors_and_aborts_set_the_status() {
    let (dir, log) = scratch("errors");
    let mut c = Collection::create_with_log(&dir, header(), &log).unwrap();
    let mut failed = Item::new(ItemStatus::Error, "/unreadable");
    failed.reason = Some("Input/output error (os error 5)".into());
    c.add(failed).unwrap();
    let m = c
        .finish(Completion::Done { errors: vec![] })
        .unwrap()
        .manifest;
    assert_eq!(m.status, Status::CompleteWithErrors);
    assert_eq!(m.totals.errors, 1);

    let (dir, log) = scratch("aborted");
    let c = Collection::create_with_log(&dir, header(), &log).unwrap();
    let m = c
        .finish(Completion::Aborted {
            reason: "connection lost".into(),
        })
        .unwrap()
        .manifest;
    assert_eq!(m.status, Status::Aborted);
    assert_eq!(m.errors, ["connection lost"]);
    let records = audit_records(&log);
    assert_eq!(records.last().unwrap().outcome, audit::Outcome::Error);
}

#[test]
fn create_and_add_refuse_what_would_corrupt_the_record() {
    let (dir, log) = scratch("refuse");
    let mut c = Collection::create_with_log(&dir, header(), &log).unwrap();
    let err = Collection::create_with_log(&dir, header(), &log)
        .err()
        .unwrap();
    assert!(
        format!("{err:#}").contains("already holds a collection"),
        "{err:#}"
    );

    let mut no_hash = Item::new(ItemStatus::Acquired, "/x");
    no_hash.size = Some(1);
    assert!(c.add(no_hash.clone()).is_err());
    no_hash.hashes.sha256 = Some("ABC".into());
    assert!(c.add(no_hash).is_err());
    for escape in ["../outside", "/etc/passwd", "data/../../x", ""] {
        let mut item = acquired(&dir, "ok.txt", b"ok");
        item.stored_as = Some(escape.into());
        assert!(c.add(item).is_err(), "{escape:?} was accepted");
    }
    // Nothing refused reached the record
    assert_eq!(c.manifest().totals.acquired, 0);
    // A directory or symlink is acquired as metadata, without content hash
    let mut d = Item::new(ItemStatus::Acquired, "/etc");
    d.kind = Some("directory".into());
    d.metadata = json!({"mode": "0755"});
    c.add(d).unwrap();
    let mut file = Item::new(ItemStatus::Acquired, "/etc/hosts");
    file.kind = Some("file".into());
    assert!(c.add(file).is_err());

    let (dir2, log2) = scratch("badscope");
    let mut h = header();
    h.scope.not_before = Some("yesterday".into());
    h.scope.time_basis = Some("mtime".into());
    assert!(Collection::create_with_log(&dir2, h, &log2).is_err());
    assert!(!dir2.join(MANIFEST).exists());
}

#[test]
fn resume_continues_after_a_crash() {
    let (dir, log) = scratch("resume");
    let mut c = Collection::create_with_log(&dir, header(), &log).unwrap();
    c.add(acquired(&dir, "a.txt", b"alpha")).unwrap();
    c.add(Item::out_of_scope("/skip", "excluded by /skip"))
        .unwrap();
    // The process dies in the middle of the next append
    drop(c);
    let mut f = OpenOptions::new()
        .append(true)
        .open(dir.join(ITEMS))
        .unwrap();
    f.write_all(b"{\"seq\":3,\"status\":\"acq").unwrap();
    drop(f);

    let mut done = Vec::new();
    for_each_item(&dir, |i| {
        done.push(i.path);
        Ok(())
    })
    .unwrap();
    assert_eq!(done, ["/a.txt", "/skip"]);

    let mut c = Collection::resume_with_log(&dir, &log).unwrap();
    assert_eq!(c.manifest().totals.acquired, 1);
    assert_eq!(c.manifest().totals.out_of_scope, 1);
    assert!(c
        .manifest()
        .warnings
        .iter()
        .any(|w| w.contains("torn last line of items.jsonl")));
    assert_eq!(c.manifest().audit_resumed.len(), 1);
    assert_eq!(c.add(acquired(&dir, "b.txt", b"beta")).unwrap(), 3);
    let m = c
        .finish(Completion::Done { errors: vec![] })
        .unwrap()
        .manifest;
    assert_eq!(m.status, Status::Complete);
    assert_eq!(m.totals.acquired, 2);

    let actions: Vec<String> = audit_records(&log).into_iter().map(|r| r.action).collect();
    assert_eq!(
        actions,
        [
            "logical_collection_started",
            "logical_collection_resumed",
            "logical_collection_finished"
        ]
    );
    assert!(verify(&dir).unwrap().ok());

    // A finished collection cannot be reopened
    let err = Collection::resume_with_log(&dir, &log).err().unwrap();
    assert!(
        format!("{err:#}").contains("only an incomplete collection"),
        "{err:#}"
    );
}

#[test]
fn csv_cells_are_quoted_and_guarded() {
    assert_eq!(csv_cell("plain"), "plain");
    assert_eq!(csv_cell("a,b"), "\"a,b\"");
    assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
    assert_eq!(csv_cell("line\nbreak"), "\"line\nbreak\"");
    assert_eq!(csv_cell("=1+1"), "'=1+1");
    assert_eq!(csv_cell("-rf"), "'-rf");
    assert_eq!(csv_cell("@SUM(A1)"), "'@SUM(A1)");
    assert_eq!(csv_cell(" lead"), "\" lead\"");
    assert_eq!(csv_cell(""), "");
}

#[test]
fn an_open_collection_is_locked() {
    let (dir, log) = scratch("lock");
    let c = Collection::create_with_log(&dir, header(), &log).unwrap();
    let err = Collection::resume_with_log(&dir, &log).err().unwrap();
    assert!(
        format!("{err:#}").contains("open in another process"),
        "{err:#}"
    );
    drop(c);
    // Released with the collection; an incomplete one resumes
    Collection::resume_with_log(&dir, &log).unwrap();
}

#[test]
fn a_corrupt_record_is_an_error_not_a_torn_line() {
    let (dir, log) = scratch("corrupt");
    let mut c = Collection::create_with_log(&dir, header(), &log).unwrap();
    c.add(acquired(&dir, "a.txt", b"alpha")).unwrap();
    drop(c);
    // A complete line (it has its newline) that is not a record: tampering or
    // damage, never a crash during an append
    let mut f = OpenOptions::new()
        .append(true)
        .open(dir.join(ITEMS))
        .unwrap();
    f.write_all(b"{\"seq\":2,\"status\":\"acquired\"\n")
        .unwrap();
    drop(f);
    let before = std::fs::read(dir.join(ITEMS)).unwrap();
    let err = Collection::resume_with_log(&dir, &log).err().unwrap();
    assert!(
        format!("{err:#}").contains("line 2 is not a valid record"),
        "{err:#}"
    );
    assert_eq!(std::fs::read(dir.join(ITEMS)).unwrap(), before);
    assert!(for_each_item(&dir, |_| Ok(())).is_err());
}

#[test]
fn container_members_are_left_to_the_tool() {
    let (dir, log) = scratch("member");
    let mut c = Collection::create_with_log(&dir, header(), &log).unwrap();
    std::fs::write(dir.join("data.zip"), b"PK...").unwrap();
    let mut item = Item::new(ItemStatus::Acquired, "/a.txt");
    item.stored_as = Some("data.zip".into());
    item.member = Some("a.txt".into());
    item.size = Some(5);
    item.hashes.sha256 = Some(sha256_hex(b"alpha"));
    c.add(item).unwrap();
    c.finish(Completion::Done { errors: vec![] }).unwrap();
    let r = verify(&dir).unwrap();
    assert!(r.ok(), "{r:?}");
    assert_eq!((r.items_ok, r.items_unchecked), (0, 1));
}

#[test]
fn out_of_scope_items_can_be_counted_without_names() {
    let (dir, log) = scratch("unlisted");
    let mut c = Collection::create_with_log(&dir, header(), &log).unwrap();
    c.count_out_of_scope("matches no include pattern");
    c.count_out_of_scope("matches no include pattern");
    c.count_out_of_scope("mtime before the time window");
    c.add(acquired(&dir, "a.txt", b"alpha")).unwrap();
    let m = c
        .finish(Completion::Done { errors: vec![] })
        .unwrap()
        .manifest;
    assert_eq!(m.totals.out_of_scope, 0);
    assert_eq!(
        m.totals.unlisted_out_of_scope["matches no include pattern"],
        2
    );
    assert_eq!(
        m.totals.unlisted_out_of_scope["mtime before the time window"],
        1
    );
    let items = std::fs::read_to_string(dir.join(ITEMS)).unwrap();
    assert_eq!(items.lines().count(), 1);
    assert!(verify(&dir).unwrap().ok());
}
