//! Signed heads catch lines cut from the end of a log; pruning removes old
//! receipts and leaves a receipt of its own (C2, C3).

use cleimesh_receipt::*;
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::path::{Path, PathBuf};

fn key() -> SigningKey {
    SigningKey::from_bytes(&[4; 32])
}

fn entry(n: u64) -> Entry {
    Entry {
        step_id: format!("step-{n}"),
        action_id: "cleimesh.tool_call".into(),
        params: json!({"tool": "echo", "n": n}),
        success: true,
        ts_ms: 1_000 * n,
        actor: None,
    }
}

fn log_of(n: u64) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("r.jsonl");
    let mut log = ReceiptLog::open(&path, key()).unwrap();
    for i in 1..=n {
        log.append(entry(i)).unwrap();
    }
    (dir, path)
}

fn head(path: &Path) -> Head {
    let h = Head::read(&head_path(path)).unwrap();
    h.verify(&key().verifying_key()).unwrap();
    h
}

#[test]
fn head_follows_every_append_and_matches() {
    let (_dir, path) = log_of(3);
    let h = head(&path);
    assert_eq!(h.lines, 3);
    assert_eq!(check_head(&std::fs::read(&path).unwrap(), &h).unwrap(), HeadStatus::Matches);
}

#[test]
fn cutting_the_last_lines_is_caught_by_the_head() {
    let (_dir, path) = log_of(4);
    let text = std::fs::read_to_string(&path).unwrap();
    let cut: String = text.lines().take(2).map(|l| format!("{l}\n")).collect();
    assert!(verify_log(cut.as_bytes(), &key().verifying_key()).ok(), "the chain alone can't see the cut");
    let e = check_head(cut.as_bytes(), &head(&path)).unwrap_err();
    assert!(e.0.contains("truncated"), "{e}");
}

#[test]
fn replacing_the_covered_line_is_caught() {
    let (_dir, path) = log_of(2);
    let h = head(&path);
    let (_other_dir, other) = log_of(2);
    let mut lines: Vec<String> = std::fs::read_to_string(&path).unwrap().lines().map(String::from).collect();
    lines[1] = std::fs::read_to_string(&other).unwrap().lines().nth(1).unwrap().replace("step-2", "step-x");
    let log = lines.iter().map(|l| format!("{l}\n")).collect::<String>();
    assert!(check_head(log.as_bytes(), &h).unwrap_err().0.contains("differs"));
}

#[test]
fn a_log_ahead_of_its_head_is_behind_not_broken() {
    let (_dir, path) = log_of(2);
    let saved = head(&path);
    let mut log = ReceiptLog::open(&path, key()).unwrap();
    log.append(entry(3)).unwrap();
    assert_eq!(check_head(&std::fs::read(&path).unwrap(), &saved).unwrap(), HeadStatus::Behind(1));
}

#[test]
fn forged_or_foreign_head_is_refused() {
    let (_dir, path) = log_of(2);
    let mut h = head(&path);
    h.lines = 1;
    assert!(h.verify(&key().verifying_key()).is_err());
    let other = Head::sign(&SigningKey::from_bytes(&[5; 32]), 2, "x", 0);
    assert!(other.verify(&key().verifying_key()).unwrap_err().0.contains("another key"));
}

#[test]
fn prune_removes_old_receipts_and_opens_the_new_log_with_its_own_receipt() {
    let (_dir, path) = log_of(5);
    let before = std::fs::read_to_string(&path).unwrap();
    let old_last = sha256_hex(before.lines().last().unwrap().as_bytes());

    let dry = prune(&path, &key(), &key().verifying_key(), 3_500, 9_000, true).unwrap();
    assert_eq!((dry.removed, dry.kept, dry.receipt.is_none()), (3, 2, true));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), before, "a dry run changed the log");

    let done = prune(&path, &key(), &key().verifying_key(), 3_500, 9_000, false).unwrap();
    assert_eq!((done.removed, done.kept), (3, 2));
    let after = std::fs::read(&path).unwrap();
    let report = verify_log(&after, &key().verifying_key());
    assert!(report.ok(), "{:?}", report.failures);
    assert_eq!(report.lines, 3);
    assert_eq!(check_head(&after, &head(&path)).unwrap(), HeadStatus::Matches);

    let text = String::from_utf8(after).unwrap();
    let receipts: Vec<Receipt> = text.lines().map(|l| Receipt::parse(l).unwrap()).collect();
    assert_eq!(receipts[0].action_id, PRUNE_ACTION_ID);
    assert_eq!(receipts[0].params["removed_lines"], 3);
    assert_eq!(receipts[0].params["previous_last_sha256"], old_last.as_str());
    // Kept receipts keep their content.
    assert_eq!((receipts[1].step_id.as_str(), receipts[1].params["n"].as_u64()), ("step-4", Some(4)));
    assert_eq!(receipts[2].step_id, "step-5");

    // Appending after a prune continues the new chain.
    let mut log = ReceiptLog::open(&path, key()).unwrap();
    log.append(entry(6)).unwrap();
    assert!(verify_log(&std::fs::read(&path).unwrap(), &key().verifying_key()).ok());
}

#[test]
fn prune_refuses_an_altered_log() {
    let (_dir, path) = log_of(3);
    let text = std::fs::read_to_string(&path).unwrap().replacen("\"n\":1", "\"n\":7", 1);
    std::fs::write(&path, &text).unwrap();
    let e = prune(&path, &key(), &key().verifying_key(), 10_000, 20_000, false).unwrap_err();
    assert!(e.0.contains("fails verification"), "{e}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
}

#[test]
fn a_second_writer_on_the_same_log_is_refused() {
    let (_dir, path) = log_of(1);
    let first = ReceiptLog::open(&path, key()).unwrap();
    let e = ReceiptLog::open(&path, key()).err().expect("two writers on one log");
    assert!(e.0.contains("in use by another process"), "{e}");
    drop(first);
    ReceiptLog::open(&path, key()).unwrap();
}
