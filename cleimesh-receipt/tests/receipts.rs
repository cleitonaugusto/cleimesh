//! Receipt format and log checks (C2), starting with
//! the test vectors of draft-sahu-agent-action-receipts-00, appendix A.

use cleimesh_receipt::*;
use ed25519_dalek::SigningKey;
use serde_json::json;

/// Appendix A test key: the seed 0x01 repeated 32 times.
fn test_key() -> SigningKey {
    SigningKey::from_bytes(&[1u8; 32])
}

const VECTOR_1: &str = r#"{"step_id":"01J8Z7QX9K","action_id":"kriya.gate.decision","params":{"rule_id":"npm-publish","tier":"approve","class":"publish"},"success":true,"ts_ms":1755300000000,"actor":{"agent":"claude-code","user":"alice"},"public_key":"8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c","signature":"ab6afa750440d38f72dc5601f45b1df918de60049b2accbb438dd909222f42755a534ee67e2eb1397f9d3ca6bd0bf67f1ec078ecc60c08c92438acd2b7dc5802"}"#;
const VECTOR_1_CANONICAL: &str = r#"{"step_id":"01J8Z7QX9K","action_id":"kriya.gate.decision","params":{"class":"publish","rule_id":"npm-publish","tier":"approve"},"success":true,"ts_ms":1755300000000,"actor":{"agent":"claude-code","user":"alice"}}"#;
const VECTOR_1_HASH: &str = "18a2a79ac5e4dcc31172783a0f33efc1518d426c5cf0ccd24982d41c9aa3ee4c";

const VECTOR_2: &str = r#"{"step_id":"01J8Z7QXB2","action_id":"kriya.gate.approval","params":{"rule_id":"npm-publish","approver":"alice","decision":"approved"},"success":true,"ts_ms":1755300012000,"actor":{"agent":"claude-code","user":"alice"},"prev_hash":"18a2a79ac5e4dcc31172783a0f33efc1518d426c5cf0ccd24982d41c9aa3ee4c","public_key":"8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c","signature":"891dc88a6dc93507faca8d52eceb0baf107f325a1b3bb5c60e3e357cac86d6ccfd2a0bcf3cee3b7237040483fe1b8c4f049fa72c6a59eb97a22d2c7e97d2cc02"}"#;
const VECTOR_2_CANONICAL: &str = r#"{"step_id":"01J8Z7QXB2","action_id":"kriya.gate.approval","params":{"approver":"alice","decision":"approved","rule_id":"npm-publish"},"success":true,"ts_ms":1755300012000,"actor":{"agent":"claude-code","user":"alice"},"prev_hash":"18a2a79ac5e4dcc31172783a0f33efc1518d426c5cf0ccd24982d41c9aa3ee4c"}"#;

fn log(lines: &[&str]) -> Vec<u8> {
    lines.iter().map(|l| format!("{l}\n")).collect::<String>().into_bytes()
}

fn failures(report: &Report) -> Vec<usize> {
    report.failures.iter().map(|f| f.line).collect()
}

#[test]
fn test_key_matches_the_draft() {
    assert_eq!(
        hex(test_key().verifying_key().as_bytes()),
        "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
    );
}

#[test]
fn vectors_canonicalize_and_hash_as_published() {
    let v1 = Receipt::parse(VECTOR_1).unwrap();
    let v2 = Receipt::parse(VECTOR_2).unwrap();
    assert_eq!(String::from_utf8(v1.canonical().unwrap()).unwrap(), VECTOR_1_CANONICAL);
    assert_eq!(String::from_utf8(v2.canonical().unwrap()).unwrap(), VECTOR_2_CANONICAL);
    assert_eq!(sha256_hex(VECTOR_1.as_bytes()), VECTOR_1_HASH);
}

#[test]
fn signing_the_vectors_reproduces_their_signatures() {
    // Ed25519 is deterministic, so our signer must produce the same bytes.
    for line in [VECTOR_1, VECTOR_2] {
        let v = Receipt::parse(line).unwrap();
        let entry = Entry { step_id: v.step_id.clone(), action_id: v.action_id.clone(), params: v.params.clone(), success: v.success, ts_ms: v.ts_ms, actor: v.actor.clone() };
        let ours = sign(&test_key(), entry, v.prev_hash.clone()).unwrap();
        assert_eq!(ours.signature, v.signature);
    }
}

#[test]
fn vector_log_verifies() {
    let report = verify_log(&log(&[VECTOR_1, VECTOR_2]), &test_key().verifying_key());
    assert!(report.ok(), "{:?}", report.failures);
    assert_eq!(report.lines, 2);
}

#[test]
fn vector_3_modification_fails_at_lines_1_and_2() {
    let tampered = VECTOR_1.replace("\"user\":\"alice\"", "\"user\":\"mallory\"");
    let report = verify_log(&log(&[&tampered, VECTOR_2]), &test_key().verifying_key());
    assert_eq!(failures(&report), vec![1, 2]);
    assert!(report.failures[0].reason.contains("signature"));
    assert!(report.failures[1].reason.contains("prev_hash"));
}

#[test]
fn log_signed_by_another_key_fails() {
    let other = SigningKey::from_bytes(&[2u8; 32]).verifying_key();
    let report = verify_log(&log(&[VECTOR_1, VECTOR_2]), &other);
    assert_eq!(failures(&report), vec![1, 2]);
    assert!(report.failures[0].reason.contains("another key"));
}

fn entry(n: u64) -> Entry {
    Entry {
        step_id: format!("step-{n}"),
        action_id: "cleimesh.tool_call".into(),
        params: json!({"tool": "echo", "n": n}),
        success: true,
        ts_ms: 1_800_000_000_000 + n,
        actor: None,
    }
}

/// A log of `n` receipts written through `ReceiptLog`.
fn written(n: u64) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("receipts").join("receipts.jsonl");
    let mut log = ReceiptLog::open(&path, test_key()).unwrap();
    for i in 0..n {
        log.append(entry(i)).unwrap();
    }
    (dir, path)
}

fn lines_of(path: &std::path::Path) -> Vec<String> {
    read_lines(path).unwrap()
}

fn verify_lines(lines: &[String]) -> Report {
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    verify_log(&log(&refs), &test_key().verifying_key())
}

#[test]
fn written_log_verifies_and_survives_reopening() {
    let (_dir, path) = written(3);
    let mut reopened = ReceiptLog::open(&path, test_key()).unwrap();
    reopened.append(entry(3)).unwrap();

    let report = verify_log(&std::fs::read(&path).unwrap(), &test_key().verifying_key());
    assert!(report.ok(), "{:?}", report.failures);
    assert_eq!(report.lines, 4);
}

#[test]
fn edited_line_is_pointed_out() {
    let (_dir, path) = written(4);
    let mut lines = lines_of(&path);
    lines[1] = lines[1].replace("\"n\":1", "\"n\":9");
    assert_eq!(failures(&verify_lines(&lines)), vec![2, 3]);
}

#[test]
fn removed_interior_line_is_pointed_out() {
    let (_dir, path) = written(4);
    let mut lines = lines_of(&path);
    lines.remove(1);
    assert_eq!(failures(&verify_lines(&lines)), vec![2]);
}

#[test]
fn reordered_lines_are_pointed_out() {
    let (_dir, path) = written(4);
    let mut lines = lines_of(&path);
    lines.swap(1, 2);
    assert!(!verify_lines(&lines).ok());
}

#[test]
fn removed_first_line_is_pointed_out() {
    let (_dir, path) = written(3);
    let mut lines = lines_of(&path);
    lines.remove(0);
    assert_eq!(failures(&verify_lines(&lines)), vec![1]);
}

#[test]
fn inserted_garbage_line_is_reported_not_skipped() {
    let (_dir, path) = written(3);
    let mut lines = lines_of(&path);
    lines.insert(1, "not json".into());
    let report = verify_lines(&lines);
    assert!(failures(&report).contains(&2), "{:?}", report.failures);
}

#[test]
fn duplicate_member_is_refused() {
    let doubled = VECTOR_1.replacen("\"success\":true", "\"success\":true,\"success\":false", 1);
    assert!(Receipt::parse(&doubled).unwrap_err().0.contains("duplicate"));
}

#[test]
fn partial_last_line_is_reported_and_blocks_appending() {
    let (_dir, path) = written(2);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.truncate(bytes.len() - 10);
    std::fs::write(&path, &bytes).unwrap();

    assert!(!verify_log(&bytes, &test_key().verifying_key()).ok());
    assert!(ReceiptLog::open(&path, test_key()).is_err());
}

#[test]
fn canonical_json_sorts_nested_objects() {
    let v = json!({"b": {"y": 1, "x": [ {"d": 1, "c": 2} ]}, "a": "\u{1}é\n"});
    assert_eq!(canonical_json(&v).unwrap(), "{\"a\":\"\\u0001é\\n\",\"b\":{\"x\":[{\"c\":2,\"d\":1}],\"y\":1}}");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Accepts `ok` lines, then fails like a full disk.
struct FailingSink {
    ok: usize,
    lines: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

impl ReceiptSink for FailingSink {
    fn write_line(&mut self, line: &[u8]) -> std::io::Result<()> {
        if self.ok == 0 {
            return Err(std::io::Error::other("no space left on device"));
        }
        self.ok -= 1;
        self.lines.lock().unwrap().extend_from_slice(line);
        Ok(())
    }
    fn sync(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn failed_write_leaves_the_log_refusing_appends() {
    let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut log = ReceiptLog::with_sink(Box::new(FailingSink { ok: 1, lines: lines.clone() }), test_key(), None);
    log.append(entry(0)).unwrap();
    assert!(log.append(entry(1)).unwrap_err().0.contains("no space"));
    assert!(log.append(entry(2)).unwrap_err().0.contains("damaged"));
    assert!(verify_log(&lines.lock().unwrap(), &test_key().verifying_key()).ok());
}
