//! Writes seed inputs into fuzz/corpus/<target>/: valid presentations and
//! logs signed with the fixtures' key, so fuzzing starts from inputs that
//! pass every check and mutates from there.

use cleimesh_aat::{derive, issue_root, pop, Jwk, Presentation, SigningKey, Tools};
use cleimesh_fuzz::*;
use cleimesh_receipt::{Entry, ReceiptLog};
use std::path::Path;

fn tools(v: serde_json::Value) -> Tools {
    serde_json::from_value(v).unwrap()
}

fn write(target: &str, name: &str, bytes: &[u8]) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus").join(target);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(name), bytes).unwrap();
}

fn main() {
    let (tool, args) = call();
    let b = SigningKey::from_bytes(&[2; 32]);
    let c = SigningKey::from_bytes(&[3; 32]);
    let root = issue_root(&anchor_key(), "urn:fuzz", &Jwk::from_key(&b.verifying_key()), tools(serde_json::json!({"echo": {"message": {"constraint_type": "wildcard"}}})), NOW, 3600, 3).unwrap();
    let root_pop = pop(&b, &root, tool, &args, Some(AUDIENCE), NOW).unwrap();
    let child = derive(&root, &b, &Jwk::from_key(&c.verifying_key()), tools(serde_json::json!({"echo": {"message": {"constraint_type": "any", "constraints": [{"constraint_type": "exact", "value": "oi"}, {"constraint_type": "range", "max": 3}]}}})), NOW, 600, None).unwrap();
    let child_pop = pop(&c, &child, tool, &args, Some(AUDIENCE), NOW).unwrap();

    let one = Presentation { chain: vec![root.clone()], pop: root_pop };
    let two = Presentation { chain: vec![root.clone(), child.clone()], pop: child_pop.clone() };
    write("aat_verify", "root.json", &serde_json::to_vec(&one).unwrap());
    write("aat_verify", "delegated.json", &serde_json::to_vec(&two).unwrap());
    write("aat_verify", "delegated.lines", format!("{}\n{}\n{}", root, child, child_pop).as_bytes());

    let dir = std::env::temp_dir().join(format!("cleimesh-fuzz-seeds-{}", std::process::id()));
    let path = dir.join("log.jsonl");
    let mut log = ReceiptLog::open(&path, anchor_key()).unwrap();
    for n in 0..3u64 {
        log.append(Entry {
            step_id: format!("s{n}"),
            action_id: "cleimesh.tool_call".into(),
            params: serde_json::json!({"tool": "echo", "n": n, "nested": {"b": [1, "x"], "a": null}, "esc": "\u{1}\"é"}),
            success: n % 2 == 0,
            ts_ms: 1_800_000_000_000 + n,
            actor: None,
        })
        .unwrap();
    }
    write("receipt_log", "three.jsonl", &std::fs::read(&path).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
    println!("seeds written to fuzz/corpus/");
}
