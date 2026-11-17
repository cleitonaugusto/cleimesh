//! Verifiable provenance that survives the agent. A multi-step pipeline writes
//! signed, hash-chained receipts; this example adds the RFC 6962 transparency
//! layer and plays the part a regulator or a downstream agent actually cares
//! about: an auditor who holds only the signed tree head and one receipt — not
//! the whole log, and no trust in the agent — proves that receipt is in the log,
//! and later proves the log only grew. No real actions; the receipts are a demo.
//!
//!   cargo run -p cleimesh-receipt --example transparency

use std::sync::{Arc, Mutex};

use cleimesh_receipt::{
    consistency_proof, inclusion_proof, leaf_hash, leaves_from_log, verify_consistency,
    verify_inclusion, Entry, ReceiptLog, ReceiptSink, SignedTreeHead,
};
use ed25519_dalek::SigningKey;
use serde_json::json;

/// An in-memory log sink, so the example needs no files.
struct VecSink(Arc<Mutex<Vec<u8>>>);
impl ReceiptSink for VecSink {
    fn write_line(&mut self, line: &[u8]) -> std::io::Result<()> {
        self.0.lock().unwrap().extend_from_slice(line);
        Ok(())
    }
    fn sync(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn step(name: &str, action: &str, params: serde_json::Value) -> Entry {
    Entry { step_id: name.into(), action_id: action.into(), params, success: true, ts_ms: 1_793_000_000_000, actor: None }
}

/// The non-empty lines of a log, as the auditor would see one of them.
fn lines(log: &[u8]) -> Vec<Vec<u8>> {
    log.split(|&b| b == b'\n').filter(|l| !l.is_empty()).map(|l| l.to_vec()).collect()
}

fn main() {
    let node = SigningKey::from_bytes(&[42u8; 32]);
    let anchor = node.verifying_key(); // what the auditor trusts, and nothing else

    // --- A multi-step agent pipeline writes a real, chained receipt log. ---
    let buf = Arc::new(Mutex::new(Vec::new()));
    let mut log = ReceiptLog::with_sink(Box::new(VecSink(buf.clone())), node.clone(), None);
    log.append(step("1", "read_repo", json!({ "repo": "acme/app" }))).unwrap();
    log.append(step("2", "apply_patch", json!({ "sha": "a1b2c3" }))).unwrap();
    log.append(step("3", "run_tests", json!({ "passed": 118 }))).unwrap();

    let log_v1 = buf.lock().unwrap().clone();
    let leaves_v1 = leaves_from_log(&log_v1);
    let sth_v1 = SignedTreeHead::sign(&node, &leaves_v1);
    println!("The agent ran 3 steps and signed a tree head over the log:");
    println!("  tree_size = {}, root = {}…\n", sth_v1.tree_size, &sth_v1.root[..16]);

    // --- The auditor holds ONLY the head + one receipt. Not the log. ---
    let receipt = &lines(&log_v1)[1]; // step 2, apply_patch
    let proof = inclusion_proof(&leaves_v1, 1).unwrap();
    println!("An auditor is handed the signed head and ONE receipt (step 2), nothing else.");
    assert!(sth_v1.verify(&anchor).is_ok(), "the head is signed by the node it claims");
    let ok = verify_inclusion(&leaf_hash(receipt), 1, sth_v1.tree_size, &proof, &sth_v1.root_hash().unwrap());
    println!("  verify head signature  -> ok");
    println!("  prove receipt in log   -> {}", if ok { "ok. it is in the log, without the auditor ever seeing the other receipts." } else { "FAIL" });

    // A forged receipt at the same slot is caught.
    let forged = b"{\"step_id\":\"2\",\"action_id\":\"apply_patch\",\"params\":{\"sha\":\"evil\"}}".to_vec();
    let caught = !verify_inclusion(&leaf_hash(&forged), 1, sth_v1.tree_size, &proof, &sth_v1.root_hash().unwrap());
    println!("  a forged step 2        -> {}\n", if caught { "refused. the proof only matches the receipt the node actually signed." } else { "ACCEPTED?!" });

    // --- Later the log grows. The auditor proves it only appended. ---
    log.append(step("4", "publish_evidence", json!({ "url": "acme/app/run/42" }))).unwrap();
    log.append(step("5", "notify", json!({ "to": "team" }))).unwrap();
    let log_v2 = buf.lock().unwrap().clone();
    let leaves_v2 = leaves_from_log(&log_v2);
    let sth_v2 = SignedTreeHead::sign(&node, &leaves_v2);

    let cproof = consistency_proof(&leaves_v2, sth_v1.tree_size).unwrap();
    let grew = verify_consistency(sth_v1.tree_size, sth_v2.tree_size, &cproof, &sth_v1.root_hash().unwrap(), &sth_v2.root_hash().unwrap());
    println!("The log grew from {} to {} receipts; the auditor checks the two heads:", sth_v1.tree_size, sth_v2.tree_size);
    println!("  prove append-only      -> {}", if grew { "ok. nothing was changed or removed, only added." } else { "FAIL" });

    // A rewritten history yields a different old root, so consistency fails.
    let mut rewritten = leaves_v2.clone();
    rewritten[1] = leaf_hash(&forged);
    let forged_old = cleimesh_receipt::merkle_root(&rewritten[..sth_v1.tree_size]);
    let rejected = !verify_consistency(sth_v1.tree_size, sth_v2.tree_size, &cproof, &forged_old, &sth_v2.root_hash().unwrap());
    println!("  a rewritten old history-> {}\n", if rejected { "refused. the earlier head no longer matches." } else { "ACCEPTED?!" });

    println!("The proof travels with the receipt, not the agent. The log can be verified");
    println!("after the agent is gone, and by a party that never saw the rest of it.");
}
