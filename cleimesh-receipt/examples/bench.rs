//! Measured numbers for the receipt layer and its RFC 6962 transparency log.
//! No network, no sandbox: pure CPU, so the figures are reproducible.
//!
//!   cargo run --release -p cleimesh-receipt --example bench

use std::time::Instant;

use cleimesh_receipt::{inclusion_proof, leaf_hash, merkle_root, sign, verify_inclusion, Entry};
use ed25519_dalek::SigningKey;
use serde_json::json;

fn entry(i: usize) -> Entry {
    Entry {
        step_id: format!("{i:016x}"),
        action_id: "tool_call".into(),
        params: json!({ "to": "demo", "amount": i % 100 }),
        success: true,
        ts_ms: 1_793_000_000_000 + i as u64,
        actor: None,
    }
}

fn main() {
    let key = SigningKey::from_bytes(&[7u8; 32]);

    // --- Signing a receipt (the per-call "governance tax" on the receipt side) ---
    let n = 50_000;
    let t = Instant::now();
    let mut last = None;
    for i in 0..n {
        let r = sign(&key, entry(i), last.clone()).unwrap();
        last = Some(r.signature.clone());
    }
    let per = t.elapsed().as_secs_f64() / n as f64;
    println!("Signing a receipt (Ed25519 over canonical bytes):");
    println!("  {:.1} µs each  ->  ~{:.0} receipts/s\n", per * 1e6, 1.0 / per);

    // --- Transparency log: verify ONE receipt in a huge log ---
    println!("RFC 6962 transparency log — prove one receipt is in a log of N:");
    println!("  {:>12}  {:>10}  {:>12}  {:>12}  {:>12}", "N receipts", "proof len", "build root", "make proof", "verify");
    for &size in &[1_000usize, 100_000, 1_000_000] {
        // Synthetic leaves (a real log would leaf-hash each receipt line).
        let leaves: Vec<[u8; 32]> = (0..size).map(|i| leaf_hash(format!("receipt-{i}").as_bytes())).collect();

        let t = Instant::now();
        let root = merkle_root(&leaves);
        let build = t.elapsed();

        let m = size / 2;
        let t = Instant::now();
        let proof = inclusion_proof(&leaves, m).unwrap();
        let mk = t.elapsed();

        let t = Instant::now();
        let ok = verify_inclusion(&leaves[m], m, size, &proof, &root);
        let vf = t.elapsed();
        assert!(ok);

        println!(
            "  {:>12}  {:>7} ({:>3} B)  {:>10.2?}  {:>12.3?}  {:>12.3?}",
            size,
            proof.len(),
            proof.len() * 32,
            build,
            mk,
            vf
        );
    }
    println!("\n  The auditor checks a receipt against the signed head with only the");
    println!("  proof — a few hundred bytes — never the other receipts, and never the agent.");
}
