//! Cost of a receipt (R11): signing, appending with and
//! without fsync, and verifying a log.

use cleimesh_receipt::*;
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use ed25519_dalek::SigningKey;
use serde_json::json;

fn entry(n: u64) -> Entry {
    Entry {
        step_id: format!("step-{n}"),
        action_id: "cleimesh.tool_call".into(),
        params: json!({"profile": "cleimesh.tool_call/2", "tool": "echo", "decision": "allowed",
                       "input_sha256": sha256_hex(b"in"), "authority": {"kind": "aat", "depth": 2}}),
        success: true,
        ts_ms: 1_800_000_000_000 + n,
        actor: None,
    }
}

struct Discard;

impl ReceiptSink for Discard {
    fn write_line(&mut self, line: &[u8]) -> std::io::Result<()> {
        black_box(line);
        Ok(())
    }
    fn sync(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn bench_receipts(c: &mut Criterion) {
    let key = SigningKey::from_bytes(&[7; 32]);
    let mut group = c.benchmark_group("receipt");

    let mut memory = ReceiptLog::with_sink(Box::new(Discard), key.clone(), None);
    let mut n = 0;
    group.bench_function("sign_and_chain", |b| {
        b.iter(|| {
            n += 1;
            memory.append(entry(n)).unwrap()
        })
    });

    let dir = tempfile::tempdir().unwrap();
    let mut file = ReceiptLog::open(&dir.path().join("receipts.jsonl"), key.clone()).unwrap();
    group.bench_function("append_with_fsync", |b| {
        b.iter(|| {
            n += 1;
            file.append(entry(n)).unwrap()
        })
    });

    let log_path = dir.path().join("verify.jsonl");
    let mut log = ReceiptLog::open(&log_path, key.clone()).unwrap();
    for i in 0..1000 {
        log.append(entry(i)).unwrap();
    }
    let bytes = std::fs::read(&log_path).unwrap();
    let anchor = key.verifying_key();
    group.throughput(Throughput::Elements(1000));
    group.bench_function("verify_log_1000_lines", |b| b.iter(|| assert!(verify_log(black_box(&bytes), &anchor).ok())));
    group.finish();
}

criterion_group!(benches, bench_receipts);
criterion_main!(benches);
