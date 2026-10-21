//! Cost of verifying an AAT delegation chain by depth
//! (R11): every link's signature and attenuation plus the proof of possession.

use cleimesh_aat::*;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use serde_json::json;

const NOW: i64 = 1_800_000_000;

fn key() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

/// A chain of `depth` delegations below the root, each narrowing `echo`.
fn chain(depth: u32) -> (Jwk, Presentation, serde_json::Value) {
    let anchor = key();
    let mut holder = key();
    let tools = |v| serde_json::from_value::<Tools>(v).unwrap();
    let mut tokens = vec![issue_root(&anchor, "urn:bench", &Jwk::from_key(&holder.verifying_key()), tools(json!({"echo": {"message": {"constraint_type": "wildcard"}}})), NOW, 3600, depth).unwrap()];
    for _ in 0..depth {
        let next = key();
        let child = derive(tokens.last().unwrap(), &holder, &Jwk::from_key(&next.verifying_key()), tools(json!({"echo": {"message": {"constraint_type": "one_of", "values": ["oi", "ola"]}}})), NOW, 600, None).unwrap();
        tokens.push(child);
        holder = next;
    }
    let args = json!({"message": "oi"});
    let pop = pop(&holder, tokens.last().unwrap(), "echo", &args, Some("node"), NOW).unwrap();
    (Jwk::from_key(&anchor.verifying_key()), Presentation { chain: tokens, pop }, args)
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("aat_verify");
    for depth in [0u32, 2, 7, 15] {
        let (anchor, presentation, args) = chain(depth);
        let anchors = [anchor];
        let policy = Policy { trust_anchors: &anchors, audience: Some("node"), now: NOW };
        verify(&presentation, &policy, "echo", &args).expect("bench chain verifies");
        // Chain length = delegations + the root.
        group.bench_with_input(BenchmarkId::new("chain_length", depth + 1), &presentation, |b, p| {
            b.iter(|| verify(black_box(p), &policy, "echo", &args).unwrap())
        });
    }
    group.finish();
}

criterion_group!(benches, bench_verify);
criterion_main!(benches);
