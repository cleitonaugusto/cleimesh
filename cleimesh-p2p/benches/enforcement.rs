//! What enforcement costs per call (R11): an `echo`
//! through `run_local` (AAT chain of two, sandbox grants, decision and result
//! receipts with fsync) against the same `echo` straight in the sandbox.

use cleimesh_core::{AgentIdentity, ToolPayload};
use cleimesh_p2p::aat::{self, Jwk, Presentation, SigningKey};
use cleimesh_p2p::{CleiMeshNode, P2PConfig, ToolRequest};
use cleimesh_wasm_sandbox::{SandboxConfig, WasmSandbox};
use criterion::{criterion_group, criterion_main, Criterion};
use serde_json::json;

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

fn bench_enforcement(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let args = json!({"message": "oi"});
    let mut group = c.benchmark_group("echo_call");
    group.sample_size(30);

    let sandbox = WasmSandbox::new(SandboxConfig::default()).unwrap();
    sandbox.register_wasm_module("echo", include_bytes!("../../wasm-tools/builtins.wasm").to_vec()).unwrap();
    group.bench_function("sandbox_only", |b| {
        b.iter(|| {
            let payload = ToolPayload { tool_name: "echo".into(), arguments: args.clone(), timeout_ms: Some(5000) };
            let out = rt.block_on(sandbox.execute_in_sandbox("echo", payload)).unwrap();
            assert!(out.success);
        })
    });

    let dir = tempfile::tempdir().unwrap();
    let config = P2PConfig { listen_addresses: Vec::new(), enable_mdns: false, receipts_path: Some(dir.path().join("r.jsonl")), ..P2PConfig::default() };
    let mut node = CleiMeshNode::new(config, AgentIdentity::new("bench")).unwrap();
    let (agent, subagent) = (SigningKey::generate(&mut rand::rngs::OsRng), SigningKey::generate(&mut rand::rngs::OsRng));
    let tools = serde_json::from_value(json!({"echo": {}})).unwrap();
    let root = node.issue_aat_root(&Jwk::from_key(&agent.verifying_key()), tools, 3600, 1).unwrap();
    let child = aat::derive(&root, &agent, &Jwk::from_key(&subagent.verifying_key()), serde_json::from_value(json!({"echo": {}})).unwrap(), now(), 3600, None).unwrap();
    let audience = node.aat_audience();
    group.bench_function("run_local_aat_receipts", |b| {
        b.iter(|| {
            let pop = aat::pop(&subagent, &child, "echo", &args, Some(&audience), now()).unwrap();
            let request = ToolRequest {
                tool_name: "echo".into(),
                payload: args.clone(),
                request_id: "bench".into(),
                capability: None,
                presentation: Some(Presentation { chain: vec![root.clone(), child.clone()], pop }),
                context: None,
            };
            let out = rt.block_on(node.run_local("bench", request));
            assert!(out.success, "{:?}", out.error);
        })
    });
    group.finish();
}

criterion_group!(benches, bench_enforcement);
criterion_main!(benches);
