//! Replayable receipts (C4): an auditor re-runs a call
//! from its receipts and checks the outcome, instead of trusting the node.

use cleimesh_core::AgentIdentity;
use cleimesh_p2p::aat::{self, Jwk, Presentation, SigningKey};
use cleimesh_p2p::replay::{replay, Replay};
use cleimesh_p2p::{CleiMeshNode, P2PConfig, ToolRequest};
use cleimesh_receipt::{Entry, ReceiptLog};
use cleimesh_wasm_sandbox::{SandboxConfig, WasmSandbox};
use serde_json::{json, Value};

const BUILTINS: &[u8] = include_bytes!("../../wasm-tools/builtins.wasm");

/// Returns `"dddd-c"`: 4 digits from WASI random bytes, the last digit of the
/// clock's seconds. Only a replay with the recorded seed and clock matches.
const PROBE: &str = r#"(module
    (import "wasi_snapshot_preview1" "random_get" (func $rand (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "clock_time_get" (func $clock (param i32 i64 i32) (result i32)))
    (memory (export "memory") 1)
    (data (i32.const 2048) "{\"ok\":\"0000-0\"}")
    (func (export "cleimesh_alloc") (param i32) (result i32) i32.const 1024)
    (func $digit (param $from i32) (param $to i32)
        (i32.store8 (local.get $to) (i32.add (i32.rem_u (i32.load8_u (local.get $from)) (i32.const 10)) (i32.const 48))))
    (func (export "cleimesh_execute") (param i32 i32) (result i64)
        (drop (call $rand (i32.const 3000) (i32.const 4)))
        (drop (call $clock (i32.const 0) (i64.const 1) (i32.const 3104)))
        (call $digit (i32.const 3000) (i32.const 2055))
        (call $digit (i32.const 3001) (i32.const 2056))
        (call $digit (i32.const 3002) (i32.const 2057))
        (call $digit (i32.const 3003) (i32.const 2058))
        (i32.store8 (i32.const 2060)
            (i32.add (i32.wrap_i64 (i64.rem_u (i64.div_u (i64.load (i32.const 3104)) (i64.const 1000000000)) (i64.const 10))) (i32.const 48)))
        i64.const 8796093022223))"#;

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

struct Setup {
    dir: tempfile::TempDir,
    node: CleiMeshNode,
    node_key: SigningKey,
    agent: SigningKey,
    chain: Vec<String>,
}

fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("node.key");
    std::fs::create_dir_all(dir.path().join("data")).unwrap();
    std::fs::write(dir.path().join("data/f"), "x").unwrap();
    let config = P2PConfig {
        listen_addresses: vec![],
        enable_mdns: false,
        identity_key_path: Some(key_path.clone()),
        receipts_path: Some(dir.path().join("r.jsonl")),
        ..P2PConfig::default()
    };
    let sandbox = WasmSandbox::new(SandboxConfig::default()).unwrap();
    for tool in ["echo", "json_transform", "file_read"] {
        sandbox.register_wasm_module(tool, BUILTINS.to_vec()).unwrap();
    }
    sandbox.register_wasm_module("probe", PROBE.as_bytes().to_vec()).unwrap();
    let node = CleiMeshNode::new(config, AgentIdentity::new("t")).unwrap().with_sandbox(sandbox);
    let node_key = cleimesh_p2p::node_key::aat_signing_key(&cleimesh_p2p::node_key::load_or_generate(&key_path).unwrap()).unwrap();
    let agent = SigningKey::generate(&mut rand::rngs::OsRng);
    let data = dir.path().join("data").canonicalize().unwrap().to_string_lossy().into_owned();
    let grants = cleimesh_p2p::grants::Grants::from([("file_read".to_string(), cleimesh_p2p::grants::ToolGrant { read: vec![data], ..Default::default() })]);
    let tools = serde_json::from_value(json!({"echo": {}, "json_transform": {}, "probe": {}, "file_read": {}})).unwrap();
    let chain = vec![node.issue_aat_root_granting(&Jwk::from_key(&agent.verifying_key()), tools, &grants, 600, 0).unwrap()];
    Setup { dir, node, node_key, agent, chain }
}

impl Setup {
    /// Runs a call and returns the step id of its decision receipt.
    async fn call(&mut self, tool: &str, args: Value) -> (bool, String) {
        let pop = aat::pop(&self.agent, &self.chain[0], tool, &args, Some(&self.node.aat_audience()), now()).unwrap();
        let request = ToolRequest {
            tool_name: tool.into(),
            payload: args,
            request_id: uuid::Uuid::new_v4().to_string(),
            capability: None,
            presentation: Some(Presentation { chain: self.chain.clone(), pop }),
            context: None,
        };
        let response = self.node.run_local("auditoria", request).await;
        let log = std::fs::read_to_string(self.dir.path().join("r.jsonl")).unwrap();
        let decision = log.lines().rev().map(|l| cleimesh_receipt::Receipt::parse(l).unwrap()).find(|r| r.action_id == "cleimesh.tool_call").unwrap();
        (response.success, decision.step_id)
    }

    fn log(&self) -> Vec<u8> {
        std::fs::read(self.dir.path().join("r.jsonl")).unwrap()
    }

    async fn replay(&self, step: &str, args: &Value, wasm: &[u8]) -> Result<Replay, String> {
        replay(&self.log(), &self.node_key.verifying_key(), step, args, wasm).await
    }
}

fn reproduced(r: Result<Replay, String>) {
    match r {
        Ok(Replay::Reproduced { .. }) => {}
        other => panic!("not reproduced: {other:?}"),
    }
}

#[tokio::test]
async fn calls_replay_from_their_receipts() {
    let mut s = setup();
    let echo = json!({"message": "oi"});
    let transform = json!({"input": {"a": [{"b": 1}, {"b": 2}]}, "filter": "a[].b"});
    let (ok, e) = s.call("echo", echo.clone()).await;
    assert!(ok);
    let (ok, t) = s.call("json_transform", transform.clone()).await;
    assert!(ok);
    reproduced(s.replay(&e, &echo, BUILTINS).await);
    reproduced(s.replay(&t, &transform, BUILTINS).await);
    // A short suffix of the step id is enough when it is unique.
    reproduced(s.replay(&e[e.len() - 8..], &echo, BUILTINS).await);
}

#[tokio::test]
async fn a_tool_reading_clock_and_randomness_replays_exactly() {
    let mut s = setup();
    let (_, first) = s.call("probe", json!({})).await;
    let (_, second) = s.call("probe", json!({})).await;
    reproduced(s.replay(&first, &json!({}), PROBE.as_bytes()).await);
    reproduced(s.replay(&second, &json!({}), PROBE.as_bytes()).await);
}

#[tokio::test]
async fn wrong_input_or_module_is_refused() {
    let mut s = setup();
    let (_, e) = s.call("echo", json!({"message": "oi"})).await;
    let err = s.replay(&e, &json!({"message": "tchau"}), BUILTINS).await.unwrap_err();
    assert!(err.contains("not the call's"), "{err}");
    let err = s.replay(&e, &json!({"message": "oi"}), PROBE.as_bytes()).await.unwrap_err();
    assert!(err.contains("not the one that ran"), "{err}");
}

#[tokio::test]
async fn calls_that_touch_files_or_were_denied_are_not_replayable() {
    let mut s = setup();
    let path = s.dir.path().join("data/f").canonicalize().unwrap();
    let (ok, read) = s.call("file_read", json!({"path": path})).await;
    assert!(ok);
    let err = s.replay(&read, &json!({"path": path}), BUILTINS).await.unwrap_err();
    assert!(err.contains("not replayable") && err.contains("reads directories"), "{err}");

    let (ok, denied) = s.call("file_write", json!({"path": "/x", "content": "x"})).await;
    assert!(!ok);
    assert!(s.replay(&denied, &json!({"path": "/x", "content": "x"}), BUILTINS).await.unwrap_err().contains("denied"));
}

// The point of replaying: a node whose signed record lies is caught.
#[tokio::test]
async fn a_signed_but_false_result_is_caught_by_replay() {
    let mut s = setup();
    let args = json!({"message": "oi"});
    let (_, step) = s.call("echo", args.clone()).await;
    let receipts: Vec<cleimesh_receipt::Receipt> = String::from_utf8(s.log()).unwrap().lines().map(|l| cleimesh_receipt::Receipt::parse(l).unwrap()).collect();
    let decision = receipts.iter().find(|r| r.step_id == step).unwrap();
    let mut result = receipts.iter().find(|r| r.params["decision_step"] == step.as_str()).unwrap().clone();
    result.params["observed"]["output_sha256"] = json!(cleimesh_receipt::sha256_hex(b"what the node wishes it had returned"));

    // The node re-signs a log with the lie: every signature checks out.
    let forged = s.dir.path().join("forged.jsonl");
    let mut log = ReceiptLog::open(&forged, s.node_key.clone()).unwrap();
    for r in [decision, &result] {
        log.append(Entry { step_id: r.step_id.clone(), action_id: r.action_id.clone(), params: r.params.clone(), success: r.success, ts_ms: r.ts_ms, actor: None }).unwrap();
    }
    let forged = std::fs::read(&forged).unwrap();
    assert!(cleimesh_receipt::verify_log(&forged, &s.node_key.verifying_key()).ok());

    match replay(&forged, &s.node_key.verifying_key(), &step, &args, BUILTINS).await {
        Ok(Replay::Mismatch { recorded, replayed, .. }) => assert_ne!(recorded, replayed),
        other => panic!("the lie was not caught: {other:?}"),
    }
}

#[tokio::test]
async fn an_altered_log_cannot_be_replayed() {
    let mut s = setup();
    let args = json!({"message": "oi"});
    let (_, step) = s.call("echo", args.clone()).await;
    let altered = String::from_utf8(s.log()).unwrap().replacen("\"tool\":\"echo\"", "\"tool\":\"ech0\"", 1);
    let err = replay(altered.as_bytes(), &s.node_key.verifying_key(), &step, &args, BUILTINS).await.unwrap_err();
    assert!(err.contains("fails verification"), "{err}");
}

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/replay");

/// Records the fixture `a_log_recorded_on_another_machine_replays_here`
/// replays: a probe call (clock and randomness) and an echo, with the
/// node's public key. Rerun after an engine upgrade, which by design makes
/// old receipts unreplayable with the new binary:
/// `cargo test -p cleimesh-p2p --test replay -- --ignored record_fixture`.
#[tokio::test]
#[ignore]
async fn record_fixture() {
    let mut s = setup();
    let (_, probe) = s.call("probe", json!({})).await;
    let (_, echo) = s.call("echo", json!({"message": "gravado em outra máquina"})).await;
    std::fs::create_dir_all(FIXTURE).unwrap();
    std::fs::write(format!("{FIXTURE}/r.jsonl"), s.log()).unwrap();
    std::fs::write(format!("{FIXTURE}/node.pub"), s.node_key.verifying_key().to_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>()).unwrap();
    std::fs::write(format!("{FIXTURE}/steps"), format!("{probe}\n{echo}\n")).unwrap();
}

// The auditor is somewhere else: a log recorded on the developer's machine
// is replayed by CI on another one, from the files alone (log, node public
// key, input, module), and must come out the same, clock and randomness
// included.
#[tokio::test]
async fn a_log_recorded_on_another_machine_replays_here() {
    let log = std::fs::read(format!("{FIXTURE}/r.jsonl")).unwrap();
    let hex = std::fs::read_to_string(format!("{FIXTURE}/node.pub")).unwrap();
    let key: [u8; 32] = (0..32).map(|i| u8::from_str_radix(&hex.trim()[2 * i..2 * i + 2], 16).unwrap()).collect::<Vec<_>>().try_into().unwrap();
    let anchor = aat::VerifyingKey::from_bytes(&key).unwrap();
    let steps = std::fs::read_to_string(format!("{FIXTURE}/steps")).unwrap();
    let steps: Vec<&str> = steps.lines().collect();
    reproduced(replay(&log, &anchor, steps[0], &json!({}), PROBE.as_bytes()).await);
    reproduced(replay(&log, &anchor, steps[1], &json!({"message": "gravado em outra máquina"}), BUILTINS).await);
}
