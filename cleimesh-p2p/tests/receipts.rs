//! Every tool call a node receives leaves a signed receipt
//! (C2): allowed or denied, chained, verifiable offline
//! against the node key, and free of the call's content.

use cleimesh_core::AgentIdentity;
use cleimesh_p2p::aat::{self, Jwk, Presentation, SigningKey};
use cleimesh_p2p::{CleiMeshNode, P2PConfig};
use serde_json::{json, Value};
use std::time::Duration;

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

fn node(receipts: Option<std::path::PathBuf>) -> CleiMeshNode {
    let config = P2PConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".to_string()],
        enable_mdns: false,
        receipts_path: receipts,
        ..P2PConfig::default()
    };
    CleiMeshNode::new(config, AgentIdentity::new("test")).unwrap()
}

#[tokio::test]
async fn allowed_and_denied_calls_leave_verifiable_receipts() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("receipts.jsonl");
    let mut provider = node(Some(log_path.clone()));
    let (provider_id, audience) = (provider.local_peer_id(), provider.aat_audience());
    let anchor = provider.aat_trust_anchor().verifying_key().unwrap();

    let holder = SigningKey::generate(&mut rand::rngs::OsRng);
    let tools = serde_json::from_value(json!({"echo": {"message": {"constraint_type": "exact", "value": "segredo-do-titular"}}})).unwrap();
    let root = provider.issue_aat_root(&Jwk::from_key(&holder.verifying_key()), tools, 600, 0).unwrap();
    let present = |args: &Value| Presentation {
        chain: vec![root.clone()],
        pop: aat::pop(&holder, &root, "echo", args, Some(&audience), now()).unwrap(),
    };

    provider.start().await.unwrap();
    let provider_handle = provider.handle();
    tokio::spawn(async move { provider.run_event_loop().await });
    let addr = loop {
        if let Some(addr) = provider_handle.listen_addrs().await.unwrap().into_iter().next() {
            break addr;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };

    let mut client = node(None);
    client.start().await.unwrap();
    client.add_peer_address(provider_id, addr).unwrap();
    let ok_args = json!({"message": "segredo-do-titular"});
    let ok = client.invoke_tool_presenting(provider_id, "echo".into(), ok_args.clone(), present(&ok_args)).await.unwrap();
    assert!(ok.success, "{:?}", ok.error);
    let bad_args = json!({"message": "outro-segredo"});
    let bad = client.invoke_tool_presenting(provider_id, "echo".into(), bad_args.clone(), present(&bad_args)).await.unwrap();
    assert!(!bad.success);

    let log = std::fs::read(&log_path).unwrap();
    let report = cleimesh_receipt::verify_log(&log, &anchor);
    assert!(report.ok(), "{:?}", report.failures);
    assert_eq!(report.lines, 3, "decision + result for the allowed call, one for the denied");

    let text = String::from_utf8(log).unwrap();
    assert!(!text.contains("segredo"), "a receipt carries call content: {text}");
    let receipts: Vec<_> = text.lines().map(|l| cleimesh_receipt::Receipt::parse(l).unwrap()).collect();

    // The decision is on record before the tool runs.
    let allowed = &receipts[0].params;
    assert_eq!(receipts[0].action_id, "cleimesh.tool_call");
    assert_eq!(allowed["decision"], "allowed");
    assert_eq!(allowed["tool"], "echo");
    assert_eq!(allowed["caller"], client.local_peer_id().to_string());
    assert_eq!(allowed["authority"]["kind"], "aat");
    assert_eq!(allowed["authority"]["holder"], Jwk::from_key(&holder.verifying_key()).thumbprint_uri());
    assert_eq!(allowed["sandbox"]["allow_network"], false);
    assert!(allowed["wasm_sha256"].as_str().is_some_and(|h| h.len() == 64));

    let result = &receipts[1];
    assert_eq!(result.action_id, "cleimesh.tool_result");
    assert!(result.success);
    assert_eq!(result.params["decision_step"], receipts[0].step_id);
    assert_eq!(result.params["observed"]["success"], true);

    let denied = &receipts[2].params;
    assert!(!receipts[2].success);
    assert_eq!(denied["decision"], "denied");
    assert!(denied["denial"].as_str().unwrap().contains("out of bounds"));
    assert!(denied.get("observed").is_none(), "a denied call must not look executed");
}

/// Accepts no line, like a full disk.
struct FullDisk(std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl cleimesh_receipt::ReceiptSink for FullDisk {
    fn write_line(&mut self, _: &[u8]) -> std::io::Result<()> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(std::io::Error::other("no space left on device"))
    }
    fn sync(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// No receipt, no run: a call the node cannot record is refused before the
// tool starts.
#[tokio::test]
async fn call_is_refused_when_its_receipt_cannot_be_written() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("must-not-exist");
    let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let log = cleimesh_receipt::ReceiptLog::with_sink(Box::new(FullDisk(attempts.clone())), SigningKey::generate(&mut rand::rngs::OsRng), None);
    let config = P2PConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".to_string()],
        enable_mdns: false,
        public_tools: vec!["file_write".to_string()],
        ..P2PConfig::default()
    };
    let sandbox = cleimesh_wasm_sandbox::WasmSandbox::new(cleimesh_wasm_sandbox::SandboxConfig {
        writable_paths: vec![dir.path().to_string_lossy().into_owned()],
        ..Default::default()
    })
    .unwrap();
    sandbox.register_wasm_module("file_write", include_bytes!("../../wasm-tools/builtins.wasm").to_vec()).unwrap();
    let mut provider = CleiMeshNode::new(config, AgentIdentity::new("test")).unwrap().with_sandbox(sandbox).with_receipt_log(log);
    let provider_id = provider.local_peer_id();
    provider.start().await.unwrap();
    let handle = provider.handle();
    tokio::spawn(async move { provider.run_event_loop().await });
    let addr = loop {
        if let Some(addr) = handle.listen_addrs().await.unwrap().into_iter().next() {
            break addr;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };

    let mut client = node(None);
    client.start().await.unwrap();
    client.add_peer_address(provider_id, addr).unwrap();
    let args = json!({"path": target.to_string_lossy(), "content": "x"});
    let response = client.invoke_tool(provider_id, "file_write".into(), args).await.unwrap();

    assert!(!response.success);
    assert!(response.error.unwrap().contains("cannot record the call"));
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(!target.exists(), "the tool ran although its decision was not recorded");
}
