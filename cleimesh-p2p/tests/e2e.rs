//! End-to-end tool calls between two in-process nodes over real TCP
//! (R1). Before the fix, a remote call never returned:
//! responses were logged and dropped, so every invoke hit the 30s timeout.

use cleimesh_core::AgentIdentity;
use cleimesh_p2p::{CleiMeshNode, Constraints, NodeHandle, P2PConfig};
use libp2p::{Multiaddr, PeerId};
use std::time::Duration;

fn node() -> CleiMeshNode {
    let config = P2PConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".to_string()],
        enable_mdns: false,
        ..P2PConfig::default()
    };
    CleiMeshNode::new(config, AgentIdentity::new("test")).unwrap()
}

/// Starts `node`'s event loop in a task and returns its handle and the
/// address it listens on.
async fn serve(mut node: CleiMeshNode) -> (NodeHandle, Multiaddr) {
    node.start().await.unwrap();
    let handle = node.handle();
    tokio::spawn(async move { node.run_event_loop().await });
    let addr = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(addr) = handle.listen_addrs().await.unwrap().into_iter().next() {
                break addr;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("provider never started listening");
    (handle, addr)
}

/// A provider serving `echo`, and a client that holds a capability for it.
async fn provider_and_client() -> (NodeHandle, PeerId, Multiaddr, CleiMeshNode, cleimesh_p2p::auth::Capability) {
    let provider = node();
    let provider_id = provider.local_peer_id();
    let mut client = node();
    let capability = provider.issue_capability(&client.local_peer_id(), "echo", Constraints::default()).unwrap();
    let (provider_handle, addr) = serve(provider).await;
    client.start().await.unwrap();
    (provider_handle, provider_id, addr, client, capability)
}

fn echo_args() -> serde_json::Value {
    serde_json::json!({"message": "hello"})
}

#[tokio::test]
async fn remote_call_returns_the_tool_output() {
    let (_provider, provider_id, addr, mut client, capability) = provider_and_client().await;
    client.add_peer_address(provider_id, addr).unwrap();

    let response = client
        .invoke_tool_with_capability(provider_id, "echo".to_string(), echo_args(), Some(capability))
        .await
        .unwrap();

    assert!(response.success, "call failed: {:?}", response.error);
    assert_eq!(response.output, serde_json::json!({"message": "hello"}));
}

#[tokio::test]
async fn remote_call_without_capability_is_refused() {
    let (_provider, provider_id, addr, mut client, _) = provider_and_client().await;
    client.add_peer_address(provider_id, addr).unwrap();

    let response = client.invoke_tool(provider_id, "echo".to_string(), echo_args()).await.unwrap();

    assert!(!response.success);
    let error = response.error.unwrap();
    assert!(error.contains("no valid capability"), "unexpected error: {error}");
}

// Before the fix, the event loop took the swarm, so a node running it could
// not call anyone ("Swarm not initialized").
#[tokio::test]
async fn node_running_its_event_loop_can_call_through_its_handle() {
    let (_provider, provider_id, addr, client, capability) = provider_and_client().await;
    let client = {
        let handle = client.handle();
        let mut client = client;
        tokio::spawn(async move { client.run_event_loop().await });
        handle
    };
    client.add_peer_address(provider_id, addr).unwrap();

    let first = client
        .invoke_tool(provider_id, "echo".to_string(), echo_args(), Some(capability.clone()))
        .await
        .unwrap();
    let second = client
        .invoke_tool(provider_id, "echo".to_string(), serde_json::json!({"message": "again"}), Some(capability))
        .await
        .unwrap();

    assert!(first.success && second.success);
    assert_eq!(second.output, serde_json::json!({"message": "again"}));
}

#[tokio::test]
async fn call_to_an_unreachable_peer_fails_fast() {
    let mut client = node();
    client.start().await.unwrap();
    let nobody = PeerId::random();
    client.add_peer_address(nobody, "/ip4/127.0.0.1/tcp/1".parse().unwrap()).unwrap();

    let started = std::time::Instant::now();
    let err = client.invoke_tool(nobody, "echo".to_string(), echo_args()).await.unwrap_err();

    assert!(err.to_string().contains("Request failed"), "unexpected error: {err}");
    assert!(started.elapsed() < Duration::from_secs(10), "waited for the timeout instead of the dial failure");
}

// RE1: `doctor` checks that the node an agent is registered with answers,
// and is the node its tokens name, without leaving a receipt there.
#[tokio::test]
async fn connect_reaches_the_node_and_refuses_another_one_at_its_address() {
    let provider = node();
    let provider_id = provider.local_peer_id();
    let (_provider, addr) = serve(provider).await;

    let client = client_of(provider_id, addr.clone()).await;
    client.connect(provider_id).await.unwrap();

    let impostor = PeerId::random();
    let client = client_of(impostor, addr).await;
    let err = client.connect(impostor).await.unwrap_err().to_string();
    assert!(err.contains("cannot connect") && err.contains(&provider_id.to_string()), "unexpected error: {err}");

    let nobody = PeerId::random();
    let client = client_of(nobody, "/ip4/127.0.0.1/tcp/1".parse().unwrap()).await;
    assert!(client.connect(nobody).await.is_err());
}

#[tokio::test]
async fn handle_shutdown_stops_the_event_loop() {
    let (provider, _, _, _, _) = provider_and_client().await;
    provider.shutdown().unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(provider.listen_addrs().await.is_err(), "loop still answering after shutdown");
}


// R2: before the fix, the bootstrap address was filed under the node's own
// PeerId, so bootstrapping never reached the remote peer.
fn node_with(bootstrap_peers: Vec<String>, public_tools: Vec<String>) -> CleiMeshNode {
    let config = P2PConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".to_string()],
        enable_mdns: false,
        bootstrap_peers,
        public_tools,
        ..P2PConfig::default()
    };
    CleiMeshNode::new(config, AgentIdentity::new("test")).unwrap()
}

#[tokio::test]
async fn bootstrap_address_is_enough_to_call_the_peer() {
    let provider = node_with(Vec::new(), vec!["echo".to_string()]);
    let provider_id = provider.local_peer_id();
    let (_provider, addr) = serve(provider).await;

    // Call right after start(), while the bootstrap dial may still be in flight.
    let mut client = node_with(vec![format!("{addr}/p2p/{provider_id}")], Vec::new());
    client.start().await.unwrap();
    let response = client.invoke_tool(provider_id, "echo".to_string(), echo_args()).await.unwrap();

    assert!(response.success, "call failed: {:?}", response.error);
    assert_eq!(response.output, echo_args());
}

#[tokio::test]
async fn bootstrap_address_without_peer_id_is_rejected() {
    let mut client = node_with(vec!["/ip4/127.0.0.1/tcp/4001".to_string()], Vec::new());
    let err = client.start().await.unwrap_err();
    assert!(err.to_string().contains("/p2p/<peer id>"), "unexpected error: {err}");
}

#[tokio::test]
async fn invalid_bootstrap_address_is_rejected() {
    let mut client = node_with(vec!["not-an-address".to_string()], Vec::new());
    assert!(client.start().await.is_err());
}

// R3: before the fix, the event loop awaited each tool run, so a slow tool
// held every other request (and the rest of the network) until it finished.
#[tokio::test]
async fn slow_tool_does_not_hold_other_requests() {
    let spin = r#"(module
        (memory (export "memory") 1)
        (func (export "cleimesh_alloc") (param i32) (result i32) i32.const 1024)
        (func (export "cleimesh_execute") (param i32 i32) (result i64) (loop $l (br $l)) i64.const 0))"#;
    let limits = cleimesh_wasm_sandbox::SandboxLimits { max_instructions: u64::MAX, ..Default::default() };
    let sandbox = cleimesh_wasm_sandbox::WasmSandbox::new(cleimesh_wasm_sandbox::SandboxConfig { limits, ..Default::default() }).unwrap();
    sandbox.register_wasm_module("spin", spin.as_bytes().to_vec()).unwrap();
    sandbox.register_wasm_module("echo", include_bytes!("../../wasm-tools/builtins.wasm").to_vec()).unwrap();
    let provider = node_with(Vec::new(), vec!["spin".to_string(), "echo".to_string()]).with_sandbox(sandbox);
    let provider_id = provider.local_peer_id();
    let (_provider, addr) = serve(provider).await;

    let mut client = node();
    client.start().await.unwrap();
    client.add_peer_address(provider_id, addr).unwrap();
    let client = {
        let handle = client.handle();
        tokio::spawn(async move { client.run_event_loop().await });
        handle
    };

    // The provider stops `spin` at its 5s request timeout.
    let slow = {
        let client = client.clone();
        tokio::spawn(async move { client.invoke_tool(provider_id, "spin".to_string(), serde_json::json!({}), None).await })
    };
    tokio::time::sleep(Duration::from_millis(500)).await;
    let fast = client.invoke_tool(provider_id, "echo".to_string(), echo_args(), None).await.unwrap();

    assert!(fast.success, "echo failed: {:?}", fast.error);
    assert!(!slow.is_finished(), "spin finished before echo: the loop ran them one at a time");
    let slow = slow.await.unwrap().unwrap();
    assert!(!slow.success, "spin should have timed out");
}

/// A provider serving `spin` (runs until the 5s execution timeout) and
/// `echo` to anyone, and a running client for it.
async fn provider_with_spin(extra: &[(&str, Vec<u8>)]) -> (PeerId, Multiaddr, NodeHandle) {
    let spin = r#"(module
        (memory (export "memory") 1)
        (func (export "cleimesh_alloc") (param i32) (result i32) i32.const 1024)
        (func (export "cleimesh_execute") (param i32 i32) (result i64) (loop $l (br $l)) i64.const 0))"#;
    let limits = cleimesh_wasm_sandbox::SandboxLimits { max_instructions: u64::MAX, ..Default::default() };
    let sandbox = cleimesh_wasm_sandbox::WasmSandbox::new(cleimesh_wasm_sandbox::SandboxConfig { limits, ..Default::default() }).unwrap();
    sandbox.register_wasm_module("spin", spin.as_bytes().to_vec()).unwrap();
    sandbox.register_wasm_module("echo", include_bytes!("../../wasm-tools/builtins.wasm").to_vec()).unwrap();
    let mut public = vec!["spin".to_string(), "echo".to_string()];
    for (name, wasm) in extra {
        sandbox.register_wasm_module(name, wasm.clone()).unwrap();
        public.push(name.to_string());
    }
    let provider = node_with(Vec::new(), public).with_sandbox(sandbox);
    let provider_id = provider.local_peer_id();
    let (_provider, addr) = serve(provider).await;
    (provider_id, addr.clone(), client_of(provider_id, addr).await)
}

async fn client_of(provider_id: PeerId, addr: Multiaddr) -> NodeHandle {
    let mut client = node();
    client.start().await.unwrap();
    client.add_peer_address(provider_id, addr).unwrap();
    let handle = client.handle();
    tokio::spawn(async move { client.run_event_loop().await });
    handle
}

// S11: before the limit, one peer could start any number of runs at once.
#[tokio::test]
async fn one_peer_cannot_run_more_than_its_share_at_once() {
    let (provider_id, addr, client) = provider_with_spin(&[]).await;
    let spins: Vec<_> = (0..cleimesh_p2p::MAX_IN_FLIGHT_PER_PEER)
        .map(|_| {
            let client = client.clone();
            tokio::spawn(async move { client.invoke_tool(provider_id, "spin".to_string(), serde_json::json!({}), None).await })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(1000)).await;

    let refused = client.invoke_tool(provider_id, "echo".to_string(), echo_args(), None).await.unwrap();
    assert!(!refused.success, "a call over the limit ran");
    assert!(refused.error.as_deref().unwrap_or("").contains("already running"), "{:?}", refused.error);

    let other = client_of(provider_id, addr).await;
    let served = other.invoke_tool(provider_id, "echo".to_string(), echo_args(), None).await.unwrap();
    assert!(served.success, "another peer should be served: {:?}", served.error);

    for spin in spins {
        assert!(!spin.await.unwrap().unwrap().success, "spin should have timed out");
    }
    let again = client.invoke_tool(provider_id, "echo".to_string(), echo_args(), None).await.unwrap();
    assert!(again.success, "the slots should free up once the runs end: {:?}", again.error);
}

// S11: an output over MAX_RESPONSE_BYTES is answered with an error, not sent.
#[tokio::test]
async fn an_output_over_the_limit_comes_back_as_an_error() {
    // Writes {"ok":"aaa…"} with 9 MiB of 'a' (the limit is 8 MiB).
    let big = r#"(module
        (memory (export "memory") 150)
        (data (i32.const 0) "{\"ok\":\"")
        (func (export "cleimesh_alloc") (param i32) (result i32) i32.const 9500000)
        (func (export "cleimesh_execute") (param i32 i32) (result i64)
            (memory.fill (i32.const 7) (i32.const 97) (i32.const 9437184))
            (i32.store16 (i32.const 9437191) (i32.const 0x7d22))
            i64.const 9437193))"#;
    let (provider_id, _addr, client) = provider_with_spin(&[("big", big.as_bytes().to_vec())]).await;
    let response = client.invoke_tool(provider_id, "big".to_string(), serde_json::json!({}), None).await.unwrap();
    assert!(!response.success, "an output over the limit was sent");
    assert!(response.error.as_deref().unwrap_or("").contains("byte limit"), "{:?}", response.error);
}
