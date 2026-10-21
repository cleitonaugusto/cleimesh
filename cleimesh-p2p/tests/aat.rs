//! AAT delegation chains enforced by the node (S4 part 2):
//! node A issues the root to B, B derives for C offline, C calls A.

use cleimesh_core::AgentIdentity;
use cleimesh_p2p::aat::{self, Jwk, Presentation, SigningKey, Tools};
use cleimesh_p2p::{CleiMeshNode, Constraints, NodeHandle, P2PConfig, ToolRequest};
use libp2p::{Multiaddr, PeerId};
use serde_json::{json, Value};
use std::time::Duration;

fn node() -> CleiMeshNode {
    let config = P2PConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".to_string()],
        enable_mdns: false,
        ..P2PConfig::default()
    };
    CleiMeshNode::new(config, AgentIdentity::new("test")).unwrap()
}

fn key() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

fn jwk(key: &SigningKey) -> Jwk {
    Jwk::from_key(&key.verifying_key())
}

fn tools(v: Value) -> Tools {
    serde_json::from_value(v).unwrap()
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

/// C's side of a chain issued by `node`: B holds `echo` with any message and
/// gives C `echo` limited to "hello".
struct Holder {
    c: SigningKey,
    chain: Vec<String>,
}

fn delegate(node: &CleiMeshNode) -> Holder {
    let (b, c) = (key(), key());
    let root = node
        .issue_aat_root(&jwk(&b), tools(json!({"echo": {"message": {"constraint_type": "wildcard"}}})), 3600, 2)
        .unwrap();
    let child = aat::derive(&root, &b, &jwk(&c), tools(json!({"echo": {"message": {"constraint_type": "exact", "value": "hello"}}})), now(), 600, None)
        .unwrap();
    Holder { c, chain: vec![root, child] }
}

impl Holder {
    fn present(&self, tool: &str, args: &Value, aud: &str) -> Presentation {
        let pop = aat::pop(&self.c, self.chain.last().unwrap(), tool, args, Some(aud), now()).unwrap();
        Presentation { chain: self.chain.clone(), pop }
    }
}

fn request(tool: &str, args: Value, presentation: Presentation) -> ToolRequest {
    ToolRequest {
        tool_name: tool.to_string(),
        payload: args,
        request_id: "test".to_string(),
        capability: None,
        presentation: Some(presentation),
        context: None,
    }
}

fn hello() -> Value {
    json!({"message": "hello"})
}

fn denied<T: std::fmt::Debug>(result: Result<T, String>, why: &str) {
    let err = result.expect_err("accepted, expected a denial");
    assert!(err.contains(why), "denied for {err:?}, expected {why:?}");
}

#[test]
fn delegated_chain_is_accepted() {
    let mut a = node();
    let holder = delegate(&a);
    let req = request("echo", hello(), holder.present("echo", &hello(), &a.aat_audience()));
    a.authorize_tool_request(&PeerId::random(), &req).unwrap();
}

#[test]
fn call_outside_the_delegated_constraint_is_refused() {
    let mut a = node();
    let holder = delegate(&a);
    let args = json!({"message": "bye"});
    let req = request("echo", args.clone(), holder.present("echo", &args, &a.aat_audience()));
    denied(a.authorize_tool_request(&PeerId::random(), &req), "out of bounds");
}

#[test]
fn replayed_presentation_is_refused() {
    let mut a = node();
    let holder = delegate(&a);
    let req = request("echo", hello(), holder.present("echo", &hello(), &a.aat_audience()));
    a.authorize_tool_request(&PeerId::random(), &req).unwrap();
    denied(a.authorize_tool_request(&PeerId::random(), &req), "replayed");
}

#[test]
fn chain_rooted_in_another_node_is_refused() {
    let mut a = node();
    let other = node();
    let holder = delegate(&other);
    let req = request("echo", hello(), holder.present("echo", &hello(), &a.aat_audience()));
    denied(a.authorize_tool_request(&PeerId::random(), &req), "trust anchor");
}

#[test]
fn presentation_addressed_to_another_node_is_refused() {
    let mut a = node();
    let holder = delegate(&a);
    let req = request("echo", hello(), holder.present("echo", &hello(), &PeerId::random().to_string()));
    denied(a.authorize_tool_request(&PeerId::random(), &req), "another audience");
}

#[test]
fn presentation_for_other_arguments_is_refused() {
    // B may send any message, so only the proof's binding to its arguments
    // stops a relay from swapping them.
    let mut a = node();
    let b = key();
    let root = a.issue_aat_root(&jwk(&b), tools(json!({"echo": {"message": {"constraint_type": "wildcard"}}})), 600, 0).unwrap();
    let pop = aat::pop(&b, &root, "echo", &hello(), Some(&a.aat_audience()), now()).unwrap();
    let req = request("echo", json!({"message": "rm -rf"}), Presentation { chain: vec![root], pop });
    denied(a.authorize_tool_request(&PeerId::random(), &req), "other arguments");
}

#[test]
fn intermediate_holder_cannot_skip_its_own_link() {
    // B's key signs a token for C claiming to sit directly under the node.
    let mut a = node();
    let b = key();
    let forged = aat::issue_root(&b, "urn:cleimesh:node:fake", &jwk(&b), tools(json!({"echo": {}})), now(), 600, 0).unwrap();
    let pop = aat::pop(&b, &forged, "echo", &hello(), Some(&a.aat_audience()), now()).unwrap();
    let req = request("echo", hello(), Presentation { chain: vec![forged], pop });
    denied(a.authorize_tool_request(&PeerId::random(), &req), "trust anchor");
}

#[test]
fn capability_and_presentation_together_are_refused() {
    let mut a = node();
    let holder = delegate(&a);
    let peer = PeerId::random();
    let mut req = request("echo", hello(), holder.present("echo", &hello(), &a.aat_audience()));
    req.capability = Some(a.issue_capability(&peer, "echo", Constraints::default()).unwrap());
    denied(a.authorize_tool_request(&peer, &req), "both");
}

/// Starts `node`'s event loop in a task and returns its handle and address.
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

#[tokio::test]
async fn delegated_agent_calls_the_node_over_the_network() {
    let a = node();
    let (a_id, audience) = (a.local_peer_id(), a.aat_audience());
    let holder = delegate(&a);
    let (_a, addr) = serve(a).await;

    let mut c = node();
    c.start().await.unwrap();
    c.add_peer_address(a_id, addr).unwrap();

    let ok = c
        .invoke_tool_presenting(a_id, "echo".to_string(), hello(), holder.present("echo", &hello(), &audience))
        .await
        .unwrap();
    assert!(ok.success, "call failed: {:?}", ok.error);
    assert_eq!(ok.output, hello());

    let bye = json!({"message": "bye"});
    let refused = c
        .invoke_tool_presenting(a_id, "echo".to_string(), bye.clone(), holder.present("echo", &bye, &audience))
        .await
        .unwrap();
    assert!(!refused.success);
    assert!(refused.error.unwrap().contains("out of bounds"));
}
