//! Attack tests for remote tool authorization (Phase 1).
//! Each test describes a request that must be refused.

use cleimesh_core::AgentIdentity;
use cleimesh_p2p::auth::Capability;
use cleimesh_p2p::{CleiMeshNode, Constraints, P2PConfig, ToolRequest};
use libp2p::PeerId;

fn node(public_tools: &[&str]) -> CleiMeshNode {
    let config = P2PConfig {
        public_tools: public_tools.iter().map(|t| t.to_string()).collect(),
        ..P2PConfig::default()
    };
    CleiMeshNode::new(config, AgentIdentity::new("owner")).unwrap()
}

fn request(tool: &str, args: serde_json::Value, capability: Option<Capability>) -> ToolRequest {
    ToolRequest {
        tool_name: tool.to_string(),
        payload: args,
        request_id: "test".to_string(),
        capability,
        presentation: None,
        context: None,
    }
}

/// A request that relies on capabilities stored on the node.
fn call(tool: &str) -> ToolRequest {
    request(tool, serde_json::json!({}), None)
}

// S1: before the fix, a tool with no registered capability was open to any peer.
#[test]
fn peer_without_capability_cannot_write_files() {
    let mut node = node(&[]);
    let attacker = PeerId::random();

    let err = node.authorize_tool_request(&attacker, &call("file_write")).unwrap_err();
    assert!(err.contains("no valid capability"), "unexpected error: {err}");
}

#[test]
fn no_tool_is_public_by_default() {
    let mut node = node(&[]);
    let peer = PeerId::random();

    for tool in ["echo", "json_transform", "file_read", "file_write"] {
        assert!(node.authorize_tool_request(&peer, &call(tool)).is_err(), "{tool} should be denied");
    }
}

#[test]
fn public_tools_are_an_explicit_opt_in() {
    let mut node = node(&["echo"]);
    let peer = PeerId::random();

    assert!(node.authorize_tool_request(&peer, &call("echo")).is_ok());
    assert!(node.authorize_tool_request(&peer, &call("file_write")).is_err());
}

#[test]
fn capability_only_authorizes_its_subject_and_tool() {
    let mut node = node(&[]);
    let alice = PeerId::random();
    let mallory = PeerId::random();
    let cap = node.issue_capability(&alice, "file_read", Constraints::default()).unwrap();
    node.grant_capability(cap);

    assert!(node.authorize_tool_request(&alice, &call("file_read")).is_ok());
    assert!(node.authorize_tool_request(&alice, &call("file_write")).is_err());
    assert!(node.authorize_tool_request(&mallory, &call("file_read")).is_err());
}

#[test]
fn exhausted_capability_is_refused() {
    let mut node = node(&[]);
    let alice = PeerId::random();
    let constraints = Constraints { max_calls: Some(1), ..Constraints::default() };
    let cap = node.issue_capability(&alice, "echo", constraints).unwrap();
    node.grant_capability(cap);

    assert!(node.authorize_tool_request(&alice, &call("echo")).is_ok());
    let err = node.authorize_tool_request(&alice, &call("echo")).unwrap_err();
    assert!(err.contains("Max calls exceeded"), "unexpected error: {err}");
}

// S2: the signature must cover the whole capability. Before the fix,
// constraints were unsigned and actions were concatenated without separators.
fn signed_capability() -> (Capability, Vec<u8>) {
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let public_key = keypair.public().encode_protobuf();
    let issuer = AgentIdentity::from_keypair(public_key.clone(), keypair.public().to_peer_id().to_string());
    let constraints = Constraints {
        max_calls: Some(3),
        max_duration_ms: Some(1_000),
        allowed_args: Some(vec![serde_json::json!({"path": "/data/a.txt"})]),
        rate_limit: Some(cleimesh_p2p::auth::RateLimit { calls_per_window: 1, window_ms: 60_000 }),
        expiration: Some(4_000_000_000),
    };
    let mut cap = Capability::new(
        issuer,
        AgentIdentity::from_peer_id(PeerId::random().to_string()),
        "tool:file_read",
        vec!["exe".to_string(), "cute".to_string()],
        constraints,
    )
    .with_audience(&PeerId::random());
    cap.sign(&keypair).unwrap();
    assert!(cap.verify(&public_key).unwrap(), "untampered capability must verify");
    (cap, public_key)
}

#[test]
fn tampering_with_any_field_invalidates_the_signature() {
    let tamperings: Vec<(&str, fn(&mut Capability))> = vec![
        ("remove max_calls", |c| c.constraints.max_calls = None),
        ("raise max_calls", |c| c.constraints.max_calls = Some(1_000)),
        ("remove max_duration_ms", |c| c.constraints.max_duration_ms = None),
        ("remove allowed_args", |c| c.constraints.allowed_args = None),
        ("widen allowed_args", |c| c.constraints.allowed_args = Some(vec![serde_json::json!({"path": "/etc/passwd"})])),
        ("remove rate_limit", |c| c.constraints.rate_limit = None),
        ("remove expiration", |c| c.constraints.expiration = None),
        ("extend expiration", |c| c.constraints.expiration = Some(u64::MAX)),
        ("merge actions", |c| c.actions = vec!["execute".to_string()]),
        ("add wildcard action", |c| c.actions.push("*".to_string())),
        ("change resource", |c| c.resource = "tool:file_write".to_string()),
        ("change subject", |c| c.subject = AgentIdentity::from_peer_id(PeerId::random().to_string())),
        ("change issuer", |c| c.issuer = AgentIdentity::new("someone-else")),
        ("change audience", |c| c.audience = Some(PeerId::random().to_string())),
        ("remove audience", |c| c.audience = None),
        ("change signed_at", |c| c.proof.signed_at += 1),
        ("change nonce", |c| c.proof.nonce[0] ^= 1),
    ];

    for (name, tamper) in tamperings {
        let (mut cap, public_key) = signed_capability();
        tamper(&mut cap);
        assert!(!cap.verify(&public_key).unwrap(), "signature still valid after: {name}");
    }
}

#[test]
fn signature_does_not_verify_under_another_key() {
    let (cap, _) = signed_capability();
    let other = libp2p::identity::Keypair::generate_ed25519().public().encode_protobuf();
    assert!(!cap.verify(&other).unwrap());
}

// The canonical signing bytes rely on serde_json sorting object keys. If some
// dependency turns on `preserve_order`, this fails before signatures drift.
#[test]
fn serde_json_objects_serialize_with_sorted_keys() {
    let value = serde_json::json!({"b": 1, "a": 2});
    assert_eq!(serde_json::to_string(&value).unwrap(), r#"{"a":2,"b":1}"#);
}

// S3: attenuation may only narrow. Before the fix, the resource could be
// swapped for any other and allowed_args were merged as a union.
fn delegable_capability() -> Capability {
    let (cap, _) = signed_capability();
    cap
}

fn delegate_peer() -> AgentIdentity {
    AgentIdentity::from_peer_id(PeerId::random().to_string())
}

#[test]
fn attenuation_cannot_change_the_resource() {
    let cap = delegable_capability();
    let err = cap
        .attenuate(delegate_peer(), Some("tool:file_write".to_string()), None, Constraints::default())
        .unwrap_err();
    assert!(err.to_string().contains("resource"), "unexpected error: {err}");
}

#[test]
fn attenuation_cannot_add_actions_or_a_wildcard() {
    let cap = delegable_capability();
    for actions in [vec!["execute".to_string()], vec!["*".to_string()], vec!["exe".to_string(), "admin".to_string()]] {
        assert!(
            cap.attenuate(delegate_peer(), None, Some(actions.clone()), Constraints::default()).is_err(),
            "escalated to actions {actions:?}"
        );
    }
}

#[test]
fn attenuation_cannot_widen_allowed_args() {
    let cap = delegable_capability();
    let widened = Constraints {
        allowed_args: Some(vec![
            serde_json::json!({"path": "/data/a.txt"}),
            serde_json::json!({"path": "/etc/passwd"}),
        ]),
        ..Constraints::default()
    };
    let delegated = cap.attenuate(delegate_peer(), None, None, widened).unwrap();
    assert_eq!(delegated.constraints.allowed_args, Some(vec![serde_json::json!({"path": "/data/a.txt"})]));
    assert!(!delegated.can_execute("exe", &serde_json::json!({"path": "/etc/passwd"})));

    let disjoint = Constraints {
        allowed_args: Some(vec![serde_json::json!({"path": "/etc/passwd"})]),
        ..Constraints::default()
    };
    assert!(cap.attenuate(delegate_peer(), None, None, disjoint).is_err());
}

#[test]
fn attenuation_cannot_loosen_limits() {
    let cap = delegable_capability();
    let looser = Constraints {
        max_calls: Some(1_000),
        max_duration_ms: Some(u64::MAX),
        rate_limit: Some(cleimesh_p2p::auth::RateLimit { calls_per_window: 1_000, window_ms: 1 }),
        expiration: Some(u64::MAX),
        allowed_args: None,
    };
    let delegated = cap.attenuate(delegate_peer(), None, None, looser).unwrap();
    assert_eq!(delegated.constraints, cap.constraints, "limits must stay at the original's");

    // Omitting a limit keeps the original's instead of removing it.
    let delegated = cap.attenuate(delegate_peer(), None, None, Constraints::default()).unwrap();
    assert_eq!(delegated.constraints, cap.constraints);
}

#[test]
fn attenuation_can_narrow() {
    let cap = delegable_capability();
    let tighter = Constraints { max_calls: Some(1), ..Constraints::default() };
    let delegated = cap
        .attenuate(delegate_peer(), Some(cap.resource.clone()), Some(vec!["exe".to_string()]), tighter)
        .unwrap();
    assert_eq!(delegated.actions, vec!["exe".to_string()]);
    assert_eq!(delegated.constraints.max_calls, Some(1));
}

// S5: before the fix, start() generated a new keypair on every run, so every
// capability granted to the node's PeerId died on restart.
fn persistent_node(key_path: &std::path::Path) -> CleiMeshNode {
    let config = P2PConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".to_string()],
        enable_mdns: false,
        identity_key_path: Some(key_path.to_path_buf()),
        ..P2PConfig::default()
    };
    CleiMeshNode::new(config, AgentIdentity::new("owner")).unwrap()
}

#[tokio::test]
async fn node_identity_survives_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("cleimesh").join("identity.key");

    let mut first = persistent_node(&key_path);
    let before_start = first.local_peer_id();
    first.start().await.unwrap();
    assert_eq!(first.local_peer_id(), before_start, "start() must not switch keys");
    drop(first);

    let mut second = persistent_node(&key_path);
    second.start().await.unwrap();
    assert_eq!(second.local_peer_id(), before_start);
}

#[cfg(unix)]
#[test]
fn node_key_is_private_to_its_owner() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("identity.key");
    persistent_node(&key_path);
    let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);

    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let config = P2PConfig { identity_key_path: Some(key_path), ..P2PConfig::default() };
    let err = CleiMeshNode::new(config, AgentIdentity::new("owner")).err().expect("loose key permissions accepted");
    assert!(err.to_string().contains("chmod 600"), "unexpected error: {err}");
}

#[test]
fn corrupt_node_key_is_never_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("identity.key");
    persistent_node(&key_path);
    std::fs::write(&key_path, b"not a key").unwrap();

    let config = P2PConfig { identity_key_path: Some(key_path.clone()), ..P2PConfig::default() };
    assert!(CleiMeshNode::new(config, AgentIdentity::new("owner")).is_err());
    assert_eq!(std::fs::read(&key_path).unwrap(), b"not a key", "corrupt key was overwritten");
}

#[test]
fn node_agent_identity_is_its_peer_id() {
    let node = node(&[]);
    assert_eq!(node.agent_identity().peer_id, node.local_peer_id().to_string());
}

// S6: before the fix, the node trusted any capability added to its store
// (unsigned, from any issuer) and never checked the call's real arguments.
fn expired() -> Constraints {
    Constraints { expiration: Some(1), ..Constraints::default() }
}

fn denial(node: &mut CleiMeshNode, peer: &PeerId, request: &ToolRequest) -> String {
    node.authorize_tool_request(peer, request).expect_err("request was authorized")
}

#[test]
fn presented_capability_authorizes_its_subject() {
    let mut node = node(&[]);
    let alice = PeerId::random();
    let cap = node.issue_capability(&alice, "echo", Constraints::default()).unwrap();

    assert!(node.authorize_tool_request(&alice, &request("echo", serde_json::json!({}), Some(cap))).is_ok());
}

#[test]
fn capability_for_peer_a_used_by_peer_b_is_refused() {
    let mut node = node(&[]);
    let alice = PeerId::random();
    let mallory = PeerId::random();
    let cap = node.issue_capability(&alice, "echo", Constraints::default()).unwrap();

    let err = denial(&mut node, &mallory, &request("echo", serde_json::json!({}), Some(cap)));
    assert!(err.contains("subject is not the requesting peer"), "unexpected error: {err}");
}

#[test]
fn capability_issued_by_another_node_is_refused() {
    let mut node_x = node(&[]);
    let node_y = node(&[]);
    let alice = PeerId::random();
    let cap = node_y.issue_capability(&alice, "echo", Constraints::default()).unwrap();

    let err = denial(&mut node_x, &alice, &request("echo", serde_json::json!({}), Some(cap.clone())));
    assert!(err.contains("audience is not this node"), "unexpected error: {err}");

    // Storing it on node X does not make it valid there either.
    node_x.grant_capability(cap);
    assert!(node_x.authorize_tool_request(&alice, &call("echo")).is_err());
}

#[test]
fn unsigned_capability_in_the_store_is_refused() {
    let mut node = node(&[]);
    let alice = PeerId::random();
    let mut cap = node.issue_capability(&alice, "echo", Constraints::default()).unwrap();
    cap.proof.signature.clear();
    node.grant_capability(cap.clone());

    assert!(denial(&mut node, &alice, &call("echo")).contains("no valid capability"));
    let err = denial(&mut node, &alice, &request("echo", serde_json::json!({}), Some(cap)));
    assert!(err.contains("signature is invalid"), "unexpected error: {err}");
}

#[test]
fn tampered_presented_capability_is_refused() {
    let mut node = node(&[]);
    let alice = PeerId::random();
    let mut cap = node.issue_capability(&alice, "echo", Constraints { max_calls: Some(1), ..Constraints::default() }).unwrap();
    cap.constraints.max_calls = None;

    let err = denial(&mut node, &alice, &request("echo", serde_json::json!({}), Some(cap)));
    assert!(err.contains("signature is invalid"), "unexpected error: {err}");
}

// An attacker signs with their own key but claims the node's PeerId as issuer.
#[test]
fn issuer_key_must_match_the_node_peer_id() {
    let mut node = node(&[]);
    let mallory_key = libp2p::identity::Keypair::generate_ed25519();
    let mallory = mallory_key.public().to_peer_id();
    let forged_issuer = AgentIdentity::from_keypair(
        mallory_key.public().encode_protobuf(),
        node.local_peer_id().to_string(),
    );
    let mut cap = Capability::new(
        forged_issuer,
        AgentIdentity::from_peer_id(mallory.to_string()),
        "tool:file_write",
        vec!["execute".to_string()],
        Constraints::default(),
    )
    .with_audience(&node.local_peer_id());
    cap.sign(&mallory_key).unwrap();

    let err = denial(&mut node, &mallory, &request("file_write", serde_json::json!({}), Some(cap)));
    assert!(err.contains("issuer key does not match"), "unexpected error: {err}");
}

#[test]
fn expired_capability_is_refused() {
    let mut node = node(&[]);
    let alice = PeerId::random();
    let cap = node.issue_capability(&alice, "echo", expired()).unwrap();

    let err = denial(&mut node, &alice, &request("echo", serde_json::json!({}), Some(cap)));
    assert!(err.contains("expired"), "unexpected error: {err}");
}

#[test]
fn revoked_capability_is_refused_even_when_presented() {
    let mut node = node(&[]);
    let alice = PeerId::random();
    let cap = node.issue_capability(&alice, "echo", Constraints::default()).unwrap();
    node.grant_capability(cap.clone());
    node.capability_store_mut().revoke_capability(&cap);

    assert!(denial(&mut node, &alice, &call("echo")).contains("no valid capability"));
    let err = denial(&mut node, &alice, &request("echo", serde_json::json!({}), Some(cap)));
    assert!(err.contains("revoked"), "unexpected error: {err}");
}

#[test]
fn capability_for_one_tool_does_not_cover_another() {
    let mut node = node(&[]);
    let alice = PeerId::random();
    let cap = node.issue_capability(&alice, "file_read", Constraints::default()).unwrap();

    let err = denial(&mut node, &alice, &request("file_write", serde_json::json!({}), Some(cap)));
    assert!(err.contains("is for tool:file_read"), "unexpected error: {err}");
}

#[test]
fn allowed_args_are_checked_against_the_real_arguments() {
    let mut node = node(&[]);
    let alice = PeerId::random();
    let constraints = Constraints {
        allowed_args: Some(vec![serde_json::json!({"path": "/data/a.txt"})]),
        ..Constraints::default()
    };
    let cap = node.issue_capability(&alice, "file_read", constraints).unwrap();

    let allowed = request("file_read", serde_json::json!({"path": "/data/a.txt"}), Some(cap.clone()));
    assert!(node.authorize_tool_request(&alice, &allowed).is_ok());
    let err = denial(&mut node, &alice, &request("file_read", serde_json::json!({"path": "/etc/passwd"}), Some(cap)));
    assert!(err.contains("allowed_args"), "unexpected error: {err}");
}

#[test]
fn presenting_a_stored_capability_shares_its_call_budget() {
    let mut node = node(&[]);
    let alice = PeerId::random();
    let cap = node.issue_capability(&alice, "echo", Constraints { max_calls: Some(1), ..Constraints::default() }).unwrap();
    node.grant_capability(cap.clone());

    assert!(node.authorize_tool_request(&alice, &call("echo")).is_ok());
    let err = denial(&mut node, &alice, &request("echo", serde_json::json!({}), Some(cap)));
    assert!(err.contains("Max calls exceeded"), "unexpected error: {err}");
}

// Old clients send requests without the field; they still deserialize.
#[test]
fn request_without_capability_field_still_deserializes() {
    let json = r#"{"tool_name":"echo","payload":{},"request_id":"1"}"#;
    let request: ToolRequest = serde_json::from_str(json).unwrap();
    assert!(request.capability.is_none());
}
