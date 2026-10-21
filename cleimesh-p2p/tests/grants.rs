//! The token decides what the sandbox lets a tool touch
//! (C1): directories, network and limits come from the AAT chain, and each
//! delegation can only narrow them.

use cleimesh_core::AgentIdentity;
use cleimesh_p2p::aat::{self, Jwk, Presentation, SigningKey, Tools};
use cleimesh_p2p::grants::{self, Grants, ToolGrant};
use cleimesh_p2p::{CleiMeshNode, P2PConfig, ToolResponse};
use libp2p::PeerId;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Duration;

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

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

fn file_read() -> Tools {
    serde_json::from_value(json!({"file_read": {}})).unwrap()
}

fn reading(dirs: &[&Path]) -> Grants {
    grant(ToolGrant { read: dirs.iter().map(|d| d.to_string_lossy().into_owned()).collect(), ..ToolGrant::default() })
}

fn grant(g: ToolGrant) -> Grants {
    Grants::from([("file_read".to_string(), g)])
}

/// A holder's key and the chain it holds.
struct Holder {
    key: SigningKey,
    chain: Vec<String>,
}

impl Holder {
    fn root(node: &CleiMeshNode, grants: &Grants) -> Holder {
        let key = key();
        let chain = vec![node.issue_aat_root_granting(&jwk(&key), file_read(), grants, 600, 3).unwrap()];
        Holder { key, chain }
    }

    /// Derives for a new holder, granting `grants` (which the node, not the
    /// deriver, checks against this holder's).
    fn derive(&self, grants: &Grants) -> Holder {
        let key = key();
        let extra = if grants.is_empty() { vec![] } else { vec![grants::entry(grants)] };
        let child = aat::derive_with(self.chain.last().unwrap(), &self.key, &jwk(&key), file_read(), extra, now(), 600, None).unwrap();
        Holder { key, chain: [self.chain.clone(), vec![child]].concat() }
    }

    fn present(&self, args: &Value, aud: &str) -> Presentation {
        Presentation { chain: self.chain.clone(), pop: aat::pop(&self.key, self.chain.last().unwrap(), "file_read", args, Some(aud), now()).unwrap() }
    }
}

/// A served provider and a client to call it.
struct Net {
    client: CleiMeshNode,
    provider: PeerId,
    audience: String,
}

impl Net {
    async fn start(provider: CleiMeshNode) -> Net {
        let (provider_id, audience) = (provider.local_peer_id(), provider.aat_audience());
        let mut provider = provider;
        provider.start().await.unwrap();
        let handle = provider.handle();
        tokio::spawn(async move { provider.run_event_loop().await });
        let addr = loop {
            if let Some(addr) = handle.listen_addrs().await.unwrap().into_iter().next() {
                break addr;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        let mut client = node();
        client.start().await.unwrap();
        client.add_peer_address(provider_id, addr).unwrap();
        Net { client, provider: provider_id, audience }
    }

    async fn read(&mut self, holder: &Holder, file: &Path) -> ToolResponse {
        let args = json!({"path": file.to_string_lossy()});
        let presentation = holder.present(&args, &self.audience);
        self.client.invoke_tool_presenting(self.provider, "file_read".into(), args, presentation).await.unwrap()
    }
}

/// A canonical temp directory holding `dirs`, each with a file `f`.
fn tree(dirs: &[&str]) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().canonicalize().unwrap();
    for dir in dirs {
        std::fs::create_dir_all(base.join(dir)).unwrap();
        std::fs::write(base.join(dir).join("f"), format!("in {dir}")).unwrap();
    }
    (tmp, base)
}

fn read_ok(r: &ToolResponse, expected: &str) {
    assert!(r.success, "read failed: {:?}", r.error);
    assert_eq!(r.output["content"], expected);
}

fn refused(r: &ToolResponse, why: &str) {
    assert!(!r.success, "read succeeded: {:?}", r.output);
    let error = r.error.clone().unwrap_or_default();
    assert!(error.contains(why), "failed for {error:?}, expected {why:?}");
}

#[tokio::test]
async fn same_tool_sees_only_the_directory_its_token_grants() {
    let (_tmp, base) = tree(&["a", "b"]);
    let provider = node();
    let only_a = Holder::root(&provider, &reading(&[&base.join("a")]));
    let only_b = Holder::root(&provider, &reading(&[&base.join("b")]));
    let mut net = Net::start(provider).await;

    read_ok(&net.read(&only_a, &base.join("a/f")).await, "in a");
    refused(&net.read(&only_a, &base.join("b/f")).await, "cannot read");
    read_ok(&net.read(&only_b, &base.join("b/f")).await, "in b");
    refused(&net.read(&only_b, &base.join("a/f")).await, "cannot read");
}

#[tokio::test]
async fn subagent_cannot_reach_what_its_parent_can() {
    let (_tmp, base) = tree(&["proj", "proj/sub"]);
    let provider = node();
    let agent = Holder::root(&provider, &reading(&[&base.join("proj")]));
    let subagent = agent.derive(&reading(&[&base.join("proj/sub")]));
    let mut net = Net::start(provider).await;

    read_ok(&net.read(&agent, &base.join("proj/f")).await, "in proj");
    read_ok(&net.read(&subagent, &base.join("proj/sub/f")).await, "in proj/sub");
    refused(&net.read(&subagent, &base.join("proj/f")).await, "cannot read");
}

#[tokio::test]
async fn token_without_grants_runs_with_no_directory() {
    let (_tmp, base) = tree(&["a"]);
    let provider = node();
    let bare = Holder::root(&provider, &Grants::new());
    let mut net = Net::start(provider).await;
    refused(&net.read(&bare, &base.join("a/f")).await, "cannot read");
}

#[tokio::test]
async fn derived_grant_wider_than_its_parent_is_refused() {
    let (_tmp, base) = tree(&["proj", "other"]);
    let provider = node();
    let agent = Holder::root(&provider, &reading(&[&base.join("proj")]));
    let sibling = agent.derive(&reading(&[&base.join("other")]));
    let similar_prefix = agent.derive(&reading(&[&base.join("projX")]));
    let writer = agent.derive(&grant(ToolGrant { write: vec![base.join("proj").to_string_lossy().into()], ..ToolGrant::default() }));
    let networked = agent.derive(&grant(ToolGrant { network: true, ..ToolGrant::default() }));
    let mut net = Net::start(provider).await;

    refused(&net.read(&sibling, &base.join("other/f")).await, "not granted by the parent");
    refused(&net.read(&similar_prefix, &base.join("proj/f")).await, "not granted by the parent");
    refused(&net.read(&writer, &base.join("proj/f")).await, "write access");
    refused(&net.read(&networked, &base.join("proj/f")).await, "network");
}

#[tokio::test]
async fn symlink_inside_a_grant_cannot_lead_outside_it() {
    let (_tmp, base) = tree(&["proj", "secret"]);
    std::os::unix::fs::symlink(base.join("secret"), base.join("proj/link")).unwrap();
    let provider = node();
    let agent = Holder::root(&provider, &reading(&[&base.join("proj")]));
    let subagent = agent.derive(&reading(&[&base.join("proj/link")]));
    let mut net = Net::start(provider).await;
    refused(&net.read(&subagent, &base.join("secret/f")).await, "outside what the root grants");
}

#[tokio::test]
async fn missing_directory_refuses_the_call() {
    let (_tmp, base) = tree(&["proj"]);
    let provider = node();
    let agent = Holder::root(&provider, &reading(&[&base.join("gone")]));
    let mut net = Net::start(provider).await;
    refused(&net.read(&agent, &base.join("gone/f")).await, "unusable");
}

#[tokio::test]
async fn raised_limit_and_unknown_grant_field_are_refused() {
    let (_tmp, base) = tree(&["proj"]);
    let provider = node();
    let mut capped = ToolGrant { read: vec![base.join("proj").to_string_lossy().into()], ..ToolGrant::default() };
    capped.timeout_ms = Some(1000);
    let agent = Holder::root(&provider, &grant(capped.clone()));
    let raised = agent.derive(&grant(ToolGrant { timeout_ms: Some(5000), ..capped.clone() }));

    // A field this node doesn't know might be a restriction it can't apply.
    let unknown_key = key();
    let unknown = json!({"type": "cleimesh_sandbox", "tools": {"file_read": {"read": [base.join("proj")], "exec_only": true}}});
    let child = aat::derive_with(&agent.chain[0], &agent.key, &jwk(&unknown_key), file_read(), vec![unknown], now(), 600, None).unwrap();
    let with_unknown = Holder { key: unknown_key, chain: vec![agent.chain[0].clone(), child] };

    let mut net = Net::start(provider).await;
    refused(&net.read(&raised, &base.join("proj/f")).await, "limit raised");
    refused(&net.read(&with_unknown, &base.join("proj/f")).await, "unknown field");
    read_ok(&net.read(&agent, &base.join("proj/f")).await, "in proj");
}
