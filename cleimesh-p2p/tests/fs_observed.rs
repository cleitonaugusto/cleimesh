//! What a call touched on disk, in its result receipt
//! (C5): per granted directory, the directories read and written as HMAC
//! pseudonyms and the file counts. No file or folder name in clear.

use cleimesh_core::AgentIdentity;
use cleimesh_p2p::aat::{self, Jwk, Presentation, SigningKey};
use cleimesh_p2p::grants::{Grants, ToolGrant};
use cleimesh_p2p::receipts::{fs_dir_pseudonym, FS_MAX_DEPTH, RESULT_ACTION_ID};
use cleimesh_p2p::{node_key, CleiMeshNode, P2PConfig, ToolRequest, ToolResponse};
use cleimesh_receipt::Receipt;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

struct World {
    dir: tempfile::TempDir,
    project: PathBuf,
    out: PathBuf,
}

fn world() -> World {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().canonicalize().unwrap();
    let (project, out) = (base.join("project"), base.join("out"));
    std::fs::create_dir_all(project.join("clientes/joao-silva")).unwrap();
    std::fs::create_dir_all(project.join("docs")).unwrap();
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(project.join("clientes/joao-silva/contrato-divorcio.txt"), "sigiloso").unwrap();
    std::fs::write(project.join("docs/guia.md"), "guia").unwrap();
    World { dir, project, out }
}

impl World {
    fn node(&self) -> CleiMeshNode {
        let config = P2PConfig {
            listen_addresses: vec![],
            enable_mdns: false,
            identity_key_path: Some(self.dir.path().join("node.key")),
            receipts_path: Some(self.dir.path().join("r.jsonl")),
            ..P2PConfig::default()
        };
        CleiMeshNode::new(config, AgentIdentity::new("t")).unwrap()
    }

    fn node_key(&self) -> SigningKey {
        node_key::aat_signing_key(&node_key::load_or_generate(&self.dir.path().join("node.key")).unwrap()).unwrap()
    }

    fn results(&self) -> Vec<(String, Value)> {
        let text = std::fs::read_to_string(self.dir.path().join("r.jsonl")).unwrap();
        text.lines()
            .map(|l| (l.to_string(), Receipt::parse(l).unwrap()))
            .filter(|(_, r)| r.action_id == RESULT_ACTION_ID)
            .map(|(l, r)| (l, r.params["observed"].clone()))
            .collect()
    }
}

struct Agent {
    key: SigningKey,
    chain: Vec<String>,
}

impl Agent {
    fn new(node: &CleiMeshNode, w: &World) -> Agent {
        let s = |p: &Path| p.to_string_lossy().into_owned();
        let grants = Grants::from([
            ("file_read".to_string(), ToolGrant { read: vec![s(&w.project)], ..Default::default() }),
            ("file_write".to_string(), ToolGrant { write: vec![s(&w.out)], ..Default::default() }),
        ]);
        let tools: aat::Tools = serde_json::from_value(json!({"file_read": {}, "file_write": {}, "echo": {}})).unwrap();
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let root = node.issue_aat_root_granting(&Jwk::from_key(&key.verifying_key()), tools, &grants, 600, 3).unwrap();
        Agent { key, chain: vec![root] }
    }

    async fn call(&self, node: &mut CleiMeshNode, tool: &str, args: Value) -> ToolResponse {
        let pop = aat::pop(&self.key, self.chain.last().unwrap(), tool, &args, Some(&node.aat_audience()), now()).unwrap();
        let request = ToolRequest {
            tool_name: tool.into(),
            payload: args,
            request_id: uuid::Uuid::new_v4().to_string(),
            capability: None,
            presentation: Some(Presentation { chain: self.chain.clone(), pop }),
            context: None,
        };
        node.run_local("agente", request).await
    }
}

fn components(path: &str) -> Vec<String> {
    path.split('/').map(String::from).collect()
}

#[tokio::test]
async fn the_result_receipt_names_directories_only_by_pseudonym() {
    let w = world();
    let mut node = w.node();
    let agent = Agent::new(&node, &w);
    let contract = w.project.join("clientes/joao-silva/contrato-divorcio.txt");
    assert!(agent.call(&mut node, "file_read", json!({"path": contract})).await.success);
    assert!(agent.call(&mut node, "echo", json!({"message": "oi"})).await.success);
    drop(node);

    let results = w.results();
    let (line, observed) = &results[0];
    for secret in ["joao-silva", "clientes", "contrato-divorcio"] {
        assert!(!line.contains(secret), "{secret} in clear in the receipt: {line}");
    }
    let key = w.node_key();
    let project = w.project.to_string_lossy().into_owned();
    let read = observed["fs"]["grants"].as_array().unwrap().iter().find(|g| g["grant"] == project.as_str()).unwrap();
    assert_eq!(read["read"], json!([fs_dir_pseudonym(&key, &project, &components("clientes/joao-silva"))]));
    assert_eq!((read["files_read"].clone(), read["refused"].clone()), (json!(1), json!(0)));
    assert_eq!(observed["fs"]["truncated"], json!(false));
    // The hierarchy shows: the parent's pseudonym prefixes the child's.
    let parent = fs_dir_pseudonym(&key, &project, &components("clientes"));
    assert!(read["read"][0].as_str().unwrap().starts_with(&format!("{parent}/")));

    let (_, echo) = &results[1];
    assert!(echo.get("fs").is_none(), "a call without directories has no fs block");
}

#[tokio::test]
async fn deep_directories_collapse_to_their_parents() {
    let w = world();
    let deep = w.project.join("a/b/c/d/e");
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::write(deep.join("f.txt"), "x").unwrap();
    let mut node = w.node();
    let agent = Agent::new(&node, &w);
    assert!(agent.call(&mut node, "file_read", json!({"path": deep.join("f.txt")})).await.success);
    drop(node);

    let key = w.node_key();
    let project = w.project.to_string_lossy().into_owned();
    let (_, deep_call) = &w.results()[0];
    let grant = deep_call["fs"]["grants"].as_array().unwrap().iter().find(|g| g["grant"] == project.as_str()).unwrap();
    let cut = components("a/b/c/d")[..FS_MAX_DEPTH].to_vec();
    assert_eq!(grant["read"], json!([fs_dir_pseudonym(&key, &project, &cut)]));
    assert_eq!(deep_call["fs"]["truncated"], json!(true));
}

// C5 acceptance: ten calls that only touch docs/ suggest reading docs/
// alone; the token derived from the suggestion still allows those calls
// and refuses the rest. The unused write tool is dropped.
#[tokio::test]
async fn ten_calls_in_docs_suggest_a_token_for_docs_only() {
    use cleimesh_p2p::grants;
    use cleimesh_p2p::report::Lang;
    use cleimesh_p2p::suggest::{self, Window};

    let w = world();
    let mut node = w.node();
    let agent = Agent::new(&node, &w);
    let guide = json!({"path": w.project.join("docs/guia.md")});
    for _ in 0..10 {
        assert!(agent.call(&mut node, "file_read", guide.clone()).await.success);
    }

    let log = std::fs::read(w.dir.path().join("r.jsonl")).unwrap();
    let leaf = aat::inspect(agent.chain.last().unwrap()).unwrap();
    let tools: Vec<String> = leaf.tools().unwrap().unwrap().keys().cloned().collect();
    let granted = grants::of(&leaf).unwrap();
    let key = w.node_key();
    let found = suggest::suggest(&log, &key.verifying_key(), &key, &leaf.cnf.jwk.thumbprint_uri(), &tools, &granted, &Window::default());
    assert!(found.verified);
    assert_eq!(found.calls, 10);
    let docs = w.project.join("docs").to_string_lossy().into_owned();
    assert_eq!(found.grants()["file_read"].read, vec![docs]);
    assert_eq!(found.kept_tools(), vec!["file_read".to_string()], "file_write and echo were never called");
    assert!(suggest::to_text(&found, Lang::En).contains("never called"));
    assert!(suggest::to_text(&found, Lang::Pt).contains("nunca chamada"));

    // The holder derives the suggested token for itself.
    let kept: aat::Tools = serde_json::from_value(json!({"file_read": {}})).unwrap();
    let child = aat::derive_with(agent.chain.last().unwrap(), &agent.key, &Jwk::from_key(&agent.key.verifying_key()), kept, vec![grants::entry(&found.grants())], now(), 600, None).unwrap();
    let narrower = Agent { key: agent.key.clone(), chain: vec![agent.chain[0].clone(), child] };
    assert!(narrower.call(&mut node, "file_read", guide).await.success, "what the agent used still works");
    let contract = narrower.call(&mut node, "file_read", json!({"path": w.project.join("clientes/joao-silva/contrato-divorcio.txt")})).await;
    assert!(!contract.success, "outside docs/ is refused now");
    assert!(!narrower.call(&mut node, "file_write", json!({"path": w.out.join("x.txt"), "content": "x"})).await.success);
}
