//! LGPD reports (C3), acceptance scenario: two data
//! subjects and two agents; each report lists exactly the right operations,
//! and no receipt carries the subjects' ids.

use cleimesh_core::AgentIdentity;
use cleimesh_p2p::aat::{self, Jwk, Presentation, SigningKey};
use cleimesh_p2p::report::{self, Filter};
use cleimesh_p2p::{subject_pseudonym, CallContext, CleiMeshNode, P2PConfig, ToolRequest};
use serde_json::json;

const T1: &str = "cpf:529.982.247-25";
const T2: &str = "cpf:111.444.777-35";

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

struct Agent {
    key: SigningKey,
    chain: Vec<String>,
}

impl Agent {
    fn new(node: &CleiMeshNode, tools: serde_json::Value) -> Agent {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let chain = vec![node.issue_aat_root(&Jwk::from_key(&key.verifying_key()), serde_json::from_value(tools).unwrap(), 600, 0).unwrap()];
        Agent { key, chain }
    }

    fn holder(&self) -> String {
        Jwk::from_key(&self.key.verifying_key()).thumbprint_uri()
    }

    fn request(&self, node: &CleiMeshNode, tool: &str, subject: Option<&str>, purpose: Option<&str>) -> ToolRequest {
        let args = json!({"message": "oi"});
        let pop = aat::pop(&self.key, &self.chain[0], tool, &args, Some(&node.aat_audience()), now()).unwrap();
        ToolRequest {
            tool_name: tool.into(),
            payload: args,
            request_id: uuid::Uuid::new_v4().to_string(),
            capability: None,
            presentation: Some(Presentation { chain: self.chain.clone(), pop }),
            context: Some(CallContext { data_subject: subject.map(String::from), purpose: purpose.map(String::from) }),
        }
    }
}

struct Scenario {
    _dir: tempfile::TempDir,
    log: Vec<u8>,
    node_key: SigningKey,
    a: Agent,
    b: Agent,
}

/// Node key fixed so the test can compute pseudonyms like `audit report` does.
async fn scenario() -> Scenario {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("node.key");
    let receipts = dir.path().join("r.jsonl");
    let config = P2PConfig { listen_addresses: vec![], enable_mdns: false, identity_key_path: Some(key_path.clone()), receipts_path: Some(receipts.clone()), ..P2PConfig::default() };
    let mut node = CleiMeshNode::new(config, AgentIdentity::new("t")).unwrap();
    let node_key = cleimesh_p2p::node_key::aat_signing_key(&cleimesh_p2p::node_key::load_or_generate(&key_path).unwrap()).unwrap();

    let a = Agent::new(&node, json!({"echo": {}}));
    let b = Agent::new(&node, json!({"echo": {}}));
    for (agent, tool, subject, purpose, ok) in [
        (&a, "echo", Some(T1), Some("atendimento"), true),
        (&a, "echo", Some(T2), Some("cobrança"), true),
        (&a, "echo", Some(T1), Some("atendimento"), true),
        (&b, "file_read", Some(T2), Some("marketing"), false),
        (&b, "echo", None, None, true),
    ] {
        let request = agent.request(&node, tool, subject, purpose);
        let response = node.run_local("teste", request).await;
        assert_eq!(response.success, ok, "{tool} for {subject:?}: {:?}", response.error);
    }
    Scenario { log: std::fs::read(&receipts).unwrap(), _dir: dir, node_key, a, b }
}

fn ops(s: &Scenario, filter: Filter) -> Vec<report::Operation> {
    let r = report::build(&s.log, &s.node_key.verifying_key(), &filter);
    assert!(r.verified, "{:?}", r.failures);
    r.operations
}

#[tokio::test]
async fn report_per_data_subject_lists_exactly_their_operations() {
    let s = scenario().await;
    let t1 = ops(&s, Filter { data_subject: Some(subject_pseudonym(&s.node_key, T1)), ..Filter::default() });
    assert_eq!(t1.len(), 2);
    assert!(t1.iter().all(|o| o.holder.as_deref() == Some(s.a.holder().as_str()) && o.purpose.as_deref() == Some("atendimento") && o.succeeded == Some(true)));

    let t2 = ops(&s, Filter { data_subject: Some(subject_pseudonym(&s.node_key, T2)), ..Filter::default() });
    assert_eq!(t2.len(), 2);
    assert_eq!(t2[0].holder.as_deref(), Some(s.a.holder().as_str()));
    assert_eq!(t2[1].decision, "denied");
    assert_eq!(t2[1].holder, None, "a denied call has no verified holder");
    assert!(t2[1].denial.as_deref().unwrap().contains("not granted"));
}

#[tokio::test]
async fn report_per_agent_is_its_record_of_operations() {
    let s = scenario().await;
    let a = ops(&s, Filter { agent: Some(s.a.holder()), ..Filter::default() });
    assert_eq!(a.len(), 3);
    // B's allowed call is attributed to its key; its denied call never got
    // that far, so the report names it by caller only.
    let b = ops(&s, Filter { agent: Some(s.b.holder()), ..Filter::default() });
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].tool, "echo");
}

#[tokio::test]
async fn receipts_never_hold_the_subject_id_and_pseudonyms_depend_on_the_node_key() {
    let s = scenario().await;
    let text = String::from_utf8(s.log.clone()).unwrap();
    assert!(!text.contains("529.982") && !text.contains("111.444"), "a receipt holds a subject id");
    let other = SigningKey::generate(&mut rand::rngs::OsRng);
    assert_ne!(subject_pseudonym(&s.node_key, T1), subject_pseudonym(&other, T1));
    assert_ne!(subject_pseudonym(&s.node_key, T1), subject_pseudonym(&s.node_key, T2));
}

#[tokio::test]
async fn markdown_report_reads_in_portuguese_and_a_tampered_log_is_flagged() {
    let s = scenario().await;
    let pseudonym = subject_pseudonym(&s.node_key, T2);
    let built = report::build(&s.log, &s.node_key.verifying_key(), &Filter { data_subject: Some(pseudonym.clone()), ..Filter::default() });
    let md = report::to_markdown(&built, "node", Some(&pseudonym), None, report::Lang::Pt);
    for expected in ["# Relatório de tratamento por titular", "íntegro", "Operações: 2 (1 permitidas, 1 negadas", "cobrança", "negada: Authorization failed", "nenhum arquivo, sem rede"] {
        assert!(md.contains(expected), "missing {expected:?} in:\n{md}");
    }

    let tampered = String::from_utf8(s.log.clone()).unwrap().replacen("\"decision\":\"denied\"", "\"decision\":\"allowed\"", 1);
    let flagged = report::build(tampered.as_bytes(), &s.node_key.verifying_key(), &Filter::default());
    assert!(!flagged.verified);
    assert!(report::to_markdown(&flagged, "node", None, None, report::Lang::Pt).contains("NÃO passou na verificação"));
    assert!(report::to_markdown(&flagged, "node", None, None, report::Lang::En).contains("did NOT pass verification"));
}

#[tokio::test]
async fn oversized_purpose_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let config = P2PConfig { listen_addresses: vec![], enable_mdns: false, receipts_path: Some(dir.path().join("r.jsonl")), ..P2PConfig::default() };
    let mut node = CleiMeshNode::new(config, AgentIdentity::new("t")).unwrap();
    let a = Agent::new(&node, json!({"echo": {}}));
    let long = "x".repeat(201);
    let response = node.run_local("teste", a.request(&node, "echo", None, Some(&long))).await;
    assert!(!response.success);
    assert!(response.error.unwrap().contains("purpose longer than 200"));
    let log = std::fs::read_to_string(dir.path().join("r.jsonl")).unwrap();
    assert!(!log.contains(&long), "the oversized purpose went into the receipt");
}
