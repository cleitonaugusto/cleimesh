//! Conformance vectors for flow labels on a delegation chain (`taints`,
//! `clean_only`, `when_tainted`): each case gives the labels each link puts on
//! a tool, whether a holder in the chain read untrusted content, and a call;
//! the verdict must match. The suite is read from `FLOW_VECTORS` (skipped when
//! unset). The decision is the node's: the chain must attenuate
//! (`grants::effective`), and a tainted chain calling a clean-only tool must
//! satisfy every link's `when_tainted` (`grants::tainted_admits`).

use cleimesh_p2p::aat::{Claims, Jwk, SigningKey};
use cleimesh_p2p::grants::{self, Grants, ToolGrant};
use serde_json::{json, Value};

fn claims(tool: &str, labels: &Value) -> Result<Claims, String> {
    let jwk = Jwk::from_key(&SigningKey::from_bytes(&[9; 32]).verifying_key());
    let mut details = vec![json!({"type": "attenuating_agent_token", "tools": {tool: {}}})];
    if !labels.is_null() {
        let grant: ToolGrant = serde_json::from_value(labels.clone()).map_err(|e| e.to_string())?;
        details.push(grants::entry(&Grants::from([(tool.to_string(), grant)])));
    }
    serde_json::from_value(json!({
        "jti": "j", "iss": "urn:x", "iat": 0, "exp": 1, "cnf": {"jwk": jwk},
        "del_depth": 0, "del_max_depth": 3, "authorization_details": details,
    }))
    .map_err(|e| e.to_string())
}

fn decide(case: &Value) -> Result<(), String> {
    let tool = case["call"]["tool"].as_str().unwrap();
    let chain = case["links"].as_array().unwrap().iter().map(|l| claims(tool, l)).collect::<Result<Vec<_>, _>>()?;
    let (leaf, _) = grants::effective(&chain, tool)?;
    if case["tainted"] == true && leaf.clean_only {
        grants::tainted_admits(&chain, tool, &case["call"]["arguments"])?;
    }
    Ok(())
}

#[test]
fn flow_label_vectors() {
    let Ok(path) = std::env::var("FLOW_VECTORS") else {
        eprintln!("FLOW_VECTORS not set; skipping the flow-label vector suite");
        return;
    };
    let suite: Value = serde_json::from_slice(&std::fs::read(&path).expect("read FLOW_VECTORS")).expect("suite is JSON");
    let cases = suite["cases"].as_array().expect("cases");
    let mut wrong = Vec::new();
    for case in cases {
        let got = match decide(case) {
            Ok(()) => "permit",
            Err(_) => "deny",
        };
        if got != case["expect"] {
            wrong.push(format!("{}: expected {}, got {} ({:?})", case["id"], case["expect"], got, decide(case).err()));
        }
    }
    assert!(wrong.is_empty(), "{} of {} vectors disagree:\n{}", wrong.len(), cases.len(), wrong.join("\n"));
    eprintln!("flow-label vectors: {}/{} agree", cases.len(), cases.len());
}
