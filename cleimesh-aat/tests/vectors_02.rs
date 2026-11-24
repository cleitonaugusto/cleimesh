//! Conformance against the byte-exact JWS test vectors of
//! draft-niyikiza-oauth-attenuating-agent-tokens-02 (Appendix E.5), the
//! suite published at tenuo-ai/tenuo `tests/vectors/aat-jws-vectors.json`.
//!
//! The suite is not vendored. Point `AAT_VECTORS` at a local copy:
//!
//! ```sh
//! curl -sLo /tmp/aat-jws-vectors.json \
//!   https://raw.githubusercontent.com/tenuo-ai/tenuo/main/tests/vectors/aat-jws-vectors.json
//! AAT_VECTORS=/tmp/aat-jws-vectors.json cargo test -p cleimesh-aat --test vectors_02 -- --nocapture
//! ```
//!
//! Verdicts are compared, not failing steps: the draft lets some steps be
//! reordered (Appendix E.5).

use cleimesh_aat::{verify_json, Jwk, Limits, Policy, Presentation, ReplayGuard, TrustAnchor};
use serde_json::Value;

#[test]
fn draft_02_vectors() {
    let Ok(path) = std::env::var("AAT_VECTORS") else {
        eprintln!("AAT_VECTORS not set; skipping the draft -02 vector suite");
        return;
    };
    let suite: Value = serde_json::from_slice(&std::fs::read(&path).expect("read AAT_VECTORS")).expect("suite is JSON");
    assert_eq!(suite["spec"], "draft-niyikiza-oauth-attenuating-agent-tokens-02");

    let anchors: Vec<TrustAnchor> = suite["trust_anchors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| TrustAnchor { iss: a["iss"].as_str().unwrap().to_string(), jwk: serde_json::from_value::<Jwk>(a["jwk"].clone()).unwrap() })
        .collect();
    let defaults = &suite["params"];

    let (mut pass, mut fail) = (0, Vec::new());
    let vectors = suite["vectors"].as_array().unwrap();
    for v in vectors {
        let id = v["id"].as_str().unwrap();
        let param = |k: &str| v["params"].get(k).or_else(|| defaults.get(k)).cloned().unwrap();
        let int = |k: &str| param(k).as_i64().unwrap();
        let limits = Limits {
            max_iat_skew: int("max_iat_skew"),
            max_token_lifetime: int("max_token_lifetime"),
            max_delegation_depth: int("max_delegation_depth") as u32,
            max_constraint_depth: int("max_constraint_depth") as usize,
            max_token_size: int("max_token_size") as usize,
            max_chain_size: int("max_chain_size") as usize,
            pop_window: int("pop_window"),
        };
        let policy_in = &v["policy"];
        let flag = |k: &str| policy_in.get(k).and_then(Value::as_bool).unwrap_or(false);
        let audience = param("audience");
        let nonce = policy_in.get("nonce").and_then(Value::as_str);
        let policy = Policy {
            trust_anchors: &anchors,
            audience: audience.as_str(),
            require_pop_aud: flag("require_pop_aud"),
            require_chain_aud: flag("require_chain_aud"),
            nonces: nonce.as_ref().map(std::slice::from_ref).unwrap_or(&[]),
            require_nonce: nonce.is_some(),
            now: v["now"].as_i64().unwrap(),
            limits,
        };
        let presentation = Presentation {
            chain: v["presentation"]["aat_chain"].as_array().unwrap().iter().map(|t| t.as_str().unwrap().to_string()).collect(),
            pop: v["presentation"]["aat_pop"].as_str().unwrap().to_string(),
        };
        let tool = v["tool"].as_str().unwrap();
        let args = v["args_json"].as_str().unwrap();

        let mut outcome = verify_json(&presentation, &policy, tool, args);
        if flag("track_pop_jti") {
            let mut guard = ReplayGuard::new();
            for seen in v["replay_state"]["before"].as_array().unwrap() {
                guard.remember(seen.as_str().unwrap(), policy.now);
            }
            outcome = outcome.and_then(|ok| guard.check(&ok, policy.now).map(|()| ok));
        }

        let expected = v["expected"]["verdict"].as_str().unwrap();
        let got = if outcome.is_ok() { "PERMIT" } else { "DENY" };
        if std::env::var_os("AAT_VECTORS_VERBOSE").is_some() {
            let why = outcome.as_ref().err().map(|e| e.0.clone()).unwrap_or_default();
            eprintln!("{id}\t{expected}\t{}\t{why}", v["expected"]["step"]);
        }
        if got == expected {
            pass += 1;
        } else {
            let why = outcome.err().map(|e| e.0).unwrap_or_default();
            fail.push(format!("{id} [{}] expected {expected} (step {}), got {got} {why}", v["title"].as_str().unwrap(), v["expected"]["step"]));
        }
    }
    eprintln!("draft -02 vectors: {pass}/{} agree", vectors.len());
    for f in &fail {
        eprintln!("  MISMATCH {f}");
    }
    assert!(fail.is_empty(), "{} of {} vectors disagree", fail.len(), vectors.len());
}
