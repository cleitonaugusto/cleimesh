//! Property tests (S17): for random chains of sandbox
//! grants, whatever `grants::effective` accepts gives the leaf nothing that
//! any token above it did not grant.

use cleimesh_p2p::aat::{Claims, Jwk, SigningKey};
use cleimesh_p2p::grants::{self, Grants, ToolGrant};
use proptest::prelude::*;
use std::path::Path;

const DIRS: &[&str] = &["/r", "/r/a", "/r/a/b", "/r/b", "/r/ab", "/s"];

fn dirs() -> impl Strategy<Value = Vec<String>> {
    prop::sample::subsequence(DIRS.to_vec(), 0..3).prop_map(|d| d.into_iter().map(String::from).collect())
}

fn grant() -> impl Strategy<Value = ToolGrant> {
    let limit = prop::option::of(prop::sample::select(vec![10u64, 100, 1000]));
    (dirs(), dirs(), any::<bool>(), limit.clone(), limit.clone(), limit, any::<bool>(), any::<bool>()).prop_map(|(read, write, network, i, m, t, taints, clean_only)| ToolGrant {
        read,
        write,
        network,
        max_instructions: i,
        max_memory_bytes: m.map(|m| m as usize),
        timeout_ms: t,
        taints,
        clean_only,
    })
}

fn claims(grant: &Option<ToolGrant>) -> Claims {
    let jwk = Jwk::from_key(&SigningKey::from_bytes(&[9; 32]).verifying_key());
    let mut details = vec![serde_json::json!({"type": "attenuating_agent_token", "tools": {"file_read": {}}})];
    if let Some(g) = grant {
        details.push(grants::entry(&Grants::from([("file_read".to_string(), g.clone())])));
    }
    serde_json::from_value(serde_json::json!({
        "jti": "j", "iss": "urn:x", "iat": 0, "exp": 1, "cnf": {"jwk": jwk},
        "del_depth": 0, "del_max_depth": 3, "authorization_details": details,
    }))
    .unwrap()
}

fn under(dir: &str, of: &[String]) -> bool {
    of.iter().any(|p| Path::new(dir).starts_with(p))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 20_000, ..ProptestConfig::default() })]

    #[test]
    fn accepted_chain_never_widens(chain in prop::collection::vec(prop::option::of(grant()), 1..4)) {
        let tokens: Vec<Claims> = chain.iter().map(claims).collect();
        let Ok((leaf, root)) = grants::effective(&tokens, "file_read") else { return Ok(()) };
        prop_assert_eq!(&root, &chain[0].clone().unwrap_or_default());
        for token in chain.iter().map(|g| g.clone().unwrap_or_default()) {
            let readable: Vec<String> = token.read.iter().chain(&token.write).cloned().collect();
            for dir in &leaf.read {
                prop_assert!(under(dir, &readable), "leaf reads {} beyond {:?}", dir, token);
            }
            for dir in &leaf.write {
                prop_assert!(under(dir, &token.write), "leaf writes {} beyond {:?}", dir, token);
            }
            prop_assert!(!leaf.network || token.network);
            // Flow restrictions only ever accumulate down the chain.
            prop_assert!(!token.taints || leaf.taints, "taints shed below {:?}", token);
            prop_assert!(!token.clean_only || leaf.clean_only, "clean_only shed below {:?}", token);
            for (l, t) in [(leaf.max_instructions, token.max_instructions), (leaf.timeout_ms, token.timeout_ms), (leaf.max_memory_bytes.map(|m| m as u64), token.max_memory_bytes.map(|m| m as u64))] {
                if let Some(t) = t {
                    prop_assert!(l.is_some_and(|l| l <= t), "limit {:?} above {}", l, t);
                }
            }
        }
    }
}
