//! Property tests (S17): for random chains of sandbox
//! grants, whatever `grants::effective` accepts gives the leaf nothing that
//! any token above it did not grant.

use cleimesh_p2p::aat::{Claims, Constraint, Jwk, SigningKey};
use cleimesh_p2p::grants::{self, Grants, ToolGrant};
use proptest::prelude::*;
use std::path::Path;

const DIRS: &[&str] = &["/r", "/r/a", "/r/a/b", "/r/b", "/r/ab", "/s"];

fn dirs() -> impl Strategy<Value = Vec<String>> {
    prop::sample::subsequence(DIRS.to_vec(), 0..3).prop_map(|d| d.into_iter().map(String::from).collect())
}

const HOSTS: &[&str] = &["api.example", "API.example.", "api.example:8443", "cdn.example", "evil.example"];

fn hosts() -> impl Strategy<Value = Vec<String>> {
    prop::sample::subsequence(HOSTS.to_vec(), 0..3).prop_map(|h| h.into_iter().map(String::from).collect())
}

fn grant() -> impl Strategy<Value = ToolGrant> {
    let limit = prop::option::of(prop::sample::select(vec![10u64, 100, 1000]));
    let to = prop::option::of(prop::sample::subsequence(vec!["a@corp.test", "b@corp.test", "x@evil.test"], 0..=3));
    let flow = (any::<bool>(), any::<bool>(), hosts(), any::<bool>(), to);
    (dirs(), dirs(), any::<bool>(), limit.clone(), limit.clone(), limit, flow).prop_map(|(read, write, network, i, m, t, (taints, clean_only, hosts, private, to))| ToolGrant {
        read,
        write,
        network,
        hosts,
        private,
        max_instructions: i,
        max_memory_bytes: m.map(|m| m as usize),
        timeout_ms: t,
        taints,
        clean_only,
        // Only a clean_only grant may carry it (`of` refuses it otherwise).
        when_tainted: match to {
            Some(to) if clean_only => [("to".to_string(), Constraint::one_of(to))].into(),
            _ => Default::default(),
        },
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
            for host in &leaf.hosts {
                prop_assert!(token.hosts.iter().any(|t| cleimesh_wasm_sandbox::egress::grant_covers(t, host)), "leaf fetches {} beyond {:?}", host, token);
            }
            prop_assert!(!leaf.private || token.private, "private shed below {:?}", token);
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

    /// A tainted chain lets a call through only if every link that keeps the
    /// tool clean_only would: a link can't widen what an earlier one allowed.
    #[test]
    fn tainted_chain_admits_only_what_every_clean_only_link_allows(
        chain in prop::collection::vec(prop::option::of(grant()), 1..4),
        to in prop::sample::select(vec!["a@corp.test", "b@corp.test", "x@evil.test"]),
        extra in any::<bool>(),
    ) {
        let tokens: Vec<Claims> = chain.iter().map(claims).collect();
        if grants::effective(&tokens, "file_read").is_err() { return Ok(()); }
        let mut args = serde_json::json!({"to": to});
        if extra { args["bcc"] = serde_json::json!("x@evil.test"); }
        if grants::tainted_admits(&tokens, "file_read", &args).is_ok() {
            prop_assert!(!extra, "an unlisted argument went through");
            let mut any = false;
            for link in chain.iter().flatten().filter(|g| g.clean_only) {
                any = true;
                let c = link.when_tainted.get("to");
                prop_assert!(c.is_some_and(|c| c.check(&serde_json::json!(to))), "{} admitted beyond {:?}", to, link);
            }
            prop_assert!(any, "admitted with no clean_only link");
        }
    }
}
