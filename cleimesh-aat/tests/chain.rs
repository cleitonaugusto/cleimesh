//! Delegation chains A → B → C (S4), against
//! draft-niyikiza-oauth-attenuating-agent-tokens-01.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use cleimesh_aat::*;
use ed25519_dalek::Signer;
use serde_json::{json, Value};

const NOW: i64 = 1_800_000_000;
const NODE: &str = "urn:cleimesh:node:A";

fn key() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

fn jwk(key: &SigningKey) -> Jwk {
    Jwk::from_key(&key.verifying_key())
}

fn tools(v: Value) -> Tools {
    serde_json::from_value(v).unwrap()
}

/// Signs arbitrary claims, bypassing the checks of `derive`: how an attacker
/// would build a token.
fn sign_raw(key: &SigningKey, claims: &Value) -> String {
    let input = format!("{}.{}", URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA"}"#), URL_SAFE_NO_PAD.encode(claims.to_string()));
    format!("{}.{}", input, URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).to_bytes()))
}

fn payload(token: &str) -> Value {
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token.split('.').nth(1).unwrap()).unwrap()).unwrap()
}

fn par_hash(token: &str) -> String {
    let input = token.rsplit_once('.').unwrap().0;
    URL_SAFE_NO_PAD.encode(<sha2::Sha256 as sha2::Digest>::digest(input.as_bytes()))
}

struct Chain {
    a: SigningKey,
    c: SigningKey,
    root: String,
    child: String,
}

/// A (the node, trust anchor) grants B `echo` with any message and `add`
/// with a ≤ 10; B derives for C `echo` limited to "hello".
fn chain() -> Chain {
    let (a, b, c) = (key(), key(), key());
    let root = issue_root(&a, NODE, &jwk(&b), tools(json!({"echo": {"message": {"constraint_type": "wildcard"}}, "add": {}})), NOW, 3600, 3).unwrap();
    let child = derive(&root, &b, &jwk(&c), tools(json!({"echo": {"message": {"constraint_type": "exact", "value": "hello"}}})), NOW, 600, None).unwrap();
    Chain { a, c, root, child }
}

fn present(chain: &Chain, tool: &str, args: &Value, aud: Option<&str>) -> Presentation {
    Presentation { chain: vec![chain.root.clone(), chain.child.clone()], pop: pop(&chain.c, &chain.child, tool, args, aud, NOW).unwrap() }
}

fn check(chain: &Chain, p: &Presentation, tool: &str, args: &Value) -> Result<Verified> {
    let anchors = [jwk(&chain.a)];
    verify(p, &Policy { trust_anchors: &anchors, audience: Some("node-A"), now: NOW }, tool, args)
}

fn denied(r: Result<Verified>, why: &str) {
    match r {
        Ok(_) => panic!("accepted, expected denial containing {why:?}"),
        Err(e) => assert!(e.0.contains(why), "denied for {:?}, expected {:?}", e.0, why),
    }
}

#[test]
fn delegated_chain_authorizes_the_narrowed_call() {
    let ch = chain();
    let args = json!({"message": "hello"});
    let v = check(&ch, &present(&ch, "echo", &args, Some("node-A")), "echo", &args).unwrap();
    assert_eq!(v.leaf.del_depth, 1);
    assert_eq!(v.root.iss, NODE);
}

#[test]
fn leaf_constraints_bind_the_call() {
    let ch = chain();
    let other = json!({"message": "bye"});
    denied(check(&ch, &present(&ch, "echo", &other, Some("node-A")), "echo", &other), "out of bounds");
    let extra = json!({"message": "hello", "x": 1});
    denied(check(&ch, &present(&ch, "echo", &extra, Some("node-A")), "echo", &extra), "not allowed");
    // `add` was granted to B but not passed on to C.
    let add = json!({"a": 1});
    denied(check(&ch, &present(&ch, "add", &add, Some("node-A")), "add", &add), "not granted");
}

#[test]
fn forged_link_is_refused() {
    let ch = chain();
    // C makes itself a child of the root, signing with its own key.
    let forged = sign_raw(&ch.c, &json!({
        "jti": "forged", "iss": jwk(&ch.c).thumbprint_uri(), "iat": NOW, "exp": NOW + 60,
        "cnf": {"jwk": jwk(&ch.c)}, "del_depth": 1, "del_max_depth": 3, "par_hash": par_hash(&ch.root),
        "authorization_details": [{"type": "attenuating_agent_token", "tools": {"add": {}}}]
    }));
    let args = json!({"a": 1});
    let p = Presentation { chain: vec![ch.root.clone(), forged.clone()], pop: pop(&ch.c, &forged, "add", &args, Some("node-A"), NOW).unwrap() };
    denied(check(&ch, &p, "add", &args), "bad signature");
    // A chain that does not start at a trust anchor.
    let p = Presentation { chain: vec![forged.clone()], pop: pop(&ch.c, &forged, "add", &args, Some("node-A"), NOW).unwrap() };
    denied(check(&ch, &p, "add", &args), "trust anchor");
}

#[test]
fn widening_link_is_refused() {
    let (a, b, c) = (key(), key(), key());
    let root = issue_root(&a, NODE, &jwk(&b), tools(json!({"add": {"a": {"constraint_type": "range", "max": 10}}})), NOW, 3600, 3).unwrap();
    // `derive` refuses to build it...
    let wider = tools(json!({"add": {"a": {"constraint_type": "range", "max": 100}}}));
    assert!(derive(&root, &b, &jwk(&c), wider.clone(), NOW, 60, None).unwrap_err().0.contains("widened"));
    assert!(derive(&root, &b, &jwk(&c), tools(json!({"rm": {}})), NOW, 60, None).unwrap_err().0.contains("not granted"));
    // ...and a hand-signed one is refused by the verifier.
    let child = sign_raw(&b, &json!({
        "jti": "wide", "iss": jwk(&b).thumbprint_uri(), "iat": NOW, "exp": NOW + 60,
        "cnf": {"jwk": jwk(&c)}, "del_depth": 1, "del_max_depth": 3, "par_hash": par_hash(&root),
        "authorization_details": [{"type": "attenuating_agent_token", "tools": wider}]
    }));
    let args = json!({"a": 50});
    let p = Presentation { chain: vec![root, child.clone()], pop: pop(&c, &child, "add", &args, None, NOW).unwrap() };
    let anchors = [jwk(&a)];
    denied(verify(&p, &Policy { trust_anchors: &anchors, audience: None, now: NOW }, "add", &args), "widened");
}

#[test]
fn child_bound_to_another_parent_is_refused() {
    let (a, b, c) = (key(), key(), key());
    let grant = tools(json!({"add": {}}));
    let root1 = issue_root(&a, NODE, &jwk(&b), grant.clone(), NOW, 3600, 3).unwrap();
    let root2 = issue_root(&a, NODE, &jwk(&b), grant.clone(), NOW, 3600, 3).unwrap();
    let child = derive(&root1, &b, &jwk(&c), grant, NOW, 60, None).unwrap();
    let args = json!({});
    let p = Presentation { chain: vec![root2, child.clone()], pop: pop(&c, &child, "add", &args, None, NOW).unwrap() };
    let anchors = [jwk(&a)];
    denied(verify(&p, &Policy { trust_anchors: &anchors, audience: None, now: NOW }, "add", &args), "par_hash");
}

#[test]
fn depth_ceiling_holds() {
    let (a, b, c, d) = (key(), key(), key(), key());
    let grant = tools(json!({"add": {}}));
    let root = issue_root(&a, NODE, &jwk(&b), grant.clone(), NOW, 3600, 1).unwrap();
    let child = derive(&root, &b, &jwk(&c), grant.clone(), NOW, 60, None).unwrap();
    assert!(derive(&child, &c, &jwk(&d), grant.clone(), NOW, 60, None).unwrap_err().0.contains("deeper"));
    assert!(derive(&root, &b, &jwk(&c), grant, NOW, 60, Some(2)).unwrap_err().0.contains("raised"));
}

#[test]
fn only_the_holder_can_derive() {
    let ch = chain();
    let intruder = key();
    let err = derive(&ch.root, &intruder, &jwk(&intruder), tools(json!({"add": {}})), NOW, 60, None).unwrap_err();
    assert!(err.0.contains("does not hold"), "{err}");
}

#[test]
fn proof_of_possession_binds_holder_call_and_audience() {
    let ch = chain();
    let args = json!({"message": "hello"});
    // Signed by someone else than the leaf holder.
    let p = Presentation { chain: vec![ch.root.clone(), ch.child.clone()], pop: pop(&key(), &ch.child, "echo", &args, Some("node-A"), NOW).unwrap() };
    denied(check(&ch, &p, "echo", &args), "bad signature");
    denied(check(&ch, &present(&ch, "echo", &args, Some("node-B")), "echo", &args), "audience");
    denied(check(&ch, &present(&ch, "echo", &args, None), "echo", &args), "audience");
    // A proof made for other arguments than the ones executed.
    let p = present(&ch, "echo", &args, Some("node-A"));
    let other = json!({"message": "hello", "extra": true});
    assert!(check(&ch, &p, "echo", &other).is_err());
    // Stale proof.
    let p = Presentation { chain: p.chain.clone(), pop: pop(&ch.c, &ch.child, "echo", &args, Some("node-A"), NOW - 120).unwrap() };
    denied(check(&ch, &p, "echo", &args), "stale");
}

#[test]
fn arguments_compare_canonically() {
    let (a, b) = (key(), key());
    let root = issue_root(&a, NODE, &jwk(&b), tools(json!({"add": {"n": {"constraint_type": "exact", "value": 1}}})), NOW, 3600, 0).unwrap();
    let p = Presentation { chain: vec![root.clone()], pop: pop(&b, &root, "add", &json!({"n": 1.0}), None, NOW).unwrap() };
    let anchors = [jwk(&a)];
    verify(&p, &Policy { trust_anchors: &anchors, audience: None, now: NOW }, "add", &json!({"n": 1})).unwrap();
}

#[test]
fn replayed_proof_is_refused_once_seen() {
    let ch = chain();
    let args = json!({"message": "hello"});
    let p = present(&ch, "echo", &args, Some("node-A"));
    let mut guard = ReplayGuard::new();
    guard.check(&check(&ch, &p, "echo", &args).unwrap(), NOW).unwrap();
    assert!(guard.check(&check(&ch, &p, "echo", &args).unwrap(), NOW).unwrap_err().0.contains("replayed"));
    // A fresh proof for the same call is fine.
    guard.check(&check(&ch, &present(&ch, "echo", &args, Some("node-A")), "echo", &args).unwrap(), NOW).unwrap();
}

#[test]
fn time_bounds_hold() {
    let ch = chain();
    let args = json!({"message": "hello"});
    let p = present(&ch, "echo", &args, Some("node-A"));
    let anchors = [jwk(&ch.a)];
    let late = NOW + 601;
    let p_late = Presentation { chain: p.chain.clone(), pop: pop(&ch.c, &ch.child, "echo", &args, Some("node-A"), late).unwrap() };
    denied(verify(&p_late, &Policy { trust_anchors: &anchors, audience: Some("node-A"), now: late }, "echo", &args), "expired");
    // The child is clamped to its parent's lifetime.
    let (a, b, c) = (key(), key(), key());
    let root = issue_root(&a, NODE, &jwk(&b), tools(json!({"add": {}})), NOW, 60, 3).unwrap();
    let child = derive(&root, &b, &jwk(&c), tools(json!({"add": {}})), NOW, 3600, None).unwrap();
    assert_eq!(payload(&child)["exp"], payload(&root)["exp"]);
}

#[test]
fn malformed_tokens_are_refused() {
    let ch = chain();
    let args = json!({});
    let anchors = [jwk(&ch.a)];
    let policy = Policy { trust_anchors: &anchors, audience: None, now: NOW };
    let base = json!({
        "jti": "r", "iss": NODE, "iat": NOW, "exp": NOW + 60, "cnf": {"jwk": jwk(&ch.c)},
        "del_depth": 0, "del_max_depth": 0,
        "authorization_details": [{"type": "attenuating_agent_token", "tools": {"add": {}}}]
    });
    let with = |f: &dyn Fn(&mut Value)| {
        let mut claims = base.clone();
        f(&mut claims);
        let root = sign_raw(&ch.a, &claims);
        let pop = pop(&ch.c, &root, "add", &args, None, NOW).unwrap();
        verify(&Presentation { chain: vec![root], pop }, &policy, "add", &args)
    };
    with(&|_| {}).unwrap();
    denied(with(&|c| c["authorization_details"][0]["tools"]["add"] = json!({"a": {"constraint_type": "regex", "pattern": ".*"}})), "invalid claims");
    denied(with(&|c| c["cnf"]["jwk"]["d"] = json!("secret")), "private key");
    denied(with(&|c| c["iss"] = json!("not a uri")), "URI");
    denied(with(&|c| c["authorization_details"] = json!([])), "no attenuating_agent_token");
    denied(with(&|c| c["del_max_depth"] = json!(99)), "implementation limit");
    denied(with(&|c| { c["authorization_details"].as_array_mut().unwrap().push(base["authorization_details"][0].clone()); }), "more than one");
    // Other authorization_details types are ignored.
    with(&|c| { c["authorization_details"].as_array_mut().unwrap().push(json!({"type": "payment", "amount": 1})); }).unwrap();
    // Unknown top-level claims are ignored (passthrough metadata).
    with(&|c| c["cleimesh_sandbox"] = json!({"net": false})).unwrap();

    // Duplicate keys, which serde_json would silently collapse.
    let dup = base.to_string().replacen(r#""tools":{"add":{}}"#, r#""tools":{"add":{},"add":{"a":{"constraint_type":"exact","value":1}}}"#, 1);
    assert!(dup.contains(r#""add":{},"add""#));
    let input = format!("{}.{}", URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA"}"#), URL_SAFE_NO_PAD.encode(&dup));
    let root = format!("{}.{}", input, URL_SAFE_NO_PAD.encode(ch.a.sign(input.as_bytes()).to_bytes()));
    let pop_dup = pop(&ch.c, &root, "add", &args, None, NOW).unwrap();
    denied(verify(&Presentation { chain: vec![root], pop: pop_dup }, &policy, "add", &args), "duplicate key");

    // alg none, or anything but EdDSA.
    let good = sign_raw(&ch.a, &base);
    let none = format!("{}.{}.", URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#), good.split('.').nth(1).unwrap());
    let pop_none = pop(&ch.c, &good, "add", &args, None, NOW).unwrap();
    assert!(verify(&Presentation { chain: vec![none], pop: pop_none }, &policy, "add", &args).is_err());
}

/// RFC 8037 appendix A: the JWK thumbprint and the EdDSA JWS of the
/// specification's example key.
#[test]
fn rfc8037_vectors() {
    let d: [u8; 32] = URL_SAFE_NO_PAD.decode("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A").unwrap().try_into().unwrap();
    let key = SigningKey::from_bytes(&d);
    let jwk = jwk(&key);
    assert_eq!(jwk.x, "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
    assert_eq!(jwk.thumbprint_uri(), "urn:ietf:params:oauth:jwk-thumbprint:sha-256:kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
    let input = format!("{}.{}", URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA"}"#), URL_SAFE_NO_PAD.encode("Example of Ed25519 signing"));
    let jws = format!("{}.{}", input, URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).to_bytes()));
    assert_eq!(jws, "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg");
}
