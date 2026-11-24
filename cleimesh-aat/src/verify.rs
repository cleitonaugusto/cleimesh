//! Chain verification, draft -02 section 8. Step numbers in comments refer to it.

use std::collections::{HashMap, HashSet};

use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::{Map, Value};

use crate::constraint::{Constraint, MAX_CONSTRAINT_DEPTH};
use crate::grant::{admissible_numbers, grant, Grant};
use crate::jws::{Compact, Jwk, AAT_TYP, POP_TYP};
use crate::token::{is_uri, reject_duplicate_keys, Claims, PopClaims, Presentation};
use crate::{deny, Result, MAX_DELEGATION_DEPTH, MAX_IAT_SKEW, MAX_STACK_SIZE, MAX_TOKEN_LIFETIME, MAX_TOKEN_SIZE, POP_IAT_TOLERANCE};

/// A root issuer the enforcement point trusts: its key and the `iss` its
/// root tokens must carry (step 3k).
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    pub iss: String,
    pub jwk: Jwk,
}

impl TrustAnchor {
    pub fn new(iss: impl Into<String>, jwk: Jwk) -> Self {
        TrustAnchor { iss: iss.into(), jwk }
    }

    /// An anchor named by its own key: `iss` is the key's RFC 9278
    /// thumbprint URI, the same name derived tokens use. For a deployment
    /// where the key is the identity (a single owner signing its own
    /// allowances); step 3k still applies.
    pub fn for_key(jwk: Jwk) -> Self {
        TrustAnchor { iss: jwk.thumbprint_uri(), jwk }
    }
}

/// The implementation-defined limits of section 8.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_iat_skew: i64,
    pub max_token_lifetime: i64,
    pub max_delegation_depth: u32,
    pub max_constraint_depth: usize,
    pub max_token_size: usize,
    pub max_chain_size: usize,
    /// Accepted distance between a proof of possession's `iat` and now.
    pub pop_window: i64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_iat_skew: MAX_IAT_SKEW,
            max_token_lifetime: MAX_TOKEN_LIFETIME,
            max_delegation_depth: MAX_DELEGATION_DEPTH,
            max_constraint_depth: MAX_CONSTRAINT_DEPTH,
            max_token_size: MAX_TOKEN_SIZE,
            max_chain_size: MAX_STACK_SIZE,
            pop_window: POP_IAT_TOLERANCE,
        }
    }
}

/// What the enforcement point trusts and requires.
pub struct Policy<'a> {
    /// Root issuers whose tokens are honored.
    pub trust_anchors: &'a [TrustAnchor],
    /// This enforcement point's audience identifier. A chain `aud` or a
    /// proof's `aat_aud`, when present, must equal it.
    pub audience: Option<&'a str>,
    /// Refuse a proof of possession without `aat_aud` (step 7d).
    pub require_pop_aud: bool,
    /// Refuse a chain in which no token carries `aud` (step 6c).
    pub require_chain_aud: bool,
    /// Nonces this enforcement point issued and still accepts (step 7h).
    pub nonces: &'a [&'a str],
    /// Refuse a proof of possession without one of `nonces`.
    pub require_nonce: bool,
    /// Current time, in seconds since the epoch.
    pub now: i64,
    pub limits: Limits,
}

impl<'a> Policy<'a> {
    /// No audience, nonce or chain-audience requirement; default limits.
    pub fn new(trust_anchors: &'a [TrustAnchor], now: i64) -> Self {
        Policy { trust_anchors, audience: None, require_pop_aud: false, require_chain_aud: false, nonces: &[], require_nonce: false, now, limits: Limits::default() }
    }

    /// Requires proofs of possession addressed to `audience`.
    pub fn for_audience(trust_anchors: &'a [TrustAnchor], audience: &'a str, now: i64) -> Self {
        Policy { audience: Some(audience), require_pop_aud: true, ..Policy::new(trust_anchors, now) }
    }
}

/// A chain that passed, with what a caller needs for replay tracking and
/// for the execution receipt.
#[derive(Debug, Clone)]
pub struct Verified {
    pub root: Claims,
    pub leaf: Claims,
    /// Every token's claims, root first, for extensions that attenuate
    /// along the chain.
    pub chain: Vec<Claims>,
    pub pop_jti: String,
    pub pop_iat: i64,
}

/// Verifies that `presentation` authorizes calling `tool` with `args`.
/// `args` is already parsed, so duplicate members were lost on the way;
/// when the arguments arrive as text, [`verify_json`] checks them as written.
pub fn verify(presentation: &Presentation, policy: &Policy, tool: &str, args: &Value) -> Result<Verified> {
    verify_json(presentation, policy, tool, &serde_json::to_string(args)?)
}

/// Verifies that `presentation` authorizes calling `tool` with the JSON
/// object `args_json`, read as written: duplicate members and numbers that
/// do not survive JCS are refused (step 6b).
pub fn verify_json(presentation: &Presentation, policy: &Policy, tool: &str, args_json: &str) -> Result<Verified> {
    let limits = &policy.limits;
    let chain = &presentation.chain;
    // 1.
    if chain.is_empty() {
        return Err(deny("empty chain"));
    }
    // 2a, 2b.
    if chain.iter().any(|t| t.len() > limits.max_token_size) {
        return Err(deny("token too large"));
    }
    if chain.iter().map(String::len).sum::<usize>() > limits.max_chain_size {
        return Err(deny("chain too large"));
    }
    let compacts = chain.iter().map(|t| Compact::parse(t)).collect::<Result<Vec<_>>>()?;
    // 2c. Cycle detection on untrusted jti values.
    let mut jtis = HashSet::new();
    for c in &compacts {
        if !jtis.insert(c.unverified_jti()?) {
            return Err(deny("token repeated in chain"));
        }
    }

    // 3a, 3b. Header, then the signature, then parse.
    compacts[0].check_header(AAT_TYP)?;
    let (root_payload, anchor) = policy
        .trust_anchors
        .iter()
        .find_map(|anchor| compacts[0].verify(&anchor.jwk, AAT_TYP).ok().map(|p| (p, anchor)))
        .ok_or_else(|| deny("root token not signed by a trust anchor"))?;
    let root = parse_claims(&root_payload)?;
    check_root(&root, anchor, policy.now, limits)?;
    // 3m, 3n.
    let mut grants = vec![grant(&root.authorization_details, limits.max_constraint_depth)?];

    // 4.
    let mut claims = vec![root.clone()];
    for pair in compacts.windows(2) {
        let (parent_compact, child_compact) = (&pair[0], &pair[1]);
        let parent = claims.last().expect("chain starts with the root");
        let child = parse_claims(&child_compact.verify(&parent.cnf.jwk, AAT_TYP)?)?;
        let parent_grant = grants.last().expect("one grant per token");
        let child_grant = check_link(parent, parent_grant, &parent_compact.signing_input_hash(), &child, policy.now, limits)?;
        claims.push(child);
        grants.push(child_grant);
    }
    let leaf = claims.last().expect("chain starts with the root").clone();
    let leaf_grant = grants.last().expect("one grant per token");

    // 5.
    if chain.len() as u64 != leaf.del_depth as u64 + 1 {
        return Err(deny("chain length does not match leaf del_depth"));
    }

    // 7a, 7b before 6b: whoever does not hold the leaf key can't make us
    // evaluate constraints.
    let pop_payload = Compact::parse(&presentation.pop)?.verify(&leaf.cnf.jwk, POP_TYP)?;
    let pop = PopClaims::parse(&pop_payload)?;

    // 6a was `grant`. 6b.
    reject_duplicate_keys(args_json.as_bytes())?;
    admissible_numbers(args_json)?;
    let args: Value = serde_json::from_str(args_json)?;
    let args = args.as_object().ok_or_else(|| deny("tool arguments must be a JSON object"))?;
    check_call(leaf_grant, tool, args)?;
    // 6c.
    check_audiences(&claims, policy)?;

    // 7c.
    if pop.jti.is_empty() || pop.aat_id.is_empty() || pop.aat_hash.is_empty() || pop.aat_tool.is_empty() {
        return Err(deny("proof of possession has an empty jti, aat_id, aat_hash or aat_tool"));
    }
    if !pop.hta.is_object() {
        return Err(deny("proof of possession hta is not an object"));
    }
    if pop.aat_id != leaf.jti {
        return Err(deny("proof of possession is for another token"));
    }
    if pop.aat_hash != compacts.last().expect("chain is not empty").signing_input_hash() {
        return Err(deny("proof of possession aat_hash does not match the leaf"));
    }
    // 7d.
    match (&pop.aat_aud, policy.audience) {
        (Some(aud), Some(me)) if aud == me => {}
        (Some(_), _) => return Err(deny("proof of possession is for another audience")),
        (None, _) if policy.require_pop_aud => return Err(deny("proof of possession has no aat_aud")),
        (None, _) => {}
    }
    // 7e.
    if pop.aat_tool != tool {
        return Err(deny("proof of possession is for another tool"));
    }
    // 7f.
    #[derive(Deserialize)]
    struct Hta<'a> {
        #[serde(borrow)]
        hta: &'a RawValue,
    }
    let hta: Hta = serde_json::from_slice(&pop_payload)?;
    admissible_numbers(hta.hta.get())?;
    if canonical(&pop.hta)? != canonical(&Value::Object(args.clone()))? {
        return Err(deny("proof of possession is for other arguments"));
    }
    // 7g.
    if (pop.iat - policy.now).abs() > limits.pop_window {
        return Err(deny("proof of possession is stale or from the future"));
    }
    // 7h.
    if policy.require_nonce && !pop.nonce.as_deref().is_some_and(|n| policy.nonces.contains(&n)) {
        return Err(deny("proof of possession has no nonce this enforcement point issued"));
    }

    // 7i is the caller's ReplayGuard. 8.
    Ok(Verified { root, leaf, chain: claims, pop_jti: pop.jti, pop_iat: pop.iat })
}

/// Claims of a token whose signature passed, with the numbers of its
/// `authorization_details` read as written (section 3.4).
fn parse_claims(payload: &[u8]) -> Result<Claims> {
    let claims = Claims::parse(payload)?;
    #[derive(Deserialize)]
    struct Details<'a> {
        #[serde(borrow)]
        authorization_details: &'a RawValue,
    }
    let details: Details = serde_json::from_slice(payload)?;
    admissible_numbers(details.authorization_details.get())?;
    Ok(claims)
}

fn canonical(v: &Value) -> Result<Vec<u8>> {
    serde_json_canonicalizer::to_vec(v).map_err(|e| deny(format!("cannot canonicalize: {}", e)))
}

/// Steps 3c to 3l.
fn check_root(root: &Claims, anchor: &TrustAnchor, now: i64, limits: &Limits) -> Result<()> {
    if root.del_depth != 0 {
        return Err(deny("root del_depth is not 0"));
    }
    if root.par_hash.is_some() {
        return Err(deny("root has par_hash"));
    }
    check_times(root, now, limits)?;
    if root.exp > root.iat + limits.max_token_lifetime {
        return Err(deny("root lifetime too long"));
    }
    if root.del_max_depth > limits.max_delegation_depth {
        return Err(deny("root del_max_depth above the implementation limit"));
    }
    if root.jti.is_empty() {
        return Err(deny("root jti is empty"));
    }
    if !is_uri(&root.iss) {
        return Err(deny("root iss is not a URI"));
    }
    if anchor.iss != root.iss {
        return Err(deny("root iss is not the verifying trust anchor's issuer"));
    }
    root.cnf.jwk.verifying_key()?;
    Ok(())
}

/// `exp > now`, `iat <= now + skew`, `exp > iat`.
fn check_times(token: &Claims, now: i64, limits: &Limits) -> Result<()> {
    if token.exp <= now {
        return Err(deny("token expired"));
    }
    if token.iat > now + limits.max_iat_skew {
        return Err(deny("token issued in the future"));
    }
    if token.exp <= token.iat {
        return Err(deny("token exp not after iat"));
    }
    Ok(())
}

/// Steps 4b1 to 4q for a child whose signature under `parent.cnf.jwk` is
/// already checked (or, when deriving, about to be made). `parent_hash` is
/// the hash of the parent's JWS Signing Input. Returns the child's grant.
pub(crate) fn check_link(parent: &Claims, parent_grant: &Grant, parent_hash: &str, child: &Claims, now: i64, limits: &Limits) -> Result<Grant> {
    // b1, b2, b5.
    if child.jti.is_empty() {
        return Err(deny("child jti is empty"));
    }
    child.cnf.jwk.verifying_key()?;
    let par_hash = child.par_hash.as_deref().ok_or_else(|| deny("child has no par_hash"))?;
    // c. I1
    if child.iss != parent.cnf.jwk.thumbprint_uri() {
        return Err(deny("child not issued by the parent's holder"));
    }
    // d-g, m. I2
    if child.del_depth != parent.del_depth + 1 {
        return Err(deny("del_depth does not increase by one"));
    }
    if child.del_depth > parent.del_max_depth || child.del_depth > limits.max_delegation_depth || child.del_depth > child.del_max_depth {
        return Err(deny("delegation deeper than allowed"));
    }
    if child.del_max_depth > parent.del_max_depth {
        return Err(deny("del_max_depth raised"));
    }
    // h-l. I3
    if child.exp > parent.exp {
        return Err(deny("child outlives its parent"));
    }
    if child.iat < parent.iat {
        return Err(deny("child issued before its parent"));
    }
    check_times(child, now, limits)?;
    // n, o.
    let child_grant = grant(&child.authorization_details, limits.max_constraint_depth)?;
    // p. I4
    check_attenuation(parent_grant, &child_grant)?;
    // q. I5
    if par_hash != parent_hash {
        return Err(deny("par_hash does not match the parent"));
    }
    Ok(child_grant)
}

/// Step 4p, over normalized maps (section 4.5).
fn check_attenuation(parent: &Grant, child: &Grant) -> Result<()> {
    let wildcard = Constraint::Wildcard;
    for (tool, c) in child {
        // p1.
        let p = parent.get(tool).ok_or_else(|| deny(format!("tool {} not granted by the parent", tool)))?;
        // p2.
        if let Some(k) = c.named.keys().find(|k| !p.star && !p.named.contains_key(*k)) {
            return Err(deny(format!("tool {} argument {} not named by the parent", tool, k)));
        }
        for (k, (_, optional)) in &p.named {
            if !c.named.contains_key(k) && (!optional || c.star) {
                return Err(deny(format!("tool {} argument {} dropped", tool, k)));
            }
        }
        if c.star && !p.star {
            return Err(deny(format!("tool {} adds \"*\"", tool)));
        }
        // p3, p4.
        for (k, (child_constraint, child_optional)) in &c.named {
            let parent_constraint = match p.named.get(k) {
                Some((pc, parent_optional)) => {
                    if *child_optional && !parent_optional {
                        return Err(deny(format!("tool {} argument {} made optional", tool, k)));
                    }
                    pc
                }
                None => &wildcard,
            };
            if !child_constraint.subsumes(parent_constraint) {
                return Err(deny(format!("tool {} argument {} widened", tool, k)));
            }
        }
    }
    Ok(())
}

/// Step 6b, closed-world: an argument the map does not name passes only
/// under `"*"`, and a required argument must be there.
fn check_call(grant: &Grant, tool: &str, args: &Map<String, Value>) -> Result<()> {
    let map = grant.get(tool).ok_or_else(|| deny(format!("tool {} not granted", tool)))?;
    for (arg, value) in args {
        match map.named.get(arg) {
            Some((constraint, _)) if !constraint.check(value) => return Err(deny(format!("argument {} out of bounds", arg))),
            Some(_) => {}
            None if map.star => {}
            None => return Err(deny(format!("argument {} not allowed", arg))),
        }
    }
    if let Some((arg, _)) = map.named.iter().find(|(arg, (_, optional))| !optional && !args.contains_key(*arg)) {
        return Err(deny(format!("argument {} missing", arg)));
    }
    Ok(())
}

/// Step 6c: every `aud` in the chain names this enforcement point.
fn check_audiences(chain: &[Claims], policy: &Policy) -> Result<()> {
    let mut any = false;
    for token in chain {
        let Some(aud) = token.extra.get("aud") else { continue };
        any = true;
        let values: Vec<&str> = match aud {
            Value::String(s) => vec![s.as_str()],
            Value::Array(items) => items.iter().map(|v| v.as_str().ok_or_else(|| deny("aud holds a non-string"))).collect::<Result<_>>()?,
            _ => return Err(deny("aud is not a string or an array of strings")),
        };
        if !policy.audience.is_some_and(|me| values.contains(&me)) {
            return Err(deny("a token in the chain is for another audience"));
        }
    }
    if policy.require_chain_aud && !any {
        return Err(deny("no token in the chain carries aud"));
    }
    Ok(())
}

/// Accepts each proof of possession once (stateful `jti` tracking, step
/// 7i), which tools with side effects require. A proof is forgotten once
/// its `iat` leaves the tolerance window, since `verify` refuses it from
/// then on anyway.
#[derive(Debug, Default)]
pub struct ReplayGuard {
    seen: HashMap<String, i64>,
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the proof of `verified`; fails if it was already used. Run
    /// it only after every other check passed.
    pub fn check(&mut self, verified: &Verified, now: i64) -> Result<()> {
        self.seen.retain(|_, until| *until >= now);
        if self.seen.contains_key(&verified.pop_jti) {
            return Err(deny("proof of possession replayed"));
        }
        self.seen.insert(verified.pop_jti.clone(), verified.pop_iat + POP_IAT_TOLERANCE);
        Ok(())
    }

    /// Marks `jti` as already accepted until `until` (state carried over
    /// from another replica or a restart).
    pub fn remember(&mut self, jti: &str, until: i64) {
        self.seen.insert(jti.to_string(), until);
    }
}
