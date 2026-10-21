//! Chain verification, draft section 7. Step numbers in comments refer to it.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::Value;

use crate::jws::{Compact, Jwk};
use crate::token::{is_uri, Claims, PopClaims, Presentation, Tools};
use crate::{deny, Result, MAX_DELEGATION_DEPTH, MAX_IAT_SKEW, MAX_STACK_SIZE, MAX_TOKEN_LIFETIME, MAX_TOKEN_SIZE, POP_IAT_TOLERANCE};

/// What the enforcement point trusts and requires.
pub struct Policy<'a> {
    /// Keys whose root tokens are honored.
    pub trust_anchors: &'a [Jwk],
    /// When set, the proof of possession must carry this `aat_aud`.
    pub audience: Option<&'a str>,
    /// Current time, in seconds since the epoch.
    pub now: i64,
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
pub fn verify(presentation: &Presentation, policy: &Policy, tool: &str, args: &Value) -> Result<Verified> {
    let chain = &presentation.chain;
    // 1.
    if chain.is_empty() {
        return Err(deny("empty chain"));
    }
    // 2a, 2b.
    if chain.iter().any(|t| t.len() > MAX_TOKEN_SIZE) {
        return Err(deny("token too large"));
    }
    if chain.iter().map(String::len).sum::<usize>() > MAX_STACK_SIZE {
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

    // 3a, 3b. Signature first, then parse.
    let root_payload = policy
        .trust_anchors
        .iter()
        .find_map(|anchor| compacts[0].verify(anchor).ok())
        .ok_or_else(|| deny("root token not signed by a trust anchor"))?;
    let root = Claims::parse(&root_payload)?;
    check_root(&root, policy.now)?;

    // 4.
    let mut claims = vec![root.clone()];
    for pair in compacts.windows(2) {
        let (parent_compact, child_compact) = (&pair[0], &pair[1]);
        let parent = claims.last().expect("chain starts with the root");
        let child = Claims::parse(&child_compact.verify(&parent.cnf.jwk)?)?;
        check_link(parent, &parent_compact.signing_input_hash(), &child, policy.now)?;
        claims.push(child);
    }
    let leaf = claims.last().expect("chain starts with the root").clone();

    // 5.
    if chain.len() as u64 != leaf.del_depth as u64 + 1 {
        return Err(deny("chain length does not match leaf del_depth"));
    }

    // 6.
    let tools = leaf.tools()?.ok_or_else(|| deny("leaf has no attenuating_agent_token entry"))?;
    check_call(&tools, tool, args)?;

    // 7.
    let pop = PopClaims::parse(&Compact::parse(&presentation.pop)?.verify(&leaf.cnf.jwk)?)?;
    if pop.aat_id != leaf.jti {
        return Err(deny("proof of possession is for another token"));
    }
    if let Some(audience) = policy.audience {
        if pop.aat_aud.as_deref() != Some(audience) {
            return Err(deny("proof of possession is for another audience"));
        }
    }
    if pop.aat_tool != tool {
        return Err(deny("proof of possession is for another tool"));
    }
    if canonical(&pop.hta)? != canonical(args)? {
        return Err(deny("proof of possession is for other arguments"));
    }
    if (pop.iat - policy.now).abs() > POP_IAT_TOLERANCE {
        return Err(deny("proof of possession is stale or from the future"));
    }

    // 8.
    Ok(Verified { root, leaf, chain: claims, pop_jti: pop.jti, pop_iat: pop.iat })
}

fn canonical(v: &Value) -> Result<Vec<u8>> {
    serde_json_canonicalizer::to_vec(v).map_err(|e| deny(format!("cannot canonicalize: {}", e)))
}

/// Steps 3c to 3n.
fn check_root(root: &Claims, now: i64) -> Result<()> {
    if root.del_depth != 0 {
        return Err(deny("root del_depth is not 0"));
    }
    if root.par_hash.is_some() {
        return Err(deny("root has par_hash"));
    }
    check_times(root, now)?;
    if root.exp > root.iat + MAX_TOKEN_LIFETIME {
        return Err(deny("root lifetime too long"));
    }
    if root.del_max_depth > MAX_DELEGATION_DEPTH {
        return Err(deny("root del_max_depth above the implementation limit"));
    }
    if root.jti.is_empty() {
        return Err(deny("root jti is empty"));
    }
    if !is_uri(&root.iss) {
        return Err(deny("root iss is not a URI"));
    }
    root.cnf.jwk.verifying_key()?;
    if root.tools()?.is_none() {
        return Err(deny("root has no attenuating_agent_token entry"));
    }
    Ok(())
}

/// `exp > now`, `iat <= now + skew`, `exp > iat`.
fn check_times(token: &Claims, now: i64) -> Result<()> {
    if token.exp <= now {
        return Err(deny("token expired"));
    }
    if token.iat > now + MAX_IAT_SKEW {
        return Err(deny("token issued in the future"));
    }
    if token.exp <= token.iat {
        return Err(deny("token exp not after iat"));
    }
    Ok(())
}

/// Steps 4b1 to 4q for a child whose signature under `parent.cnf.jwk` is
/// already checked (or, when deriving, about to be made). `parent_hash` is
/// the hash of the parent's JWS Signing Input.
pub(crate) fn check_link(parent: &Claims, parent_hash: &str, child: &Claims, now: i64) -> Result<()> {
    // b1, b2.
    if child.jti.is_empty() {
        return Err(deny("child jti is empty"));
    }
    child.cnf.jwk.verifying_key()?;
    // c. I1
    if child.iss != parent.cnf.jwk.thumbprint_uri() {
        return Err(deny("child not issued by the parent's holder"));
    }
    // d-g, m. I2
    if child.del_depth != parent.del_depth + 1 {
        return Err(deny("del_depth does not increase by one"));
    }
    if child.del_depth > parent.del_max_depth || child.del_depth > MAX_DELEGATION_DEPTH || child.del_depth > child.del_max_depth {
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
    check_times(child, now)?;
    // n-p. I4
    let parent_tools = parent.tools()?.unwrap_or_default();
    let child_tools = child.tools()?.unwrap_or_default();
    check_attenuation(&parent_tools, &child_tools)?;
    // q. I5
    if child.par_hash.as_deref() != Some(parent_hash) {
        return Err(deny("par_hash does not match the parent"));
    }
    Ok(())
}

/// Step 4p.
fn check_attenuation(parent: &Tools, child: &Tools) -> Result<()> {
    for (tool, child_args) in child {
        let parent_args = parent.get(tool).ok_or_else(|| deny(format!("tool {} not granted by the parent", tool)))?;
        if parent_args.is_empty() {
            continue;
        }
        if !parent_args.keys().eq(child_args.keys()) {
            return Err(deny(format!("tool {} argument set changed", tool)));
        }
        for (arg, parent_constraint) in parent_args {
            if !child_args[arg].subsumes(parent_constraint) {
                return Err(deny(format!("tool {} argument {} widened", tool, arg)));
            }
        }
    }
    Ok(())
}

/// Step 6b, closed-world when the tool has constraints.
fn check_call(tools: &Tools, tool: &str, args: &Value) -> Result<()> {
    let constraints: &BTreeMap<_, _> = tools.get(tool).ok_or_else(|| deny(format!("tool {} not granted", tool)))?;
    let args = args.as_object().ok_or_else(|| deny("tool arguments must be a JSON object"))?;
    if constraints.is_empty() {
        return Ok(());
    }
    if let Some(extra) = args.keys().find(|k| !constraints.contains_key(*k)) {
        return Err(deny(format!("argument {} not allowed", extra)));
    }
    for (arg, constraint) in constraints {
        let value = args.get(arg).ok_or_else(|| deny(format!("argument {} missing", arg)))?;
        if !constraint.check(value) {
            return Err(deny(format!("argument {} out of bounds", arg)));
        }
    }
    Ok(())
}

/// Accepts each proof of possession once (stateful `jti` tracking, draft
/// section 8.5), which tools with side effects require. A proof is
/// forgotten once its `iat` leaves the tolerance window, since `verify`
/// refuses it from then on anyway.
#[derive(Debug, Default)]
pub struct ReplayGuard {
    seen: HashMap<(String, String), i64>,
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the proof of `verified`; fails if it was already used.
    pub fn check(&mut self, verified: &Verified, now: i64) -> Result<()> {
        self.seen.retain(|_, until| *until >= now);
        let key = (verified.leaf.cnf.jwk.thumbprint_uri(), verified.pop_jti.clone());
        if self.seen.contains_key(&key) {
            return Err(deny("proof of possession replayed"));
        }
        self.seen.insert(key, verified.pop_iat + POP_IAT_TOLERANCE);
        Ok(())
    }
}
