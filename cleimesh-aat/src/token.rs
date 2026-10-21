//! Token claims, issuance, derivation and proof of possession.

use std::collections::{BTreeMap, HashSet};

use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::constraint::Constraint;
use crate::jws::{self, Compact, Jwk};
use crate::{deny, Result, SigningKey, MAX_DELEGATION_DEPTH, MAX_TOKEN_LIFETIME};

/// `type` of the `authorization_details` entry this profile reads.
pub const AAT_TYPE: &str = "attenuating_agent_token";

/// Tool name → argument name → constraint. An empty argument map authorizes
/// the tool with any arguments; a non-empty one is closed-world.
pub type Tools = BTreeMap<String, BTreeMap<String, Constraint>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cnf {
    pub jwk: Jwk,
}

/// Claims of an AAT. Unknown claims are kept in `extra` (passthrough
/// metadata, draft appendix B.6) and never cause a rejection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub jti: String,
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
    pub cnf: Cnf,
    pub del_depth: u32,
    pub del_max_depth: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub par_hash: Option<String>,
    pub authorization_details: Vec<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Claims {
    /// Parses verified payload bytes. Duplicate JSON keys anywhere are
    /// refused, so a tool or argument can't be read two ways.
    pub(crate) fn parse(payload: &[u8]) -> Result<Self> {
        reject_duplicate_keys(payload)?;
        Ok(serde_json::from_slice(payload)?)
    }

    /// The tools of the single `attenuating_agent_token` entry; `None` when
    /// there is no such entry (the empty capability set).
    pub fn tools(&self) -> Result<Option<Tools>> {
        let mut entries = self.authorization_details.iter().filter(|d| d.get("type").and_then(Value::as_str) == Some(AAT_TYPE));
        let Some(entry) = entries.next() else { return Ok(None) };
        if entries.next().is_some() {
            return Err(deny("more than one attenuating_agent_token entry"));
        }
        let tools = entry.get("tools").ok_or_else(|| deny("attenuating_agent_token entry has no tools"))?;
        let tools: Tools = serde_json::from_value(tools.clone())?;
        if !tools.values().flat_map(BTreeMap::values).all(Constraint::validate) {
            return Err(deny("constraint too deep or exact value not a scalar"));
        }
        Ok(Some(tools))
    }

    /// The `authorization_details` entries of another `type`: extensions
    /// this profile carries but does not interpret (RFC 9396).
    pub fn details_of_type<'a>(&'a self, ty: &'a str) -> impl Iterator<Item = &'a Value> + 'a {
        self.authorization_details.iter().filter(move |d| d.get("type").and_then(Value::as_str) == Some(ty))
    }

    fn sign(&self, key: &SigningKey) -> Result<String> {
        Ok(jws::sign(key, &serde_json::to_vec(self)?))
    }
}

/// The `attenuating_agent_token` entry, then `extra` entries, each an object
/// with a `type` of its own.
fn details(tools: Tools, extra: Vec<Value>) -> Result<Vec<Value>> {
    let mut details = vec![serde_json::json!({"type": AAT_TYPE, "tools": tools})];
    for entry in extra {
        match entry.get("type").and_then(Value::as_str) {
            Some(AAT_TYPE) => return Err(deny("extra authorization_details entry reuses the attenuating_agent_token type")),
            Some(_) => details.push(entry),
            None => return Err(deny("extra authorization_details entry has no type")),
        }
    }
    Ok(details)
}

/// Whether `s` starts with a URI scheme (RFC 3986: ALPHA *( ALPHA / DIGIT
/// / "+" / "-" / "." ) ":").
pub(crate) fn is_uri(s: &str) -> bool {
    let Some((scheme, rest)) = s.split_once(':') else { return false };
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
        && !rest.is_empty()
}

/// Issues a root token: `issuer_key` (a trust anchor of the enforcement
/// point) grants `tools` to the holder of `holder`, for `ttl_secs`, allowing
/// `del_max_depth` further delegations. `iss` must be a URI.
pub fn issue_root(issuer_key: &SigningKey, iss: &str, holder: &Jwk, tools: Tools, now: i64, ttl_secs: i64, del_max_depth: u32) -> Result<String> {
    issue_root_with(issuer_key, iss, holder, tools, Vec::new(), now, ttl_secs, del_max_depth)
}

/// Like [`issue_root`], also carrying `extra` `authorization_details`
/// entries (see [`Claims::details_of_type`]).
#[allow(clippy::too_many_arguments)]
pub fn issue_root_with(issuer_key: &SigningKey, iss: &str, holder: &Jwk, tools: Tools, extra: Vec<Value>, now: i64, ttl_secs: i64, del_max_depth: u32) -> Result<String> {
    if !is_uri(iss) {
        return Err(deny("root iss must be a URI"));
    }
    if ttl_secs <= 0 || ttl_secs > MAX_TOKEN_LIFETIME {
        return Err(deny("ttl out of range"));
    }
    if del_max_depth > MAX_DELEGATION_DEPTH {
        return Err(deny("del_max_depth above the implementation limit"));
    }
    holder.verifying_key()?;
    let claims = Claims {
        jti: uuid::Uuid::now_v7().to_string(),
        iss: iss.to_string(),
        iat: now,
        exp: now + ttl_secs,
        cnf: Cnf { jwk: holder.clone() },
        del_depth: 0,
        del_max_depth,
        par_hash: None,
        authorization_details: details(tools, extra)?,
        extra: Map::new(),
    };
    claims.tools()?;
    claims.sign(issuer_key)
}

/// Derives a child of `parent` for `new_holder`, signed by `holder_key`
/// (which must hold `parent`). The child expires `ttl_secs` from now, or
/// with its parent if sooner. `del_max_depth` defaults to the parent's.
/// Refused if `tools` is not an attenuation of the parent's.
pub fn derive(parent: &str, holder_key: &SigningKey, new_holder: &Jwk, tools: Tools, now: i64, ttl_secs: i64, del_max_depth: Option<u32>) -> Result<String> {
    derive_with(parent, holder_key, new_holder, tools, Vec::new(), now, ttl_secs, del_max_depth)
}

/// Like [`derive`], also carrying `extra` `authorization_details` entries.
/// Their attenuation is the extension's to check, not this profile's.
#[allow(clippy::too_many_arguments)]
pub fn derive_with(parent: &str, holder_key: &SigningKey, new_holder: &Jwk, tools: Tools, extra: Vec<Value>, now: i64, ttl_secs: i64, del_max_depth: Option<u32>) -> Result<String> {
    // Read, not verified: the enforcement point verifies the whole chain.
    // Deriving only needs us to hold the parent.
    let compact = Compact::parse(parent)?;
    let parent_claims = Claims::parse(&compact.unverified_payload()?)?;
    let our_key = Jwk::from_key(&holder_key.verifying_key());
    if parent_claims.cnf.jwk.verifying_key()? != holder_key.verifying_key() {
        return Err(deny("signing key does not hold the parent token"));
    }
    new_holder.verifying_key()?;
    let iat = now.max(parent_claims.iat);
    let child = Claims {
        jti: uuid::Uuid::now_v7().to_string(),
        iss: our_key.thumbprint_uri(),
        iat,
        exp: (iat + ttl_secs).min(parent_claims.exp),
        cnf: Cnf { jwk: new_holder.clone() },
        del_depth: parent_claims.del_depth + 1,
        del_max_depth: del_max_depth.unwrap_or(parent_claims.del_max_depth),
        par_hash: Some(compact.signing_input_hash()),
        authorization_details: details(tools, extra)?,
        extra: Map::new(),
    };
    crate::verify::check_link(&parent_claims, &compact.signing_input_hash(), &child, now)?;
    child.sign(holder_key)
}

/// The claims of `token` **without checking its signature**: for a holder
/// looking at what it holds, e.g. to refuse a widening before deriving.
/// Never base an authorization decision on it; [`crate::verify`] does that.
pub fn inspect(token: &str) -> Result<Claims> {
    Claims::parse(&Compact::parse(token)?.unverified_payload()?)
}

/// What a holder presents with a call: the chain, root first, and the proof
/// of possession for this call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Presentation {
    pub chain: Vec<String>,
    pub pop: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct PopClaims {
    pub jti: String,
    pub iat: i64,
    pub aat_id: String,
    pub aat_tool: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aat_aud: Option<String>,
    pub hta: Value,
}

/// Proof of possession for calling `tool` with `args` (a JSON object) under
/// `leaf`, signed by its holder. `aud` names the enforcement point.
pub fn pop(holder_key: &SigningKey, leaf: &str, tool: &str, args: &Value, aud: Option<&str>, now: i64) -> Result<String> {
    if !args.is_object() {
        return Err(deny("tool arguments must be a JSON object"));
    }
    let leaf = Compact::parse(leaf)?;
    let claims = PopClaims {
        jti: uuid::Uuid::new_v4().to_string(),
        iat: now,
        aat_id: leaf.unverified_jti()?,
        aat_tool: tool.to_string(),
        aat_aud: aud.map(str::to_string),
        hta: args.clone(),
    };
    let payload = serde_json_canonicalizer::to_vec(&claims).map_err(|e| deny(format!("cannot canonicalize: {}", e)))?;
    Ok(jws::sign(holder_key, &payload))
}

impl PopClaims {
    pub(crate) fn parse(payload: &[u8]) -> Result<Self> {
        reject_duplicate_keys(payload)?;
        Ok(serde_json::from_slice(payload)?)
    }
}

/// Walks the JSON and fails on the first object with a repeated key.
/// `serde_json::Value` would keep the last one silently.
fn reject_duplicate_keys(payload: &[u8]) -> Result<()> {
    struct Checked;
    struct V;
    impl<'de> Deserialize<'de> for Checked {
        fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
            d.deserialize_any(V)
        }
    }
    impl<'de> Visitor<'de> for V {
        type Value = Checked;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("JSON")
        }
        fn visit_bool<E>(self, _: bool) -> std::result::Result<Checked, E> {
            Ok(Checked)
        }
        fn visit_i64<E>(self, _: i64) -> std::result::Result<Checked, E> {
            Ok(Checked)
        }
        fn visit_u64<E>(self, _: u64) -> std::result::Result<Checked, E> {
            Ok(Checked)
        }
        fn visit_f64<E>(self, _: f64) -> std::result::Result<Checked, E> {
            Ok(Checked)
        }
        fn visit_str<E>(self, _: &str) -> std::result::Result<Checked, E> {
            Ok(Checked)
        }
        fn visit_unit<E>(self) -> std::result::Result<Checked, E> {
            Ok(Checked)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Checked, A::Error> {
            while seq.next_element::<Checked>()?.is_some() {}
            Ok(Checked)
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Checked, A::Error> {
            let mut seen = HashSet::new();
            while let Some(key) = map.next_key::<String>()? {
                if !seen.insert(key.clone()) {
                    return Err(de::Error::custom(format!("duplicate key {:?}", key)));
                }
                map.next_value::<Checked>()?;
            }
            Ok(Checked)
        }
    }
    serde_json::from_slice::<Checked>(payload).map(|_| ()).map_err(|e| deny(format!("invalid JSON: {}", e)))
}
