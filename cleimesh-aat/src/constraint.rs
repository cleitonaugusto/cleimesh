//! Argument constraints (draft section 3.4) and their subsumption rules
//! (section 4.5). An unknown `constraint_type` fails to parse, so the token
//! carrying it is denied (fail-closed).

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use url::Url;

use crate::{deny, Result};

/// Deepest `all`/`any` nesting accepted (draft recommends 32).
pub const MAX_CONSTRAINT_DEPTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "constraint_type", rename_all = "snake_case")]
pub enum Constraint {
    Exact { value: Value },
    Range {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        min: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max: Option<f64>,
        // Written only when exclusive: the draft forbids an inclusivity flag
        // without its bound, and `true` is the default anyway.
        #[serde(default = "inclusive", skip_serializing_if = "is_inclusive")]
        min_inclusive: bool,
        #[serde(default = "inclusive", skip_serializing_if = "is_inclusive")]
        max_inclusive: bool,
    },
    OneOf { values: Vec<Value> },
    NotOneOf { excluded: Vec<Value> },
    /// The value is a URL string whose host is one of `hosts` (exact host,
    /// case-insensitive, port ignored). An egress allowlist: a tool argument
    /// that carries a URL — a fetch target, a webhook, a redirect — may only
    /// reach a named host, so a prompt-injected agent cannot exfiltrate to its
    /// own domain. Parsed with a real URL parser, so `https://ok.test@evil.test/`
    /// has host `evil.test`, not `ok.test`. Empty `hosts` admits nothing.
    HostIn { hosts: Vec<String> },
    Contains { required: Vec<Value> },
    Subset { allowed: Vec<Value> },
    Wildcard,
    All { constraints: Vec<Constraint> },
    Any { constraints: Vec<Constraint> },
}

fn inclusive() -> bool {
    true
}

fn is_inclusive(flag: &bool) -> bool {
    *flag
}

/// JSON equality after JCS canonicalization, so `1` and `1.0` are equal and
/// key order does not matter.
fn same(a: &Value, b: &Value) -> bool {
    match (serde_json_canonicalizer::to_vec(a), serde_json_canonicalizer::to_vec(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn member(values: &[Value], v: &Value) -> bool {
    values.iter().any(|x| same(x, v))
}

fn all_members(of: &[Value], values: &[Value]) -> bool {
    values.iter().all(|v| member(of, v))
}

/// The value is a URL string whose host is in `hosts` (exact, case-insensitive).
/// A real parser decides the host, so userinfo (`host@`) can't disguise it.
fn host_allowed(v: &Value, hosts: &[String]) -> bool {
    let Some(s) = v.as_str() else { return false };
    let Ok(url) = Url::parse(s) else { return false };
    let Some(host) = url.host_str() else { return false };
    hosts.iter().any(|h| h.eq_ignore_ascii_case(host))
}

/// Every host in `child` is in `parent` (case-insensitive): the child allowlist
/// is a subset, so it can only narrow.
fn host_subset(child: &[String], parent: &[String]) -> bool {
    child.iter().all(|h| parent.iter().any(|p| p.eq_ignore_ascii_case(h)))
}

impl Constraint {
    pub fn exact(value: impl Into<Value>) -> Self {
        Constraint::Exact { value: value.into() }
    }

    pub fn one_of<V: Into<Value>>(values: impl IntoIterator<Item = V>) -> Self {
        Constraint::OneOf { values: values.into_iter().map(Into::into).collect() }
    }

    /// Nesting depth: 1 for a leaf constraint.
    pub fn depth(&self) -> usize {
        match self {
            Constraint::All { constraints } | Constraint::Any { constraints } => {
                1 + constraints.iter().map(Constraint::depth).max().unwrap_or(0)
            }
            _ => 1,
        }
    }

    /// Whether `v` satisfies the constraint.
    pub fn check(&self, v: &Value) -> bool {
        match self {
            Constraint::Exact { value } => same(value, v),
            Constraint::Range { min, max, min_inclusive, max_inclusive } => {
                let Some(n) = v.as_f64() else { return false };
                let above = match min {
                    Some(m) if *min_inclusive => n >= *m,
                    Some(m) => n > *m,
                    None => true,
                };
                let below = match max {
                    Some(m) if *max_inclusive => n <= *m,
                    Some(m) => n < *m,
                    None => true,
                };
                above && below
            }
            Constraint::OneOf { values } => member(values, v),
            Constraint::NotOneOf { excluded } => !member(excluded, v),
            Constraint::HostIn { hosts } => host_allowed(v, hosts),
            Constraint::Contains { required } => v.as_array().is_some_and(|a| all_members(a, required)),
            Constraint::Subset { allowed } => v.as_array().is_some_and(|a| all_members(allowed, a)),
            Constraint::Wildcard => true,
            Constraint::All { constraints } => constraints.iter().all(|c| c.check(v)),
            Constraint::Any { constraints } => constraints.iter().any(|c| c.check(v)),
        }
    }

    /// Whether `self`, in a derived token, is at least as restrictive as
    /// `parent` (`self ⊑ parent`). Pairs the draft does not list are refused.
    pub fn subsumes(&self, parent: &Constraint) -> bool {
        use Constraint::*;
        match (self, parent) {
            (Wildcard, Wildcard) => true,
            (Wildcard, _) => false,
            (_, Wildcard) => true,
            (Exact { value }, Exact { value: p }) => same(value, p),
            (Exact { value }, Range { .. }) => value.is_number() && parent.check(value),
            (Exact { value }, OneOf { values }) => member(values, value),
            // A single exact URL narrows a host allowlist, if its host is allowed.
            (Exact { value }, HostIn { hosts }) => host_allowed(value, hosts),
            (Exact { .. }, _) => false,
            (Range { min, max, min_inclusive, max_inclusive }, Range { min: pmin, max: pmax, min_inclusive: pmin_inc, max_inclusive: pmax_inc }) => {
                bound_ok(*min, *min_inclusive, *pmin, *pmin_inc, |a, b| a > b)
                    && bound_ok(*max, *max_inclusive, *pmax, *pmax_inc, |a, b| a < b)
            }
            (OneOf { values }, OneOf { values: p }) => all_members(p, values),
            (NotOneOf { excluded }, NotOneOf { excluded: p }) => all_members(excluded, p),
            (HostIn { hosts }, HostIn { hosts: p }) => host_subset(hosts, p),
            (Contains { required }, Contains { required: p }) => all_members(required, p),
            (Subset { allowed }, Subset { allowed: p }) => all_members(p, allowed),
            // Every parent clause subsumes at least one derived clause; one
            // derived clause may serve several (draft section 4.5).
            (All { constraints }, All { constraints: p }) => {
                !constraints.is_empty() && p.iter().all(|pc| constraints.iter().any(|c| c.subsumes(pc)))
            }
            (Any { constraints }, Any { constraints: p }) => {
                !constraints.is_empty() && constraints.iter().all(|c| p.iter().any(|pc| c.subsumes(pc)))
            }
            _ => false,
        }
    }

    /// Reads a constraint the way the draft requires it written (section
    /// 3.4, "well-formed"): a known type, no undefined member, members of the
    /// right JSON type, `one_of`/`all`/`any` non-empty, a range whose `min`
    /// is not above its `max` and whose inclusivity flags sit beside their
    /// bound, and nesting at most `max_depth` deep. `optional` is accepted
    /// only on a top-level map entry (`top`); the caller reads it.
    pub(crate) fn parse(value: &Value, top: bool, max_depth: usize) -> Result<Constraint> {
        Self::parse_at(value, top, 1, max_depth)
    }

    fn parse_at(value: &Value, top: bool, depth: usize, max_depth: usize) -> Result<Constraint> {
        if depth > max_depth {
            return Err(deny("constraint tree too deep"));
        }
        let obj = value.as_object().ok_or_else(|| deny("constraint is not an object"))?;
        let ty = obj.get("constraint_type").and_then(Value::as_str).ok_or_else(|| deny("constraint has no constraint_type"))?;
        let members: &[&str] = match ty {
            "exact" => &["value"],
            "range" => &["min", "max", "min_inclusive", "max_inclusive"],
            "one_of" => &["values"],
            "not_one_of" => &["excluded"],
            "contains" => &["required"],
            "subset" => &["allowed"],
            "wildcard" => &[],
            "all" | "any" => &["constraints"],
            "host_in" => &["hosts"],
            other => return Err(deny(format!("unknown constraint_type {:?}", other))),
        };
        if let Some(extra) = obj.keys().find(|k| *k != "constraint_type" && !(top && *k == "optional") && !members.contains(&k.as_str())) {
            return Err(deny(format!("{} constraint has undefined member {}", ty, extra)));
        }
        Ok(match ty {
            "exact" => {
                let value = obj.get("value").ok_or_else(|| deny("exact has no value"))?;
                if value.is_array() || value.is_object() {
                    return Err(deny("exact value is not a scalar"));
                }
                Constraint::Exact { value: value.clone() }
            }
            "range" => {
                let bound = |k: &str| match obj.get(k) {
                    None => Ok(None),
                    Some(n) => n.as_f64().filter(|_| n.is_number()).map(Some).ok_or_else(|| deny(format!("range {} is not a number", k))),
                };
                let (min, max) = (bound("min")?, bound("max")?);
                if let (Some(lo), Some(hi)) = (min, max) {
                    if lo > hi {
                        return Err(deny("range min is greater than max"));
                    }
                }
                let flag = |k: &str, bound: Option<f64>| match obj.get(k) {
                    None => Ok(true),
                    Some(Value::Bool(b)) if bound.is_some() => Ok(*b),
                    Some(_) => Err(deny(format!("range {} is not a boolean beside its bound", k))),
                };
                Constraint::Range { min, max, min_inclusive: flag("min_inclusive", min)?, max_inclusive: flag("max_inclusive", max)? }
            }
            "one_of" => {
                let values = array(obj, "values")?;
                if values.is_empty() {
                    return Err(deny("one_of has no values"));
                }
                Constraint::OneOf { values: values.clone() }
            }
            "not_one_of" => Constraint::NotOneOf { excluded: array(obj, "excluded")?.clone() },
            "contains" => Constraint::Contains { required: array(obj, "required")?.clone() },
            "subset" => Constraint::Subset { allowed: array(obj, "allowed")?.clone() },
            "wildcard" => Constraint::Wildcard,
            "host_in" => Constraint::HostIn {
                hosts: array(obj, "hosts")?.iter().map(|h| h.as_str().map(str::to_string).ok_or_else(|| deny("host_in host is not a string"))).collect::<Result<_>>()?,
            },
            _ => {
                let clauses = array(obj, "constraints")?;
                if clauses.is_empty() {
                    return Err(deny(format!("{} has no constraints", ty)));
                }
                let clauses = clauses.iter().map(|c| Self::parse_at(c, false, depth + 1, max_depth)).collect::<Result<Vec<_>>>()?;
                if ty == "all" {
                    Constraint::All { constraints: clauses }
                } else {
                    Constraint::Any { constraints: clauses }
                }
            }
        })
    }

    /// Structural checks the type system does not cover: nesting depth and
    /// `exact` holding a scalar.
    pub(crate) fn validate(&self) -> bool {
        self.depth() <= MAX_CONSTRAINT_DEPTH && self.scalar_exacts()
    }

    fn scalar_exacts(&self) -> bool {
        match self {
            Constraint::Exact { value } => !value.is_array() && !value.is_object(),
            Constraint::All { constraints } | Constraint::Any { constraints } => constraints.iter().all(Constraint::scalar_exacts),
            _ => true,
        }
    }
}

fn array<'a>(obj: &'a Map<String, Value>, key: &str) -> Result<&'a Vec<Value>> {
    obj.get(key).and_then(Value::as_array).ok_or_else(|| deny(format!("{} is not an array", key)))
}

/// A derived range bound against its parent's. A missing parent bound is
/// unbounded; a missing derived bound is only valid if the parent's is
/// missing too. At an equal value, the derived bound may only go from
/// inclusive to exclusive. `tighter(a, b)`: `a` is strictly inside `b`.
fn bound_ok(child: Option<f64>, child_inc: bool, parent: Option<f64>, parent_inc: bool, tighter: fn(f64, f64) -> bool) -> bool {
    match (child, parent) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(c), Some(p)) => tighter(c, p) || (c == p && (parent_inc || !child_inc)),
    }
}

#[cfg(test)]
mod host_in_tests {
    use super::Constraint;
    use serde_json::json;

    fn host_in(hosts: &[&str]) -> Constraint {
        Constraint::HostIn { hosts: hosts.iter().map(|s| s.to_string()).collect() }
    }

    #[test]
    fn admits_only_the_listed_host() {
        let c = host_in(&["api.stripe.com"]);
        assert!(c.check(&json!("https://api.stripe.com/v1/charges")));
        assert!(c.check(&json!("https://API.Stripe.com/x"))); // case-insensitive
        assert!(c.check(&json!("https://api.stripe.com:8443/x"))); // port ignored
        assert!(!c.check(&json!("https://evil.example/collect")));
        assert!(!c.check(&json!("https://apistripe.com/x"))); // not a substring match
    }

    #[test]
    fn userinfo_cannot_disguise_the_host() {
        // The real host is evil.example; api.stripe.com is only userinfo.
        assert!(!host_in(&["api.stripe.com"]).check(&json!("https://api.stripe.com@evil.example/collect")));
    }

    #[test]
    fn non_url_and_non_string_are_refused() {
        let c = host_in(&["api.stripe.com"]);
        assert!(!c.check(&json!("not a url")));
        assert!(!c.check(&json!("/charges"))); // relative, no host
        assert!(!c.check(&json!(42)));
        assert!(!c.check(&json!({ "url": "https://api.stripe.com" })));
    }

    #[test]
    fn empty_allowlist_admits_nothing() {
        assert!(!host_in(&[]).check(&json!("https://api.stripe.com/x")));
    }

    #[test]
    fn a_child_allowlist_may_only_be_a_subset() {
        let parent = host_in(&["api.stripe.com", "api.github.com"]);
        assert!(host_in(&["api.stripe.com"]).subsumes(&parent)); // narrower
        assert!(host_in(&["api.stripe.com", "api.github.com"]).subsumes(&parent)); // equal
        assert!(!host_in(&["evil.example"]).subsumes(&parent)); // outside
        assert!(!host_in(&["api.stripe.com", "evil.example"]).subsumes(&parent)); // adds a host
    }

    #[test]
    fn an_exact_url_narrows_a_host_allowlist() {
        let parent = host_in(&["api.stripe.com"]);
        assert!(Constraint::exact("https://api.stripe.com/v1/charges").subsumes(&parent));
        assert!(!Constraint::exact("https://evil.example/x").subsumes(&parent));
    }

    #[test]
    fn host_in_narrows_wildcard_but_not_the_reverse() {
        assert!(host_in(&["api.stripe.com"]).subsumes(&Constraint::Wildcard));
        assert!(!Constraint::Wildcard.subsumes(&host_in(&["api.stripe.com"])));
    }
}
