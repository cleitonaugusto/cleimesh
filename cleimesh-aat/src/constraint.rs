//! Argument constraints (draft section 3.4) and their subsumption rules
//! (section 4.5). An unknown `constraint_type` fails to parse, so the token
//! carrying it is denied (fail-closed).

use serde::{Deserialize, Serialize};
use serde_json::Value;

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
        #[serde(default = "inclusive")]
        min_inclusive: bool,
        #[serde(default = "inclusive")]
        max_inclusive: bool,
    },
    OneOf { values: Vec<Value> },
    NotOneOf { excluded: Vec<Value> },
    Contains { required: Vec<Value> },
    Subset { allowed: Vec<Value> },
    Wildcard,
    All { constraints: Vec<Constraint> },
    Any { constraints: Vec<Constraint> },
}

fn inclusive() -> bool {
    true
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
            (Exact { .. }, _) => false,
            (Range { min, max, min_inclusive, max_inclusive }, Range { min: pmin, max: pmax, min_inclusive: pmin_inc, max_inclusive: pmax_inc }) => {
                bound_ok(*min, *min_inclusive, *pmin, *pmin_inc, |a, b| a > b)
                    && bound_ok(*max, *max_inclusive, *pmax, *pmax_inc, |a, b| a < b)
            }
            (OneOf { values }, OneOf { values: p }) => all_members(p, values),
            (NotOneOf { excluded }, NotOneOf { excluded: p }) => all_members(excluded, p),
            (Contains { required }, Contains { required: p }) => all_members(required, p),
            (Subset { allowed }, Subset { allowed: p }) => all_members(p, allowed),
            (All { constraints }, All { constraints: p }) => match_all(p, constraints, &mut vec![false; constraints.len()], 0),
            (Any { constraints }, Any { constraints: p }) => {
                !constraints.is_empty() && constraints.iter().all(|c| p.iter().any(|pc| c.subsumes(pc)))
            }
            _ => false,
        }
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

/// One-to-one assignment of every parent `all` clause to a distinct derived
/// clause that subsumes it, with backtracking (draft section 4.5).
fn match_all(parents: &[Constraint], derived: &[Constraint], used: &mut Vec<bool>, idx: usize) -> bool {
    let Some(parent) = parents.get(idx) else { return true };
    for i in 0..derived.len() {
        if !used[i] && derived[i].subsumes(parent) {
            used[i] = true;
            if match_all(parents, derived, used, idx + 1) {
                return true;
            }
            used[i] = false;
        }
    }
    false
}
