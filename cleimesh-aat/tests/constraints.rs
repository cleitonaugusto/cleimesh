//! Constraint checks and subsumption rules, draft sections 3.4 and 4.5.

use cleimesh_aat::Constraint;
use serde_json::json;

fn c(v: serde_json::Value) -> Constraint {
    serde_json::from_value(v).unwrap()
}

#[test]
fn checks() {
    assert!(c(json!({"constraint_type": "range", "min": 1, "max": 5, "max_inclusive": false})).check(&json!(4.9)));
    assert!(!c(json!({"constraint_type": "range", "min": 1, "max": 5, "max_inclusive": false})).check(&json!(5)));
    assert!(!c(json!({"constraint_type": "range", "max": 5})).check(&json!("3")));
    assert!(c(json!({"constraint_type": "contains", "required": ["a"]})).check(&json!(["a", "b"])));
    assert!(!c(json!({"constraint_type": "subset", "allowed": ["a"]})).check(&json!(["a", "b"])));
    assert!(!c(json!({"constraint_type": "not_one_of", "excluded": ["rm"]})).check(&json!("rm")));
    let any = c(json!({"constraint_type": "any", "constraints": [{"constraint_type": "exact", "value": "pdf"}, {"constraint_type": "exact", "value": "csv"}]}));
    assert!(any.check(&json!("csv")) && !any.check(&json!("doc")));
}

#[test]
fn range_inclusivity_only_tightens() {
    let parent = c(json!({"constraint_type": "range", "min": 0, "max": 10}));
    assert!(c(json!({"constraint_type": "range", "min": 0, "max": 10, "max_inclusive": false})).subsumes(&parent));
    assert!(c(json!({"constraint_type": "range", "min": 2, "max": 8})).subsumes(&parent));
    assert!(!c(json!({"constraint_type": "range", "min": 0})).subsumes(&parent), "dropping a bound widens");
    let exclusive = c(json!({"constraint_type": "range", "min": 0, "max": 10, "max_inclusive": false}));
    assert!(!parent.subsumes(&exclusive), "exclusive to inclusive widens");
    assert!(c(json!({"constraint_type": "range", "min": 0, "max": 10})).subsumes(&c(json!({"constraint_type": "range"}))));
}

#[test]
fn cross_type_rules() {
    let one_of = Constraint::one_of(["pdf", "csv"]);
    assert!(Constraint::exact("pdf").subsumes(&one_of));
    assert!(!Constraint::exact("doc").subsumes(&one_of));
    assert!(Constraint::exact(3).subsumes(&c(json!({"constraint_type": "range", "max": 5}))));
    assert!(!c(json!({"constraint_type": "not_one_of", "excluded": ["doc"]})).subsumes(&one_of));
    assert!(one_of.subsumes(&Constraint::Wildcard));
    assert!(!Constraint::Wildcard.subsumes(&one_of));
    assert!(!Constraint::exact("pdf").subsumes(&c(json!({"constraint_type": "not_one_of", "excluded": []}))), "pair not listed by the draft");
}

#[test]
fn all_needs_a_one_to_one_match() {
    let r = |max: i64| json!({"constraint_type": "range", "max": max});
    let parent = c(json!({"constraint_type": "all", "constraints": [r(10), r(5)]}));
    // A greedy match gives r(3) to r(10) and is stuck on r(5); backtracking
    // finds r(7) → r(10), r(3) → r(5).
    assert!(c(json!({"constraint_type": "all", "constraints": [r(3), r(7)]})).subsumes(&parent));
    assert!(!c(json!({"constraint_type": "all", "constraints": [r(6), r(7)]})).subsumes(&parent));
    assert!(c(json!({"constraint_type": "all", "constraints": [r(4), r(3), r(1)]})).subsumes(&parent));
    // One derived clause cannot stand for two parent clauses.
    assert!(!c(json!({"constraint_type": "all", "constraints": [r(3)]})).subsumes(&parent));
}

#[test]
fn any_may_only_drop_clauses() {
    let e = |v: &str| json!({"constraint_type": "exact", "value": v});
    let parent = c(json!({"constraint_type": "any", "constraints": [e("pdf"), e("csv"), e("xlsx")]}));
    assert!(c(json!({"constraint_type": "any", "constraints": [e("pdf"), e("csv")]})).subsumes(&parent));
    assert!(!c(json!({"constraint_type": "any", "constraints": [e("pdf"), e("docx")]})).subsumes(&parent));
    assert!(!c(json!({"constraint_type": "any", "constraints": []})).subsumes(&parent));
}

#[test]
fn depth_is_counted() {
    let mut deep = json!({"constraint_type": "wildcard"});
    for _ in 0..40 {
        deep = json!({"constraint_type": "all", "constraints": [deep]});
    }
    assert!(c(deep).depth() > cleimesh_aat::MAX_CONSTRAINT_DEPTH);
}
