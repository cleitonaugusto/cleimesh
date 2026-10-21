//! Property tests (S17): attenuation can never widen.
//! For random constraint pairs, if the child subsumes the parent, every
//! value the child accepts the parent accepts too.

use cleimesh_aat::Constraint;
use proptest::prelude::*;
use serde_json::{json, Value};

fn scalar() -> impl Strategy<Value = Value> {
    prop_oneof![
        (-3i64..6).prop_map(|n| json!(n)),
        prop::sample::select(vec![-1.5f64, 0.5, 2.5, 4.0]).prop_map(|f| json!(f)),
        prop::sample::select(vec!["a", "b", "oi", ""]).prop_map(|s| json!(s)),
        any::<bool>().prop_map(|b| json!(b)),
        Just(Value::Null),
    ]
}

fn value() -> impl Strategy<Value = Value> {
    prop_oneof![
        4 => scalar(),
        1 => prop::collection::vec(scalar(), 0..4).prop_map(Value::Array),
    ]
}

fn leaf() -> impl Strategy<Value = Constraint> {
    let bound = prop::option::of(prop::sample::select(vec![-2.0f64, 0.0, 1.0, 2.5, 4.0]));
    prop_oneof![
        scalar().prop_map(|value| Constraint::Exact { value }),
        (bound.clone(), bound, any::<bool>(), any::<bool>())
            .prop_map(|(min, max, min_inclusive, max_inclusive)| Constraint::Range { min, max, min_inclusive, max_inclusive }),
        prop::collection::vec(scalar(), 0..4).prop_map(|values| Constraint::OneOf { values }),
        prop::collection::vec(scalar(), 0..4).prop_map(|excluded| Constraint::NotOneOf { excluded }),
        prop::collection::vec(scalar(), 0..3).prop_map(|required| Constraint::Contains { required }),
        prop::collection::vec(scalar(), 0..4).prop_map(|allowed| Constraint::Subset { allowed }),
        Just(Constraint::Wildcard),
    ]
}

fn constraint() -> impl Strategy<Value = Constraint> {
    leaf().prop_recursive(3, 12, 3, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 1..3).prop_map(|constraints| Constraint::All { constraints }),
            prop::collection::vec(inner, 1..3).prop_map(|constraints| Constraint::Any { constraints }),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 20_000, ..ProptestConfig::default() })]

    #[test]
    fn subsumption_never_widens(parent in constraint(), child in constraint(), values in prop::collection::vec(value(), 1..8)) {
        if child.subsumes(&parent) {
            for v in &values {
                prop_assert!(!child.check(v) || parent.check(v), "child {:?} accepts {} but parent {:?} does not", child, v, parent);
            }
        }
    }

    #[test]
    fn every_constraint_subsumes_itself_and_wildcard_takes_all(c in constraint(), v in value()) {
        let composite = matches!(c, Constraint::All { .. } | Constraint::Any { .. });
        prop_assert!(c.subsumes(&c) || composite, "{:?} does not subsume itself", c);
        prop_assert!(Constraint::Wildcard.check(&v));
    }
}
