//! The tool grant of a verified token, read the way the draft's section 8
//! reads it: the single `attenuating_agent_token` entry, every constraint
//! well-formed (section 3.4), every constraint map normalized (section 3.3),
//! and every number admissible.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::constraint::Constraint;
use crate::token::AAT_TYPE;
use crate::{deny, Result};

/// One tool's constraint map, normalized: `named` maps an argument to its
/// constraint and whether it is `optional`; `star` is the `"*"` entry, which
/// admits any argument the map does not name. An empty map is `{"*":
/// wildcard}`.
#[derive(Debug, Clone)]
pub(crate) struct ArgMap {
    pub named: BTreeMap<String, (Constraint, bool)>,
    pub star: bool,
}

/// Tool identifier → its normalized constraint map.
pub(crate) type Grant = BTreeMap<String, ArgMap>;

/// Steps 3m/3n, 4n/4o and 6a: exactly one `attenuating_agent_token` entry,
/// whose `tools` is an object of objects, every constraint in it well-formed
/// and at most `max_depth` deep. Entries of other types are ignored.
pub(crate) fn grant(details: &[Value], max_depth: usize) -> Result<Grant> {
    let mut entries = details.iter().filter(|d| d.get("type").and_then(Value::as_str) == Some(AAT_TYPE));
    let entry = entries.next().ok_or_else(|| deny("no attenuating_agent_token entry"))?;
    if entries.next().is_some() {
        return Err(deny("more than one attenuating_agent_token entry"));
    }
    let tools = entry.get("tools").and_then(Value::as_object).ok_or_else(|| deny("attenuating_agent_token entry has no tools object"))?;
    tools
        .iter()
        .map(|(tool, map)| {
            let map = map.as_object().ok_or_else(|| deny(format!("tool {}: constraint map is not an object", tool)))?;
            Ok((tool.clone(), arg_map(tool, map, max_depth)?))
        })
        .collect()
}

fn arg_map(tool: &str, map: &Map<String, Value>, max_depth: usize) -> Result<ArgMap> {
    let mut out = ArgMap { named: BTreeMap::new(), star: map.is_empty() };
    for (arg, value) in map {
        let entry = value.as_object().ok_or_else(|| deny(format!("tool {} argument {}: constraint is not an object", tool, arg)))?;
        if arg == "*" {
            // Only `{"constraint_type": "wildcard"}`, with no `optional`.
            if entry.len() != 1 || entry.get("constraint_type").and_then(Value::as_str) != Some("wildcard") {
                return Err(deny(format!("tool {}: the \"*\" entry is not a plain wildcard", tool)));
            }
            out.star = true;
            continue;
        }
        let optional = match entry.get("optional") {
            None => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err(deny(format!("tool {} argument {}: optional is not a boolean", tool, arg))),
        };
        out.named.insert(arg.clone(), (Constraint::parse(value, true, max_depth)?, optional));
    }
    Ok(out)
}

/// Fails on the first JSON number in `text` that is not admissible (section
/// 3.4): its double-precision value, serialized the JCS way, must denote the
/// same mathematical value as the number as written. `text` must be valid
/// JSON; strings are skipped.
pub(crate) fn admissible_numbers(text: &str) -> Result<()> {
    let bytes = text.as_bytes();
    let (mut i, mut in_string) = (0, false);
    while i < bytes.len() {
        let c = bytes[i];
        if in_string {
            match c {
                b'\\' => i += 2,
                b'"' => {
                    in_string = false;
                    i += 1;
                }
                _ => i += 1,
            }
            continue;
        }
        if c == b'"' {
            in_string = true;
            i += 1;
        } else if c == b'-' || c.is_ascii_digit() {
            let start = i;
            while i < bytes.len() && matches!(bytes[i], b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E') {
                i += 1;
            }
            let literal = &text[start..i];
            if !admissible(literal) {
                return Err(deny(format!("number {} does not survive JCS canonicalization", literal)));
            }
        } else {
            i += 1;
        }
    }
    Ok(())
}

fn admissible(literal: &str) -> bool {
    let Ok(double) = literal.parse::<f64>() else { return false };
    // `{:e}` prints the shortest digits that round-trip, as JCS does.
    double.is_finite() && decimal(literal).is_some() && decimal(literal) == decimal(&format!("{:e}", double))
}

/// A decimal literal as (negative, significant digits, exponent), the value
/// being 0.d1d2… × 10^exponent. Zero, of either sign, is (false, "", 0).
fn decimal(s: &str) -> Option<(bool, String, i64)> {
    let (negative, s) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let (mantissa, exponent) = match s.find(['e', 'E']) {
        Some(i) => (&s[..i], s[i + 1..].parse::<i64>().ok()?),
        None => (s, 0),
    };
    let (int, frac) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let mut digits = format!("{}{}", int, frac);
    let mut exponent = exponent.checked_add(int.len() as i64)?;
    let leading = digits.len() - digits.trim_start_matches('0').len();
    digits.drain(..leading);
    exponent -= leading as i64;
    digits.truncate(digits.trim_end_matches('0').len());
    if digits.is_empty() {
        return Some((false, String::new(), 0));
    }
    Some((negative, digits, exponent))
}

#[cfg(test)]
mod tests {
    use super::admissible_numbers;

    #[test]
    fn the_drafts_examples() {
        for ok in ["0.1", "1e20", "9007199254740994", "-0", "0", "1.50", "100", "-2.5e-3"] {
            assert!(admissible_numbers(ok).is_ok(), "{ok}");
        }
        for bad in ["9007199254740993", "1.00000000000000001", "1e400"] {
            assert!(admissible_numbers(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn numbers_inside_strings_are_not_numbers() {
        assert!(admissible_numbers(r#"{"id":"9007199254740993","n":[1,2.5]}"#).is_ok());
        assert!(admissible_numbers(r#"{"s":"a\"9007199254740993","n":9007199254740993}"#).is_err());
    }
}
