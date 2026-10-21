//! "A commandment without a test is marketing" (docs/commandments.md). Every
//! commandment in both languages names tests and the files that hold them;
//! this fails if a named test no longer exists in those files.

use std::collections::BTreeSet;
use std::path::Path;

/// (commandment number, test names, test files) for each "### N." section.
fn sections(doc: &str) -> Vec<(u32, BTreeSet<String>, BTreeSet<String>)> {
    let mut out: Vec<(u32, BTreeSet<String>, BTreeSet<String>)> = Vec::new();
    for line in doc.lines() {
        if let Some(rest) = line.strip_prefix("### ") {
            let n = rest.split('.').next().unwrap().parse().unwrap();
            out.push((n, BTreeSet::new(), BTreeSet::new()));
            continue;
        }
        let Some((_, tests, files)) = out.last_mut() else { continue };
        if line.starts_with("## ") {
            break;
        }
        for (i, quoted) in line.split('`').enumerate() {
            if i % 2 == 0 {
                continue;
            }
            if quoted.ends_with(".rs") {
                files.insert(quoted.to_string());
            } else if quoted.contains('_') && quoted.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
                tests.insert(quoted.to_string());
            }
        }
    }
    out
}

#[test]
fn every_commandment_names_tests_that_exist() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let english = sections(&std::fs::read_to_string(root.join("docs/commandments.md")).unwrap());
    let portuguese = sections(&std::fs::read_to_string(root.join("docs/mandamentos.md")).unwrap());

    assert_eq!(english.iter().map(|s| s.0).collect::<Vec<_>>(), (1..=10).collect::<Vec<_>>());
    assert_eq!(english, portuguese, "both languages must name the same tests for each commandment");

    for (n, tests, files) in &english {
        assert!(!tests.is_empty(), "commandment {n} names no test");
        let sources: String = files.iter().map(|f| std::fs::read_to_string(root.join(f)).unwrap_or_else(|_| panic!("commandment {n}: {f} not found"))).collect();
        for test in tests {
            assert!(sources.contains(&format!("fn {test}(")), "commandment {n}: test {test} not found in {files:?}");
        }
    }
}
