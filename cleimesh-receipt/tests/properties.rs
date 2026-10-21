//! Property tests (S17): changing any byte of a
//! receipt log is caught, except a change on the last line that leaves its
//! signed content the same (e.g. an equivalent JSON escape).

use cleimesh_receipt::*;
use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use serde_json::json;

fn log() -> Vec<u8> {
    let key = SigningKey::from_bytes(&[5; 32]);
    let mut lines = Vec::new();
    let mut prev = None;
    for n in 0..3u64 {
        let entry = Entry {
            step_id: format!("step-{n}"),
            action_id: "cleimesh.tool_call".into(),
            params: json!({"tool": "echo", "n": n, "nested": {"z": [1, "é"], "a": null}}),
            success: n != 1,
            ts_ms: 1_800_000_000_000 + n,
            actor: None,
        };
        let receipt = sign(&key, entry, prev.clone()).unwrap();
        let line = receipt.to_line().unwrap();
        prev = Some(sha256_hex(line.as_bytes()));
        lines.extend_from_slice(line.as_bytes());
        lines.push(b'\n');
    }
    lines
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1_000, ..ProptestConfig::default() })]

    #[test]
    fn any_changed_byte_is_caught(index in any::<prop::sample::Index>(), byte in any::<u8>()) {
        let original = log();
        let anchor = SigningKey::from_bytes(&[5; 32]).verifying_key();
        let i = index.index(original.len());
        prop_assume!(original[i] != byte);
        let mut changed = original.clone();
        changed[i] = byte;

        let report = verify_log(&changed, &anchor);
        let last_line_start = original[..original.len() - 1].iter().rposition(|b| *b == b'\n').unwrap() + 1;
        if i < last_line_start {
            prop_assert!(!report.ok(), "byte {} changed before the last line went unnoticed", i);
        } else if report.ok() {
            // Only a change that keeps the signed content may pass.
            let text = |b: &[u8]| String::from_utf8(b[last_line_start..b.len() - 1].to_vec()).unwrap();
            let (a, b) = (Receipt::parse(&text(&original)).unwrap(), Receipt::parse(&text(&changed)).unwrap());
            prop_assert_eq!(a.canonical().unwrap(), b.canonical().unwrap());
        }
    }
}
