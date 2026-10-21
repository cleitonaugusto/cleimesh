//! Arbitrary bytes as a receipt log: verification must never panic, and a
//! log it calls valid must parse line by line with good signatures.
#![no_main]

use cleimesh_fuzz::*;
use cleimesh_receipt::{verify_log, Receipt};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let anchor = anchor_key().verifying_key();
    let report = verify_log(data, &anchor);
    if report.ok() && !data.is_empty() {
        let text = std::str::from_utf8(data).expect("a valid log is UTF-8");
        for line in text.strip_suffix('\n').expect("a valid log ends with a newline").split('\n') {
            let receipt = Receipt::parse(line).expect("a valid log's lines parse");
            assert_eq!(receipt.verify_signature().expect("and verify"), anchor);
        }
    }
    for line in data.split(|b| *b == b'\n') {
        if let Ok(text) = std::str::from_utf8(line) {
            let _ = Receipt::parse(text).map(|r| r.canonical());
        }
    }
});
