//! Arbitrary bytes as an AAT presentation: verification must never panic,
//! and must never accept a presentation it can't fully check.
#![no_main]

use cleimesh_aat::{verify, Policy, Presentation};
use cleimesh_fuzz::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Either a JSON presentation (how it travels) or raw lines: tokens, then
    // the proof of possession last.
    let presentation = match serde_json::from_slice::<Presentation>(data) {
        Ok(p) => p,
        Err(_) => {
            let text = String::from_utf8_lossy(data);
            let mut parts: Vec<String> = text.split('\n').map(str::to_string).collect();
            let pop = parts.pop().unwrap_or_default();
            Presentation { chain: parts, pop }
        }
    };
    let anchors = [anchor_jwk()];
    let policy = Policy { trust_anchors: &anchors, audience: Some(AUDIENCE), now: NOW };
    let (tool, args) = call();
    if let Ok(verified) = verify(&presentation, &policy, tool, &args) {
        // Whatever passed is a chain of the claimed length, rooted in the anchor.
        assert_eq!(verified.chain.len(), presentation.chain.len());
        assert_eq!(verified.leaf.del_depth as usize + 1, presentation.chain.len());
    }
});
