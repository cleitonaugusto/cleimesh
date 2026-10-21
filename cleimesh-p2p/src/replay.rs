//! Replaying a call from its receipts (C4): instead of
//! trusting the node's signature on "this ran and returned that", run the
//! same module on the same input under the same sandbox terms, frozen clock
//! and seed, and compare.
//!
//! Only calls that depend on nothing but their input are replayable: no
//! directories, no network (the decision receipt says so, and why not).
//! The input is never in a receipt; whoever replays must supply it, and it
//! must hash to the receipt's `input_sha256`. The module must hash to its
//! `wasm_sha256`.

use std::time::Duration;

use cleimesh_aat::VerifyingKey;
use cleimesh_receipt::{sha256_hex, verify_log, Receipt};
use cleimesh_wasm_sandbox::{Determinism, SandboxConfig, WasmSandbox, ENGINE};
use serde_json::Value;

use crate::behaviour::ToolRequest;
use crate::receipts::{json_sha256, DECISION_ACTION_ID, RESULT_ACTION_ID};

/// The outcome of a replay that could run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Replay {
    /// Same success and output digest as the result receipt.
    Reproduced { step_id: String, output_sha256: String },
    /// The receipts say one thing, the replay another: the node's record is
    /// wrong, or the run was not deterministic.
    Mismatch { step_id: String, recorded: String, replayed: String },
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..32).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()).collect();
    bytes?.try_into().ok()
}

/// Replays the call whose decision receipt's `step_id` ends with `step`.
/// Refuses (`Err`) a log that fails verification, an unknown or ambiguous
/// step, a call that isn't replayable, another engine, or an input or
/// module that doesn't match the receipt.
pub async fn replay(log: &[u8], anchor: &VerifyingKey, step: &str, args: &Value, wasm: &[u8]) -> Result<Replay, String> {
    let check = verify_log(log, anchor);
    if !check.ok() {
        let f = &check.failures[0];
        return Err(format!("the log fails verification (line {}: {}); nothing it says can be replayed", f.line, f.reason));
    }
    let receipts: Vec<Receipt> = String::from_utf8_lossy(log).lines().filter_map(|l| Receipt::parse(l).ok()).collect();
    let decisions: Vec<&Receipt> = receipts.iter().filter(|r| r.action_id == DECISION_ACTION_ID && r.step_id.ends_with(step)).collect();
    let decision = match decisions.as_slice() {
        [one] => *one,
        [] => return Err(format!("no decision receipt ends with {}", step)),
        _ => return Err(format!("{} decision receipts end with {}; give more of the step id", decisions.len(), step)),
    };
    let p = &decision.params;
    if p["decision"] != "allowed" {
        return Err("that call was denied: nothing ran".into());
    }
    let terms = &p["sandbox"];
    if terms["replayable"] != true {
        return Err(format!("that call is not replayable: {}", terms["not_replayable_because"]));
    }
    let r = &terms["replay"];
    if r["engine"] != ENGINE {
        return Err(format!("recorded on {}, this build runs {}", r["engine"], ENGINE));
    }
    let result = receipts
        .iter()
        .find(|x| x.action_id == RESULT_ACTION_ID && x.params["decision_step"] == decision.step_id.as_str())
        .ok_or("the call has no result receipt (cut short?)")?;

    if json_sha256(args) != p["input_sha256"].as_str().unwrap_or_default() {
        return Err("these arguments are not the call's: their digest differs from input_sha256".into());
    }
    if sha256_hex(wasm) != p["wasm_sha256"].as_str().unwrap_or_default() {
        return Err("this module is not the one that ran: its digest differs from wasm_sha256".into());
    }
    let determinism = Determinism {
        clock_ns: r["clock_ns"].as_u64().ok_or("receipt has no clock")?,
        seed: hex32(r["seed"].as_str().unwrap_or_default()).ok_or("receipt has no seed")?,
    };
    let mut config = SandboxConfig {
        allow_network: false,
        allow_filesystem_read: false,
        allow_filesystem_write: false,
        allowed_paths: Vec::new(),
        writable_paths: Vec::new(),
        determinism: Some(determinism),
        ..SandboxConfig::default()
    };
    config.limits.max_instructions = terms["max_instructions"].as_u64().ok_or("receipt has no instruction budget")?;
    config.max_memory_bytes = terms["max_memory_bytes"].as_u64().ok_or("receipt has no memory limit")? as usize;
    config.max_execution_time = Duration::from_millis(terms["timeout_ms"].as_u64().ok_or("receipt has no timeout")?);

    let tool = p["tool"].as_str().unwrap_or_default().to_string();
    let sandbox = WasmSandbox::new(config.clone()).map_err(|e| e.to_string())?;
    sandbox.register_wasm_module(&tool, wasm.to_vec()).map_err(|e| e.to_string())?;
    let request = ToolRequest {
        tool_name: tool,
        payload: args.clone(),
        request_id: p["request_id"].as_str().unwrap_or_default().to_string(),
        capability: None,
        presentation: None,
        context: None,
    };
    let response = crate::run_tool(sandbox, request, config).await;

    let observed = &result.params["observed"];
    let describe = |success: bool, output: &str, error: Option<&str>| format!("success={} output_sha256={} error_sha256={}", success, output, error.unwrap_or("-"));
    let recorded = describe(observed["success"] == true, observed["output_sha256"].as_str().unwrap_or_default(), observed["error_sha256"].as_str());
    let output_sha256 = json_sha256(&response.output);
    let error_sha256 = response.error.as_ref().map(|e| sha256_hex(e.as_bytes()));
    let replayed = describe(response.success, &output_sha256, error_sha256.as_deref());
    Ok(if recorded == replayed {
        Replay::Reproduced { step_id: decision.step_id.clone(), output_sha256 }
    } else {
        Replay::Mismatch { step_id: decision.step_id.clone(), recorded, replayed }
    })
}
