//! Receipts as OCSF events (IG3): one JSON object per line, for SIEMs and
//! agent sandboxes that keep their audit trail in OCSF (NVIDIA OpenShell, AWS
//! Security Lake). Every receipt becomes an API Activity event (class 6003):
//! the operation is the tool, `action` and `disposition` say whether the node
//! allowed it, and what only CleiMesh has (step id, chain link, signature,
//! the receipt's own params) goes under `unmapped.cleimesh`, so the event can
//! be traced back to a line `audit verify` checks.
//!
//! The params carry digests and pseudonyms only, never the data a call
//! touched, so exporting them leaks nothing a receipt doesn't.

use cleimesh_receipt::Receipt;
use serde_json::{json, Value};

/// The OCSF schema version the events follow.
pub const OCSF_VERSION: &str = "1.8.0";

const API_ACTIVITY: u64 = 6003;

/// One receipt as one OCSF API Activity event. `log_verified` says whether
/// the whole log passed `audit verify` when it was exported.
pub fn event(r: &Receipt, log_verified: bool) -> Value {
    let p = &r.params;
    let text = |v: &Value| v.as_str().unwrap_or_default().to_string();
    let tool = text(&p["tool"]);
    let (operation, kind) = if r.action_id == cleimesh_receipt::PRUNE_ACTION_ID {
        ("prune".to_string(), Kind::Admin)
    } else if r.action_id == cleimesh_p2p::receipts::TAINT_CLEARED_ACTION_ID {
        ("taint_clear".to_string(), Kind::Admin)
    } else if r.action_id == "cleimesh.tool_result" {
        (tool.clone(), Kind::Result)
    } else if p["decision"].as_str() == Some("denied") {
        (tool.clone(), Kind::Denied)
    } else {
        (tool.clone(), Kind::Allowed)
    };
    // API Activity activities: 1 Create, 2 Read, 3 Update, 4 Delete, 99 Other.
    let (activity_id, activity_name) = match operation.as_str() {
        "file_read" => (2, "Read"),
        "file_write" => (3, "Update"),
        _ => (99, "Other"),
    };
    let ok = match kind {
        Kind::Denied => false,
        Kind::Result => r.success,
        Kind::Allowed | Kind::Admin => true,
    };
    let (severity_id, severity) = match kind {
        Kind::Denied => (3, "Medium"),
        Kind::Result if !r.success => (2, "Low"),
        _ => (1, "Informational"),
    };
    let message = match kind {
        Kind::Allowed => format!("{} allowed", operation),
        Kind::Denied => format!("{} denied: {}", operation, text(&p["denial"])),
        Kind::Result => format!("{} {}", operation, if r.success { "succeeded" } else { "failed" }),
        Kind::Admin if operation == "taint_clear" => format!("taint cleared by a human: {}", text(&p["reason"])),
        Kind::Admin => format!("{} receipt(s) removed by retention", p["removed_lines"]),
    };
    let authority = &p["authority"];
    let who = authority["holder"].as_str().or_else(|| p["holder"].as_str()).or_else(|| p["caller"].as_str());
    let mut event = json!({
        "class_uid": API_ACTIVITY,
        "class_name": "API Activity",
        "category_uid": 6,
        "category_name": "Application Activity",
        "activity_id": activity_id,
        "activity_name": activity_name,
        "type_uid": API_ACTIVITY * 100 + activity_id,
        "time": r.ts_ms,
        "severity_id": severity_id,
        "severity": severity,
        "status_id": if ok { 1 } else { 2 },
        "status": if ok { "Success" } else { "Failure" },
        "message": message,
        "metadata": {
            "product": { "name": "CleiMesh", "vendor_name": "CleiMesh", "version": env!("CARGO_PKG_VERSION") },
            "version": OCSF_VERSION,
            "uid": r.step_id,
            "log_name": "receipts",
        },
        "api": { "operation": operation, "service": { "name": "cleimesh" }, "request": { "uid": r.step_id } },
        "unmapped": { "cleimesh": {
            "action_id": r.action_id,
            "prev_hash": r.prev_hash,
            "public_key": r.public_key,
            "signature": r.signature,
            "log_verified": log_verified,
            "params": p,
        } },
    });
    if matches!(kind, Kind::Allowed | Kind::Denied) {
        let allowed = matches!(kind, Kind::Allowed);
        event["action_id"] = json!(if allowed { 1 } else { 2 });
        event["action"] = json!(if allowed { "Allowed" } else { "Denied" });
        event["disposition_id"] = json!(if allowed { 1 } else { 2 });
        event["disposition"] = json!(if allowed { "Allowed" } else { "Blocked" });
    }
    if let Some(who) = who {
        event["actor"] = json!({ "user": { "uid": who } });
    }
    if let Some(caller) = p["caller"].as_str() {
        event["src_endpoint"] = json!({ "uid": caller });
    }
    event
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Allowed,
    Denied,
    Result,
    Admin,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt(action_id: &str, params: Value, success: bool) -> Receipt {
        Receipt {
            step_id: "01a1380f-5427-733b-a9fe-fe4bba621fab".into(),
            action_id: action_id.into(),
            params,
            success,
            ts_ms: 1_791_941_891_111,
            actor: None,
            prev_hash: Some("abc".into()),
            public_key: "0a7f".into(),
            signature: "cfda".into(),
        }
    }

    #[test]
    fn an_allowed_read_is_an_api_read_with_the_holder_as_actor() {
        let params = json!({"tool": "file_read", "decision": "allowed", "caller": "12D3KooWCaller",
                            "authority": {"kind": "aat", "holder": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:GMuj"}});
        let e = event(&receipt("cleimesh.tool_call", params, true), true);
        assert_eq!(e["class_uid"], 6003);
        assert_eq!(e["type_uid"], 600302);
        assert_eq!(e["activity_name"], "Read");
        assert_eq!(e["action"], "Allowed");
        assert_eq!(e["disposition"], "Allowed");
        assert_eq!(e["status"], "Success");
        assert_eq!(e["api"]["operation"], "file_read");
        assert_eq!(e["actor"]["user"]["uid"], "urn:ietf:params:oauth:jwk-thumbprint:sha-256:GMuj");
        assert_eq!(e["src_endpoint"]["uid"], "12D3KooWCaller");
        assert_eq!(e["metadata"]["version"], OCSF_VERSION);
        assert_eq!(e["unmapped"]["cleimesh"]["signature"], "cfda");
        assert_eq!(e["unmapped"]["cleimesh"]["log_verified"], true);
    }

    #[test]
    fn a_denied_write_is_blocked_with_the_reason() {
        let params = json!({"tool": "file_write", "decision": "denied", "caller": "c",
                            "denial": "holder received untrusted content"});
        let e = event(&receipt("cleimesh.tool_call", params, false), true);
        assert_eq!(e["activity_name"], "Update");
        assert_eq!(e["action"], "Denied");
        assert_eq!(e["disposition"], "Blocked");
        assert_eq!(e["status"], "Failure");
        assert_eq!(e["severity"], "Medium");
        assert_eq!(e["message"], "file_write denied: holder received untrusted content");
    }

    #[test]
    fn a_failed_result_and_a_taint_clearing_carry_no_decision() {
        let failed = event(&receipt("cleimesh.tool_result", json!({"tool": "echo", "decision_step": "x"}), false), true);
        assert_eq!(failed["status"], "Failure");
        assert!(failed.get("action").is_none());
        let cleared = event(
            &receipt(cleimesh_p2p::receipts::TAINT_CLEARED_ACTION_ID, json!({"holder": "h", "reason": "e-mail revisado"}), true),
            false,
        );
        assert_eq!(cleared["api"]["operation"], "taint_clear");
        assert_eq!(cleared["actor"]["user"]["uid"], "h");
        assert_eq!(cleared["unmapped"]["cleimesh"]["log_verified"], false);
    }
}
