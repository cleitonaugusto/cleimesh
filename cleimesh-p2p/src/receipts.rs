//! What a node records about each tool call it receives
//! (C2), in the format of `cleimesh_receipt`. A denied call gets one receipt.
//! An allowed call gets two: the decision, written before the tool runs (no
//! receipt, no run), and the result, pointing back at it. All the detail
//! sits in `params`, the signed member, as profile `cleimesh.tool_call/2`.
//!
//! Receipts carry digests, never content: arguments, output and errors are
//! SHA-256 of their canonical JSON (or text), so a log can go to an auditor
//! without the personal data a call touched (draft section 10).

use std::time::Instant;

use cleimesh_receipt::{canonical_json, sha256_hex, Entry};
use cleimesh_wasm_sandbox::SandboxConfig;
use serde::Serialize;
use serde_json::{json, Value};

use crate::behaviour::{ToolRequest, ToolResponse};

/// Longest purpose accepted, in characters: a label, not a document.
pub const MAX_PURPOSE_CHARS: usize = 200;

/// What a call says about the personal data it handles (LGPD, C3): whose
/// data (the data subject, e.g. a customer id) and why (the purpose). Both
/// optional. The subject never reaches a receipt in clear: see
/// [`subject_pseudonym`]. The purpose is recorded as written, so it must not
/// carry personal data itself.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct CallContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

/// The data subject as receipts record it: HMAC-SHA256 under a key derived
/// from the node key. Anyone can check a receipt's signature, but only the
/// node's owner (the controller) can tell which receipts are about a given
/// person, by computing the same pseudonym (LGPD art. 13 §4). A plain hash
/// would not do: ids such as CPFs are few enough to brute-force.
pub fn subject_pseudonym(node_key: &cleimesh_aat::SigningKey, data_subject: &str) -> String {
    let tag = node_hmac(node_key, b"cleimesh/data-subject-pseudonym/v1\0", data_subject.as_bytes());
    format!("hmac-sha256:{}", tag.iter().map(|b| format!("{:02x}", b)).collect::<String>())
}

/// HMAC-SHA256 of `message` under a key derived from the node key and `label`.
fn node_hmac(node_key: &cleimesh_aat::SigningKey, label: &[u8], message: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};
    let mut derive = Sha256::new();
    derive.update(label);
    derive.update(node_key.to_bytes());
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&derive.finalize()).expect("HMAC takes any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// Deepest level a result receipt names below a granted directory, and
/// most directories it names (C5); past either, it names the parents.
pub const FS_MAX_DEPTH: usize = 3;
pub const FS_MAX_DIRS: usize = 64;

/// A directory below `grant` as receipts name it: each component replaced
/// by an HMAC of the path up to it, so folders named after people stay
/// private, the hierarchy stays visible, and the node's owner can map them
/// back by walking the disk. The grant itself is `"."`.
pub fn fs_dir_pseudonym(node_key: &cleimesh_aat::SigningKey, grant: &str, components: &[String]) -> String {
    if components.is_empty() {
        return ".".into();
    }
    (1..=components.len())
        .map(|i| {
            let message = format!("{}\0{}", grant, components[..i].join("/"));
            let tag = node_hmac(node_key, b"cleimesh/fs-dir-pseudonym/v1\0", message.as_bytes());
            format!("h:{}", tag[..8].iter().map(|b| format!("{:02x}", b)).collect::<String>())
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// The `fs` block of a result receipt: per granted directory, the
/// directories read and written (pseudonymized, at most [`FS_MAX_DEPTH`]
/// deep and [`FS_MAX_DIRS`] in all) and the file counts. `None` when the
/// call had no directory.
pub(crate) fn fs_observed(fs: &cleimesh_wasm_sandbox::FsObserved, node_key: &cleimesh_aat::SigningKey) -> Option<Value> {
    use std::collections::BTreeSet;
    if fs.grants.is_empty() {
        return None;
    }
    let cut = |set: &BTreeSet<Vec<String>>, depth: usize| -> BTreeSet<Vec<String>> { set.iter().map(|c| c[..c.len().min(depth)].to_vec()).collect() };
    let mut depth = FS_MAX_DEPTH;
    let lists = loop {
        let lists: Vec<_> = fs.grants.iter().map(|g| (cut(&g.read, depth), cut(&g.write, depth))).collect();
        let total: usize = lists.iter().map(|(r, w)| r.len() + w.len()).sum();
        if total <= FS_MAX_DIRS || depth == 0 {
            break lists;
        }
        depth -= 1;
    };
    let truncated = fs.grants.iter().any(|g| g.read.iter().chain(&g.write).any(|c| c.len() > depth));
    let grants: Vec<Value> = fs
        .grants
        .iter()
        .zip(lists)
        .map(|(g, (read, write))| {
            let names = |set: BTreeSet<Vec<String>>| set.iter().map(|c| fs_dir_pseudonym(node_key, &g.grant, c)).collect::<Vec<_>>();
            json!({
                "grant": g.grant,
                "read": names(read),
                "write": names(write),
                "files_read": g.files_read,
                "files_written": g.files_written,
                "refused": g.refused,
            })
        })
        .collect();
    Some(json!({"grants": grants, "truncated": truncated}))
}

/// `action_id` of the receipt deciding a call: allowed (written before it
/// runs) or denied.
pub const DECISION_ACTION_ID: &str = "cleimesh.tool_call";
/// `action_id` of a human clearing a holder's taint (C6).
pub const TAINT_CLEARED_ACTION_ID: &str = "cleimesh.taint_cleared";

/// `action_id` of the receipt of what an allowed call did.
pub const RESULT_ACTION_ID: &str = "cleimesh.tool_result";
/// Layout of `params`; bump on incompatible changes.
pub const PROFILE: &str = "cleimesh.tool_call/2";

/// What allowed a call, as its receipt records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Authority {
    /// Listed in `P2PConfig::public_tools`.
    PublicTool,
    /// A legacy capability (S6), by its nonce.
    Capability { nonce: String, subject: String },
    /// An AAT chain: who issued the root, who holds the leaf, how deep, and
    /// the digest of the exact chain presented.
    Aat {
        root_iss: String,
        root_jti: String,
        leaf_jti: String,
        holder: String,
        depth: u32,
        chain_sha256: String,
        /// Every holder in the chain, root's first (JWK thumbprint URIs).
        lineage: Vec<String>,
        /// The tool's flow policy along the chain (C6).
        taints: bool,
        clean_only: bool,
    },
}

/// SHA-256 of the canonical JSON of `value`: how receipts commit to
/// arguments and outputs.
pub fn json_sha256(value: &Value) -> String {
    let canonical = canonical_json(value).unwrap_or_else(|_| value.to_string());
    sha256_hex(canonical.as_bytes())
}

/// A call as received: the part of its receipt known before any decision.
pub(crate) struct Call {
    request_id: String,
    tool: String,
    caller: String,
    input_sha256: String,
    data_subject: Option<String>,
    purpose: Option<String>,
    received: Instant,
}

impl Call {
    /// `node_key` derives the data subject's pseudonym.
    pub(crate) fn new(caller: &str, request: &ToolRequest, node_key: &cleimesh_aat::SigningKey) -> Self {
        let context = request.context.clone().unwrap_or_default();
        Call {
            request_id: request.request_id.clone(),
            tool: request.tool_name.clone(),
            caller: caller.to_string(),
            input_sha256: json_sha256(&request.payload),
            data_subject: context.data_subject.map(|s| subject_pseudonym(node_key, &s)),
            // An oversized purpose is refused by the node; only its digest is kept.
            purpose: context.purpose.map(|p| if p.chars().count() > MAX_PURPOSE_CHARS { format!("sha256:{}", sha256_hex(p.as_bytes())) } else { p }),
            received: Instant::now(),
        }
    }

    fn params(&self, decision: &str) -> serde_json::Map<String, Value> {
        let mut params = serde_json::Map::new();
        params.insert("profile".into(), json!(PROFILE));
        params.insert("request_id".into(), json!(self.request_id));
        params.insert("tool".into(), json!(self.tool));
        params.insert("caller".into(), json!(self.caller));
        params.insert("decision".into(), json!(decision));
        params.insert("input_sha256".into(), json!(self.input_sha256));
        if let Some(subject) = &self.data_subject {
            params.insert("data_subject".into(), json!(subject));
        }
        if let Some(purpose) = &self.purpose {
            params.insert("purpose".into(), json!(purpose));
        }
        params
    }

    /// Receipt of a refused call; nothing ran.
    pub(crate) fn denied(self, reason: &str) -> Entry {
        let mut params = self.params("denied");
        params.insert("denial".into(), json!(reason));
        entry(DECISION_ACTION_ID, Value::Object(params), false)
    }

    /// Receipt of the decision to run the call, written before it runs:
    /// what allowed it and what the sandbox will be given. The node refuses
    /// the call if this receipt can't be written. The returned `Outcome`
    /// makes the second receipt, once the call ran.
    pub(crate) fn allowed(self, authority: &Authority, wasm_sha256: Option<String>, sandbox: Value) -> (Entry, Outcome) {
        let mut params = self.params("allowed");
        params.insert("authority".into(), serde_json::to_value(authority).expect("authority serializes"));
        params.insert("wasm_sha256".into(), wasm_sha256.map_or(Value::Null, Value::String));
        params.insert("sandbox".into(), sandbox);
        let decision = entry(DECISION_ACTION_ID, Value::Object(params), true);
        let taints = match authority {
            Authority::Aat { lineage, taints: true, .. } => lineage.clone(),
            _ => Vec::new(),
        };
        let outcome = Outcome {
            request_id: self.request_id,
            tool: self.tool,
            decision_step: decision.step_id.clone(),
            received: self.received,
            taints,
        };
        (decision, outcome)
    }
}

/// An allowed call on its way through the sandbox.
pub(crate) struct Outcome {
    request_id: String,
    tool: String,
    decision_step: String,
    received: Instant,
    /// Holders the run taints once it returns (C6).
    pub(crate) taints: Vec<String>,
}

impl Outcome {
    pub(crate) fn decision_step(&self) -> &str {
        &self.decision_step
    }

    /// Receipt of what was observed when the call ran, pointing at its
    /// decision receipt.
    /// `fs` is what the call touched, from [`fs_observed`].
    pub(crate) fn ran(self, response: &ToolResponse, fs: Option<Value>) -> Entry {
        let mut observed = serde_json::Map::new();
        observed.insert("success".into(), json!(response.success));
        observed.insert("output_sha256".into(), json!(json_sha256(&response.output)));
        if let Some(error) = &response.error {
            observed.insert("error_sha256".into(), json!(sha256_hex(error.as_bytes())));
        }
        observed.insert("duration_ms".into(), json!(self.received.elapsed().as_millis() as u64));
        if let Some(fs) = fs {
            observed.insert("fs".into(), fs);
        }
        let params = json!({
            "profile": PROFILE,
            "request_id": self.request_id,
            "tool": self.tool,
            "decision_step": self.decision_step,
            "observed": observed,
        });
        entry(RESULT_ACTION_ID, params, response.success)
    }
}

/// The grants and limits a call runs under, as the receipt states them.
/// Also what a replay needs: the engine, the frozen clock and the seed,
/// and whether the call depends on nothing but its input.
pub(crate) fn sandbox_terms(config: &SandboxConfig) -> Value {
    let mut not_replayable = Vec::new();
    if config.allow_network {
        not_replayable.push("network");
    }
    if config.allow_filesystem_read && !config.allowed_paths.is_empty() {
        not_replayable.push("reads directories");
    }
    if !config.writable_paths.is_empty() {
        not_replayable.push("writes directories");
    }
    if config.determinism.is_none() {
        not_replayable.push("real clock and randomness");
    }
    let replay = config.determinism.map(|d| {
        json!({
            "engine": cleimesh_wasm_sandbox::ENGINE,
            "clock_ns": d.clock_ns,
            "seed": d.seed.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
        })
    });
    json!({
        "replayable": not_replayable.is_empty(),
        "not_replayable_because": not_replayable,
        "replay": replay,
        "allow_network": config.allow_network,
        "allow_filesystem_read": config.allow_filesystem_read,
        "allow_filesystem_write": config.allow_filesystem_write,
        "allowed_paths": config.allowed_paths,
        "writable_paths": config.writable_paths,
        "max_instructions": config.limits.max_instructions,
        "max_memory_bytes": config.max_memory_bytes,
        "timeout_ms": config.max_execution_time.as_millis() as u64,
    })
}

/// What a call to a native MCP server runs under (`cleimesh mcp wrap`):
/// nothing confines it, so it reaches whatever the server's OS user can,
/// and it can't be replayed. Only the time limit is enforced.
pub(crate) fn external_terms(server_sha256: &str, config: &SandboxConfig) -> Value {
    json!({
        "confined": false,
        "runs_in": "native MCP server",
        "server_sha256": server_sha256,
        "replayable": false,
        "not_replayable_because": ["native MCP server outside the sandbox"],
        "replay": null,
        "timeout_ms": config.max_execution_time.as_millis() as u64,
    })
}

fn entry(action_id: &str, params: Value, success: bool) -> Entry {
    let ts_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    Entry {
        step_id: uuid::Uuid::now_v7().to_string(),
        action_id: action_id.to_string(),
        params,
        success,
        ts_ms,
        actor: None,
    }
}

/// Receipt of a human clearing `holder`'s taint (C6).
pub(crate) fn taint_cleared(holder: &str, reason: &str) -> Entry {
    entry(TAINT_CLEARED_ACTION_ID, json!({"profile": PROFILE, "holder": holder, "reason": reason}), true)
}

/// Which holders are tainted, by the decision step of the call that tainted
/// them, as a log records it: an allowed call whose tool taints taints its
/// lineage from its decision on, whether or not its result was recorded (a
/// call cut short taints too: the safe side, cleared by a human); a
/// clearing receipt clears a holder.
pub fn tainted_holders(log: &[u8]) -> std::collections::HashMap<String, String> {
    let mut tainted: std::collections::HashMap<String, String> = Default::default();
    for line in String::from_utf8_lossy(log).lines() {
        let Ok(r) = cleimesh_receipt::Receipt::parse(line) else { continue };
        let p = &r.params;
        match r.action_id.as_str() {
            // From the decision, not the result: the result receipt may never
            // have been written although the content went out (C6, R12).
            DECISION_ACTION_ID if p["decision"] == "allowed" && p["authority"]["taints"] == true => {
                for holder in p["authority"]["lineage"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                    tainted.insert(holder.to_string(), r.step_id.clone());
                }
            }
            TAINT_CLEARED_ACTION_ID => {
                if let Some(holder) = p["holder"].as_str() {
                    tainted.remove(holder);
                }
            }
            _ => {}
        }
    }
    tainted
}

#[cfg(test)]
mod tests {
    use super::*;
    use cleimesh_wasm_sandbox::{FsObserved, GrantUse};

    #[test]
    fn too_many_directories_collapse_until_they_fit() {
        let key = cleimesh_aat::SigningKey::from_bytes(&[7; 32]);
        let read = (0..FS_MAX_DIRS + 6).map(|i| vec!["many".to_string(), format!("d{i}")]).collect();
        let fs = FsObserved { grants: vec![GrantUse { grant: "/p".into(), read, ..Default::default() }] };
        let block = fs_observed(&fs, &key).unwrap();
        let names = block["grants"][0]["read"].as_array().unwrap();
        assert_eq!(names, &vec![json!(fs_dir_pseudonym(&key, "/p", &["many".to_string()]))]);
        assert_eq!(block["truncated"], json!(true));

        let few = FsObserved { grants: vec![GrantUse { grant: "/p".into(), read: [vec![]].into(), ..Default::default() }] };
        let block = fs_observed(&few, &key).unwrap();
        assert_eq!((block["grants"][0]["read"].clone(), block["truncated"].clone()), (json!(["."]), json!(false)));
        assert!(fs_observed(&FsObserved::default(), &key).is_none());
    }
}
