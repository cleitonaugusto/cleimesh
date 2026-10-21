//! Sandbox grants carried in an AAT chain (C1, decision
//! D6): what a tool may touch when it runs, not only whether it may be
//! called.
//!
//! AAT constrains tool arguments only, so the grants travel as an extra
//! `authorization_details` entry of type `cleimesh_sandbox` (RFC 9396 typed
//! entries), signed with the token:
//!
//! ```json
//! {"type": "cleimesh_sandbox",
//!  "tools": {"file_read": {"read": ["/srv/projeto"], "write": [],
//!                          "network": false, "max_instructions": 1000000,
//!                          "max_memory_bytes": 16777216, "timeout_ms": 2000}}}
//! ```
//!
//! Every token may only narrow its parent's grants: directories inside the
//! parent's, network only if the parent had it, limits no higher. A token
//! without the entry grants nothing, so the tool runs with no directory and
//! no network. Unknown fields are refused, never ignored.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use cleimesh_aat::Claims;
use cleimesh_wasm_sandbox::SandboxConfig;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `type` of the grants entry.
pub const SANDBOX_TYPE: &str = "cleimesh_sandbox";

/// What one tool may use while it runs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolGrant {
    /// Directories the tool may read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read: Vec<String>,
    /// Directories the tool may read and write.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub write: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub network: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_instructions: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_memory_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// This tool brings in content from outside (mail, web, shared files):
    /// once it returns, every holder in the call's chain is tainted (C6).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub taints: bool,
    /// This tool acts on the world (send, write, pay): refused while any
    /// holder in the call's chain is tainted, so injected instructions
    /// can't drive it (C6).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub clean_only: bool,
}

/// Tool name → grant.
pub type Grants = BTreeMap<String, ToolGrant>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    #[serde(rename = "type")]
    _type: String,
    tools: Grants,
}

/// The `authorization_details` entry carrying `grants`, for
/// `aat::issue_root_with` and `aat::derive_with`.
pub fn entry(grants: &Grants) -> Value {
    serde_json::json!({"type": SANDBOX_TYPE, "tools": grants})
}

/// The grants of one token; none if it has no entry.
pub fn of(claims: &Claims) -> Result<Grants, String> {
    let mut entries = claims.details_of_type(SANDBOX_TYPE);
    let Some(entry) = entries.next() else { return Ok(Grants::new()) };
    if entries.next().is_some() {
        return Err("more than one cleimesh_sandbox entry".into());
    }
    let entry: Entry = serde_json::from_value(entry.clone()).map_err(|e| format!("invalid cleimesh_sandbox entry: {}", e))?;
    for grant in entry.tools.values() {
        for dir in grant.read.iter().chain(&grant.write) {
            check_dir(dir)?;
        }
    }
    Ok(entry.tools)
}

/// Absolute, with no `.` or `..`: such a path names one place lexically,
/// so "inside" can be checked component by component.
fn check_dir(dir: &str) -> Result<(), String> {
    let path = Path::new(dir);
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::CurDir | Component::ParentDir)) {
        return Err(format!("granted directory {:?} must be absolute, without . or ..", dir));
    }
    Ok(())
}

fn inside(dir: &str, of: &[&String]) -> bool {
    of.iter().any(|parent| Path::new(dir).starts_with(parent.as_str()))
}

/// Whether `child` grants nothing beyond `parent`.
fn narrows(child: &ToolGrant, parent: &ToolGrant) -> Result<(), String> {
    let parent_readable: Vec<&String> = parent.read.iter().chain(&parent.write).collect();
    let parent_writable: Vec<&String> = parent.write.iter().collect();
    if let Some(dir) = child.read.iter().find(|d| !inside(d, &parent_readable)) {
        return Err(format!("read access to {} not granted by the parent", dir));
    }
    if let Some(dir) = child.write.iter().find(|d| !inside(d, &parent_writable)) {
        return Err(format!("write access to {} not granted by the parent", dir));
    }
    if child.network && !parent.network {
        return Err("network not granted by the parent".into());
    }
    let raised = |c: Option<u64>, p: Option<u64>| matches!((c, p), (Some(c), Some(p)) if c > p);
    if parent.taints && !child.taints {
        return Err("taints dropped: the parent marks this tool's output as untrusted".into());
    }
    if parent.clean_only && !child.clean_only {
        return Err("clean_only dropped: the parent keeps this tool from tainted chains".into());
    }
    if raised(child.max_instructions, parent.max_instructions)
        || raised(child.max_memory_bytes.map(|m| m as u64), parent.max_memory_bytes.map(|m| m as u64))
        || raised(child.timeout_ms, parent.timeout_ms)
    {
        return Err("limit raised above the parent's".into());
    }
    Ok(())
}

/// Whether `child` grants, for every tool, nothing beyond `parent`: the
/// rule the node applies to each link, also for a holder to check before
/// deriving.
pub fn check_narrows(child: &Grants, parent: &Grants) -> Result<(), String> {
    for (name, grant) in child {
        let parent = parent.get(name).cloned().unwrap_or_default();
        narrows(grant, &parent).map_err(|e| format!("tool {}: {}", name, e))?;
    }
    Ok(())
}

/// What `tool` may use under a verified chain (root first): the leaf's
/// directories and network, after checking every link narrows its parent,
/// and the lowest of each limit along the chain.
pub fn effective(chain: &[Claims], tool: &str) -> Result<(ToolGrant, ToolGrant), String> {
    let grants = chain.iter().map(of).collect::<Result<Vec<_>, _>>()?;
    for pair in grants.windows(2) {
        check_narrows(&pair[1], &pair[0])?;
    }
    let for_tool = |g: &Grants| g.get(tool).cloned().unwrap_or_default();
    let root = grants.first().map(for_tool).unwrap_or_default();
    let mut leaf = grants.last().map(for_tool).unwrap_or_default();
    let lowest = |pick: fn(&ToolGrant) -> Option<u64>| grants.iter().filter_map(|g| g.get(tool).and_then(pick)).min();
    leaf.max_instructions = lowest(|g| g.max_instructions);
    leaf.max_memory_bytes = lowest(|g| g.max_memory_bytes.map(|m| m as u64)).map(|m| m as usize);
    leaf.timeout_ms = lowest(|g| g.timeout_ms);
    // Flow flags hold if any link sets them: a token that just leaves the
    // tool out of its grants can't shed them.
    leaf.taints = grants.iter().any(|g| g.get(tool).is_some_and(|t| t.taints));
    leaf.clean_only = grants.iter().any(|g| g.get(tool).is_some_and(|t| t.clean_only));
    Ok((leaf, root))
}

/// The sandbox a call runs in: `base` (the node's own limits) narrowed by
/// `grant`. Directories are resolved on disk and must still lie inside the
/// root's once symlinks are followed, so a link inside a granted directory
/// cannot reach outside it; a directory that doesn't exist refuses the call.
/// The node's own directories never apply: the chain is the policy.
pub fn sandbox_config(base: &SandboxConfig, grant: &ToolGrant, root: &ToolGrant, max_timeout_ms: u64) -> Result<SandboxConfig, String> {
    let resolve = |dir: &String| std::fs::canonicalize(dir).map_err(|e| format!("granted directory {} unusable: {}", dir, e));
    let resolve_all = |dirs: &[String]| dirs.iter().map(resolve).collect::<Result<Vec<PathBuf>, _>>();
    let (read, write) = (resolve_all(&grant.read)?, resolve_all(&grant.write)?);
    let root_readable = resolve_all(&[root.read.clone(), root.write.clone()].concat())?;
    let root_writable = resolve_all(&root.write)?;
    let within = |dir: &PathBuf, of: &[PathBuf]| of.iter().any(|p| dir.starts_with(p));
    if let Some(dir) = read.iter().find(|d| !within(d, &root_readable)).or_else(|| write.iter().find(|d| !within(d, &root_writable))) {
        return Err(format!("granted directory resolves to {}, outside what the root grants", dir.display()));
    }

    let as_strings = |dirs: Vec<PathBuf>| dirs.into_iter().map(|d| d.to_string_lossy().into_owned()).collect::<Vec<_>>();
    let mut config = base.clone();
    config.allow_filesystem_read = !read.is_empty();
    config.allow_filesystem_write = false;
    config.allowed_paths = as_strings(read);
    config.writable_paths = as_strings(write);
    config.allow_network = base.allow_network && grant.network;
    if let Some(max) = grant.max_instructions {
        config.limits.max_instructions = config.limits.max_instructions.min(max);
    }
    if let Some(max) = grant.max_memory_bytes {
        config.max_memory_bytes = config.max_memory_bytes.min(max);
    }
    let timeout = grant.timeout_ms.unwrap_or(max_timeout_ms).min(max_timeout_ms);
    config.max_execution_time = Duration::from_millis(timeout);
    Ok(config)
}
