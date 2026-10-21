//! `cleimesh doctor` (RE1): checks the keys, the receipt log, the sandbox and
//! the agents set up to use CleiMesh, without changing any of them.
//!
//! The agent checks matter most: CleiMesh only contains the tools that go
//! through it, so an agent that keeps its own file or shell tools can do
//! what a token refuses (seen with OpenClaw and a local model: the injection
//! wrote the file with OpenClaw's own tool and no receipt). Agents are only
//! reported when CleiMesh is registered in them, so a machine without them
//! is not "unhealthy".

use cleimesh_core::{Result, ToolPayload};
use cleimesh_p2p::node_key;
use cleimesh_wasm_sandbox::{SandboxConfig, WasmSandbox};
use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

pub struct Check {
    pub level: Level,
    pub what: &'static str,
    pub detail: String,
}

fn check(level: Level, what: &'static str, detail: impl Into<String>) -> Check {
    Check { level, what, detail: detail.into() }
}

/// A key file: missing is fine (it is created on first use), readable by
/// others or undecodable is not.
pub fn key(what: &'static str, path: &Path) -> Check {
    if !path.exists() {
        return check(Level::Warn, what, format!("{} does not exist yet; it is created on first use", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.permissions().mode() & 0o077 != 0 {
                return check(Level::Fail, what, format!("{} is readable by other users (chmod 600 it)", path.display()));
            }
        }
    }
    // The file exists, so this only loads and decodes it.
    match node_key::load_or_generate(path) {
        Ok(keypair) => check(Level::Ok, what, format!("{} ({})", path.display(), keypair.public().to_peer_id())),
        Err(e) => check(Level::Fail, what, e.to_string()),
    }
}

/// The receipt log: every line verifies against the node key, and a signed
/// head exists to catch lines cut from the end.
pub fn receipts(path: &Path, node_key_path: &Path) -> Vec<Check> {
    const WHAT: &str = "receipts";
    let log = match std::fs::read(path) {
        Ok(log) => log,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return vec![check(Level::Ok, WHAT, format!("{} does not exist yet (no call recorded)", path.display()))];
        }
        Err(e) => return vec![check(Level::Fail, WHAT, format!("cannot read {}: {}", path.display(), e))],
    };
    if !node_key_path.exists() {
        return vec![check(Level::Warn, WHAT, format!("{} exists but the node key {} does not, so it cannot be verified", path.display(), node_key_path.display()))];
    }
    let anchor = match node_key::load_or_generate(node_key_path).and_then(|k| node_key::aat_signing_key(&k)) {
        Ok(key) => key.verifying_key(),
        Err(e) => return vec![check(Level::Fail, WHAT, format!("cannot load the node key: {}", e))],
    };
    let report = cleimesh_receipt::verify_log(&log, &anchor);
    let mut checks = vec![if report.ok() {
        check(Level::Ok, WHAT, format!("{} receipts in {} verify", report.lines, path.display()))
    } else {
        check(Level::Fail, WHAT, format!("{} of {} receipts in {} fail verification (see `cleimesh audit verify`)", report.failures.len(), report.lines, path.display()))
    }];
    if report.lines > 0 && !cleimesh_receipt::head_path(path).exists() {
        checks.push(check(Level::Warn, WHAT, "no signed head next to the log: lines cut from the end would go unnoticed"));
    }
    checks
}

/// The sandbox runs a builtin tool, and refuses a file it was not granted.
pub async fn sandbox() -> Check {
    const WHAT: &str = "sandbox";
    let sandbox = match WasmSandbox::new(SandboxConfig::default()) {
        Ok(sandbox) => sandbox,
        Err(e) => return check(Level::Fail, WHAT, format!("cannot start: {}", e)),
    };
    let builtins = include_bytes!("../../wasm-tools/builtins.wasm").to_vec();
    for tool in ["echo", "file_read"] {
        if let Err(e) = sandbox.register_wasm_module(tool, builtins.clone()) {
            return check(Level::Fail, WHAT, format!("cannot load the builtin tools: {}", e));
        }
    }
    let call = |tool: &str, arguments: Value| ToolPayload { tool_name: tool.into(), arguments, timeout_ms: Some(5000) };
    match sandbox.execute_in_sandbox("echo", call("echo", serde_json::json!({ "message": "doctor" }))).await {
        Ok(result) if result.success && result.output["message"] == "doctor" => {}
        Ok(result) => return check(Level::Fail, WHAT, format!("echo returned {}", result.output)),
        Err(e) => return check(Level::Fail, WHAT, format!("echo failed: {}", e)),
    }
    // A file that surely exists, outside any grant.
    let Ok(exe) = std::env::current_exe() else {
        return check(Level::Ok, WHAT, "runs a builtin tool (could not find a file to test the refusal)");
    };
    match sandbox.execute_in_sandbox("file_read", call("file_read", serde_json::json!({ "path": exe.to_string_lossy() }))).await {
        Ok(result) if result.success => check(Level::Fail, WHAT, format!("read {} without a grant", exe.display())),
        _ => check(Level::Ok, WHAT, "runs a builtin tool and refuses a file it was not granted"),
    }
}

/// Whether an MCP server entry (`{"command": ..., "args": [...]}`) runs CleiMesh.
fn runs_cleimesh(server: &Value) -> bool {
    let mentions = |v: &Value| v.as_str().is_some_and(|s| s.contains("cleimesh"));
    mentions(&server["command"]) || server["args"].as_array().is_some_and(|args| args.iter().any(mentions))
}

/// Every MCP server entry anywhere in `config` that runs CleiMesh.
fn cleimesh_servers<'a>(config: &'a Value, found: &mut Vec<&'a Value>) {
    match config {
        Value::Object(map) if map.contains_key("command") && runs_cleimesh(config) => found.push(config),
        Value::Object(map) => map.values().for_each(|v| cleimesh_servers(v, found)),
        Value::Array(items) => items.iter().for_each(|v| cleimesh_servers(v, found)),
        _ => {}
    }
}

/// Whether any MCP server entry anywhere in `config` runs CleiMesh.
fn registers_cleimesh(config: &Value) -> bool {
    let mut found = Vec::new();
    cleimesh_servers(config, &mut found);
    !found.is_empty()
}

/// The agent configs doctor reads: Claude Code's user file and the
/// `.mcp.json` of each project it knows (project scope), and OpenClaw's.
fn agent_configs(home: &Path) -> Vec<PathBuf> {
    let mut files = vec![home.join(".claude.json"), home.join(".openclaw").join("openclaw.json")];
    if let Some(Ok(config)) = read_json5(&home.join(".claude.json")) {
        if let Some(projects) = config["projects"].as_object() {
            files.extend(projects.keys().map(|dir| Path::new(dir).join(".mcp.json")));
        }
    }
    files
}

/// Whether an agent reaches CleiMesh through a node run elsewhere
/// (`mcp serve --node`, the node under its own OS user), whose keys and log
/// this user is not meant to have.
pub fn calls_remote_node(home: &Path) -> bool {
    agent_configs(home).iter().filter_map(|f| read_json5(f)?.ok()).any(|config| {
        let mut found = Vec::new();
        cleimesh_servers(&config, &mut found);
        found.iter().any(|server| server["args"].as_array().is_some_and(|args| args.iter().any(|a| a == "--node")))
    })
}

fn read_json5(path: &Path) -> Option<std::result::Result<Value, String>> {
    let text = std::fs::read_to_string(path).ok()?;
    Some(json5::from_str(&text).map_err(|e| e.to_string()))
}

/// Claude Code's own tools that reach files or a shell.
const CLAUDE_NATIVE: [&str; 5] = ["Bash", "Read", "Write", "Edit", "NotebookEdit"];

/// Claude Code: CleiMesh registered in `~/.claude.json` (user or project
/// scope), and the native file and shell tools denied in a settings file.
pub fn claude_code(home: &Path) -> Option<Check> {
    const WHAT: &str = "Claude Code";
    let config = match read_json5(&home.join(".claude.json"))? {
        Ok(config) => config,
        Err(e) => return Some(check(Level::Warn, WHAT, format!("cannot parse ~/.claude.json: {}", e))),
    };
    let mut settings = vec![home.join(".claude").join("settings.json")];
    let mut registered = config["mcpServers"].as_object().is_some_and(|s| s.values().any(runs_cleimesh));
    if let Some(projects) = config["projects"].as_object() {
        for (dir, project) in projects {
            // Local scope lives here; project scope in the project's .mcp.json.
            let shared = read_json5(&Path::new(dir).join(".mcp.json")).and_then(|c| c.ok());
            let in_project = shared.is_some_and(|c| c["mcpServers"].as_object().is_some_and(|s| s.values().any(runs_cleimesh)));
            if in_project || project["mcpServers"].as_object().is_some_and(|s| s.values().any(runs_cleimesh)) {
                registered = true;
                settings.push(Path::new(dir).join(".claude").join("settings.json"));
                settings.push(Path::new(dir).join(".claude").join("settings.local.json"));
            }
        }
    }
    if !registered {
        return None;
    }
    let mut denied = Vec::<String>::new();
    for file in &settings {
        if let Some(Ok(s)) = read_json5(file) {
            denied.extend(s["permissions"]["deny"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_string)));
        }
    }
    // A bare name or `Name(*)` denies the whole tool; `Bash(rm:*)` does not.
    let on: Vec<&str> = CLAUDE_NATIVE.iter().copied().filter(|t| !denied.iter().any(|d| d == t || *d == format!("{}(*)", t))).collect();
    Some(native_tools(WHAT, &on, "add them to \"permissions\": {\"deny\": [...]} in ~/.claude/settings.json"))
}

/// OpenClaw's own tools that reach files or a shell, as its tool policy names them.
const OPENCLAW_NATIVE: [&str; 7] = ["read", "write", "edit", "apply_patch", "exec", "process", "ls"];

/// OpenClaw: CleiMesh registered in `~/.openclaw/openclaw.json`, and the
/// native file and shell tools in `tools.deny`.
pub fn openclaw(home: &Path) -> Option<Check> {
    const WHAT: &str = "OpenClaw";
    let config = match read_json5(&home.join(".openclaw").join("openclaw.json"))? {
        Ok(config) => config,
        Err(e) => return Some(check(Level::Warn, WHAT, format!("cannot parse ~/.openclaw/openclaw.json: {}", e))),
    };
    if !registers_cleimesh(&config) {
        return None;
    }
    let denied: Vec<&str> = config["tools"]["deny"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    let on: Vec<&str> = OPENCLAW_NATIVE.iter().copied().filter(|t| !denied.contains(t)).collect();
    Some(native_tools(WHAT, &on, "add them to \"tools\": {\"deny\": [...]} in ~/.openclaw/openclaw.json"))
}

/// Hermes Agent: only whether CleiMesh is registered; its own tools are not
/// checked yet, so say so instead of passing it.
pub fn hermes(home: &Path) -> Option<Check> {
    let config = std::fs::read_to_string(home.join(".hermes").join("config.yaml")).ok()?;
    config.contains("cleimesh").then(|| {
        check(Level::Warn, "Hermes Agent", "CleiMesh is registered; doctor does not check Hermes' own terminal and file tools yet, so turn them off by hand")
    })
}

fn native_tools(what: &'static str, on: &[&str], fix: &str) -> Check {
    if on.is_empty() {
        check(Level::Ok, what, "uses CleiMesh, and its own file and shell tools are denied")
    } else {
        check(Level::Warn, what, format!("uses CleiMesh, but its own {} tool(s) are still on and bypass it; {}", on.join(", "), fix))
    }
}

/// Runs every check and prints them; fails if any check failed.
pub async fn run(node_key_path: PathBuf, client_key_path: PathBuf, receipts_path: PathBuf) -> Result<()> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let remote = home.as_deref().is_some_and(calls_remote_node);
    let node = if remote && !node_key_path.exists() {
        check(Level::Ok, "node key", "your agents call a node run as another user (--node); check its keys and log there: sudo -u cleimesh cleimesh doctor")
    } else {
        key("node key", &node_key_path)
    };
    let mut checks = vec![node, key("client key", &client_key_path)];
    checks.extend(receipts(&receipts_path, &node_key_path));
    checks.push(sandbox().await);
    let agents: Vec<Check> = home.iter().flat_map(|h| [claude_code(h), openclaw(h), hermes(h)]).flatten().collect();
    if agents.is_empty() {
        checks.push(check(Level::Ok, "agents", "no Claude Code, OpenClaw or Hermes Agent set up to use CleiMesh"));
    }
    checks.extend(agents);

    for c in &checks {
        let label = match c.level {
            Level::Ok => "ok  ",
            Level::Warn => "warn",
            Level::Fail => "FAIL",
        };
        println!("{}  {:<12} {}", label, c.what, c.detail);
    }
    let failed = checks.iter().filter(|c| c.level == Level::Fail).count();
    if failed > 0 {
        return Err(anyhow::anyhow!("{} check(s) failed", failed).into());
    }
    Ok(())
}
