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

/// The `--node` addresses the agents' CleiMesh entries call: Claude Code,
/// OpenClaw (JSON) and Hermes (`mcp_servers` in YAML), each once.
pub fn registered_nodes(home: &Path) -> Vec<String> {
    let mut args: Vec<Vec<String>> = Vec::new();
    for config in agent_configs(home).iter().filter_map(|f| read_json5(f)?.ok()) {
        let mut found = Vec::new();
        cleimesh_servers(&config, &mut found);
        args.extend(found.iter().map(|s| s["args"].as_array().into_iter().flatten().filter_map(|a| a.as_str().map(str::to_string)).collect()));
    }
    let hermes = std::fs::read_to_string(home.join(".hermes").join("config.yaml")).unwrap_or_default();
    for doc in yaml_rust2::YamlLoader::load_from_str(&hermes).unwrap_or_default() {
        for server in doc["mcp_servers"].as_hash().into_iter().flat_map(|h| h.values()) {
            let list: Vec<String> = server["args"].as_vec().into_iter().flatten().filter_map(|a| a.as_str().map(str::to_string)).collect();
            let command = server["command"].as_str().unwrap_or_default();
            if command.contains("cleimesh") || list.iter().any(|a| a.contains("cleimesh")) {
                args.push(list);
            }
        }
    }
    let mut nodes = Vec::new();
    for list in args {
        for pair in list.windows(2).filter(|w| w[0] == "--node") {
            if !nodes.contains(&pair[1]) {
                nodes.push(pair[1].clone());
            }
        }
    }
    nodes
}

/// Whether the node at `addr` answers as the PeerId the address names. A
/// node that restarted with another key, or is not running, leaves every
/// agent call failing while the rest of the setup looks fine.
pub async fn node_reachable(addr: &str, client_key: &Path) -> Check {
    const WHAT: &str = "node";
    let reached = async {
        let (handle, peer) = crate::remote_node(addr, client_key).await?;
        handle.connect(peer).await
    };
    match reached.await {
        Ok(()) => check(Level::Ok, WHAT, format!("answers at {}", addr)),
        Err(e) => check(
            Level::Fail,
            WHAT,
            format!("your agents call {} but it does not answer as that node: {}; check `systemctl status cleimesh`, and if it now has another key run `cleimesh setup` again", addr, e),
        ),
    }
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

use crate::setup::OPENCLAW_NATIVE;

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

/// Hermes Agent: CleiMesh registered in `~/.hermes/config.yaml`, and its own
/// terminal, file, browser and code toolsets off for the CLI.
pub fn hermes(home: &Path) -> Option<Check> {
    let config = std::fs::read_to_string(home.join(".hermes").join("config.yaml")).ok()?;
    if !config.contains("cleimesh") {
        return None;
    }
    if !crate::setup::hermes_enabled(&config) {
        return Some(check(
            Level::Fail,
            "Hermes Agent",
            "CleiMesh is in ~/.hermes/config.yaml but disabled (Hermes saves it so when it cannot start it, for one without its MCP support): run `hermes setup`, then `hermes mcp test cleimesh`",
        ));
    }
    let on = crate::setup::hermes_native_on(&config);
    Some(native_tools("Hermes Agent", &on, &format!("run: hermes tools disable {}", on.join(" "))))
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
    for addr in home.as_deref().map(registered_nodes).unwrap_or_default() {
        checks.push(node_reachable(&addr, &client_key_path).await);
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_nodes_come_from_openclaw_and_hermes_once_each() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let (a, b) = ("/ip4/127.0.0.1/tcp/7400/p2p/A", "/ip4/127.0.0.1/tcp/7401/p2p/B");
        std::fs::create_dir_all(home.join(".openclaw")).unwrap();
        let openclaw = serde_json::json!({ "mcp": { "servers": { "cleimesh": { "command": "/usr/local/bin/cleimesh", "args": ["mcp", "serve", "--node", a] } } } });
        std::fs::write(home.join(".openclaw").join("openclaw.json"), openclaw.to_string()).unwrap();
        std::fs::create_dir_all(home.join(".hermes")).unwrap();
        let hermes = format!(
            "mcp_servers:\n  cleimesh:\n    command: /usr/local/bin/cleimesh\n    args: [mcp, serve, --node, \"{a}\"]\n  other:\n    command: /usr/local/bin/cleimesh\n    args: [mcp, serve, --node, \"{b}\"]\n  unrelated:\n    command: npx\n    args: [--node, \"/ip4/1.2.3.4/tcp/1/p2p/C\"]\n"
        );
        std::fs::write(home.join(".hermes").join("config.yaml"), hermes).unwrap();
        assert_eq!(registered_nodes(home), [a, b]);
    }
}
