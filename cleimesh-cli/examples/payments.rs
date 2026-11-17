//! The real wrap, end to end: a toy `pay` MCP server put behind a signed
//! allowance by the actual `cleimesh mcp wrap --allowance`, driven by a real
//! MCP client. The agent tries to overpay and to pay the wrong recipient; the
//! allowance refuses both from outside the server, and every call lands in an
//! append-only receipt log. No real money — "pay" stands in for any tool an
//! agent calls on its own (a payment, an email send, a booking change).
//!
//! Run it (uses `cleimesh` built in the same target dir, or $CLEIMESH):
//!
//!   cargo run -p cleimesh-cli --example payments
//!
//! One binary, two roles: with `--pay-server` it IS the wrapped MCP server;
//! without it, it is the demo driver that wraps that server under an allowance.

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

// ----- the wrapped server: one `pay` tool, no real money -----

#[derive(Clone)]
struct PayServer;

impl ServerHandler for PayServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("demo-pay-server", env!("CARGO_PKG_VERSION")))
            .with_instructions("A toy payment tool for the CleiMesh allowance demo. No real money.")
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let schema = match json!({
            "type": "object",
            "properties": { "to": { "type": "string" }, "amount": { "type": "number" } },
            "required": ["to", "amount"],
        }) {
            Value::Object(m) => m,
            _ => Map::new(),
        };
        let tool = Tool::new("pay", "Pay an amount to a recipient (demo; no real money)", schema);
        Ok(ListToolsResult::with_all_items(vec![tool]))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let args = Value::Object(request.arguments.unwrap_or_default());
        let to = args.get("to").and_then(|v| v.as_str()).unwrap_or("?");
        let amount = args.get("amount").and_then(|v| v.as_f64()).unwrap_or(0.0);
        // The allowance already admitted this call; the server just performs it.
        let mut result = CallToolResult::success(vec![ContentBlock::text(format!("paid ${amount:.2} to {to}"))]);
        result.structured_content = Some(json!({ "paid": amount, "to": to }));
        Ok(result.into())
    }
}

async fn run_pay_server() -> Result<()> {
    let service = PayServer
        .serve(stdio())
        .await
        .map_err(|e| anyhow!("pay server failed to start: {e}"))?;
    service.waiting().await.map_err(|e| anyhow!("pay server stopped: {e}"))?;
    Ok(())
}

// ----- the driver: wrap the pay server under an allowance and drive it -----

fn locate_cleimesh() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("CLEIMESH") {
        return Ok(PathBuf::from(p));
    }
    // This example runs from <target>/<profile>/examples/payments; the cli
    // binary is its sibling one directory up: <target>/<profile>/cleimesh.
    let exe = std::env::current_exe().context("current_exe")?;
    let cli = exe
        .parent()
        .and_then(Path::parent)
        .map(|d| d.join("cleimesh"))
        .filter(|p| p.exists())
        .ok_or_else(|| anyhow!("cannot find the cleimesh binary; build it or set CLEIMESH=path/to/cleimesh"))?;
    Ok(cli)
}

/// Run a cleimesh subcommand, optionally feeding `stdin`, and fail on error.
fn cleimesh(cli: &Path, dir: &Path, args: &[&str], stdin: Option<&str>) -> Result<()> {
    let mut cmd = std::process::Command::new(cli);
    cmd.args(args).current_dir(dir).stdout(Stdio::null()).stderr(Stdio::null());
    if stdin.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd.spawn().with_context(|| format!("spawn cleimesh {}", args.join(" ")))?;
    if let Some(text) = stdin {
        use std::io::Write;
        child.stdin.take().unwrap().write_all(text.as_bytes())?;
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(anyhow!("cleimesh {} failed", args.join(" ")));
    }
    Ok(())
}

fn text(result: &CallToolResult) -> String {
    result.content.iter().filter_map(|c| c.as_text()).map(|t| t.text.clone()).collect()
}

async fn run_demo() -> Result<()> {
    let cli = locate_cleimesh()?;
    let self_exe = std::env::current_exe().context("current_exe")?;

    // A throwaway directory for keys, the allowance, the ledger and receipts.
    let dir = std::env::temp_dir().join(format!("cleimesh-payments-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;

    println!("An agent acting on its own: a payment, an email, a booking change.");
    println!("The limit lives OUTSIDE the agent, and every call leaves a record. Here, money.\n");

    // 1) Owner and agent keys.
    cleimesh(&cli, &dir, &["allowance", "keygen", "--out", "owner.key"], None)?;
    cleimesh(&cli, &dir, &["allowance", "keygen", "--out", "agent.key"], None)?;

    // 2) The owner signs an allowance: tool `pay`, only to `demo`, $5.00 total, 5 calls.
    println!("$ cleimesh allowance grant --max '$5.00' --tool pay --to demo --calls 5");
    cleimesh(
        &cli,
        &dir,
        &[
            "allowance", "grant", "--max", "$5.00", "--tool", "pay", "--to", "demo", "--calls", "5",
            "--owner", "owner.key", "--agent", "agent.key.pub.json", "--out", "allowance.json",
        ],
        Some("ALLOW\n"),
    )?;
    println!("  signed. the agent may pay 'demo', up to $5.00 total, at most 5 times.\n");

    // 3) Put the toy pay server behind that allowance, with a real MCP client in front.
    println!("$ cleimesh mcp wrap --allowance allowance.json --owner owner.key.pub.json --agent agent.key -- demo-pay-server");
    let mut wrap = tokio::process::Command::new(&cli);
    wrap.current_dir(&dir).args([
        "mcp", "wrap", "--allowance", "allowance.json", "--owner", "owner.key.pub.json",
        "--agent", "agent.key", "--ledger", "ledger.json", "--receipts", "receipts.jsonl", "--",
    ]);
    wrap.arg(&self_exe).arg("--pay-server");
    let client = ()
        .serve(TokioChildProcess::new(wrap).context("start the wrapped server")?)
        .await
        .context("connect to the wrapped server")?;

    let offered: Vec<String> = client.list_all_tools().await.map_err(|e| anyhow!("{e}"))?.iter().map(|t| t.name.to_string()).collect();
    println!("  tools the agent sees through the allowance: {offered:?}\n");

    // 4) The agent acts on its own. Two go through, two are refused, one fits the remainder.
    let attempts = [("demo", 2.00), ("demo", 2.50), ("demo", 2.00), ("attacker", 0.50), ("demo", 0.50)];
    for (to, amount) in attempts {
        let call = CallToolRequestParams::new("pay").with_arguments(match json!({ "to": to, "amount": amount }) {
            Value::Object(m) => m,
            _ => Map::new(),
        });
        let r = client.call_tool(call).await.map_err(|e| anyhow!("{e}"))?;
        if r.is_error == Some(true) {
            println!("  agent> pay {to} ${amount:.2}   ->  {}", text(&r));
        } else {
            println!("  agent> pay {to} ${amount:.2}   ->  ok. {}", text(&r));
        }
    }
    client.cancel().await.map_err(|e| anyhow!("{e}"))?;

    // 5) The receipt log the wrap wrote beside itself: every attempt, allowed or refused.
    let receipts = dir.join("receipts.jsonl");
    let log = std::fs::read_to_string(&receipts).unwrap_or_default();
    println!("\n$ cat {}", receipts.display());
    for line in log.lines() {
        println!("  {line}");
    }
    println!("\nThe agent acted on its own; it never went over $5.00, never paid anyone else,");
    println!("and left a record of every attempt. The limit was enforced outside it.");

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args().any(|a| a == "--pay-server") {
        run_pay_server().await
    } else {
        run_demo().await
    }
}
