//! `cleimesh allowance` and `cleimesh mcp wrap --allowance`: give an agent a
//! signed, bounded, provable budget on any MCP tool, enforced outside it.
//!
//! The engine is [`cleimesh_allowance`]; this module is the CLI around it —
//! keys, the signing prompt, persisting the spend ledger, and an MCP server
//! that admits each call before forwarding it to the wrapped tool.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use cleimesh_aat::{self as aat, Jwk, Presentation, SigningKey};
use cleimesh_allowance::{admit, issue, Admitted, Envelope, Ledger, Refusal};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation, ListToolsResult,
    PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::{RequestContext, RunningService};
use rmcp::{ErrorData as McpError, RoleClient, RoleServer, ServerHandler, ServiceExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

/// The word the owner types to sign. Anything else cancels.
const CONFIRM: &str = "ALLOW";

/// What `grant` writes and `wrap` reads.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowanceFile {
    pub token: String,
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn pub_path(key: &Path) -> PathBuf {
    let mut p = key.as_os_str().to_owned();
    p.push(".pub.json");
    PathBuf::from(p)
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    f.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("cannot create {}", path.display()))
}

/// Create an Ed25519 key (hex seed) and write its public JWK to `<key>.pub.json`.
pub fn keygen(path: &Path) -> Result<()> {
    if path.exists() {
        return Err(anyhow!("{} exists; refusing to overwrite a key", path.display()));
    }
    let mut seed = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut seed))
        .context("cannot read /dev/urandom")?;
    let key = SigningKey::from_bytes(&seed);
    let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
    write_private(path, hex.as_bytes())?;
    let jwk = Jwk::from_key(&key.verifying_key());
    std::fs::write(pub_path(path), serde_json::to_vec_pretty(&jwk)?)?;
    eprintln!("key written to {}, public key to {}", path.display(), pub_path(path).display());
    Ok(())
}

fn load_key(path: &Path) -> Result<SigningKey> {
    let text = std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    let text = text.trim();
    if text.len() != 64 {
        return Err(anyhow!("{} is not a 32-byte hex key", path.display()));
    }
    let mut seed = [0u8; 32];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|_| anyhow!("{} is not a hex key", path.display()))?;
    }
    Ok(SigningKey::from_bytes(&seed))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let bytes = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("{} is not valid", path.display()))
}

/// Parse '$5.00' or '5' into dollars.
fn parse_money(s: &str) -> Result<f64> {
    let t = s.trim().trim_start_matches('$').replace(',', "");
    let v: f64 = t.parse().map_err(|_| anyhow!("--max must be an amount like '$5.00' or '5', got {s:?}"))?;
    if !v.is_finite() || v < 0.0 {
        return Err(anyhow!("--max must be a non-negative amount"));
    }
    Ok(v)
}

/// `cleimesh allowance grant`: show the limits, sign on confirmation, write the token.
#[allow(clippy::too_many_arguments)]
pub fn grant(
    max: String,
    tool: String,
    to: String,
    calls: u32,
    ttl: i64,
    owner: PathBuf,
    agent: PathBuf,
    out: PathBuf,
) -> Result<()> {
    let max = parse_money(&max)?;
    let holder: Jwk = read_json(&agent)?;
    let env = Envelope::new(holder, tool, to, max, calls, ttl);
    let owner = load_key(&owner)?;

    let mut err = std::io::stderr();
    writeln!(err, "You are signing an allowance. The agent may, on its own:\n")?;
    for line in env.card() {
        writeln!(err, "  {line}")?;
    }
    write!(err, "\nType {CONFIRM} to sign, anything else to cancel: ")?;
    err.flush()?;
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    if answer.trim() != CONFIRM {
        return Err(anyhow!("not signed; no allowance issued"));
    }

    let token = issue(&owner, &env, now()).map_err(|e| anyhow!("cannot issue: {e}"))?;
    std::fs::write(&out, serde_json::to_vec_pretty(&AllowanceFile { token })?)?;
    eprintln!("allowance written to {}", out.display());
    Ok(())
}

/// The spend ledger on disk, so a restart keeps the budget.
pub struct LedgerStore {
    path: Option<PathBuf>,
}

impl LedgerStore {
    pub fn new(path: Option<PathBuf>) -> Self {
        LedgerStore { path }
    }

    fn load(&self) -> Result<Ledger> {
        let mut ledger = Ledger::new();
        if let Some(path) = self.path.as_ref().filter(|p| p.exists()) {
            let usage: BTreeMap<String, (u32, f64)> = read_json(path)?;
            ledger.restore(usage);
        }
        Ok(ledger)
    }

    fn save(&self, ledger: &Ledger) -> Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec(&ledger.snapshot())?)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

fn describe(why: &Refusal) -> String {
    match why {
        Refusal::NotAllowed(m) => format!("outside the allowance: {m}"),
        Refusal::CapExceeded => "over the allowance".into(),
        Refusal::CallsExhausted => "out of calls on this allowance".into(),
        other => other.to_string(),
    }
}

fn error_result(message: String) -> CallToolResponse {
    CallToolResult::error(vec![ContentBlock::text(message)]).into()
}

/// The MCP server the agent talks to; it admits each call, then forwards it.
struct AllowanceGateway {
    server: RunningService<RoleClient, ()>,
    token: String,
    agent: SigningKey,
    owner: Jwk,
    ledger: Mutex<Ledger>,
    store: LedgerStore,
    receipts: Option<PathBuf>,
    tools: Vec<Tool>,
}

impl AllowanceGateway {
    async fn new(
        server: RunningService<RoleClient, ()>,
        allowance: AllowanceFile,
        agent: SigningKey,
        owner: Jwk,
        store: LedgerStore,
        receipts: Option<PathBuf>,
    ) -> Result<Self> {
        let granted = aat::inspect(&allowance.token)
            .map_err(|e| anyhow!("allowance token: {e}"))?
            .tools()
            .map_err(|e| anyhow!("allowance token: {e}"))?
            .unwrap_or_default();
        let offered = server.list_all_tools().await.map_err(|e| anyhow!("cannot list the wrapped server's tools: {e}"))?;
        let tools = offered.into_iter().filter(|t| granted.contains_key(t.name.as_ref())).collect();
        let ledger = Mutex::new(store.load()?);
        Ok(AllowanceGateway { server, token: allowance.token, agent, owner, ledger, store, receipts, tools })
    }

    async fn decide(&self, tool: &str, args: Value) -> Result<Admitted, String> {
        let now = now();
        let pop = aat::pop(&self.agent, &self.token, tool, &args, None, now).map_err(|e| e.0)?;
        let presentation = Presentation { chain: vec![self.token.clone()], pop };
        let mut ledger = self.ledger.lock().await;
        let admitted = admit(tool, &args, &presentation, &self.owner, now, &mut ledger).map_err(|w| describe(&w))?;
        // Saved before the call runs, so a crash cannot hand back budget.
        self.store.save(&ledger).map_err(|e| format!("cannot save the ledger, call not made: {e}"))?;
        Ok(admitted)
    }

    async fn forward(&self, call: Admitted) -> CallToolResponse {
        let mut params = CallToolRequestParams::new(call.tool().to_string());
        params.arguments = call.params().as_object().cloned();
        match self.server.call_tool(params).await {
            Ok(result) => result.into(),
            Err(e) => error_result(format!("the wrapped server failed: {e}")),
        }
    }

    fn receipt(&self, tool: &str, args: &Value, outcome: Value) {
        let Some(path) = &self.receipts else { return };
        let digest = Sha256::digest(serde_json::to_vec(args).unwrap_or_default());
        let digest: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        let line = json!({ "ts": now(), "tool": tool, "args_sha256": digest, "outcome": outcome });
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(f, "{line}");
        }
    }
}

impl ServerHandler for AllowanceGateway {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("cleimesh-allowance", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "Tools of another MCP server, usable only inside a signed allowance: which tool, which recipient, \
                 how much per call and in total, how many calls. A refused call says which limit stopped it.",
            )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(self.tools.clone()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let tool = request.name.to_string();
        let args = Value::Object(request.arguments.unwrap_or_default());
        match self.decide(&tool, args.clone()).await {
            Ok(admitted) => {
                let allowance = admitted.allowance().to_string();
                self.receipt(&tool, &args, json!({ "admitted": allowance }));
                Ok(self.forward(admitted).await)
            }
            Err(why) => {
                self.receipt(&tool, &args, json!({ "refused": why }));
                Ok(error_result(format!("refused: {why}")))
            }
        }
    }
}

/// `cleimesh mcp wrap --allowance`: spawn the MCP server and serve its tools to
/// the agent inside the signed allowance.
pub async fn wrap(
    allowance: PathBuf,
    agent: PathBuf,
    owner: PathBuf,
    ledger: Option<PathBuf>,
    receipts: Option<PathBuf>,
    command: Vec<String>,
) -> Result<()> {
    let allowance: AllowanceFile = read_json(&allowance)?;
    let agent = load_key(&agent)?;
    let owner: Jwk = read_json(&owner)?;
    if ledger.is_none() {
        eprintln!("cleimesh allowance wrap: no --ledger, so a restart resets the call count and the spending cap");
    }
    let mut child = tokio::process::Command::new(&command[0]);
    child.args(&command[1..]);
    let transport = rmcp::transport::TokioChildProcess::new(child).map_err(|e| anyhow!("cannot start {}: {e}", command[0]))?;
    let server = ().serve(transport).await.map_err(|e| anyhow!("{} did not start as an MCP server: {e}", command[0]))?;
    let gateway = AllowanceGateway::new(server, allowance, agent, owner, LedgerStore::new(ledger), receipts).await?;
    let service = gateway.serve(rmcp::transport::stdio()).await.map_err(|e| anyhow!("MCP server failed to start: {e}"))?;
    service.waiting().await.map_err(|e| anyhow!("MCP server stopped: {e}"))?;
    Ok(())
}
