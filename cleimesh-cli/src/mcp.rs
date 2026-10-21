//! `cleimesh mcp serve` (M1): the node's tools as an MCP
//! server over stdio, for Claude Code, Cursor and other MCP clients.
//!
//! MCP clients don't speak AAT, so the server holds a delegation chain and
//! the key of its last holder (the agent the client runs as), and presents
//! them on every `tools/call` with a fresh proof of possession. The node
//! then enforces the call exactly as for a remote peer: chain rooted in the
//! node key, argument constraints, sandbox grants, and a decision receipt
//! before the tool runs. Without a chain every call is refused.
//!
//! The node runs in this process, or, with `--node`, as another OS user
//! that this server only forwards calls to: an agent with a shell then
//! can't reach the node key, the receipt log or the taint state.
//!
//! `cleimesh mcp wrap` puts another, native MCP server behind the same
//! token and receipts ([`Wrapper`]).

use std::sync::Arc;

use cleimesh_p2p::{aat, CleiMeshNode, NodeHandle, ToolRequest};
use cleimesh_p2p::PeerId;
use cleimesh_wasm_sandbox::tools::{builtin, BuiltinTool};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation, ListToolsResult, PaginatedRequestParams, ServerCapabilities,
    ServerConfig, Tool, ToolAnnotations,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use tokio::sync::Mutex;

/// What `tools/call` receipts name as the caller.
pub const CALLER: &str = "mcp:stdio";

/// Where calls run.
pub enum Backend {
    /// A node in this process, under this OS user.
    Local(CleiMeshNode),
    /// A node elsewhere (`cleimesh start`), reached through this process's
    /// own client node.
    Remote { handle: NodeHandle, peer: PeerId },
}

enum Runner {
    Local(Arc<Mutex<CleiMeshNode>>),
    Remote { handle: NodeHandle, peer: PeerId },
}

pub struct Gateway {
    runner: Runner,
    /// The chain presented on every call, and the key that holds its leaf.
    /// The chains presented (each a list of tokens, root first) and the key
    /// that holds their leaves.
    credentials: Option<(Vec<Vec<String>>, aat::SigningKey)>,
    audience: String,
}

impl Gateway {
    pub fn new(backend: Backend, credentials: Option<(Vec<Vec<String>>, aat::SigningKey)>) -> Self {
        // The proof of possession is addressed to the node that enforces it.
        let (runner, audience) = match backend {
            Backend::Local(node) => {
                let audience = node.aat_audience();
                (Runner::Local(Arc::new(Mutex::new(node))), audience)
            }
            Backend::Remote { handle, peer } => (Runner::Remote { handle, peer }, peer.to_string()),
        };
        Gateway { runner, credentials, audience }
    }

    /// A proof of possession for this exact call, under the first held
    /// chain whose leaf grants `tool` (read unverified: the node verifies),
    /// or the first chain, whose refusal then says why.
    fn present(&self, tool: &str, args: &serde_json::Value) -> Result<Option<aat::Presentation>, String> {
        present(self.credentials.as_ref(), &self.audience, tool, args)
    }
}

/// The tools a chain's leaf grants (read unverified: the node verifies).
fn granted_tools(chain: &[String]) -> Vec<String> {
    chain.last().and_then(|leaf| aat::inspect(leaf).ok()).and_then(|c| c.tools().ok().flatten()).map(|t| t.keys().cloned().collect()).unwrap_or_default()
}

/// A proof of possession for this exact call, under the first held chain
/// whose leaf grants `tool`, or the first chain, whose refusal then says why.
fn present(credentials: Option<&(Vec<Vec<String>>, aat::SigningKey)>, audience: &str, tool: &str, args: &serde_json::Value) -> Result<Option<aat::Presentation>, String> {
    let Some((chains, key)) = credentials else { return Ok(None) };
    let chain = chains.iter().find(|c| granted_tools(c).iter().any(|t| t == tool)).or(chains.first()).ok_or("no token chain")?;
    let leaf = chain.last().ok_or("token chain is empty")?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let pop = aat::pop(key, leaf, tool, args, Some(audience), now).map_err(|e| e.to_string())?;
    Ok(Some(aat::Presentation { chain: chain.clone(), pop }))
}

/// The built-in tools, described for `tools/list`.
fn builtin_tools() -> Vec<BuiltinTool> {
    vec![
        BuiltinTool::Echo(builtin::EchoTool),
        BuiltinTool::FileRead(builtin::FileReadTool),
        BuiltinTool::FileWrite(builtin::FileWriteTool),
        BuiltinTool::JsonTransform(builtin::JsonTransformTool),
    ]
}

/// MCP safety hints for the built-in tools, so a client can decide when to ask
/// a person before a call. They are hints: what a call may touch is decided by
/// the token and enforced by the sandbox. None of the built-ins reaches the
/// network; only file_write changes anything, by overwriting the file it names.
fn annotations(tool: &str) -> ToolAnnotations {
    let mut hints = ToolAnnotations::new();
    let writes = tool == "file_write";
    hints.read_only_hint = Some(!writes);
    if writes {
        hints.destructive_hint = Some(true);
    }
    hints.idempotent_hint = Some(true);
    hints.open_world_hint = Some(false);
    hints
}

/// Data subject and purpose from the call's `_meta`: `cleimesh/titular` and
/// `cleimesh/finalidade` (or `cleimesh/data_subject` and `cleimesh/purpose`).
fn call_context(meta: Option<&serde_json::Map<String, serde_json::Value>>) -> Option<cleimesh_p2p::CallContext> {
    let meta = meta?;
    let field = |keys: [&str; 2]| keys.iter().find_map(|k| meta.get(*k).and_then(|v| v.as_str()).map(str::to_string));
    let context = cleimesh_p2p::CallContext {
        data_subject: field(["cleimesh/titular", "cleimesh/data_subject"]),
        purpose: field(["cleimesh/finalidade", "cleimesh/purpose"]),
    };
    (context != Default::default()).then_some(context)
}

fn error_result(message: String) -> CallToolResponse {
    CallToolResult::error(vec![ContentBlock::text(message)]).into()
}

impl ServerHandler for Gateway {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("cleimesh", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "Tools run in a WASM sandbox that only reaches what this server's delegation token grants. \
                 A refused call names the restriction that stopped it; every call leaves a signed receipt.",
            )
    }

    async fn list_tools(&self, _request: Option<PaginatedRequestParams>, _context: RequestContext<RoleServer>) -> Result<ListToolsResult, McpError> {
        let tools = builtin_tools()
            .iter()
            .map(|tool| {
                let tool = tool.as_secure_tool();
                let schema = match tool.schema() {
                    serde_json::Value::Object(schema) => schema,
                    _ => serde_json::Map::new(),
                };
                Tool::new(tool.name(), tool.description(), schema).annotate(annotations(tool.name()))
            })
            .collect();
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(&self, request: CallToolRequestParams, context: RequestContext<RoleServer>) -> Result<CallToolResponse, McpError> {
        let tool = request.name.to_string();
        // rmcp hands the request's `_meta` over in the context.
        let context = call_context(Some(&context.meta.0 .0)).or_else(|| call_context(request.meta.as_ref().map(|m| &m.0 .0)));
        let args = serde_json::Value::Object(request.arguments.unwrap_or_default());
        let presentation = match self.present(&tool, &args) {
            Ok(p) => p,
            Err(e) => return Ok(error_result(format!("cannot present the token: {}", e))),
        };
        let request = ToolRequest {
            tool_name: tool,
            payload: args,
            request_id: uuid::Uuid::new_v4().to_string(),
            capability: None,
            presentation,
            context,
        };
        let response = match &self.runner {
            Runner::Local(node) => node.lock().await.run_local(CALLER, request).await,
            Runner::Remote { handle, peer } => match handle.invoke_request(*peer, request).await {
                Ok(response) => response,
                Err(e) => return Ok(error_result(format!("node unreachable: {}", e))),
            },
        };
        if !response.success {
            return Ok(error_result(response.error.unwrap_or_else(|| "tool failed".into())));
        }
        let mut result = CallToolResult::success(vec![ContentBlock::text(response.output.to_string())]);
        result.structured_content = Some(response.output);
        Ok(result.into())
    }
}

/// `cleimesh mcp wrap` (M5): another MCP server, native rather than WASM,
/// behind the same token, taint and receipts. Its client sees only the tools
/// the held chains grant; each call is decided and recorded by a node in this
/// process before it reaches the server, and only the time limit applies
/// while it runs. Nothing confines the server itself: it reaches whatever
/// its OS user can, so a token granting it directories or network is refused
/// rather than recorded as if it held.
pub struct Wrapper {
    node: Mutex<CleiMeshNode>,
    server: rmcp::service::RunningService<rmcp::RoleClient, ()>,
    /// The wrapped command line's digest, as the receipts name the server.
    server_sha256: String,
    credentials: Option<(Vec<Vec<String>>, aat::SigningKey)>,
    audience: String,
    tools: Vec<Tool>,
}

impl Wrapper {
    pub async fn new(
        node: CleiMeshNode,
        server: rmcp::service::RunningService<rmcp::RoleClient, ()>,
        server_sha256: String,
        credentials: Option<(Vec<Vec<String>>, aat::SigningKey)>,
    ) -> Result<Self, String> {
        let offered = server.list_all_tools().await.map_err(|e| format!("cannot list the wrapped server's tools: {}", e))?;
        let granted: Vec<String> = credentials.iter().flat_map(|(chains, _)| chains.iter().flat_map(|c| granted_tools(c))).collect();
        let tools = offered.into_iter().filter(|t| granted.iter().any(|g| *g == t.name)).collect();
        let audience = node.aat_audience();
        Ok(Wrapper { node: Mutex::new(node), server, server_sha256, credentials, audience, tools })
    }
}

impl ServerHandler for Wrapper {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("cleimesh-wrap", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "Tools of another MCP server, behind a delegation token: only the tools and arguments it grants are passed on, \
                 and every call leaves a signed receipt. The server itself is not sandboxed.",
            )
    }

    async fn list_tools(&self, _request: Option<PaginatedRequestParams>, _context: RequestContext<RoleServer>) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(self.tools.clone()))
    }

    async fn call_tool(&self, request: CallToolRequestParams, context: RequestContext<RoleServer>) -> Result<CallToolResponse, McpError> {
        let tool = request.name.to_string();
        let call_context = call_context(Some(&context.meta.0 .0)).or_else(|| call_context(request.meta.as_ref().map(|m| &m.0 .0)));
        let arguments = request.arguments.clone();
        let args = serde_json::Value::Object(arguments.clone().unwrap_or_default());
        let presentation = match present(self.credentials.as_ref(), &self.audience, &tool, &args) {
            Ok(p) => p,
            Err(e) => return Ok(error_result(format!("cannot present the token: {}", e))),
        };
        let request = ToolRequest {
            tool_name: tool.clone(),
            payload: args,
            request_id: uuid::Uuid::new_v4().to_string(),
            capability: None,
            presentation,
            context: call_context,
        };
        let server = &self.server;
        let run = |request: ToolRequest| async move {
            let mut params = CallToolRequestParams::new(tool);
            params.arguments = arguments;
            let (success, output, error) = match server.call_tool(params).await {
                Ok(result) => {
                    let failed = result.is_error == Some(true);
                    (!failed, serde_json::to_value(&result).unwrap_or_default(), failed.then(|| "the wrapped server reported an error".to_string()))
                }
                Err(e) => (false, serde_json::json!({}), Some(format!("the wrapped server failed: {}", e))),
            };
            cleimesh_p2p::ToolResponse { request_id: request.request_id, success, output, error }
        };
        let response = self.node.lock().await.run_external(CALLER, request, &self.server_sha256, run).await;
        // The server's own result, error or not, goes back as it gave it.
        if let Ok(result) = serde_json::from_value::<CallToolResult>(response.output.clone()) {
            return Ok(result.into());
        }
        Ok(error_result(response.error.unwrap_or_else(|| "tool failed".into())))
    }
}

