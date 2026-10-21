use cleimesh_core::{Result, AgentIdentity, ToolPayload};
use cleimesh_wasm_sandbox::{WasmSandbox, SandboxConfig};
use libp2p::{
    identity,
    noise,
    yamux,
    Swarm,
    Transport,
};
use libp2p_tcp::tokio::Transport as TokioTransport;
use std::time::Duration;
use tokio::sync::mpsc;
use libp2p::futures::StreamExt;
use libp2p::request_response::{OutboundRequestId, ResponseChannel};
use libp2p::swarm::Executor;
use std::collections::HashMap;
use crate::behaviour::{CleiMeshEvent};
use crate::auth::{Capability};
use serde::{Deserialize, Serialize};

pub mod behaviour;
pub mod protocol;
pub mod discovery;
pub mod auth;
pub mod node_key;
pub mod receipts;
pub mod grants;
pub mod report;
pub mod suggest;
pub mod replay;

pub use behaviour::{CleiMeshBehaviour, ToolRequest, ToolResponse, MAX_IN_FLIGHT_PER_PEER, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES};
pub use protocol::{AgentProtocol, ToolInvocation, ToolResponse as ProtocolToolResponse};
pub use discovery::MeshDiscovery;
pub use auth::{Constraints, RateLimit, CapabilityStore, CapabilityProof};
pub use cleimesh_aat as aat;
pub use receipts::{subject_pseudonym, Authority, CallContext};
/// For callers that address nodes (`mcp serve --node`).
pub use libp2p::{multiaddr, Multiaddr, PeerId};

#[derive(Debug, Clone)]
pub struct P2PConfig {
    pub listen_addresses: Vec<String>,
    pub bootstrap_peers: Vec<String>,
    pub enable_mdns: bool,
    pub enable_kad: bool,
    pub enable_gossipsub: bool,
    /// Reconnection settings
    pub reconnect_interval_secs: u64,
    pub max_reconnect_attempts: u32,
    /// Tools any peer may execute without a capability. Empty by default:
    /// every remote request needs a matching capability (deny by default).
    pub public_tools: Vec<String>,
    /// Where the node's Ed25519 key lives (see `node_key`). The key is loaded
    /// or created there, so the PeerId survives restarts. `None` uses a fresh
    /// in-memory key: only for tests and throwaway nodes, since capabilities
    /// granted to an ephemeral PeerId die with the process.
    pub identity_key_path: Option<std::path::PathBuf>,
    /// Receipt log (C2): every tool call this node
    /// receives, allowed or denied, is signed with the node key and appended
    /// here. `None` keeps no receipts.
    pub receipts_path: Option<std::path::PathBuf>,
}

impl Default for P2PConfig {
    fn default() -> Self {
        Self {
            listen_addresses: vec!["/ip4/0.0.0.0/tcp/0".to_string()],
            bootstrap_peers: Vec::new(),
            enable_mdns: true,
            enable_kad: true,
            enable_gossipsub: true,
            reconnect_interval_secs: 5,
            max_reconnect_attempts: 10,
            public_tools: Vec::new(),
            identity_key_path: None,
            receipts_path: None,
        }
    }
}

/// Node state for snapshot/restore
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSnapshot {
    pub peer_id: String,
    pub capabilities: Vec<Capability>,
    pub pending_requests: Vec<String>,
    pub known_peers: Vec<String>,
    pub timestamp: u64,
}

/// Outcome of an outbound tool call: the peer's response, or why no
/// response arrived.
type InvokeReply = tokio::sync::oneshot::Sender<std::result::Result<ToolResponse, String>>;

/// A finished inbound tool run, waiting for the event loop to record it and
/// send it back.
type Execution = (PeerId, ResponseChannel<ToolResponse>, ToolResponse, receipts::Outcome, cleimesh_wasm_sandbox::FsObserved);

/// How long an inbound tool run may take.
const EXECUTION_TIMEOUT_MS: u64 = 5000;
/// How long a request may take on the wire, from the request to its
/// response: the longest run plus room for the queue and the network (S11).
const REQUEST_TIMEOUT: Duration = Duration::from_millis(EXECUTION_TIMEOUT_MS + 5000);

/// Requests sent to a running event loop through a `NodeHandle`.
enum Command {
    Invoke { peer: PeerId, request: ToolRequest, reply: InvokeReply },
    AddPeerAddress { peer: PeerId, addr: Multiaddr },
    ListenAddrs { reply: tokio::sync::oneshot::Sender<Vec<Multiaddr>> },
    Shutdown,
}

/// Talks to a node whose event loop (`run_event_loop`) runs in another task.
/// The loop owns the swarm, so this is the way to use the node meanwhile.
#[derive(Clone)]
pub struct NodeHandle {
    commands: mpsc::UnboundedSender<Command>,
}

impl NodeHandle {
    /// Sends `tool_name` to `peer`, presenting `capability` if given, and
    /// waits for the response.
    pub async fn invoke_tool(
        &self,
        peer: PeerId,
        tool_name: String,
        args: serde_json::Value,
        capability: Option<Capability>,
    ) -> Result<ToolResponse> {
        self.invoke(peer, new_tool_request(tool_name, args, capability, None)).await
    }

    /// Sends `tool_name` to `peer` under an AAT delegation chain, and waits
    /// for the response. `presentation` must be made for this call (see
    /// `aat::pop`).
    pub async fn invoke_tool_presenting(
        &self,
        peer: PeerId,
        tool_name: String,
        args: serde_json::Value,
        presentation: aat::Presentation,
    ) -> Result<ToolResponse> {
        self.invoke(peer, new_tool_request(tool_name, args, None, Some(presentation))).await
    }

    /// Sends a request built by the caller (presentation, context) to
    /// `peer`, and waits for the response.
    pub async fn invoke_request(&self, peer: PeerId, request: ToolRequest) -> Result<ToolResponse> {
        self.invoke(peer, request).await
    }

    async fn invoke(&self, peer: PeerId, request: ToolRequest) -> Result<ToolResponse> {
        let (reply, rx) = tokio::sync::oneshot::channel();
        self.send(Command::Invoke { peer, request, reply })?;
        wait_for_response(rx).await
    }

    /// Records where `peer` listens; the first request to it dials there.
    pub fn add_peer_address(&self, peer: PeerId, addr: Multiaddr) -> Result<()> {
        self.send(Command::AddPeerAddress { peer, addr })
    }

    /// Addresses the node is listening on. Empty until the loop has bound them.
    pub async fn listen_addrs(&self) -> Result<Vec<Multiaddr>> {
        let (reply, rx) = tokio::sync::oneshot::channel();
        self.send(Command::ListenAddrs { reply })?;
        rx.await.map_err(|_| anyhow::anyhow!("Node event loop stopped").into())
    }

    /// Stops the event loop.
    pub fn shutdown(&self) -> Result<()> {
        self.send(Command::Shutdown)
    }

    fn send(&self, command: Command) -> Result<()> {
        self.commands.send(command).map_err(|_| anyhow::anyhow!("Node event loop stopped").into())
    }
}

fn new_tool_request(
    tool_name: String,
    payload: serde_json::Value,
    capability: Option<Capability>,
    presentation: Option<aat::Presentation>,
) -> ToolRequest {
    ToolRequest {
        tool_name,
        payload,
        request_id: uuid::Uuid::new_v4().to_string(),
        capability,
        presentation,
        context: None,
    }
}

/// Runs `request` in `sandbox` under `config`, exactly as the node does for
/// an admitted call: same payload, same error text. A replay (C4) uses it so
/// that its outcome is comparable byte for byte.
pub async fn run_tool(sandbox: WasmSandbox, request: ToolRequest, config: SandboxConfig) -> ToolResponse {
    execute(sandbox, request, config).await.0
}

/// Runs an admitted request in the sandbox under `config`. The run goes to
/// the blocking pool, not the async runtime: compiling and running WASM is
/// CPU-bound and would hold a runtime thread (the only one, on a
/// current-thread runtime). Also returns which granted directories the
/// call touched, for its result receipt (C5).
async fn execute(sandbox: WasmSandbox, request: ToolRequest, config: SandboxConfig) -> (ToolResponse, cleimesh_wasm_sandbox::FsObserved) {
    let runtime = tokio::runtime::Handle::current();
    let payload = ToolPayload {
        tool_name: request.tool_name.clone(),
        arguments: request.payload,
        timeout_ms: Some(config.max_execution_time.as_millis() as u64),
    };
    let tool_name = request.tool_name;
    let (result, fs) = tokio::task::spawn_blocking(move || runtime.block_on(sandbox.execute_observed(&tool_name, payload, &config)))
        .await
        .unwrap_or_else(|e| (Err(anyhow::anyhow!("Task failed: {}", e).into()), Default::default()));
    let response = match result {
        Ok(tool_result) => ToolResponse {
            request_id: request.request_id,
            success: tool_result.success,
            output: tool_result.output,
            error: tool_result.error,
        },
        Err(e) => ToolResponse {
            request_id: request.request_id,
            success: false,
            output: serde_json::json!({}),
            // Sandbox failures arrive as anyhow chains wrapped in Internal;
            // the caller wants "cannot read ...", not "internal error: ...".
            error: Some(match &e {
                cleimesh_core::CleiMeshError::Internal(inner) => format!("{:#}", inner),
                other => error_chain(other),
            }),
        },
    };
    (response, fs)
}

/// `e` and its causes, so a caller sees why the sandbox refused (e.g. the
/// tool's "cannot read ...") and not only "tool execution failed".
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut text = e.to_string();
    let mut source = e.source();
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        if !text.ends_with(&cause_text) {
            text = format!("{}: {}", text, cause_text);
        }
        source = cause.source();
    }
    text
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// How long a caller waits for a tool response before giving up.
const INVOKE_TIMEOUT: Duration = Duration::from_secs(30);

async fn wait_for_response(rx: tokio::sync::oneshot::Receiver<std::result::Result<ToolResponse, String>>) -> Result<ToolResponse> {
    tokio::time::timeout(INVOKE_TIMEOUT, rx).await
        .map_err(|_| anyhow::anyhow!("Request timeout"))?
        .map_err(|_| anyhow::anyhow!("Request cancelled"))?
        .map_err(|e| anyhow::anyhow!("Request failed: {}", e).into())
}

pub struct CleiMeshNode {
    config: P2PConfig,
    identity: AgentIdentity,
    local_peer_id: PeerId,
    swarm: Option<Swarm<CleiMeshBehaviour>>,
    event_tx: Option<mpsc::UnboundedSender<CleiMeshEvent>>,
    event_rx: Option<mpsc::UnboundedReceiver<CleiMeshEvent>>,
    sandbox: WasmSandbox,
    /// Outbound calls waiting for their response, resolved by the swarm
    /// event handler.
    pending_requests: HashMap<OutboundRequestId, InvokeReply>,
    /// Calls to peers we are not connected to yet, sent once the connection
    /// opens (see `send_tool_request`).
    awaiting_connection: HashMap<PeerId, Vec<(ToolRequest, InvokeReply)>>,
    commands_tx: mpsc::UnboundedSender<Command>,
    commands_rx: Option<mpsc::UnboundedReceiver<Command>>,
    /// Inbound tool runs finished off the loop (see `spawn_execution`).
    executions_tx: mpsc::UnboundedSender<Execution>,
    executions_rx: Option<mpsc::UnboundedReceiver<Execution>>,
    capability_store: CapabilityStore,
    keypair: identity::Keypair,
    /// The node key as an AAT signing key: root tokens it signs are the
    /// ones this node honors (its only trust anchor).
    aat_key: aat::SigningKey,
    /// Proofs of possession already accepted, so none runs twice.
    replay_guard: aat::ReplayGuard,
    receipts: Option<cleimesh_receipt::ReceiptLog>,
    /// Holders that received untrusted content, by the decision step of the
    /// call that tainted them (C6); rebuilt from the receipt log on start.
    tainted: HashMap<String, String>,
    /// Calls each peer has running here, capped at `MAX_IN_FLIGHT_PER_PEER`.
    in_flight: HashMap<PeerId, usize>,
    /// Shutdown signal
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    /// Reconnection state
    reconnect_attempts: HashMap<PeerId, u32>,
}

impl CleiMeshNode {
    pub fn new(config: P2PConfig, identity: AgentIdentity) -> Result<Self> {
        let keypair = match &config.identity_key_path {
            Some(path) => node_key::load_or_generate(path)?,
            None => libp2p::identity::Keypair::generate_ed25519(),
        };
        let local_peer_id = PeerId::from(keypair.public());
        let aat_key = node_key::aat_signing_key(&keypair)?;
        let tainted = match &config.receipts_path {
            Some(path) => std::fs::read(path).map(|log| receipts::tainted_holders(&log)).unwrap_or_default(),
            None => HashMap::new(),
        };
        let receipts = match &config.receipts_path {
            Some(path) => Some(
                cleimesh_receipt::ReceiptLog::open(path, aat_key.clone())
                    .map_err(|e| anyhow::anyhow!("Cannot open receipt log: {}", e))?,
            ),
            None => None,
        };
        // The node speaks for one key only: the agent identity is the PeerId
        // that Noise authenticates, whatever label the caller passed.
        let identity = AgentIdentity {
            peer_id: local_peer_id.to_string(),
            public_key: keypair.public().encode_protobuf(),
            ..identity
        };
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (commands_tx, commands_rx) = mpsc::unbounded_channel();
        let (executions_tx, executions_rx) = mpsc::unbounded_channel();
        let sandbox = WasmSandbox::new(SandboxConfig::default())?;
        
        // Register builtin tools
        sandbox.register_wasm_module("echo", include_bytes!("../../wasm-tools/builtins.wasm").to_vec())?;
        sandbox.register_wasm_module("file_read", include_bytes!("../../wasm-tools/builtins.wasm").to_vec())?;
        sandbox.register_wasm_module("file_write", include_bytes!("../../wasm-tools/builtins.wasm").to_vec())?;
        sandbox.register_wasm_module("json_transform", include_bytes!("../../wasm-tools/builtins.wasm").to_vec())?;
        
        Ok(Self {
            config,
            identity,
            local_peer_id,
            swarm: None,
            event_tx: Some(event_tx),
            event_rx: Some(event_rx),
            sandbox,
            pending_requests: HashMap::new(),
            awaiting_connection: HashMap::new(),
            commands_tx,
            commands_rx: Some(commands_rx),
            executions_tx,
            executions_rx: Some(executions_rx),
            capability_store: CapabilityStore::new(),
            keypair,
            aat_key,
            replay_guard: aat::ReplayGuard::new(),
            receipts,
            tainted,
            in_flight: HashMap::new(),
            shutdown_tx: None,
            reconnect_attempts: HashMap::new(),
        })
    }

    /// Keeps receipts in `log` instead of `P2PConfig::receipts_path`, e.g. to
    /// send them somewhere other than a local file.
    pub fn with_receipt_log(mut self, log: cleimesh_receipt::ReceiptLog) -> Self {
        self.receipts = Some(log);
        self
    }

    /// Replaces the sandbox that runs requested tools, built-ins included:
    /// register on `sandbox` every tool the node should serve.
    pub fn with_sandbox(mut self, sandbox: WasmSandbox) -> Self {
        self.sandbox = sandbox;
        self
    }

    /// A handle for using the node while `run_event_loop` runs in another task.
    pub fn handle(&self) -> NodeHandle {
        NodeHandle { commands: self.commands_tx.clone() }
    }

    /// Records where `peer` listens; the first request to it dials there.
    /// Before `run_event_loop`; afterwards use `NodeHandle::add_peer_address`.
    pub fn add_peer_address(&mut self, peer: PeerId, addr: Multiaddr) -> Result<()> {
        let swarm = self.swarm.as_mut().ok_or_else(|| anyhow::anyhow!("Swarm not initialized"))?;
        add_peer_address(swarm, peer, addr);
        Ok(())
    }

    pub fn grant_capability(&mut self, capability: Capability) {
        self.capability_store.add(capability);
    }

    pub fn capability_store_mut(&mut self) -> &mut CapabilityStore {
        &mut self.capability_store
    }

    /// Issues a capability, signed by this node and addressed to it, that
    /// lets `subject` execute `tool_name` here. Hand it to the subject to
    /// present with its requests, or store it with `grant_capability`.
    pub fn issue_capability(&self, subject: &PeerId, tool_name: &str, constraints: auth::Constraints) -> Result<Capability> {
        Capability::issue(&self.keypair, subject, format!("tool:{}", tool_name), vec!["execute".to_string()], constraints)
    }

    /// The key whose root tokens this node honors, for holders to check
    /// a chain against.
    pub fn aat_trust_anchor(&self) -> aat::Jwk {
        aat::Jwk::from_key(&self.aat_key.verifying_key())
    }

    /// The `aat_aud` a proof of possession must carry to be accepted here:
    /// the node's PeerId.
    pub fn aat_audience(&self) -> String {
        self.local_peer_id.to_string()
    }

    /// Issues a root AAT, signed by this node, granting `tools` to the
    /// holder of `holder` for `ttl_secs`, with up to `del_max_depth`
    /// offline delegations below it.
    pub fn issue_aat_root(&self, holder: &aat::Jwk, tools: aat::Tools, ttl_secs: i64, del_max_depth: u32) -> Result<String> {
        self.issue_aat_root_granting(holder, tools, &grants::Grants::new(), ttl_secs, del_max_depth)
    }

    /// Like `issue_aat_root`, also granting the sandbox access in `grants`
    /// (directories, network, limits) to the tools' runs.
    pub fn issue_aat_root_granting(&self, holder: &aat::Jwk, tools: aat::Tools, grants: &grants::Grants, ttl_secs: i64, del_max_depth: u32) -> Result<String> {
        let iss = format!("urn:cleimesh:node:{}", self.local_peer_id);
        let extra = if grants.is_empty() { Vec::new() } else { vec![grants::entry(grants)] };
        aat::issue_root_with(&self.aat_key, &iss, holder, tools, extra, unix_now(), ttl_secs, del_max_depth)
            .map_err(|e| anyhow::anyhow!("cannot issue AAT: {}", e).into())
    }

    /// Decides whether `peer`, the PeerId authenticated by Noise, may run
    /// `request`. Denies by default: the request needs an AAT presentation
    /// that `authorize_presentation` accepts, or a capability (presented
    /// with it, or stored on this node) that passes `Capability::check_request`
    /// and is not revoked, unless the tool is listed in
    /// `P2PConfig::public_tools`. Records usage on success, and returns what
    /// allowed the call, for its receipt.
    pub fn authorize_tool_request(&mut self, peer: &PeerId, request: &ToolRequest) -> std::result::Result<Authority, String> {
        self.authorize(peer, request).map(|(authority, _)| authority)
    }

    /// `authorize_tool_request`, plus the sandbox the call must run in: the
    /// grants of its AAT chain (see `grants`), or the node's own sandbox for
    /// a legacy capability or a public tool.
    fn authorize(&mut self, peer: &PeerId, request: &ToolRequest) -> std::result::Result<(Authority, SandboxConfig), String> {
        if let Some(presentation) = &request.presentation {
            if request.capability.is_some() {
                return Err("Authorization failed: request carries both a capability and an AAT presentation".to_string());
            }
            return self
                .authorize_presentation(presentation, &request.tool_name, &request.payload)
                .map_err(|e| format!("Authorization failed: {}", e));
        }

        let resource = format!("tool:{}", request.tool_name);
        let node = self.local_peer_id;
        let store = &self.capability_store;
        let check = |cap: &Capability| {
            cap.check_request(&node, peer, &resource, "execute", &request.payload)?;
            if store.is_revoked(cap) {
                return Err("capability was revoked".to_string());
            }
            Ok(())
        };

        let cap = match &request.capability {
            // A presented capability is the client's explicit claim, so its
            // refusal is reported as is.
            Some(cap) => check(cap).map(|_| cap.clone()),
            None => match store.for_resource(&resource).iter().find(|c| check(c).is_ok()) {
                Some(cap) => Ok(cap.clone()),
                None if self.config.public_tools.iter().any(|t| *t == request.tool_name) => return Ok((Authority::PublicTool, self.node_sandbox())),
                None => Err("no valid capability".to_string()),
            },
        }
        .map_err(|e| format!("Authorization failed: {}", e))?;

        self.capability_store.record_usage(&cap)
            .map_err(|e| format!("Authorization failed: {}", e))?;
        let authority = Authority::Capability {
            nonce: cap.proof.nonce.iter().map(|b| format!("{:02x}", b)).collect(),
            subject: cap.subject.peer_id.clone(),
        };
        Ok((authority, self.node_sandbox()))
    }

    /// The node's own sandbox, under the node's execution timeout.
    fn node_sandbox(&self) -> SandboxConfig {
        let mut config = self.sandbox.config().clone();
        config.max_execution_time = Duration::from_millis(EXECUTION_TIMEOUT_MS);
        config
    }

    /// Verifies an AAT chain for calling `tool` with `args` here: rooted in
    /// this node's key, proof of possession addressed to this node and not
    /// seen before. The proof binds the leaf holder's key, not the PeerId
    /// that carried the request, so any transport peer may relay it.
    fn authorize_presentation(&mut self, presentation: &aat::Presentation, tool: &str, args: &serde_json::Value) -> std::result::Result<(Authority, SandboxConfig), String> {
        let now = unix_now();
        let anchors = [self.aat_trust_anchor()];
        let audience = self.aat_audience();
        let policy = aat::Policy { trust_anchors: &anchors, audience: Some(&audience), now };
        let verified = aat::verify(presentation, &policy, tool, args).map_err(|e| e.to_string())?;
        let (grant, root_grant) = grants::effective(&verified.chain, tool)?;
        let lineage: Vec<String> = verified.chain.iter().map(|c| c.cnf.jwk.thumbprint_uri()).collect();
        // A tool that acts on the world refuses a chain in which anyone has
        // read untrusted content: instructions injected there can't drive it,
        // and delegating to a fresh subagent doesn't launder the taint (C6).
        if grant.clean_only {
            if let Some((holder, step)) = lineage.iter().find_map(|h| self.tainted.get(h).map(|s| (h, s))) {
                return Err(format!(
                    "{} refused: holder {} in this chain received untrusted content (receipt {}); clearing it takes a human (cleimesh taint clear)",
                    tool, holder, step
                ));
            }
        }
        let sandbox = grants::sandbox_config(self.sandbox.config(), &grant, &root_grant, EXECUTION_TIMEOUT_MS)?;
        self.replay_guard.check(&verified, now).map_err(|e| e.to_string())?;
        let authority = Authority::Aat {
            root_iss: verified.root.iss,
            root_jti: verified.root.jti,
            leaf_jti: verified.leaf.jti,
            holder: verified.leaf.cnf.jwk.thumbprint_uri(),
            depth: verified.leaf.del_depth,
            chain_sha256: receipts::json_sha256(&serde_json::json!(presentation.chain)),
            lineage,
            taints: grant.taints,
            clean_only: grant.clean_only,
        };
        Ok((authority, sandbox))
    }

    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// The node's agent identity, bound to its PeerId and public key.
    pub fn agent_identity(&self) -> &AgentIdentity {
        &self.identity
    }

    pub async fn start(&mut self) -> Result<()> {
        let keypair = self.keypair.clone();
        let local_peer_id = self.local_peer_id;

        struct TokioExecutor;
        
        impl Executor for TokioExecutor {
            fn exec(&self, f: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>) {
                tokio::spawn(f);
            }
        }

        let tcp = TokioTransport::new(libp2p::tcp::Config::default().nodelay(true));
        let noise = noise::Config::new(&keypair).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        // /dns4 and /dns6 addresses (NET1): agent sandboxes and Kubernetes
        // name the node's host instead of giving an IP. The resolver reads
        // /etc/hosts and the system's DNS; without a DNS configuration, the
        // node still dials IP addresses.
        let transport = match libp2p::dns::tokio::Transport::system(tcp) {
            Ok(dns) => dns
                .upgrade(libp2p::core::upgrade::Version::V1)
                .authenticate(noise)
                .multiplex(yamux::Config::default())
                .boxed(),
            Err(e) => {
                tracing::warn!("No DNS configuration ({}); /dns addresses will not resolve", e);
                TokioTransport::new(libp2p::tcp::Config::default().nodelay(true))
                    .upgrade(libp2p::core::upgrade::Version::V1)
                    .authenticate(noise)
                    .multiplex(yamux::Config::default())
                    .boxed()
            }
        };

        let behaviour = CleiMeshBehaviour::new(&keypair, REQUEST_TIMEOUT);
        let config = libp2p::swarm::Config::with_executor(TokioExecutor);
        let mut swarm = Swarm::new(transport, behaviour, local_peer_id, config);

        for addr_str in &self.config.listen_addresses {
            let addr: Multiaddr = addr_str.parse().map_err(|e| anyhow::anyhow!("{:?}", e))?;
            swarm.listen_on(addr).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        }

        if !self.config.bootstrap_peers.is_empty() {
            for peer_str in &self.config.bootstrap_peers {
                let addr: Multiaddr = peer_str.parse()
                    .map_err(|e| anyhow::anyhow!("Invalid bootstrap address {}: {:?}", peer_str, e))?;
                let peer = bootstrap_peer_id(&addr).ok_or_else(|| {
                    anyhow::anyhow!("Bootstrap address {} must end in /p2p/<peer id>", peer_str)
                })?;
                swarm.behaviour_mut().kad.add_address(&peer, addr.clone());
                add_peer_address(&mut swarm, peer, addr.clone());
                if let Err(e) = swarm.dial(peer) {
                    tracing::warn!("Dial to bootstrap peer {} failed: {}", peer, e);
                }
            }
            swarm.behaviour_mut().kad.bootstrap().ok();
        }

        self.swarm = Some(swarm);
        Ok(())
    }

    async fn handle_swarm_event(&mut self, event: libp2p::swarm::SwarmEvent<CleiMeshEvent>, swarm: &mut Swarm<CleiMeshBehaviour>) {
        match event {
            libp2p::swarm::SwarmEvent::Behaviour(behaviour_event) => {
                match behaviour_event {
                    CleiMeshEvent::Kad(kad_event) => {
                        tracing::debug!("Kademlia event: {:?}", kad_event);
                    }
                    CleiMeshEvent::Gossipsub(gossipsub_event) => {
                        tracing::debug!("Gossipsub event: {:?}", gossipsub_event);
                    }
                    CleiMeshEvent::Identify(identify_event) => {
                        tracing::debug!("Identify event: {:?}", identify_event);
                    }
                    CleiMeshEvent::Ping(ping_event) => {
                        tracing::debug!("Ping event: {:?}", ping_event);
                    }
                    CleiMeshEvent::Relay(relay_event) => {
                        tracing::debug!("Relay event: {:?}", relay_event);
                    }
                    CleiMeshEvent::RequestResponse(req_resp_event) => {
                        self.handle_request_response(req_resp_event, swarm).await;
                    }
                }
            }
            libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                tracing::info!("Listening on {}", address);
            }
            libp2p::swarm::SwarmEvent::Dialing { peer_id, .. } => {
                tracing::debug!("Dialing {:?}", peer_id);
            }
            libp2p::swarm::SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                tracing::info!("Connection established with {:?}", peer_id);
                for (request, reply) in self.awaiting_connection.remove(&peer_id).unwrap_or_default() {
                    self.send_tool_request(swarm, peer_id, request, reply);
                }
            }
            libp2p::swarm::SwarmEvent::OutgoingConnectionError { peer_id: Some(peer_id), error, .. } => {
                tracing::warn!("Connection to {} failed: {}", peer_id, error);
                if !swarm.is_connected(&peer_id) {
                    self.fail_awaiting(peer_id, &error.to_string());
                }
            }
            libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, .. } => {
                tracing::info!("Connection closed with {:?}", peer_id);
            }
            _ => {}
        }
    }

    /// Sends a tool call, dialing first if needed. Request-response could dial
    /// by itself, but it fails the call when its dial is skipped because
    /// another dial to the peer is in flight (bootstrap, Kademlia, reconnect,
    /// a second call). So the node dials, or joins the dial in flight, and
    /// sends once `ConnectionEstablished` arrives.
    fn send_tool_request(&mut self, swarm: &mut Swarm<CleiMeshBehaviour>, peer: PeerId, request: ToolRequest, reply: InvokeReply) {
        if swarm.is_connected(&peer) {
            let id = swarm.behaviour_mut().request_response.send_request(&peer, request);
            self.pending_requests.insert(id, reply);
            return;
        }
        self.awaiting_connection.entry(peer).or_default().push((request, reply));
        match swarm.dial(peer) {
            Ok(()) | Err(libp2p::swarm::DialError::DialPeerConditionFalse(_)) => {}
            Err(e) => self.fail_awaiting(peer, &e.to_string()),
        }
    }

    fn fail_awaiting(&mut self, peer: PeerId, error: &str) {
        for (_, reply) in self.awaiting_connection.remove(&peer).unwrap_or_default() {
            let _ = reply.send(Err(format!("cannot connect to {}: {}", peer, error)));
        }
    }

    async fn handle_request_response(&mut self, event: libp2p::request_response::Event<ToolRequest, ToolResponse>, swarm: &mut Swarm<CleiMeshBehaviour>) {
        match event {
            libp2p::request_response::Event::Message { peer, message, .. } => {
                match message {
                    libp2p::request_response::Message::Request { request, channel, .. } => {
                        tracing::info!("Received tool request from {:?}: {}", peer, request.tool_name);

                        // Refused before authorization, without a receipt: the
                        // call was neither decided nor run (S11).
                        let running = self.in_flight.get(&peer).copied().unwrap_or(0);
                        if running >= behaviour::MAX_IN_FLIGHT_PER_PEER {
                            tracing::warn!("Refused {} from {:?}: {} calls already running", request.tool_name, peer, running);
                            let busy = ToolResponse {
                                request_id: request.request_id.clone(),
                                success: false,
                                output: serde_json::json!({}),
                                error: Some(format!("Refused: {} calls from this peer already running, try again later", running)),
                            };
                            let _ = swarm.behaviour_mut().request_response.send_response(channel, busy);
                            return;
                        }
                        let (outcome, sandbox) = match self.admit(&peer, &peer.to_string(), &request) {
                            Ok(admitted) => admitted,
                            Err(response) => {
                                let _ = swarm.behaviour_mut().request_response.send_response(channel, response);
                                return;
                            }
                        };
                        *self.in_flight.entry(peer).or_insert(0) += 1;
                        self.spawn_execution(peer, request, channel, outcome, sandbox);
                    }
                    libp2p::request_response::Message::Response { request_id, response } => {
                        tracing::debug!("Received tool response {} from {:?}", response.request_id, peer);
                        if let Some(reply) = self.pending_requests.remove(&request_id) {
                            let _ = reply.send(Ok(response));
                        }
                    }
                }
            }
            libp2p::request_response::Event::OutboundFailure { peer, request_id, error, .. } => {
                tracing::warn!("Outbound request to {:?} failed: {:?}", peer, error);
                if let Some(reply) = self.pending_requests.remove(&request_id) {
                    let _ = reply.send(Err(error.to_string()));
                }
            }
            libp2p::request_response::Event::InboundFailure { peer, error, .. } => {
                tracing::warn!("Inbound request from {:?} failed: {:?}", peer, error);
            }
            _ => {}
        }
    }

    /// Runs an authorized request off the event loop, which keeps serving the
    /// network meanwhile; the response comes back through `executions` and the
    /// loop sends it.
    fn spawn_execution(&self, peer: PeerId, request: ToolRequest, channel: ResponseChannel<ToolResponse>, outcome: receipts::Outcome, config: SandboxConfig) {
        let sandbox = self.sandbox.clone();
        let executions = self.executions_tx.clone();
        tokio::spawn(async move {
            let (response, fs) = execute(sandbox, request, config).await;
            let _ = executions.send((peer, channel, response, outcome, fs));
        });
    }

    /// Decides a call from `caller` (as the receipts name it; `peer` is the
    /// authenticated PeerId the authorization checks): authorizes it, and
    /// writes the decision receipt before anything runs. A denial is
    /// recorded too. `Err` is the response to send instead of running.
    fn admit(&mut self, peer: &PeerId, caller: &str, request: &ToolRequest) -> std::result::Result<(receipts::Outcome, SandboxConfig), ToolResponse> {
        self.admit_to(peer, caller, request, None)
    }

    /// `admit`, for a call that runs in the WASM sandbox (`external` is
    /// `None`) or in the native MCP server whose command line hashes to
    /// `external` (`cleimesh mcp wrap`, M5). Nothing confines such a server,
    /// so a chain granting the tool directories or network is refused: those
    /// grants could not be enforced, and the receipt would claim them.
    fn admit_to(&mut self, peer: &PeerId, caller: &str, request: &ToolRequest, external: Option<&str>) -> std::result::Result<(receipts::Outcome, SandboxConfig), ToolResponse> {
        let refuse = |error: String| ToolResponse {
            request_id: request.request_id.clone(),
            success: false,
            output: serde_json::json!({}),
            error: Some(error),
        };
        let call = receipts::Call::new(caller, request, &self.aat_key);
        let purpose_chars = request.context.as_ref().and_then(|c| c.purpose.as_ref()).map_or(0, |p| p.chars().count());
        let authorized = if purpose_chars > receipts::MAX_PURPOSE_CHARS {
            Err(format!("purpose longer than {} characters", receipts::MAX_PURPOSE_CHARS))
        } else {
            self.authorize(peer, request)
        };
        let authorized = authorized.and_then(|(authority, sandbox)| match external.and(unenforceable_grants(request)) {
            Some(granted) => Err(format!(
                "{} runs in a native MCP server outside the sandbox, so the {} this token grants it can't be enforced; issue it without them",
                request.tool_name, granted
            )),
            None => Ok((authority, sandbox)),
        });
        let (authority, mut sandbox) = match authorized {
            Ok(granted) => granted,
            Err(e) => {
                tracing::warn!("Denied {} for {}: {}", request.tool_name, caller, e);
                self.record(call.denied(&e));
                return Err(refuse(e));
            }
        };

        let (decision, outcome) = match external {
            Some(server_sha256) => call.allowed(&authority, None, receipts::external_terms(server_sha256, &sandbox)),
            None => {
                // Every run sees a frozen clock and seeded randomness, recorded in the
                // decision receipt, so an auditor can replay it (C4).
                sandbox.determinism = Some(cleimesh_wasm_sandbox::Determinism {
                    clock_ns: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0),
                    seed: rand::random(),
                });
                let wasm_sha256 = self.sandbox.tool_registry().read().get_wasm_module(&request.tool_name).map(cleimesh_receipt::sha256_hex);
                call.allowed(&authority, wasm_sha256, receipts::sandbox_terms(&sandbox))
            }
        };
        // No receipt, no run: a call nobody can audit must not happen.
        if let Some(log) = self.receipts.as_mut() {
            if let Err(e) = log.append(decision) {
                tracing::error!("Refused {} for {}: receipt not written: {}", request.tool_name, caller, e);
                return Err(refuse(format!("Refused: cannot record the call ({})", e)));
            }
        }
        Ok((outcome, sandbox))
    }

    /// Runs a call made on this machine (e.g. by `cleimesh mcp serve`)
    /// through the same checks as a remote one: authorization, decision
    /// receipt, sandbox, result receipt. `caller` names it in the receipts.
    /// The node needn't be started.
    pub async fn run_local(&mut self, caller: &str, request: ToolRequest) -> ToolResponse {
        let me = self.local_peer_id;
        let (outcome, sandbox) = match self.admit(&me, caller, &request) {
            Ok(admitted) => admitted,
            Err(response) => return response,
        };
        let (response, fs) = execute(self.sandbox.clone(), request, sandbox).await;
        self.conclude(outcome, &response, &fs);
        response
    }

    /// `run_local` for a tool of a native MCP server (`cleimesh mcp wrap`,
    /// M5): the same authorization, taint and receipts, but `run` makes the
    /// call instead of the WASM sandbox, under the token's time limit.
    /// `server_sha256` names the server in the receipts (its command line
    /// may carry secrets, so only its digest is recorded).
    pub async fn run_external<F, Fut>(&mut self, caller: &str, request: ToolRequest, server_sha256: &str, run: F) -> ToolResponse
    where
        F: FnOnce(ToolRequest) -> Fut,
        Fut: std::future::Future<Output = ToolResponse>,
    {
        let me = self.local_peer_id;
        let (outcome, sandbox) = match self.admit_to(&me, caller, &request, Some(server_sha256)) {
            Ok(admitted) => admitted,
            Err(response) => return response,
        };
        let request_id = request.request_id.clone();
        let response = match tokio::time::timeout(sandbox.max_execution_time, run(request)).await {
            Ok(response) => response,
            Err(_) => ToolResponse {
                request_id,
                success: false,
                output: serde_json::json!({}),
                error: Some(format!("timed out after {} ms", sandbox.max_execution_time.as_millis())),
            },
        };
        self.conclude(outcome, &response, &Default::default());
        response
    }

    /// Records a run's result and, if its tool brings in untrusted content,
    /// taints every holder of its chain. Failures taint too: an error can
    /// carry the content.
    fn conclude(&mut self, outcome: receipts::Outcome, response: &ToolResponse, fs: &cleimesh_wasm_sandbox::FsObserved) {
        let (step, taints) = (outcome.decision_step().to_string(), outcome.taints.clone());
        let fs = receipts::fs_observed(fs, &self.aat_key);
        self.record(outcome.ran(response, fs));
        for holder in taints {
            self.tainted.insert(holder, step.clone());
        }
    }

    /// Holders currently tainted, by the decision step that tainted them.
    pub fn tainted_holders(&self) -> &HashMap<String, String> {
        &self.tainted
    }

    /// A human decision that `holder` (JWK thumbprint URI) may use
    /// clean-only tools again, recorded as a receipt. Errors if the receipt
    /// can't be written: an unrecorded clearing must not take effect.
    pub fn clear_taint(&mut self, holder: &str, reason: &str) -> std::result::Result<(), String> {
        if let Some(log) = self.receipts.as_mut() {
            log.append(receipts::taint_cleared(holder, reason)).map_err(|e| format!("clearing not recorded: {}", e))?;
        }
        self.tainted.remove(holder);
        Ok(())
    }

    /// Records a finished run and sends its response.
    fn finish_execution(&mut self, swarm: &mut Swarm<CleiMeshBehaviour>, (peer, channel, mut response, outcome, fs): Execution) {
        if let Some(running) = self.in_flight.get_mut(&peer) {
            *running -= 1;
            if *running == 0 {
                self.in_flight.remove(&peer);
            }
        }
        // Checked before the receipt, so the receipt describes what is sent.
        let size = serde_json::to_vec(&response).map_or(0, |data| data.len());
        if size > behaviour::MAX_RESPONSE_BYTES {
            response = ToolResponse {
                request_id: response.request_id,
                success: false,
                output: serde_json::json!({}),
                error: Some(format!("output of {} bytes is over the {} byte limit", size, behaviour::MAX_RESPONSE_BYTES)),
            };
        }
        // Taint before the response goes out: once the agent can see the
        // content, every later clean_only call finds its chain tainted. A
        // clean_only call admitted while this one ran had its arguments
        // fixed before the content existed for the agent (R12).
        self.conclude(outcome, &response, &fs);
        let _ = swarm.behaviour_mut().request_response.send_response(channel, response);
    }

    /// Appends a receipt, if this node keeps them. A write failure is logged,
    /// not returned: it is a denial or a result, so the decision is already
    /// made, and the damaged log refuses the next call's decision receipt.
    fn record(&mut self, entry: cleimesh_receipt::Entry) {
        if let Some(log) = self.receipts.as_mut() {
            if let Err(e) = log.append(entry) {
                tracing::error!("Receipt not written: {}", e);
            }
        }
    }

    fn handle_internal_event(&self, _event: CleiMeshEvent, _swarm: &mut Swarm<CleiMeshBehaviour>) {
    }

    /// Runs a `NodeHandle` command. Returns false when the loop must stop.
    fn handle_command(&mut self, command: Command, swarm: &mut Swarm<CleiMeshBehaviour>) -> bool {
        match command {
            Command::Invoke { peer, request, reply } => self.send_tool_request(swarm, peer, request, reply),
            Command::AddPeerAddress { peer, addr } => add_peer_address(swarm, peer, addr),
            Command::ListenAddrs { reply } => {
                let _ = reply.send(swarm.listeners().cloned().collect());
            }
            Command::Shutdown => return false,
        }
        true
    }

    pub async fn invoke_tool(&mut self, peer: PeerId, tool_name: String, args: serde_json::Value) -> Result<ToolResponse> {
        self.invoke_tool_with_capability(peer, tool_name, args, None).await
    }

    /// Like `invoke_tool`, presenting `capability` to the remote node.
    pub async fn invoke_tool_with_capability(
        &mut self,
        peer: PeerId,
        tool_name: String,
        args: serde_json::Value,
        capability: Option<Capability>,
    ) -> Result<ToolResponse> {
        self.invoke(peer, new_tool_request(tool_name, args, capability, None)).await
    }

    /// Like `invoke_tool`, under an AAT delegation chain (see
    /// `NodeHandle::invoke_tool_presenting`).
    pub async fn invoke_tool_presenting(
        &mut self,
        peer: PeerId,
        tool_name: String,
        args: serde_json::Value,
        presentation: aat::Presentation,
    ) -> Result<ToolResponse> {
        self.invoke(peer, new_tool_request(tool_name, args, None, Some(presentation))).await
    }

    /// Sends a request built by the caller (e.g. with a `context`) and waits
    /// for the response.
    pub async fn invoke_request(&mut self, peer: PeerId, request: ToolRequest) -> Result<ToolResponse> {
        self.invoke(peer, request).await
    }

    async fn invoke(&mut self, peer: PeerId, request: ToolRequest) -> Result<ToolResponse> {
        // Nobody else polls the swarm before `run_event_loop`, so drive it
        // here until the response arrives. With the loop running, the swarm
        // lives in the loop and callers use `NodeHandle` instead.
        let mut swarm = self.swarm.take().ok_or_else(|| {
            anyhow::anyhow!("Swarm not initialized (node not started, or its event loop owns it: use handle())")
        })?;
        let mut executions_rx = self.executions_rx.take().ok_or_else(|| anyhow::anyhow!("Event loop owns the node: use handle()"))?;
        let (reply, mut rx) = tokio::sync::oneshot::channel();
        self.send_tool_request(&mut swarm, peer, request, reply);

        let deadline = tokio::time::sleep(INVOKE_TIMEOUT);
        tokio::pin!(deadline);
        let outcome = loop {
            tokio::select! {
                event = swarm.next() => match event {
                    Some(event) => self.handle_swarm_event(event, &mut swarm).await,
                    None => break Err(anyhow::anyhow!("Swarm stopped")),
                },
                Some(execution) = executions_rx.recv() => {
                    self.finish_execution(&mut swarm, execution);
                }
                result = &mut rx => break result
                    .map_err(|_| anyhow::anyhow!("Request cancelled"))
                    .and_then(|r| r.map_err(|e| anyhow::anyhow!("Request failed: {}", e))),
                _ = &mut deadline => break Err(anyhow::anyhow!("Request timeout")),
            }
        };
        // On timeout the reply is dropped here; its entry goes away when the
        // call completes or fails.
        self.swarm = Some(swarm);
        self.executions_rx = Some(executions_rx);
        outcome.map_err(Into::into)
    }

    pub async fn stop(&mut self) -> Result<()> {
        // Signal graceful shutdown
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        
        if let Some(swarm) = self.swarm.take() {
            drop(swarm);
        }
        Ok(())
    }

    /// Create a snapshot of the current node state for persistence
    pub fn snapshot(&self) -> NodeSnapshot {
        // Note: Known peers are rediscovered via Kademlia bootstrap on restore
        let known_peers = Vec::new();

        NodeSnapshot {
            peer_id: self.local_peer_id.to_string(),
            capabilities: self.capability_store.all_capabilities(),
            pending_requests: self.pending_requests.keys().map(|id| id.to_string()).collect(),
            known_peers,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Restore node state from a snapshot
    pub async fn restore(&mut self, snapshot: NodeSnapshot) -> Result<()> {
        // Restore capabilities
        for cap in snapshot.capabilities {
            self.capability_store.add(cap);
        }

        // Note: pending_requests cannot be fully restored as they require active channels
        // Known peers will be rediscovered via Kademlia bootstrap

        tracing::info!("Restored node state from snapshot at {}", snapshot.timestamp);
        Ok(())
    }

    /// Save snapshot to file
    pub fn save_snapshot(&self, path: &std::path::Path) -> Result<()> {
        let snapshot = self.snapshot();
        let data = serde_json::to_vec_pretty(&snapshot)?;
        std::fs::write(path, data)?;
        Ok(())
    }

    /// Load snapshot from file
    pub async fn load_snapshot(&mut self, path: &std::path::Path) -> Result<()> {
        let data = std::fs::read(path)?;
        let snapshot: NodeSnapshot = serde_json::from_slice(&data)?;
        self.restore(snapshot).await
    }

    /// Run event loop with reconnection logic
    pub async fn run_event_loop(&mut self) -> Result<()> {
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);

        let mut swarm = self.swarm.take().ok_or_else(|| anyhow::anyhow!("Swarm not initialized"))?;
        let mut event_rx = self.event_rx.take().ok_or_else(|| anyhow::anyhow!("Event channel not initialized"))?;
        let mut commands_rx = self.commands_rx.take().ok_or_else(|| anyhow::anyhow!("Event loop already ran"))?;
        let mut executions_rx = self.executions_rx.take().ok_or_else(|| anyhow::anyhow!("Event loop already ran"))?;

        let mut kad_tick = tokio::time::interval(Duration::from_secs(30));
        let mut reconnect_tick = tokio::time::interval(Duration::from_secs(self.config.reconnect_interval_secs));

        loop {
            tokio::select! {
                event = swarm.next() => {
                    if let Some(event) = event {
                        // Handle reconnection tracking
                        if let libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, .. } = &event {
                            self.handle_disconnect(*peer_id);
                        } else if let libp2p::swarm::SwarmEvent::ConnectionEstablished { peer_id, .. } = &event {
                            self.handle_reconnect(*peer_id);
                        }
                        self.handle_swarm_event(event, &mut swarm).await;
                    }
                }
                event = event_rx.recv() => {
                    if let Some(event) = event {
                        self.handle_internal_event(event, &mut swarm);
                    }
                }
                Some(execution) = executions_rx.recv() => {
                    self.finish_execution(&mut swarm, execution);
                }
                Some(command) = commands_rx.recv() => {
                    if !self.handle_command(command, &mut swarm) {
                        tracing::info!("Shutdown requested, stopping node");
                        break;
                    }
                }
                _ = kad_tick.tick() => {
                    swarm.behaviour_mut().kad.bootstrap().ok();
                }
                _ = reconnect_tick.tick() => {
                    self.attempt_reconnections(&mut swarm).await;
                }
                _ = &mut shutdown_rx => {
                    tracing::info!("Shutdown signal received, stopping node");
                    break;
                }
            }
        }

        Ok(())
    }

    fn handle_disconnect(&mut self, peer_id: PeerId) {
        let attempts = self.reconnect_attempts.entry(peer_id).or_insert(0);
        *attempts = 0; // Reset on new disconnect
        tracing::info!("Peer disconnected: {}, will attempt reconnect", peer_id);
    }

    fn handle_reconnect(&mut self, peer_id: PeerId) {
        self.reconnect_attempts.remove(&peer_id);
        tracing::info!("Peer reconnected: {}", peer_id);
    }

    async fn attempt_reconnections(&mut self, swarm: &mut Swarm<CleiMeshBehaviour>) {
        let max_attempts = self.config.max_reconnect_attempts;
        
        // Get disconnected peers that we should reconnect to
        let peers_to_reconnect: Vec<PeerId> = self.reconnect_attempts
            .iter()
            .filter(|(_, attempts)| **attempts < max_attempts)
            .map(|(peer, _)| *peer)
            .collect();

        for peer_id in peers_to_reconnect {
            if let Some(attempts) = self.reconnect_attempts.get_mut(&peer_id) {
                *attempts += 1;
                tracing::info!("Attempting reconnect to {} (attempt {}/{})", peer_id, *attempts, max_attempts);
                
                if let Err(e) = swarm.dial(peer_id) {
                    tracing::warn!("Reconnect to {} failed: {}", peer_id, e);
                }
            }
        }

        // Clean up peers that exceeded max attempts
        self.reconnect_attempts.retain(|_, attempts| *attempts < max_attempts);
    }

    /// Graceful shutdown with state persistence
    pub async fn shutdown(&mut self, snapshot_path: Option<&std::path::Path>) -> Result<()> {
        // Save snapshot if path provided
        if let Some(path) = snapshot_path {
            self.save_snapshot(path)?;
        }

        // Signal shutdown
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        // Wait for pending requests to complete (with timeout)
        let timeout = Duration::from_secs(30);
        let start = std::time::Instant::now();
        
        while !self.pending_requests.is_empty() && start.elapsed() < timeout {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        if !self.pending_requests.is_empty() {
            tracing::warn!("Shutdown timeout: {} pending requests abandoned", self.pending_requests.len());
        }

        // Close swarm
        if let Some(swarm) = self.swarm.take() {
            drop(swarm);
        }

        tracing::info!("Node shutdown complete");
        Ok(())
    }
}

/// Records the address with request-response, so dials by PeerId find it
/// (the swarm asks each behaviour for addresses). `Swarm::add_peer_address`,
/// the suggested replacement for the deprecated call, is not handled by
/// request-response 0.26.
#[allow(deprecated)]
fn add_peer_address(swarm: &mut Swarm<CleiMeshBehaviour>, peer: PeerId, addr: Multiaddr) {
    swarm.behaviour_mut().request_response.add_address(&peer, addr);
}

/// The PeerId in a bootstrap address's trailing `/p2p/<id>`. Without it the
/// node would not know whom it is dialing, and Noise could not check it.
/// What an already verified AAT chain grants `request`'s tool that only the
/// WASM sandbox can enforce (directories, network, instruction and memory
/// limits), if anything. Read from the chain itself: the node's own sandbox
/// may have dropped a grant (network, when the node allows none) that the
/// token still claims.
fn unenforceable_grants(request: &ToolRequest) -> Option<String> {
    let presentation = request.presentation.as_ref()?;
    let chain = presentation.chain.iter().map(|t| aat::inspect(t)).collect::<std::result::Result<Vec<_>, _>>().ok()?;
    let (grant, _) = grants::effective(&chain, &request.tool_name).ok()?;
    let mut granted = Vec::new();
    if !grant.read.is_empty() || !grant.write.is_empty() {
        granted.push("directories");
    }
    if grant.network {
        granted.push("network");
    }
    if grant.max_instructions.is_some() || grant.max_memory_bytes.is_some() {
        granted.push("instruction or memory limits");
    }
    (!granted.is_empty()).then(|| granted.join(" and "))
}

fn bootstrap_peer_id(addr: &Multiaddr) -> Option<PeerId> {
    match addr.iter().last() {
        Some(libp2p::multiaddr::Protocol::P2p(peer)) => Some(peer),
        _ => None,
    }
}
