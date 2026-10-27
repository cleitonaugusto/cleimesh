use cleimesh_core::{Result, ToolPayload, AgentIdentity};
use cleimesh_wasm_sandbox::{WasmSandbox, SandboxConfig, StreamingSandbox, StreamConfig};
use cleimesh_p2p::{aat, node_key, CleiMeshNode, P2PConfig};
use cleimesh_observability::{ObservabilityConfig};
use clap::{Parser, Subcommand};

mod doctor;
mod mcp;
mod ocsf;
mod setup;
use std::time::Duration;
use std::path::{Path, PathBuf};
use std::env;

#[derive(Parser)]
#[command(name = "cleimesh")]
#[command(version, about = "CleiMesh - signed, delegable permissions for AI agents, enforced by a WASM sandbox and backed by signed receipts", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a tool locally in the WASM sandbox
    Run {
        /// Tool name to execute
        tool: String,
        /// JSON arguments for the tool
        args: String,
        /// Timeout in milliseconds
        #[arg(short, long, default_value = "5000")]
        timeout: u64,
        /// Directory the tool may read (repeatable). Nothing is readable by default.
        #[arg(long = "allow-read", value_name = "DIR")]
        allow_read: Vec<PathBuf>,
        /// Directory the tool may read and write (repeatable). Nothing is writable by default.
        #[arg(long = "allow-write", value_name = "DIR")]
        allow_write: Vec<PathBuf>,
    },
    /// Start a P2P node
    Start {
        /// Listen addresses (comma-separated)
        #[arg(short, long, default_value = "/ip4/0.0.0.0/tcp/0")]
        listen: String,
        /// Bootstrap peers (comma-separated multiaddrs)
        #[arg(short, long)]
        bootstrap: Option<String>,
        /// Enable mDNS discovery
        #[arg(long, default_value = "true")]
        mdns: bool,
        /// Node key file (default: ~/.config/cleimesh/identity.key)
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Receipt log, one signed receipt per call received
        /// (default: ~/.local/share/cleimesh/receipts/receipts.jsonl)
        #[arg(long, value_name = "FILE")]
        receipts: Option<PathBuf>,
    },
    /// Invoke a tool on a remote peer
    Invoke {
        /// Target peer ID
        peer: String,
        /// Tool name to execute
        tool: String,
        /// JSON arguments for the tool
        args: String,
        /// Timeout in milliseconds
        #[arg(short, long, default_value = "30000")]
        timeout: u64,
        /// Bootstrap peer to connect through
        #[arg(short, long)]
        bootstrap: Option<String>,
        /// Stream output chunks
        #[arg(long)]
        stream: bool,
        /// Client key file (default: ~/.config/cleimesh/client.key)
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Capability file to present (from `cleimesh capability grant`)
        #[arg(long, value_name = "FILE", conflicts_with = "token")]
        capability: Option<PathBuf>,
        /// AAT chain file to present (from `cleimesh token issue` or
        /// `derive`); the client key must hold its last token
        #[arg(long, value_name = "FILE")]
        token: Option<PathBuf>,
        /// Whose personal data the call handles (data subject under the GDPR
        /// or LGPD, e.g. a customer id). Receipts record only a keyed
        /// pseudonym of it
        #[arg(long = "subject", visible_alias = "titular", value_name = "ID")]
        titular: Option<String>,
        /// Why (purpose of the processing, up to 200 characters, no personal data)
        #[arg(long = "purpose", visible_alias = "finalidade", value_name = "TEXT")]
        finalidade: Option<String>,
    },
    /// Print the PeerId of the node key (or, with --client, of the client key)
    Id {
        /// Show the key used by `cleimesh invoke` instead of `cleimesh start`
        #[arg(long)]
        client: bool,
        /// Key file (overrides the default for --client or not)
        #[arg(long)]
        identity: Option<PathBuf>,
    },
    /// Capability management
    #[command(subcommand)]
    Capability(CapabilityCommands),
    /// MCP: serve the node's tools to MCP clients (Claude Code, Cursor...), or put another MCP server behind a token
    #[command(subcommand)]
    Mcp(McpCommands),
    /// Taint: agents that received untrusted content lose clean-only
    /// tools until a human clears them. Run with the node stopped
    #[command(subcommand)]
    Taint(TaintCommands),
    /// Execution receipts: check and read what a node recorded
    #[command(subcommand)]
    Audit(AuditCommands),
    /// Delegation chains (Attenuating Agent Tokens): a node issues the root,
    /// each holder derives narrower tokens offline
    #[command(subcommand)]
    Token(TokenCommands),
    /// Check the keys, the receipt log, the sandbox and the agents set up to
    /// use CleiMesh (warns if an agent keeps its own file or shell tools,
    /// which bypass CleiMesh). Changes nothing
    Doctor {
        /// Node key file (default: ~/.config/cleimesh/identity.key)
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Client key file (default: ~/.config/cleimesh/client.key)
        #[arg(long)]
        client_identity: Option<PathBuf>,
        /// Receipt log (default: ~/.local/share/cleimesh/receipts/receipts.jsonl)
        #[arg(long)]
        receipts: Option<PathBuf>,
    },
    /// Set up an agent to use CleiMesh safely, in one command: the node as
    /// its own user and systemd service (sudo), the agent's tokens, CleiMesh
    /// registered as its MCP server and its own file and shell tools turned
    /// off. Shows the plan and asks first; run it again to renew the tokens.
    /// Example: cleimesh setup openclaw --untrusted ~/mail/inbox --write ~/mail/out
    Setup {
        /// The agent to set up
        agent: setup::Agent,
        /// Directory the agent may read (repeatable); reading it does not taint
        #[arg(long, value_name = "DIR")]
        read: Vec<PathBuf>,
        /// Directory with outside content, such as mail or downloads (repeatable): reading it taints the agent
        #[arg(long, visible_alias = "nao-confiavel", value_name = "DIR")]
        untrusted: Vec<PathBuf>,
        /// Directory the agent may write (repeatable); refused while the agent is tainted
        #[arg(long, value_name = "DIR")]
        write: Vec<PathBuf>,
        /// OS user the node runs as
        #[arg(long = "node-user", default_value = "cleimesh")]
        node_user: String,
        /// Port the node listens on, on localhost
        #[arg(long, default_value_t = 7400)]
        port: u16,
        /// How long the agent's tokens last, in days (1 to 90)
        #[arg(long, visible_alias = "dias", default_value_t = 30)]
        days: u64,
        /// Show the plan and change nothing
        #[arg(long)]
        dry_run: bool,
        /// Don't ask before running the plan
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum McpCommands {
    /// MCP server over stdio. Every tools/call presents the token chain
    /// with a fresh proof of possession and runs under its grants, with
    /// receipts; without --token every call is refused.
    /// Example: claude mcp add cleimesh -- cleimesh mcp serve --token chain.json
    Serve {
        /// Chain file (from `cleimesh token issue` or `derive`) whose last
        /// token the --holder key holds. Repeatable: each call presents the
        /// first chain that grants its tool, and one server keeps one view of
        /// the agent's taint and one writer on the receipt log
        #[arg(long, value_name = "FILE")]
        token: Vec<PathBuf>,
        /// Key holding the chain's last token (default: ~/.config/cleimesh/client.key)
        #[arg(long, value_name = "FILE")]
        holder: Option<PathBuf>,
        /// Forward every call to this node (`cleimesh start`, as it prints:
        /// /ip4/127.0.0.1/tcp/PORT/p2p/PEER_ID) instead of running one in
        /// this process. The node key, receipt log and taint state then stay
        /// with the node's OS user, out of reach of an agent with a shell.
        /// A host name works too: /dns4/HOST/tcp/PORT/p2p/PEER_ID
        #[arg(long, value_name = "MULTIADDR", conflicts_with_all = ["identity", "receipts"])]
        node: Option<String>,
        /// Node key, the chain's trust anchor (default: ~/.config/cleimesh/identity.key)
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Receipt log (default: ~/.local/share/cleimesh/receipts/receipts.jsonl)
        #[arg(long, value_name = "FILE")]
        receipts: Option<PathBuf>,
    },
    /// Put another MCP server (a native one, not WASM) behind a token: its
    /// client sees only the tools the token grants, each call is checked
    /// against the token's argument constraints and taint, and leaves a
    /// signed receipt. The wrapped server is NOT sandboxed: it reaches
    /// whatever its OS user can, so a token granting it directories or
    /// network is refused.
    /// Example: claude mcp add fetch -- cleimesh mcp wrap --token fetch.json -- uvx mcp-server-fetch
    Wrap {
        /// Chain file whose last token the --holder key holds. Repeatable
        #[arg(long, value_name = "FILE")]
        token: Vec<PathBuf>,
        /// Key holding the chain's last token (default: ~/.config/cleimesh/client.key)
        #[arg(long, value_name = "FILE")]
        holder: Option<PathBuf>,
        /// Node key, the chain's trust anchor (default: ~/.config/cleimesh/identity.key)
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Receipt log (default: ~/.local/share/cleimesh/receipts/receipts.jsonl)
        #[arg(long, value_name = "FILE")]
        receipts: Option<PathBuf>,
        /// The MCP server's command and its arguments, after `--`
        #[arg(last = true, required = true, value_name = "COMMAND")]
        command: Vec<String>,
    },
}

#[derive(Subcommand)]
enum TaintCommands {
    /// Holders currently tainted, and the receipt that tainted each
    List {
        /// Receipt log (default: ~/.local/share/cleimesh/receipts/receipts.jsonl)
        #[arg(long, value_name = "FILE")]
        receipts: Option<PathBuf>,
        /// Node key (default: ~/.config/cleimesh/identity.key)
        #[arg(long)]
        identity: Option<PathBuf>,
    },
    /// Let a holder use clean-only tools again; recorded as a receipt
    Clear {
        /// The holder: its PeerId, or its JWK thumbprint URI from `taint list`
        holder: String,
        /// Why it is safe (recorded in the receipt)
        #[arg(long = "reason", visible_alias = "motivo")]
        motivo: String,
        /// Receipt log (default: ~/.local/share/cleimesh/receipts/receipts.jsonl)
        #[arg(long, value_name = "FILE")]
        receipts: Option<PathBuf>,
        /// Node key (default: ~/.config/cleimesh/identity.key)
        #[arg(long)]
        identity: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum AuditCommands {
    /// Check every receipt's signature and the hash chain; exits non-zero
    /// and names each failing line if anything was changed, removed or
    /// reordered
    Verify {
        /// Receipt log (default: ~/.local/share/cleimesh/receipts/receipts.jsonl)
        #[arg(long, value_name = "FILE")]
        receipts: Option<PathBuf>,
        /// Key of the node that signed it (default: ~/.config/cleimesh/identity.key)
        #[arg(long)]
        identity: Option<PathBuf>,
        /// A head saved earlier with `audit head` (kept off this machine):
        /// proves no line it covers was removed since
        #[arg(long, value_name = "FILE")]
        head: Option<PathBuf>,
    },
    /// Re-run a call from its receipts and check the outcome, instead of
    /// trusting the signature: same module, input, sandbox terms, frozen
    /// clock and seed. Only calls without directories or network replay
    Replay {
        /// Decision receipt's step id, or a unique suffix (see `audit tail`)
        step: String,
        /// The call's arguments (JSON file); they must hash to the receipt's input
        #[arg(long, value_name = "FILE")]
        args: PathBuf,
        /// The module that ran (default: the built-in tools)
        #[arg(long, value_name = "FILE")]
        wasm: Option<PathBuf>,
        /// Receipt log (default: ~/.local/share/cleimesh/receipts/receipts.jsonl)
        #[arg(long, value_name = "FILE")]
        receipts: Option<PathBuf>,
        /// Key of the node that signed the log (default: ~/.config/cleimesh/identity.key)
        #[arg(long)]
        identity: Option<PathBuf>,
    },
    /// Print the log's signed head (line count and last-line hash). Keep it
    /// somewhere else; `audit verify --head` then proves nothing was cut
    Head {
        /// Receipt log (default: ~/.local/share/cleimesh/receipts/receipts.jsonl)
        #[arg(long, value_name = "FILE")]
        receipts: Option<PathBuf>,
    },
    /// Remove receipts older than a date (retention), leaving a receipt of
    /// the removal. Run it with the node stopped
    Prune {
        /// Remove receipts before this day, YYYY-MM-DD (UTC)
        #[arg(long = "before", visible_alias = "antes", value_name = "DATE")]
        antes: String,
        /// Only report what would be removed
        #[arg(long)]
        dry_run: bool,
        /// Receipt log (default: ~/.local/share/cleimesh/receipts/receipts.jsonl)
        #[arg(long, value_name = "FILE")]
        receipts: Option<PathBuf>,
        /// Key of the node that signs the log (default: ~/.config/cleimesh/identity.key)
        #[arg(long)]
        identity: Option<PathBuf>,
    },
    /// Export the receipts for a SIEM or an agent sandbox's audit trail: one
    /// OCSF API Activity event per receipt (JSON lines), with the step id,
    /// chain link and signature kept so each event traces back to a line
    /// `audit verify` checks. Refuses a log that fails verification unless
    /// --unverified
    Export {
        /// Output format (only ocsf for now)
        #[arg(long, default_value = "ocsf", value_parser = ["ocsf"])]
        format: String,
        /// Write here instead of standard output
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
        /// Receipt log (default: ~/.local/share/cleimesh/receipts/receipts.jsonl)
        #[arg(long, value_name = "FILE")]
        receipts: Option<PathBuf>,
        /// Key of the node that signed the log (default: ~/.config/cleimesh/identity.key)
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Export even if the log fails verification; every event then says so
        #[arg(long)]
        unverified: bool,
    },
    /// LGPD report from the receipts: everything about one data subject
    /// (--subject), or the record of one agent's operations (--agent; LGPD
    /// art. 37, GDPR art. 30). Refuses a log that fails verification unless
    /// --even-if-broken
    Report {
        /// Data subject id, as given with `invoke --subject` (matched by pseudonym)
        #[arg(long = "subject", visible_alias = "titular", value_name = "ID")]
        titular: Option<String>,
        /// Agent: its PeerId (the key holding its token) or the caller name in the receipts
        #[arg(long = "agent", visible_alias = "agente", value_name = "ID")]
        agente: Option<String>,
        /// First day, YYYY-MM-DD (UTC)
        #[arg(long = "since", visible_alias = "desde", value_name = "DATE")]
        desde: Option<String>,
        /// Last day, YYYY-MM-DD (UTC), inclusive
        #[arg(long = "until", visible_alias = "ate", value_name = "DATE")]
        ate: Option<String>,
        /// md (Markdown) or json
        #[arg(long = "format", visible_alias = "formato", default_value = "md")]
        formato: String,
        /// Language of the Markdown report: en or pt
        #[arg(long, default_value = "en", value_name = "en|pt")]
        lang: String,
        /// Receipt log (default: ~/.local/share/cleimesh/receipts/receipts.jsonl)
        #[arg(long, value_name = "FILE")]
        receipts: Option<PathBuf>,
        /// Key of the node that signed the log (default: ~/.config/cleimesh/identity.key)
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Print the report even if the log fails verification, with a warning
        #[arg(long = "even-if-broken", visible_alias = "mesmo-com-falhas")]
        mesmo_com_falhas: bool,
    },
    /// Suggest a narrower token from what the agent actually used:
    /// per tool, the directories its calls read and wrote, read-only where
    /// it never wrote, and tools never called dropped. Prints the
    /// `token derive` that would apply it; nothing changes until you run it
    Suggest {
        /// The agent's chain file (its last token is the one to narrow)
        #[arg(long, value_name = "FILE")]
        token: PathBuf,
        /// First day, YYYY-MM-DD (UTC)
        #[arg(long = "since", visible_alias = "desde", value_name = "DATE")]
        desde: Option<String>,
        /// Last day, YYYY-MM-DD (UTC), inclusive
        #[arg(long = "until", visible_alias = "ate", value_name = "DATE")]
        ate: Option<String>,
        /// Write the suggested grants here, for `token derive --grants`
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
        /// md (text) or json
        #[arg(long = "format", visible_alias = "formato", default_value = "md")]
        formato: String,
        /// Language of the text: en or pt
        #[arg(long, default_value = "en", value_name = "en|pt")]
        lang: String,
        /// Receipt log (default: ~/.local/share/cleimesh/receipts/receipts.jsonl)
        #[arg(long, value_name = "FILE")]
        receipts: Option<PathBuf>,
        /// Key of the node that signed the log (default: ~/.config/cleimesh/identity.key)
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Suggest even if the log fails verification, with a warning
        #[arg(long = "even-if-broken", visible_alias = "mesmo-com-falhas")]
        mesmo_com_falhas: bool,
    },
    /// Show the latest receipts
    Tail {
        /// How many
        #[arg(short = 'n', long, default_value = "10")]
        lines: usize,
        /// Receipt log (default: ~/.local/share/cleimesh/receipts/receipts.jsonl)
        #[arg(long, value_name = "FILE")]
        receipts: Option<PathBuf>,
        /// Print the raw signed lines
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum TokenCommands {
    /// Issue a root token signed by this node's key, honored only by it
    Issue {
        /// PeerId that will hold it (see `cleimesh id --client` on its machine)
        holder: String,
        #[command(flatten)]
        grant: TokenGrant,
        /// Further delegations allowed below this token
        #[arg(long, default_value = "3")]
        max_depth: u32,
        /// Node key file that signs it (default: ~/.config/cleimesh/identity.key)
        #[arg(long)]
        identity: Option<PathBuf>,
    },
    /// Derive a narrower token from a chain you hold, for another holder.
    /// Offline: the node is not contacted
    Derive {
        /// Chain file whose last token you hold
        chain: PathBuf,
        /// PeerId that will hold the new token
        holder: String,
        #[command(flatten)]
        grant: TokenGrant,
        /// Lower the delegations allowed below the new token
        #[arg(long)]
        max_depth: Option<u32>,
        /// Key file holding the chain (default: ~/.config/cleimesh/client.key)
        #[arg(long)]
        identity: Option<PathBuf>,
    },
}

/// What a token grants, and where the resulting chain goes.
#[derive(clap::Args)]
struct TokenGrant {
    /// Tool usable with any arguments (repeatable)
    #[arg(long = "tool", value_name = "NAME")]
    tools: Vec<String>,
    /// Tools with argument constraints, as AAT JSON, e.g.
    /// '{"echo":{"message":{"constraint_type":"exact","value":"oi"}}}'
    #[arg(long = "tools", value_name = "JSON")]
    constrained: Option<String>,
    /// Directory the granted tools may read when they run (repeatable).
    /// Without --read/--write a tool sees no directory at all
    #[arg(long = "read", value_name = "DIR")]
    read: Vec<PathBuf>,
    /// Directory the granted tools may read and write (repeatable)
    #[arg(long = "write", value_name = "DIR")]
    write: Vec<PathBuf>,
    /// Let the granted tools use the network (if the node allows it)
    #[arg(long)]
    network: bool,
    /// Instruction budget per run
    #[arg(long, value_name = "N")]
    max_instructions: Option<u64>,
    /// Memory limit per run, in bytes
    #[arg(long, value_name = "BYTES")]
    max_memory: Option<usize>,
    /// Time limit per run, in milliseconds
    #[arg(long, value_name = "MS")]
    timeout_ms: Option<u64>,
    /// The granted tools bring in outside content (mail, web, shared files):
    /// after they return, every holder in the chain is tainted
    #[arg(long)]
    taints: bool,
    /// The granted tools act on the world: refused while any holder in the
    /// chain is tainted, so injected instructions can't drive them
    #[arg(long)]
    clean_only: bool,
    /// Give the sandbox flags above only to this tool (repeatable); by
    /// default every granted tool gets them. A tool without directories or
    /// network stays replayable (`audit replay`)
    #[arg(long = "sandbox-for", value_name = "TOOL")]
    sandbox_for: Vec<String>,
    /// Sandbox grants per tool from a JSON file (tool -> {read, write,
    /// network, taints, clean_only, limits}), e.g. from `audit suggest -o`,
    /// instead of the sandbox flags above
    #[arg(long, value_name = "FILE", conflicts_with_all = ["read", "write", "network", "max_instructions", "max_memory", "timeout_ms", "taints", "clean_only", "sandbox_for"])]
    grants: Option<PathBuf>,
    /// Lifetime in seconds (a derived token never outlives its parent)
    #[arg(long, default_value = "3600")]
    ttl: i64,
    /// Write the chain here instead of stdout
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Subcommand)]
enum CapabilityCommands {
    /// Issue a capability signed by this node's key, for a peer to present
    Grant {
        /// PeerId allowed to use it (see `cleimesh id --client` on its machine)
        peer: String,
        /// Resource (e.g., tool:echo)
        resource: String,
        /// Actions (comma-separated, e.g., execute,read)
        actions: String,
        /// Max calls allowed
        #[arg(long)]
        max_calls: Option<u64>,
        /// Max duration in milliseconds
        #[arg(long)]
        max_duration: Option<u64>,
        /// Expiration in seconds from now
        #[arg(long)]
        ttl: Option<u64>,
        /// Rate limit: calls per window
        #[arg(long)]
        rate_limit: Option<u64>,
        /// Rate limit window in milliseconds
        #[arg(long)]
        rate_window: Option<u64>,
        /// Node key file that signs it (default: ~/.config/cleimesh/identity.key)
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Write the capability JSON here instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() {
    // Like any Unix tool, end quietly when the reader of our output goes
    // away (`cleimesh audit tail | head`); Rust ignores SIGPIPE by default,
    // which turns that into a panic on the next print.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    if let Err(e) = run(Cli::parse()).await {
        // Errors raised by the CLI itself are anyhow messages wrapped as
        // Internal; print them as written, with their causes.
        match e {
            cleimesh_core::CleiMeshError::Internal(inner) => eprintln!("Error: {:#}", inner),
            other => eprintln!("Error: {}", other),
        }
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {

    // Initialize observability only for commands that need it
    let needs_observability = matches!(cli.command, 
        Commands::Start { .. } | 
        Commands::Invoke { .. } | 
        Commands::Run { .. }
    );

    let _obs_handle = if needs_observability {
        let obs_config = ObservabilityConfig {
            enable_metrics: false,
            enable_health: false,
            ..Default::default()
        };
        Some(cleimesh_observability::init_observability(obs_config).await?)
    } else {
        None
    };

    match cli.command {
        Commands::Run { tool, args, timeout, allow_read, allow_write } => {
            run_tool_local(tool, args, timeout, allow_read, allow_write).await?;
        }
        Commands::Start { listen, bootstrap, mdns, identity, receipts } => {
            start_node(listen, bootstrap, mdns, identity, receipts).await?;
        }
        Commands::Invoke { peer, tool, args, timeout, bootstrap, stream, identity, capability, token, titular, finalidade } => {
            let context = (titular.is_some() || finalidade.is_some()).then_some(cleimesh_p2p::CallContext { data_subject: titular, purpose: finalidade });
            invoke_remote(peer, tool, args, timeout, bootstrap, stream, identity, capability, token, context).await?;
        }
        Commands::Id { client, identity } => {
            show_id(client, identity)?;
        }
        Commands::Capability(cmd) => {
            match cmd {
                CapabilityCommands::Grant { peer, resource, actions, max_calls, max_duration, ttl, rate_limit, rate_window, identity, output } => {
                    capability_grant(peer, resource, actions, max_calls, max_duration, ttl, rate_limit, rate_window, identity, output).await?;
                }
            }
        }
        Commands::Mcp(McpCommands::Serve { token, holder, node, identity, receipts }) => mcp_serve(token, holder, node, identity, receipts).await?,
        Commands::Mcp(McpCommands::Wrap { token, holder, identity, receipts, command }) => mcp_wrap(token, holder, identity, receipts, command).await?,
        Commands::Taint(cmd) => taint(cmd)?,
        Commands::Audit(cmd) => match cmd {
            AuditCommands::Verify { receipts, identity, head } => audit_verify(receipts, identity, head)?,
            AuditCommands::Head { receipts } => audit_head(receipts)?,
            AuditCommands::Replay { step, args, wasm, receipts, identity } => audit_replay(&step, args, wasm, receipts, identity).await?,
            AuditCommands::Prune { antes, dry_run, receipts, identity } => audit_prune(&antes, dry_run, receipts, identity)?,
            AuditCommands::Tail { lines, receipts, json } => audit_tail(lines, receipts, json)?,
            AuditCommands::Suggest { token, desde, ate, output, formato, lang, receipts, identity, mesmo_com_falhas } => {
                audit_suggest(&token, desde, ate, output, &formato, &lang, receipts, identity, mesmo_com_falhas)?
            }
            AuditCommands::Export { format: _, output, receipts, identity, unverified } => audit_export(output, receipts, identity, unverified)?,
            AuditCommands::Report { titular, agente, desde, ate, formato, lang, receipts, identity, mesmo_com_falhas } => {
                audit_report(titular, agente, desde, ate, &formato, &lang, receipts, identity, mesmo_com_falhas)?
            }
        },
        Commands::Token(cmd) => match cmd {
            TokenCommands::Issue { holder, grant, max_depth, identity } => token_issue(holder, grant, max_depth, identity)?,
            TokenCommands::Derive { chain, holder, grant, max_depth, identity } => token_derive(chain, holder, grant, max_depth, identity)?,
        },
        Commands::Doctor { identity, client_identity, receipts } => doctor::run(
            identity_key_path(identity, node_key::NODE_KEY_FILE)?,
            identity_key_path(client_identity, node_key::CLIENT_KEY_FILE)?,
            receipts_path(receipts)?,
        ).await?,
        Commands::Setup { agent, read, untrusted, write, node_user, port, days, dry_run, yes } => setup::run(
            setup::Options { agent, read, untrusted, write, user: node_user, port, days },
            identity_key_path(None, node_key::CLIENT_KEY_FILE)?,
            dry_run,
            yes,
        )?,
    }

    Ok(())
}

async fn run_tool_local(
    tool: String,
    args: String,
    timeout: u64,
    allow_read: Vec<PathBuf>,
    allow_write: Vec<PathBuf>,
) -> Result<()> {
    let canonical = |dir: &PathBuf| -> Result<String> {
        let dir = dir.canonicalize()
            .map_err(|e| anyhow::anyhow!("cannot allow '{}': {}", dir.display(), e))?;
        Ok(dir.to_string_lossy().into_owned())
    };
    let mut config = SandboxConfig::default();
    config.allowed_paths = allow_read.iter().map(canonical).collect::<Result<_>>()?;
    config.writable_paths = allow_write.iter().map(canonical).collect::<Result<_>>()?;
    config.allow_filesystem_read = !config.allowed_paths.is_empty();
    let sandbox = WasmSandbox::new(config)?;

    // Register builtin tools
    sandbox.register_wasm_module("echo", include_bytes!("../../wasm-tools/builtins.wasm").to_vec())?;
    sandbox.register_wasm_module("file_read", include_bytes!("../../wasm-tools/builtins.wasm").to_vec())?;
    sandbox.register_wasm_module("file_write", include_bytes!("../../wasm-tools/builtins.wasm").to_vec())?;
    sandbox.register_wasm_module("json_transform", include_bytes!("../../wasm-tools/builtins.wasm").to_vec())?;

    let payload = ToolPayload {
        tool_name: tool,
        arguments: serde_json::from_str(&args)?,
        timeout_ms: Some(timeout),
    };

    let result = sandbox.execute_in_sandbox(&payload.tool_name.clone(), payload).await?;

    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

/// The given key file, or `<config dir>/cleimesh/<default_file>`.
fn identity_key_path(given: Option<PathBuf>, default_file: &str) -> Result<PathBuf> {
    given
        .or_else(|| cleimesh_p2p::node_key::default_key_path(default_file))
        .ok_or_else(|| anyhow::anyhow!("Cannot find a config directory; pass --identity <file>").into())
}

/// The given receipt log, or `<data dir>/cleimesh/receipts/receipts.jsonl`.
fn receipts_path(given: Option<PathBuf>) -> Result<PathBuf> {
    given
        .or_else(|| directories::ProjectDirs::from("", "", "cleimesh").map(|dirs| dirs.data_dir().join("receipts").join("receipts.jsonl")))
        .ok_or_else(|| anyhow::anyhow!("Cannot find a data directory; pass --receipts <file>").into())
}

async fn start_node(listen: String, bootstrap: Option<String>, mdns: bool, identity: Option<PathBuf>, receipts: Option<PathBuf>) -> Result<()> {
    let identity_key_path = identity_key_path(identity, cleimesh_p2p::node_key::NODE_KEY_FILE)?;
    let receipts_path = receipts_path(receipts)?;
    let config = P2PConfig {
        listen_addresses: listen.split(',').map(|s| s.trim().to_string()).collect(),
        bootstrap_peers: bootstrap.map(|b| b.split(',').map(|s| s.trim().to_string()).collect()).unwrap_or_default(),
        enable_mdns: mdns,
        enable_kad: true,
        enable_gossipsub: true,
        reconnect_interval_secs: 5,
        max_reconnect_attempts: 10,
        public_tools: Vec::new(),
        identity_key_path: Some(identity_key_path),
        receipts_path: Some(receipts_path.clone()),
    };

    let identity = AgentIdentity {
        peer_id: "cli-node".to_string(),
        public_key: vec![],
        capabilities: vec!["echo".to_string(), "file_read".to_string(), "file_write".to_string(), "json_transform".to_string()],
    };

    let mut node = CleiMeshNode::new(config, identity)?;
    node.start().await?;

    let peer_id = node.local_peer_id();
    println!("Node started. Peer ID: {}", peer_id);
    println!("Receipts: {}", receipts_path.display());

    // Print the full addresses once bound, ready to pass as --bootstrap.
    let handle = node.handle();
    tokio::spawn(async move {
        for _ in 0..50 {
            match handle.listen_addrs().await {
                Ok(addrs) if !addrs.is_empty() => {
                    for addr in addrs {
                        println!("Listening on {}/p2p/{}", addr, peer_id);
                    }
                    return;
                }
                Ok(_) => tokio::time::sleep(Duration::from_millis(100)).await,
                Err(_) => return,
            }
        }
    });

    node.run_event_loop().await?;

    Ok(())
}

fn show_id(client: bool, identity: Option<PathBuf>) -> Result<()> {
    let default_file = if client { cleimesh_p2p::node_key::CLIENT_KEY_FILE } else { cleimesh_p2p::node_key::NODE_KEY_FILE };
    let keypair = cleimesh_p2p::node_key::load_or_generate(&identity_key_path(identity, default_file)?)?;
    println!("{}", keypair.public().to_peer_id());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn invoke_remote(
    peer: String,
    tool: String,
    args: String,
    timeout: u64,
    bootstrap: Option<String>,
    stream: bool,
    identity: Option<PathBuf>,
    capability: Option<PathBuf>,
    token: Option<PathBuf>,
    context: Option<cleimesh_p2p::CallContext>,
) -> Result<()> {
    let capability = capability
        .map(|path| -> Result<cleimesh_p2p::auth::Capability> {
            let json = std::fs::read_to_string(&path)
                .map_err(|e| anyhow::anyhow!("Cannot read capability {}: {}", path.display(), e))?;
            Ok(serde_json::from_str(&json)
                .map_err(|e| anyhow::anyhow!("Invalid capability {}: {}", path.display(), e))?)
        })
        .transpose()?;
    // The client keeps its own key so capabilities granted to its PeerId
    // keep working across invocations.
    let identity_key_path = identity_key_path(identity, cleimesh_p2p::node_key::CLIENT_KEY_FILE)?;
    // Start a temporary node to send the request
    let config = P2PConfig {
        listen_addresses: vec!["/ip4/0.0.0.0/tcp/0".to_string()],
        bootstrap_peers: bootstrap.map(|b| b.split(',').map(|s| s.trim().to_string()).collect()).unwrap_or_default(),
        enable_mdns: true,
        enable_kad: true,
        enable_gossipsub: true,
        reconnect_interval_secs: 5,
        max_reconnect_attempts: 10,
        public_tools: Vec::new(),
        identity_key_path: Some(identity_key_path.clone()),
        receipts_path: None,
    };

    let identity = AgentIdentity {
        peer_id: "cli-invoke".to_string(),
        public_key: vec![],
        capabilities: vec![],
    };

    let mut node = CleiMeshNode::new(config, identity)?;
    node.start().await?;

    println!("Temporary node started. Peer ID: {}", node.local_peer_id());

    // Parse target peer ID
    let target_peer = peer.parse()
        .map_err(|e| anyhow::anyhow!("Invalid peer ID: {}", e))?;

    let payload: serde_json::Value = serde_json::from_str(&args)?;
    // The proof of possession binds this exact call to the target node.
    let presentation = token
        .map(|path| -> Result<aat::Presentation> {
            let chain = read_chain(&path)?;
            let leaf = chain.last().ok_or_else(|| anyhow::anyhow!("Chain {} is empty", path.display()))?;
            let holder_key = node_key::aat_signing_key(&node_key::load_or_generate(&identity_key_path)?)?;
            let pop = aat::pop(&holder_key, leaf, &tool, &payload, Some(&peer), unix_now())
                .map_err(|e| anyhow::anyhow!("Cannot sign the proof of possession: {}", e))?;
            Ok(aat::Presentation { chain, pop })
        })
        .transpose()?;

    if stream {
        // Streaming invocation
        println!("Streaming output from {}...", tool);
        let _sandbox = StreamingSandbox::new(SandboxConfig::default(), StreamConfig::default().buffer_size)?;
        
        // For now, fall back to non-streaming since we need the WASM module bytes
        // In a real implementation, we'd fetch the WASM module from the peer
        eprintln!("Streaming not yet fully implemented for remote invoke - falling back to non-streaming");
    }

    // Send invoke request with timeout
    let request = cleimesh_p2p::ToolRequest {
        tool_name: tool,
        payload,
        request_id: uuid::Uuid::new_v4().to_string(),
        capability: if presentation.is_some() { None } else { capability },
        presentation,
        context,
    };
    let call = node.invoke_request(target_peer, request);
    let result = tokio::time::timeout(Duration::from_millis(timeout), call)
        .await
        .map_err(|_| anyhow::anyhow!("Request timeout"))??;

    println!("{}", serde_json::to_string_pretty(&result)?);

    node.stop().await?;
    Ok(())
}

fn taint(cmd: TaintCommands) -> Result<()> {
    let (receipts, identity) = match &cmd {
        TaintCommands::List { receipts, identity } | TaintCommands::Clear { receipts, identity, .. } => (receipts.clone(), identity.clone()),
    };
    // The node rebuilds its taint state from the log, and records a clearing there.
    let config = P2PConfig {
        listen_addresses: Vec::new(),
        enable_mdns: false,
        identity_key_path: Some(identity_key_path(identity, node_key::NODE_KEY_FILE)?),
        receipts_path: Some(receipts_path(receipts)?),
        ..P2PConfig::default()
    };
    let mut node = CleiMeshNode::new(config, AgentIdentity::new("cli-taint"))?;
    match cmd {
        TaintCommands::List { .. } => {
            if node.tainted_holders().is_empty() {
                println!("No tainted holders.");
            }
            for (holder, step) in node.tainted_holders() {
                println!("{} tainted by receipt {}", holder, step);
            }
        }
        TaintCommands::Clear { holder, motivo, .. } => {
            let holder = match holder.parse() {
                Ok(peer) => node_key::holder_jwk(&peer).map(|j| j.thumbprint_uri()).unwrap_or(holder),
                Err(_) => holder,
            };
            if !node.tainted_holders().contains_key(&holder) {
                return Err(anyhow::anyhow!("{} is not tainted", holder).into());
            }
            node.clear_taint(&holder, &motivo).map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Cleared {}; the clearing is recorded as a receipt. Restart the node for it to take effect.", holder);
        }
    }
    Ok(())
}

/// A client of the node at `addr` (ending in `/p2p/PEER_ID`) under the key
/// at `holder_path`, with its event loop running: how `mcp serve --node`
/// and `doctor` reach a node run as another user.
async fn remote_node(addr: &str, holder_path: &Path) -> Result<(cleimesh_p2p::NodeHandle, cleimesh_p2p::PeerId)> {
    let addr: cleimesh_p2p::Multiaddr = addr.parse().map_err(|e| anyhow::anyhow!("Invalid --node address {}: {}", addr, e))?;
    let peer = match addr.iter().last() {
        Some(cleimesh_p2p::multiaddr::Protocol::P2p(peer)) => peer,
        _ => return Err(anyhow::anyhow!("--node {} must end in /p2p/PEER_ID, as `cleimesh start` prints it", addr).into()),
    };
    let config = P2PConfig {
        listen_addresses: Vec::new(),
        enable_mdns: false,
        identity_key_path: Some(holder_path.to_path_buf()),
        receipts_path: None,
        ..P2PConfig::default()
    };
    let mut client = CleiMeshNode::new(config, AgentIdentity::new("cli-mcp"))?;
    client.start().await?;
    let handle = client.handle();
    tokio::spawn(async move { client.run_event_loop().await });
    handle.add_peer_address(peer, addr)?;
    Ok((handle, peer))
}

/// stdout carries the MCP protocol, so nothing else may print there.
async fn mcp_serve(tokens: Vec<PathBuf>, holder: Option<PathBuf>, node: Option<String>, identity: Option<PathBuf>, receipts: Option<PathBuf>) -> Result<()> {
    use rmcp::ServiceExt;

    let holder_path = identity_key_path(holder, node_key::CLIENT_KEY_FILE)?;
    let backend = match node {
        // The node runs elsewhere, as another OS user: this process never
        // opens its key, its receipt log or its taint state.
        Some(addr) => {
            let (handle, peer) = remote_node(&addr, &holder_path).await?;
            mcp::Backend::Remote { handle, peer }
        }
        None => {
            eprintln!(
                "cleimesh mcp serve: the node key, receipt log and taint state are in this process, under this OS user. \
                 An agent that can run commands as this user can read the key and lift its own restrictions: \
                 run the node as another user and pass --node (docs/separate-user.md)"
            );
            let config = P2PConfig {
                listen_addresses: Vec::new(),
                enable_mdns: false,
                identity_key_path: Some(identity_key_path(identity, node_key::NODE_KEY_FILE)?),
                receipts_path: Some(receipts_path(receipts)?),
                ..P2PConfig::default()
            };
            mcp::Backend::Local(CleiMeshNode::new(config, AgentIdentity::new("cli-mcp"))?)
        }
    };
    let credentials = if tokens.is_empty() {
        eprintln!("cleimesh mcp serve: no --token, every tool call will be refused");
        None
    } else {
        let chains = tokens.iter().map(|p| read_chain(p)).collect::<Result<Vec<_>>>()?;
        let holder_key = node_key::aat_signing_key(&node_key::load_or_generate(&holder_path)?)?;
        Some((chains, holder_key))
    };

    let service = mcp::Gateway::new(backend, credentials)
        .serve(rmcp::transport::stdio())
        .await
        .map_err(|e| anyhow::anyhow!("MCP server failed to start: {}", e))?;
    service.waiting().await.map_err(|e| anyhow::anyhow!("MCP server stopped: {}", e))?;
    Ok(())
}

async fn mcp_wrap(tokens: Vec<PathBuf>, holder: Option<PathBuf>, identity: Option<PathBuf>, receipts: Option<PathBuf>, command: Vec<String>) -> Result<()> {
    use rmcp::ServiceExt;

    eprintln!(
        "cleimesh mcp wrap: {} is not sandboxed; the token limits which of its tools and arguments get through, \
         and every call is recorded. The node key and receipt log are in this process, under this OS user",
        command[0]
    );
    let config = P2PConfig {
        listen_addresses: Vec::new(),
        enable_mdns: false,
        identity_key_path: Some(identity_key_path(identity, node_key::NODE_KEY_FILE)?),
        receipts_path: Some(receipts_path(receipts)?),
        ..P2PConfig::default()
    };
    let node = CleiMeshNode::new(config, AgentIdentity::new("cli-mcp-wrap"))?;
    let credentials = if tokens.is_empty() {
        eprintln!("cleimesh mcp wrap: no --token, no tool of the wrapped server is offered");
        None
    } else {
        let chains = tokens.iter().map(|p| read_chain(p)).collect::<Result<Vec<_>>>()?;
        let holder_key = node_key::aat_signing_key(&node_key::load_or_generate(&identity_key_path(holder, node_key::CLIENT_KEY_FILE)?)?)?;
        Some((chains, holder_key))
    };

    let mut child = tokio::process::Command::new(&command[0]);
    child.args(&command[1..]);
    let transport = rmcp::transport::TokioChildProcess::new(child).map_err(|e| anyhow::anyhow!("cannot start {}: {}", command[0], e))?;
    let server = ().serve(transport).await.map_err(|e| anyhow::anyhow!("{} did not start as an MCP server: {}", command[0], e))?;
    // The command line may carry secrets (API keys); receipts keep its digest.
    let server_sha256 = cleimesh_receipt::sha256_hex(serde_json::to_string(&command).unwrap_or_default().as_bytes());
    let wrapper = mcp::Wrapper::new(node, server, server_sha256, credentials).await.map_err(|e| anyhow::anyhow!(e))?;

    let service = wrapper
        .serve(rmcp::transport::stdio())
        .await
        .map_err(|e| anyhow::anyhow!("MCP server failed to start: {}", e))?;
    service.waiting().await.map_err(|e| anyhow::anyhow!("MCP server stopped: {}", e))?;
    Ok(())
}

fn audit_verify(receipts: Option<PathBuf>, identity: Option<PathBuf>, saved_head: Option<PathBuf>) -> Result<()> {
    use cleimesh_receipt::{check_head, head_path, Head, HeadStatus};
    let path = receipts_path(receipts)?;
    let log = std::fs::read(&path).map_err(|e| anyhow::anyhow!("Cannot read {}: {}", path.display(), e))?;
    let keypair = node_key::load_or_generate(&identity_key_path(identity, node_key::NODE_KEY_FILE)?)?;
    let anchor = node_key::aat_signing_key(&keypair)?.verifying_key();
    let report = cleimesh_receipt::verify_log(&log, &anchor);
    if !report.ok() {
        for failure in &report.failures {
            println!("line {}: {}", failure.line, failure.reason);
        }
        return Err(anyhow::anyhow!("{} of {} receipts failed verification in {}", report.failures.len(), report.lines, path.display()).into());
    }
    // The chain can't see lines cut from the end; the signed heads can.
    let mut notes = Vec::new();
    let mut heads = Vec::new();
    if let Some(file) = saved_head {
        heads.push(("saved head", file));
    }
    let local = head_path(&path);
    if local.exists() {
        heads.push(("head", local));
    }
    for (label, file) in heads {
        let head = Head::read(&file).map_err(|e| anyhow::anyhow!("{}", e))?;
        head.verify(&anchor).map_err(|e| anyhow::anyhow!("{}: {}", file.display(), e))?;
        match check_head(&log, &head).map_err(|e| anyhow::anyhow!("{} ({})", e, file.display()))? {
            HeadStatus::Matches => notes.push(format!("{} {} matches", label, file.display())),
            HeadStatus::Behind(n) => notes.push(format!("{} {} covers all but the last {} line(s)", label, file.display(), n)),
        }
    }
    if notes.is_empty() {
        notes.push("no signed head found: lines cut from the end would go unnoticed".into());
    }
    println!("OK: {} receipts in {}, signed by {}", report.lines, path.display(), keypair.public().to_peer_id());
    for note in notes {
        println!("  {}", note);
    }
    Ok(())
}

async fn audit_replay(step: &str, args: PathBuf, wasm: Option<PathBuf>, receipts: Option<PathBuf>, identity: Option<PathBuf>) -> Result<()> {
    use cleimesh_p2p::replay::{replay, Replay};
    let path = receipts_path(receipts)?;
    let log = std::fs::read(&path).map_err(|e| anyhow::anyhow!("Cannot read {}: {}", path.display(), e))?;
    let args: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&args).map_err(|e| anyhow::anyhow!("Cannot read {}: {}", args.display(), e))?)
        .map_err(|e| anyhow::anyhow!("Arguments are not JSON: {}", e))?;
    let module = match wasm {
        Some(file) => std::fs::read(&file).map_err(|e| anyhow::anyhow!("Cannot read {}: {}", file.display(), e))?,
        None => include_bytes!("../../wasm-tools/builtins.wasm").to_vec(),
    };
    let keypair = node_key::load_or_generate(&identity_key_path(identity, node_key::NODE_KEY_FILE)?)?;
    let anchor = node_key::aat_signing_key(&keypair)?.verifying_key();
    match replay(&log, &anchor, step, &args, &module).await.map_err(|e| anyhow::anyhow!("Cannot replay: {}", e))? {
        Replay::Reproduced { step_id, output_sha256 } => {
            println!("REPRODUCED {}: same outcome and output (sha256 {})", step_id, output_sha256);
            Ok(())
        }
        Replay::Mismatch { step_id, recorded, replayed } => {
            println!("MISMATCH {}", step_id);
            println!("  receipts say: {}", recorded);
            println!("  replay gives: {}", replayed);
            Err(anyhow::anyhow!("the receipts of {} do not match what the call does", step_id).into())
        }
    }
}

fn audit_head(receipts: Option<PathBuf>) -> Result<()> {
    let path = cleimesh_receipt::head_path(&receipts_path(receipts)?);
    let head = std::fs::read_to_string(&path).map_err(|e| anyhow::anyhow!("Cannot read {}: {}", path.display(), e))?;
    println!("{}", head.trim());
    eprintln!("Keep this off this machine; `cleimesh audit verify --head <file>` proves no receipt it covers was removed.");
    Ok(())
}

fn audit_prune(antes: &str, dry_run: bool, receipts: Option<PathBuf>, identity: Option<PathBuf>) -> Result<()> {
    let date = chrono::NaiveDate::parse_from_str(antes, "%Y-%m-%d").map_err(|e| anyhow::anyhow!("Bad date {} (YYYY-MM-DD): {}", antes, e))?;
    let cutoff = date.and_hms_opt(0, 0, 0).expect("midnight").and_utc().timestamp_millis() as u64;
    let path = receipts_path(receipts)?;
    let keypair = node_key::load_or_generate(&identity_key_path(identity, node_key::NODE_KEY_FILE)?)?;
    let key = node_key::aat_signing_key(&keypair)?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    let summary = cleimesh_receipt::prune(&path, &key, &key.verifying_key(), cutoff, now, dry_run).map_err(|e| anyhow::anyhow!("{}", e))?;
    match (dry_run, summary.removed) {
        (true, n) => println!("Would remove {} receipt(s) before {}, keeping {}.", n, antes, summary.kept),
        (false, 0) => println!("Nothing before {}: {} receipt(s) kept.", antes, summary.kept),
        (false, n) => println!("Removed {} receipt(s) before {}; kept {}. The log now opens with a receipt of the removal.", n, antes, summary.kept),
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn audit_report(
    titular: Option<String>,
    agente: Option<String>,
    desde: Option<String>,
    ate: Option<String>,
    formato: &str,
    lang: &str,
    receipts: Option<PathBuf>,
    identity: Option<PathBuf>,
    mesmo_com_falhas: bool,
) -> Result<()> {
    use cleimesh_p2p::report;
    if formato != "md" && formato != "json" {
        return Err(anyhow::anyhow!("--format must be md or json").into());
    }
    let lang = report::Lang::parse(lang).ok_or_else(|| anyhow::anyhow!("--lang must be en or pt"))?;
    let day = day_ms;
    let path = receipts_path(receipts)?;
    let log = std::fs::read(&path).map_err(|e| anyhow::anyhow!("Cannot read {}: {}", path.display(), e))?;
    let keypair = node_key::load_or_generate(&identity_key_path(identity, node_key::NODE_KEY_FILE)?)?;
    let node_key = node_key::aat_signing_key(&keypair)?;
    let subject = titular.as_deref().map(|t| cleimesh_p2p::subject_pseudonym(&node_key, t));
    // An agent named by PeerId is the holder of its token's key.
    let agent = agente.as_deref().map(|a| match a.parse() {
        Ok(peer) => node_key::holder_jwk(&peer).map(|j| j.thumbprint_uri()).unwrap_or_else(|_| a.to_string()),
        Err(_) => a.to_string(),
    });
    let filter = report::Filter {
        data_subject: subject.clone(),
        agent,
        since_ms: desde.as_deref().map(|d| day(d, false)).transpose()?,
        until_ms: ate.as_deref().map(|d| day(d, true)).transpose()?,
    };
    let built = report::build(&log, &node_key.verifying_key(), &filter);
    if !built.verified && !mesmo_com_falhas {
        for f in &built.failures {
            eprintln!("line {}: {}", f.line, f.reason);
        }
        return Err(anyhow::anyhow!("{} fails verification: no report from a log that may have been altered (--even-if-broken to print it anyway, flagged)", path.display()).into());
    }
    if formato == "json" {
        println!("{}", serde_json::to_string_pretty(&built)?);
    } else {
        print!("{}", report::to_markdown(&built, &keypair.public().to_peer_id().to_string(), subject.as_deref(), agente.as_deref(), lang));
    }
    Ok(())
}

/// A day as milliseconds since the epoch: its first instant, or its last if `end`.
fn day_ms(d: &str, end: bool) -> Result<u64> {
    let date = chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").map_err(|e| anyhow::anyhow!("Bad date {} (YYYY-MM-DD): {}", d, e))?;
    let time = if end { date.and_hms_milli_opt(23, 59, 59, 999) } else { date.and_hms_opt(0, 0, 0) }.expect("valid time");
    Ok(time.and_utc().timestamp_millis() as u64)
}

#[allow(clippy::too_many_arguments)]
fn audit_suggest(
    token: &Path,
    desde: Option<String>,
    ate: Option<String>,
    output: Option<PathBuf>,
    formato: &str,
    lang: &str,
    receipts: Option<PathBuf>,
    identity: Option<PathBuf>,
    mesmo_com_falhas: bool,
) -> Result<()> {
    use cleimesh_p2p::report::Lang;
    use cleimesh_p2p::suggest;
    if formato != "md" && formato != "json" {
        return Err(anyhow::anyhow!("--format must be md or json").into());
    }
    let lang = Lang::parse(lang).ok_or_else(|| anyhow::anyhow!("--lang must be en or pt"))?;
    let chain = read_chain(token)?;
    let leaf = chain.last().ok_or_else(|| anyhow::anyhow!("Chain {} is empty", token.display()))?;
    // Read unverified: the receipts, verified below, are what is trusted.
    let claims = aat::inspect(leaf).map_err(|e| anyhow::anyhow!("Cannot read the token: {}", e))?;
    let tools: Vec<String> = claims.tools().map_err(|e| anyhow::anyhow!("Token: {}", e))?.map(|t| t.keys().cloned().collect()).unwrap_or_default();
    let granted = cleimesh_p2p::grants::of(&claims).map_err(|e| anyhow::anyhow!("Token: {}", e))?;
    let holder = claims.cnf.jwk.thumbprint_uri();

    let path = receipts_path(receipts)?;
    let log = std::fs::read(&path).map_err(|e| anyhow::anyhow!("Cannot read {}: {}", path.display(), e))?;
    let node_key = node_key::aat_signing_key(&node_key::load_or_generate(&identity_key_path(identity, node_key::NODE_KEY_FILE)?)?)?;
    let window = suggest::Window {
        since_ms: desde.as_deref().map(|d| day_ms(d, false)).transpose()?,
        until_ms: ate.as_deref().map(|d| day_ms(d, true)).transpose()?,
    };
    let found = suggest::suggest(&log, &node_key.verifying_key(), &node_key, &holder, &tools, &granted, &window);
    if !found.verified && !mesmo_com_falhas {
        for f in &found.failures {
            eprintln!("line {}: {}", f.line, f.reason);
        }
        return Err(anyhow::anyhow!("{} fails verification: no suggestion from a log that may have been altered (--even-if-broken to suggest anyway, flagged)", path.display()).into());
    }
    if let Some(out) = &output {
        std::fs::write(out, serde_json::to_string_pretty(&found.grants())?).map_err(|e| anyhow::anyhow!("Cannot write {}: {}", out.display(), e))?;
    }
    if formato == "json" {
        println!("{}", serde_json::to_string_pretty(&found)?);
        return Ok(());
    }
    print!("{}", suggest::to_text(&found, lang));
    let t = |en, pt| lang.pick(en, pt);
    let kept = found.kept_tools();
    if !found.narrows() {
        println!("\n{}", t("Nothing to narrow: the token is already the minimum the receipts show.", "Nada a reduzir: o token já é o mínimo que os recibos mostram."));
    } else if kept.is_empty() {
        println!(
            "\n{}",
            t(
                "No tool was used in the period: instead of deriving, let the token expire or revoke it.",
                "Nenhuma tool foi usada no período: em vez de derivar, deixe o token expirar ou revogue-o."
            )
        );
    } else {
        let grants_file = output.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| t("<file from -o>", "<arquivo de -o>").into());
        let tools: String = kept.iter().map(|t| format!(" --tool {}", t)).collect();
        let grants = if found.grants().is_empty() { String::new() } else { format!(" --grants {}", grants_file) };
        println!(
            "\n{}",
            t(
                "To issue the smaller token (nothing changes until you run it; the current holder derives):",
                "Para emitir o token menor (nada muda até você rodar; quem deriva é o portador atual):"
            )
        );
        println!(
            "  cleimesh token derive {} {}{}{} -o {}",
            token.display(),
            t("<PeerId of the new holder>", "<PeerId do novo portador>"),
            tools,
            grants,
            t("smaller.json", "menor.json")
        );
        if output.is_none() && !found.grants().is_empty() {
            println!("  {}", t("(run again with -o grants.json to write the suggested grants)", "(rode de novo com -o permissao.json para gravar as permissões sugeridas)"));
        }
    }
    Ok(())
}

fn audit_export(output: Option<PathBuf>, receipts: Option<PathBuf>, identity: Option<PathBuf>, unverified: bool) -> Result<()> {
    let path = receipts_path(receipts)?;
    let log = std::fs::read(&path).map_err(|e| anyhow::anyhow!("Cannot read {}: {}", path.display(), e))?;
    let keypair = node_key::load_or_generate(&identity_key_path(identity, node_key::NODE_KEY_FILE)?)?;
    let anchor = node_key::aat_signing_key(&keypair)?.verifying_key();
    let report = cleimesh_receipt::verify_log(&log, &anchor);
    if !report.ok() && !unverified {
        return Err(anyhow::anyhow!(
            "{} of {} receipts failed verification in {} (see `audit verify`); export anyway with --unverified",
            report.failures.len(),
            report.lines,
            path.display()
        )
        .into());
    }
    let mut out = String::new();
    for line in cleimesh_receipt::read_lines(&path).map_err(|e| anyhow::anyhow!("{}", e))? {
        if let Ok(r) = cleimesh_receipt::Receipt::parse(&line) {
            out.push_str(&serde_json::to_string(&ocsf::event(&r, report.ok()))?);
            out.push('\n');
        }
    }
    match output {
        Some(file) => {
            std::fs::write(&file, out).map_err(|e| anyhow::anyhow!("Cannot write {}: {}", file.display(), e))?;
            eprintln!("{} OCSF {} events written to {}", report.lines, ocsf::OCSF_VERSION, file.display());
        }
        None => print!("{}", out),
    }
    Ok(())
}

fn audit_tail(count: usize, receipts: Option<PathBuf>, json: bool) -> Result<()> {
    let path = receipts_path(receipts)?;
    let lines = cleimesh_receipt::read_lines(&path).map_err(|e| anyhow::anyhow!("{}", e))?;
    for line in &lines[lines.len().saturating_sub(count)..] {
        if json {
            println!("{}", line);
            continue;
        }
        // Display only: `audit verify` is what vouches for a line.
        match cleimesh_receipt::Receipt::parse(line) {
            Ok(r) => println!("{}", describe_receipt(&r)),
            Err(e) => println!("unreadable line: {}", e),
        }
    }
    Ok(())
}

/// One human-readable line: UTC time, what happened, and short ids (the
/// end of a UUIDv7 step id, the start of a PeerId); `--json` has it all.
fn describe_receipt(r: &cleimesh_receipt::Receipt) -> String {
    let p = &r.params;
    let field = |v: &serde_json::Value| v.as_str().unwrap_or("-").to_string();
    let tail = |s: &str| s.get(s.len().saturating_sub(6)..).unwrap_or(s).to_string();
    let head = |s: &str| if s.len() > 14 { format!("{}…", &s[..14]) } else { s.to_string() };
    let when = chrono::DateTime::from_timestamp_millis(r.ts_ms as i64)
        .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| r.ts_ms.to_string());
    let id = tail(&r.step_id);
    if r.action_id == cleimesh_receipt::PRUNE_ACTION_ID {
        return format!("{} [{}] PRUNED   {} receipt(s) before {} removed", when, id, p["removed_lines"], chrono::DateTime::from_timestamp_millis(p["removed_before_ms"].as_i64().unwrap_or(0)).map(|t| t.format("%Y-%m-%d").to_string()).unwrap_or_default());
    }
    if r.action_id == cleimesh_p2p::receipts::TAINT_CLEARED_ACTION_ID {
        let holder = field(&p["holder"]).replace("urn:ietf:params:oauth:jwk-thumbprint:sha-256:", "");
        return format!("{} [{}] CLEARED  {:<14} holder={} {}", when, id, "taint", head(&holder), field(&p["reason"]));
    }
    if r.action_id == "cleimesh.tool_result" {
        let outcome = if r.success { "succeeded" } else { "FAILED" };
        return format!("{} [{}] result   {:<14} {} (decision {})", when, id, field(&p["tool"]), outcome, tail(&field(&p["decision_step"])));
    }
    let caller = head(&field(&p["caller"]));
    match p["decision"].as_str() {
        Some("denied") => format!("{} [{}] DENIED   {:<14} caller={} {}", when, id, field(&p["tool"]), caller, field(&p["denial"])),
        _ => {
            let a = &p["authority"];
            let authority = match a["kind"].as_str() {
                Some("aat") => format!("aat depth={} holder={}", a["depth"], head(&field(&a["holder"]).replace("urn:ietf:params:oauth:jwk-thumbprint:sha-256:", ""))),
                Some(kind) => kind.to_string(),
                None => "-".into(),
            };
            format!("{} [{}] allowed  {:<14} caller={} {}", when, id, field(&p["tool"]), caller, authority)
        }
    }
}

/// A chain file: the tokens, root first.
#[derive(serde::Serialize, serde::Deserialize)]
struct ChainFile {
    chain: Vec<String>,
}

fn read_chain(path: &Path) -> Result<Vec<String>> {
    let json = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("Cannot read chain {}: {}", path.display(), e))?;
    let file: ChainFile = serde_json::from_str(&json).map_err(|e| anyhow::anyhow!("Invalid chain {}: {}", path.display(), e))?;
    Ok(file.chain)
}

fn write_chain(chain: Vec<String>, output: Option<PathBuf>) -> Result<()> {
    let json = serde_json::to_string_pretty(&ChainFile { chain })?;
    match output {
        Some(path) => {
            std::fs::write(&path, json).map_err(|e| anyhow::anyhow!("Cannot write {}: {}", path.display(), e))?;
            eprintln!("Chain written to {}", path.display());
        }
        None => println!("{}", json),
    }
    Ok(())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn holder(peer: &str) -> Result<aat::Jwk> {
    let peer = peer.parse().map_err(|e| anyhow::anyhow!("Invalid peer ID {}: {}", peer, e))?;
    node_key::holder_jwk(&peer)
}

impl TokenGrant {
    fn tools(&self) -> Result<aat::Tools> {
        let mut tools: aat::Tools = match &self.constrained {
            Some(json) => serde_json::from_str(json).map_err(|e| anyhow::anyhow!("Invalid --tools: {}", e))?,
            None => aat::Tools::new(),
        };
        for tool in &self.tools {
            if tools.insert(tool.clone(), Default::default()).is_some() {
                return Err(anyhow::anyhow!("Tool {} given twice", tool).into());
            }
        }
        if tools.is_empty() {
            return Err(anyhow::anyhow!("Grant at least one tool (--tool or --tools)").into());
        }
        Ok(tools)
    }

    /// The sandbox grants for every granted tool, empty if no sandbox flag
    /// was given. Directories are made absolute here, so the token names
    /// exactly what the node will check.
    fn sandbox_grants(&self, tools: &aat::Tools) -> Result<cleimesh_p2p::grants::Grants> {
        if let Some(path) = &self.grants {
            let json = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("Cannot read {}: {}", path.display(), e))?;
            let grants: cleimesh_p2p::grants::Grants = serde_json::from_str(&json).map_err(|e| anyhow::anyhow!("Invalid grants {}: {}", path.display(), e))?;
            if let Some(unknown) = grants.keys().find(|t| !tools.contains_key(*t)) {
                return Err(anyhow::anyhow!("{}: tool {} is not granted by this token (add --tool {})", path.display(), unknown, unknown).into());
            }
            if let Some(dir) = grants.values().flat_map(|g| g.read.iter().chain(&g.write)).find(|d| !Path::new(d).is_absolute()) {
                return Err(anyhow::anyhow!("{}: directory {} must be absolute", path.display(), dir).into());
            }
            return Ok(grants);
        }
        let absolute = |dirs: &[PathBuf]| -> Result<Vec<String>> {
            dirs.iter()
                .map(|d| std::path::absolute(d).map(|p| p.to_string_lossy().into_owned()).map_err(|e| anyhow::anyhow!("Bad directory {}: {}", d.display(), e).into()))
                .collect()
        };
        let grant = cleimesh_p2p::grants::ToolGrant {
            read: absolute(&self.read)?,
            write: absolute(&self.write)?,
            network: self.network,
            max_instructions: self.max_instructions,
            max_memory_bytes: self.max_memory,
            timeout_ms: self.timeout_ms,
            taints: self.taints,
            clean_only: self.clean_only,
        };
        if grant == Default::default() {
            return Ok(Default::default());
        }
        if let Some(unknown) = self.sandbox_for.iter().find(|t| !tools.contains_key(*t)) {
            return Err(anyhow::anyhow!("--sandbox-for {}: that tool is not granted by this token", unknown).into());
        }
        Ok(tools.keys().filter(|t| self.sandbox_for.is_empty() || self.sandbox_for.contains(t)).map(|t| (t.clone(), grant.clone())).collect())
    }
}

fn sandbox_entry(grants: &cleimesh_p2p::grants::Grants) -> Vec<serde_json::Value> {
    if grants.is_empty() { Vec::new() } else { vec![cleimesh_p2p::grants::entry(grants)] }
}

fn token_issue(holder_peer: String, grant: TokenGrant, max_depth: u32, identity: Option<PathBuf>) -> Result<()> {
    let keypair = node_key::load_or_generate(&identity_key_path(identity, node_key::NODE_KEY_FILE)?)?;
    let iss = format!("urn:cleimesh:node:{}", keypair.public().to_peer_id());
    let tools = grant.tools()?;
    let extra = sandbox_entry(&grant.sandbox_grants(&tools)?);
    let root = aat::issue_root_with(&node_key::aat_signing_key(&keypair)?, &iss, &holder(&holder_peer)?, tools, extra, unix_now(), grant.ttl, max_depth)
        .map_err(|e| anyhow::anyhow!("Cannot issue token: {}", e))?;
    write_chain(vec![root], grant.output)
}

fn token_derive(chain: PathBuf, holder_peer: String, grant: TokenGrant, max_depth: Option<u32>, identity: Option<PathBuf>) -> Result<()> {
    let mut tokens = read_chain(&chain)?;
    let parent = tokens.last().ok_or_else(|| anyhow::anyhow!("Chain {} is empty", chain.display()))?;
    let keypair = node_key::load_or_generate(&identity_key_path(identity, node_key::CLIENT_KEY_FILE)?)?;
    let tools = grant.tools()?;
    let grants = grant.sandbox_grants(&tools)?;
    // The node would refuse a wider grant at call time; say so now. Reading
    // our own parent unverified is fine: the node verifies the chain.
    let parent_claims = aat::inspect(parent).map_err(|e| anyhow::anyhow!("Cannot read the parent token: {}", e))?;
    let parent_grants = cleimesh_p2p::grants::of(&parent_claims).map_err(|e| anyhow::anyhow!("Parent token: {}", e))?;
    cleimesh_p2p::grants::check_narrows(&grants, &parent_grants).map_err(|e| anyhow::anyhow!("Cannot derive token: {}", e))?;
    let extra = sandbox_entry(&grants);
    let child = aat::derive_with(parent, &node_key::aat_signing_key(&keypair)?, &holder(&holder_peer)?, tools, extra, unix_now(), grant.ttl, max_depth)
        .map_err(|e| anyhow::anyhow!("Cannot derive token: {}", e))?;
    tokens.push(child);
    write_chain(tokens, grant.output)
}

#[allow(clippy::too_many_arguments)]
async fn capability_grant(
    peer: String,
    resource: String,
    actions: String,
    max_calls: Option<u64>,
    max_duration: Option<u64>,
    ttl: Option<u64>,
    rate_limit: Option<u64>,
    rate_window: Option<u64>,
    identity: Option<PathBuf>,
    output: Option<PathBuf>,
) -> Result<()> {
    use cleimesh_p2p::auth::{Capability, Constraints, RateLimit};
    use std::time::{SystemTime, UNIX_EPOCH};

    let subject = peer.parse()
        .map_err(|e| anyhow::anyhow!("Invalid peer ID {}: {}", peer, e))?;
    let action_list: Vec<String> = actions.split(',').map(|s| s.trim().to_string()).collect();

    let constraints = Constraints {
        max_calls,
        max_duration_ms: max_duration,
        allowed_args: None,
        rate_limit: rate_limit.zip(rate_window).map(|(calls, window)| RateLimit {
            calls_per_window: calls,
            window_ms: window,
        }),
        expiration: ttl.map(|t| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() + t
        }),
    };

    // Signed with the node's own key: only `cleimesh start` with this key
    // honors it.
    let keypair = cleimesh_p2p::node_key::load_or_generate(&identity_key_path(identity, cleimesh_p2p::node_key::NODE_KEY_FILE)?)?;
    let cap = Capability::issue(&keypair, &subject, resource, action_list, constraints)?;
    let json = serde_json::to_string_pretty(&cap)?;

    match output {
        Some(path) => {
            std::fs::write(&path, json)
                .map_err(|e| anyhow::anyhow!("Cannot write {}: {}", path.display(), e))?;
            eprintln!("Capability for {} on {} written to {}", cap.subject, cap.resource, path.display());
        }
        None => println!("{}", json),
    }
    Ok(())
}

