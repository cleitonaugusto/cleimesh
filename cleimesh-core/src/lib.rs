use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CleiMeshError {
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("tool execution error: {0}")]
    ToolExecution(String),
    #[error("sandbox error: {0}")]
    Sandbox(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, CleiMeshError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolPayload {
    pub tool_name: String,
    pub arguments: serde_json::Value,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub success: bool,
    pub output: serde_json::Value,
    pub error: Option<String>,
    pub execution_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AgentIdentity {
    pub peer_id: String,
    pub public_key: Vec<u8>,
    pub capabilities: Vec<String>,
}

impl std::fmt::Display for AgentIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.peer_id)
    }
}

impl AgentIdentity {
    pub fn new(peer_id: impl Into<String>) -> Self {
        Self {
            peer_id: peer_id.into(),
            public_key: Vec::new(),
            capabilities: Vec::new(),
        }
    }

    pub fn from_peer_id(peer_id: impl Into<String>) -> Self {
        Self::new(peer_id)
    }

    pub fn from_keypair(public_key: Vec<u8>, peer_id: impl Into<String>) -> Self {
        Self {
            peer_id: peer_id.into(),
            public_key,
            capabilities: Vec::new(),
        }
    }

    pub fn anonymous() -> Self {
        Self::new("anonymous")
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.peer_id.as_bytes()
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub id: String,
    pub content: String,
    pub embedding: Option<Vec<f32>>,
    pub metadata: serde_json::Value,
    pub timestamp: u64,
}

pub trait SecureTool: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn schema(&self) -> serde_json::Value;
    fn execute(&self, payload: ToolPayload) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ToolResult>> + Send + '_>>;
}