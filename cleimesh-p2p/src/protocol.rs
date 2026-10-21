use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentProtocol {
    pub version: String,
    pub agent_id: String,
    pub capabilities: Vec<String>,
    pub metadata: HashMap<String, serde_json::Value>,
}

impl AgentProtocol {
    pub fn new(agent_id: String, capabilities: Vec<String>) -> Self {
        Self {
            version: "1.0.0".to_string(),
            agent_id,
            capabilities,
            metadata: HashMap::new(),
        }
    }

    pub fn with_metadata(mut self, key: String, value: serde_json::Value) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInvocation {
    pub invocation_id: String,
    pub tool_name: String,
    pub arguments: serde_json::Value,
    pub timeout_ms: Option<u64>,
    pub caller_id: String,
    pub target_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResponse {
    pub invocation_id: String,
    pub success: bool,
    pub output: serde_json::Value,
    pub error: Option<String>,
    pub execution_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAnnouncement {
    pub agent: AgentProtocol,
    pub ttl: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskDelegation {
    pub task_id: String,
    pub tool_invocation: ToolInvocation,
    pub required_capabilities: Vec<String>,
    pub priority: u8,
    pub max_hops: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: String,
    pub result: ToolResponse,
    pub executor_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MeshMessage {
    Announcement(AgentAnnouncement),
    Delegation(TaskDelegation),
    Result(TaskResult),
    Heartbeat { agent_id: String, timestamp: u64 },
    CapabilityQuery { requester_id: String, capabilities: Vec<String> },
    CapabilityResponse { responder_id: String, capabilities: Vec<String> },
}

impl MeshMessage {
    pub fn topic(&self) -> String {
        match self {
            MeshMessage::Announcement(_) => "/cleimesh/announcements".to_string(),
            MeshMessage::Delegation(_) => "/cleimesh/delegations".to_string(),
            MeshMessage::Result(_) => "/cleimesh/results".to_string(),
            MeshMessage::Heartbeat { .. } => "/cleimesh/heartbeats".to_string(),
            MeshMessage::CapabilityQuery { .. } => "/cleimesh/capability-query".to_string(),
            MeshMessage::CapabilityResponse { .. } => "/cleimesh/capability-response".to_string(),
        }
    }
}