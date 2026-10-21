//! P2P Node example: Start a node and invoke remote tools
//!
//! Run with: `cargo run --example p2p_node`

use cleimesh_core::AgentIdentity;
use cleimesh_p2p::{CleiMeshNode, P2PConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure P2P node
    let config = P2PConfig {
        listen_addresses: vec!["/ip4/0.0.0.0/tcp/4001".to_string()],
        bootstrap_peers: vec![], // Add peer addresses to connect to
        enable_mdns: true,
        enable_kad: true,
        enable_gossipsub: true,
        reconnect_interval_secs: 5,
        max_reconnect_attempts: 10,
        public_tools: Vec::new(),
        identity_key_path: None,
        receipts_path: None,
    };
    
    let identity = AgentIdentity {
        peer_id: "my-agent".to_string(),
        public_key: vec![],
        capabilities: vec![
            "echo".to_string(),
            "file_read".to_string(),
            "file_write".to_string(),
            "json_transform".to_string(),
        ],
    };
    
    // Create and start node
    let mut node = CleiMeshNode::new(config, identity)?;
    node.start().await?;
    
    println!("Node started! Peer ID: {}", node.local_peer_id());
    println!("Listening for connections...");
    
    // Example: Invoke tool on another peer (if connected)
    // let target_peer: libp2p::PeerId = "12D3KooW...".parse()?;
    // let payload = ToolPayload {
    //     tool_name: "echo".to_string(),
    //     arguments: serde_json::json!({"message": "Hello from peer!"}),
    //     timeout_ms: Some(5000),
    // };
    // let result = node.invoke_tool(target_peer, "echo", payload).await?;
    // println!("Remote result: {:?}", result);
    
    // Run event loop (blocks until stopped)
    println!("Running event loop... Press Ctrl+C to stop");
    node.run_event_loop().await?;
    
    Ok(())
}