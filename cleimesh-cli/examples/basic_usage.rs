//! Basic usage example: Local tool execution
//!
//! Run with: `cargo run --example basic_usage`

use cleimesh_core::{ToolPayload};
use cleimesh_wasm_sandbox::{WasmSandbox, SandboxConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create sandbox with default config
    let config = SandboxConfig::default();
    let sandbox = WasmSandbox::new(config)?;
    
    // Register built-in tools
    sandbox.register_wasm_module("echo", include_bytes!("../../wasm-tools/builtins.wasm").to_vec())?;
    sandbox.register_wasm_module("file_read", include_bytes!("../../wasm-tools/builtins.wasm").to_vec())?;
    sandbox.register_wasm_module("file_write", include_bytes!("../../wasm-tools/builtins.wasm").to_vec())?;
    sandbox.register_wasm_module("json_transform", include_bytes!("../../wasm-tools/builtins.wasm").to_vec())?;
    
    // Execute echo tool
    let payload = ToolPayload {
        tool_name: "echo".to_string(),
        arguments: serde_json::json!({"message": "Hello, CleiMesh!"}),
        timeout_ms: Some(5000),
    };
    
    let result = sandbox.execute_in_sandbox("echo", payload).await?;
    println!("Echo result: {}", serde_json::to_string_pretty(&result)?);
    
    // Test JSON transform
    let payload = ToolPayload {
        tool_name: "json_transform".to_string(),
        arguments: serde_json::json!({
            "input": {
                "users": [
                    {"name": "Alice", "age": 30},
                    {"name": "Bob", "age": 25}
                ]
            },
            "filter": "users[].name"
        }),
        timeout_ms: Some(5000),
    };
    
    let result = sandbox.execute_in_sandbox("json_transform", payload).await?;
    println!("JSON transform result: {}", serde_json::to_string_pretty(&result)?);
    
    Ok(())
}