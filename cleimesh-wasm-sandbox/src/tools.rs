use std::collections::HashMap;
use std::pin::Pin;
use std::future::Future;

use anyhow::Result;
use cleimesh_core::{ToolPayload, ToolResult, Result as CoreResult, SecureTool, CleiMeshError};
use serde_json::{json, Value};

pub mod builtin {
    use super::*;

    #[derive(Debug, Clone)]
    pub struct EchoTool;

    impl SecureTool for EchoTool {
        fn name(&self) -> &'static str {
            "echo"
        }

        fn description(&self) -> &'static str {
            "Echoes back the input message"
        }

        fn schema(&self) -> Value {
            json!({
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "The message to echo back"
                    }
                },
                "required": ["message"]
            })
        }

        fn execute(&self, payload: ToolPayload) -> Pin<Box<dyn Future<Output = CoreResult<ToolResult>> + Send + '_>> {
            Box::pin(async move {
                let message = payload.arguments.get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                Ok(ToolResult {
                    success: true,
                    output: json!({"message": message}),
                    error: None,
                    execution_time_ms: 0,
                })
            })
        }
    }

    #[derive(Debug, Clone)]
    pub struct FileReadTool;

    impl SecureTool for FileReadTool {
        fn name(&self) -> &'static str {
            "file_read"
        }

        fn description(&self) -> &'static str {
            "Reads a file from the allowed filesystem paths"
        }

        fn schema(&self) -> Value {
            json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the file to read"
                    }
                },
                "required": ["path"]
            })
        }

        fn execute(&self, payload: ToolPayload) -> Pin<Box<dyn Future<Output = CoreResult<ToolResult>> + Send + '_>> {
            Box::pin(async move {
                let path = payload.arguments.get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| CleiMeshError::ToolExecution("missing path argument".into()))?;

                let content = tokio::fs::read_to_string(path).await
                    .map_err(|e| CleiMeshError::ToolExecution(format!("failed to read file: {}", e)))?;

                Ok(ToolResult {
                    success: true,
                    output: json!({"content": content}),
                    error: None,
                    execution_time_ms: 0,
                })
            })
        }
    }

    #[derive(Debug, Clone)]
    pub struct FileWriteTool;

    impl SecureTool for FileWriteTool {
        fn name(&self) -> &'static str {
            "file_write"
        }

        fn description(&self) -> &'static str {
            "Writes content to a file in the allowed filesystem paths"
        }

        fn schema(&self) -> Value {
            json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the file to write"
                    },
                    "content": {
                        "type": "string",
                        "description": "Content to write to the file"
                    }
                },
                "required": ["path", "content"]
            })
        }

        fn execute(&self, payload: ToolPayload) -> Pin<Box<dyn Future<Output = CoreResult<ToolResult>> + Send + '_>> {
            Box::pin(async move {
                let path = payload.arguments.get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| CleiMeshError::ToolExecution("missing path argument".into()))?;
                let content = payload.arguments.get("content")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| CleiMeshError::ToolExecution("missing content argument".into()))?;

                tokio::fs::write(path, content).await
                    .map_err(|e| CleiMeshError::ToolExecution(format!("failed to write file: {}", e)))?;

                Ok(ToolResult {
                    success: true,
                    output: json!({"written": true}),
                    error: None,
                    execution_time_ms: 0,
                })
            })
        }
    }

    #[derive(Debug, Clone)]
    pub struct JsonTransformTool;

    impl SecureTool for JsonTransformTool {
        fn name(&self) -> &'static str {
            "json_transform"
        }

        fn description(&self) -> &'static str {
            "Transforms JSON data using a JQ-like filter"
        }

        fn schema(&self) -> Value {
            json!({
                "type": "object",
                "properties": {
                    "input": {
                        "type": "object",
                        "description": "Input JSON data"
                    },
                    "filter": {
                        "type": "string",
                        "description": "JQ-style filter expression"
                    }
                },
                "required": ["input", "filter"]
            })
        }

        fn execute(&self, payload: ToolPayload) -> Pin<Box<dyn Future<Output = CoreResult<ToolResult>> + Send + '_>> {
            Box::pin(async move {
                let input = payload.arguments.get("input").cloned().unwrap_or(json!({}));
                let filter = payload.arguments.get("filter")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| CleiMeshError::ToolExecution("missing filter argument".into()))?;

                let output = apply_json_filter(&input, filter)
                    .map_err(|e| CleiMeshError::ToolExecution(format!("filter failed: {}", e)))?;

                Ok(ToolResult {
                    success: true,
                    output,
                    error: None,
                    execution_time_ms: 0,
                })
            })
        }
    }

    fn apply_json_filter(input: &Value, filter: &str) -> Result<Value> {
        let mut result = input.clone();
        
        for part in filter.split('.').filter(|s| !s.is_empty()) {
            if let Some(key) = part.strip_suffix("[]") {
                if let Value::Array(arr) = &result {
                    let mut new_arr = Vec::new();
                    for item in arr {
                        if let Value::Object(obj) = item {
                            if let Some(val) = obj.get(key) {
                                new_arr.push(val.clone());
                            }
                        }
                    }
                    result = Value::Array(new_arr);
                }
            } else if let Value::Object(obj) = &result {
                if let Some(val) = obj.get(part) {
                    result = val.clone();
                } else {
                    result = Value::Null;
                }
            }
        }

        Ok(result)
    }
}

#[derive(Debug, Clone)]
pub enum BuiltinTool {
    Echo(builtin::EchoTool),
    FileRead(builtin::FileReadTool),
    FileWrite(builtin::FileWriteTool),
    JsonTransform(builtin::JsonTransformTool),
}

impl BuiltinTool {
    pub fn name(&self) -> &'static str {
        match self {
            BuiltinTool::Echo(_) => "echo",
            BuiltinTool::FileRead(_) => "file_read",
            BuiltinTool::FileWrite(_) => "file_write",
            BuiltinTool::JsonTransform(_) => "json_transform",
        }
    }

    pub fn wasm_bytes(&self) -> &'static [u8] {
        match self {
            BuiltinTool::Echo(_) => include_bytes!("../../wasm-tools/builtins.wasm"),
            BuiltinTool::FileRead(_) => include_bytes!("../../wasm-tools/builtins.wasm"),
            BuiltinTool::FileWrite(_) => include_bytes!("../../wasm-tools/builtins.wasm"),
            BuiltinTool::JsonTransform(_) => include_bytes!("../../wasm-tools/builtins.wasm"),
        }
    }

    pub fn as_secure_tool(&self) -> &dyn SecureTool {
        match self {
            BuiltinTool::Echo(t) => t,
            BuiltinTool::FileRead(t) => t,
            BuiltinTool::FileWrite(t) => t,
            BuiltinTool::JsonTransform(t) => t,
        }
    }
}

pub struct ToolRegistry {
    tools: HashMap<String, BuiltinTool>,
    wasm_modules: HashMap<String, Vec<u8>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
            wasm_modules: HashMap::new(),
        }
    }

    pub fn register(&mut self, tool: BuiltinTool) -> Result<()> {
        let name = tool.name().to_string();
        self.tools.insert(name.clone(), tool);
        Ok(())
    }

    pub fn register_wasm_module(&mut self, name: &str, wasm_bytes: Vec<u8>) -> Result<()> {
        self.wasm_modules.insert(name.to_string(), wasm_bytes);
        Ok(())
    }

    pub fn remove_wasm_module(&mut self, name: &str) -> Option<Vec<u8>> {
        self.wasm_modules.remove(name)
    }

    pub fn get(&self, name: &str) -> Option<&BuiltinTool> {
        self.tools.get(name)
    }

    pub fn get_wasm_module(&self, name: &str) -> Option<&[u8]> {
        self.wasm_modules.get(name).map(|v| v.as_slice())
    }

    pub fn tools(&self) -> Vec<&str> {
        self.tools.keys().map(|s| s.as_str()).collect()
    }

    pub fn get_secure_tool(&self, name: &str) -> Option<&dyn SecureTool> {
        self.tools.get(name).map(|t| t.as_secure_tool())
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        let mut registry = Self::new();
        registry.register(BuiltinTool::Echo(builtin::EchoTool)).ok();
        registry.register(BuiltinTool::FileRead(builtin::FileReadTool)).ok();
        registry.register(BuiltinTool::FileWrite(builtin::FileWriteTool)).ok();
        registry.register(BuiltinTool::JsonTransform(builtin::JsonTransformTool)).ok();
        registry
    }
}

pub fn create_default_registry() -> ToolRegistry {
    ToolRegistry::default()
}