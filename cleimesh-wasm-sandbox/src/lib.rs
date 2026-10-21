use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use cleimesh_core::{Result, ToolPayload, ToolResult, CleiMeshError};
use parking_lot::RwLock;
use wasmtime::*;

pub mod sandbox;
pub mod tools;
pub mod instance;
pub mod streaming;
pub mod wasi_p2;
pub mod hot_reload;
pub mod fs_observe;

pub use sandbox::{WasmSandboxInner, SandboxHandle, InstanceHandle, create_wasi_p1_ctx};
pub use instance::{SandboxInstance, EphemeralSandbox, SandboxData};
pub use tools::{BuiltinTool, ToolRegistry, create_default_registry};
pub use streaming::{StreamingSandbox, StreamHandle, StreamConfig, stream_tool_output};
pub use wasi_p2::{WasmSandboxInnerP2, create_wasi_p2_ctx, WasiP2SandboxData, component, tool};
pub use hot_reload::{HotReloadManager, HotReloadConfig, VersionedModule};
pub use fs_observe::{FsObserved, GrantUse};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasiVersion {
    Preview1,
    Preview2,
}

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub limits: SandboxLimits,
    pub wasi_version: WasiVersion,
    pub allow_network: bool,
    pub allow_filesystem_read: bool,
    pub allow_filesystem_write: bool,
    pub allowed_paths: Vec<String>,
    /// Directories that are always read-write, independent of the flags above.
    pub writable_paths: Vec<String>,
    pub max_memory_bytes: usize,
    pub max_execution_time: Duration,
    /// When set, the guest sees a frozen clock and seeded randomness, so the
    /// same module, input and config give the same output: what lets an
    /// auditor replay a call from its receipt (C4).
    pub determinism: Option<Determinism>,
}

/// The values a deterministic run fixes; receipts record them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Determinism {
    /// What wall and monotonic clocks report, in nanoseconds since the epoch.
    pub clock_ns: u64,
    /// Seeds every random source the guest can read.
    pub seed: [u8; 32],
}

/// The wasmtime version runs depend on, for receipts.
pub const ENGINE: &str = concat!("wasmtime ", env!("WASMTIME_VERSION"));

#[derive(Debug, Clone)]
pub struct SandboxLimits {
    pub max_memory_pages: u32,
    pub max_table_elements: u32,
    pub max_instructions: u64,
    pub fuel_consumption_per_instruction: u64,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            limits: SandboxLimits::default(),
            wasi_version: WasiVersion::Preview1,
            allow_network: false,
            allow_filesystem_read: false,
            allow_filesystem_write: false,
            allowed_paths: Vec::new(),
            writable_paths: Vec::new(),
            max_memory_bytes: 16 * 1024 * 1024,
            max_execution_time: Duration::from_millis(100),
            determinism: None,
        }
    }
}

impl Default for SandboxLimits {
    fn default() -> Self {
        Self {
            max_memory_pages: 256,
            max_table_elements: 1024,
            max_instructions: 10_000_000,
            fuel_consumption_per_instruction: 1,
        }
    }
}

/// Distinct modules kept compiled; past this the cache starts over.
const MAX_PREPARED: usize = 64;

#[derive(Clone)]
pub struct WasmSandbox {
    inner: Arc<WasmSandboxInner>,
    inner_p2: Option<Arc<wasi_p2::WasmSandboxInnerP2>>,
    config: SandboxConfig,
    tool_registry: Arc<RwLock<ToolRegistry>>,
    /// Modules compiled and linked once, by SHA-256 of their bytes: a call
    /// runs exactly the bytes it hashed, and replacing a tool's bytes (hot
    /// reload) misses the cache instead of running the old code.
    prepared: Arc<RwLock<HashMap<[u8; 32], InstancePre<SandboxData>>>>,
}

impl WasmSandbox {
    pub fn new(config: SandboxConfig) -> Result<Self> {
        let inner = Arc::new(WasmSandboxInner::new(config.clone())?);
        
        // Create Preview2 inner if using Preview2
        let inner_p2 = if config.wasi_version == WasiVersion::Preview2 {
            Some(Arc::new(wasi_p2::WasmSandboxInnerP2::new(config.clone())?))
        } else {
            None
        };
        
        let tool_registry = Arc::new(RwLock::new(ToolRegistry::new()));

        Ok(Self {
            inner,
            inner_p2,
            config,
            tool_registry,
            prepared: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn with_tool_registry(mut self, registry: ToolRegistry) -> Self {
        self.tool_registry = Arc::new(RwLock::new(registry));
        self
    }

    /// The limits and grants every execution runs under.
    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }

    /// Get the tool registry for direct access
    pub fn tool_registry(&self) -> Arc<RwLock<ToolRegistry>> {
        self.tool_registry.clone()
    }

    pub async fn execute_in_sandbox(
        &self,
        tool_name: &str,
        payload: ToolPayload,
    ) -> Result<ToolResult> {
        self.run(tool_name, payload, None).await.0
    }

    /// Runs `tool_name` under `config` instead of the sandbox's own: the
    /// grants and limits of one call (C1). The engine
    /// is shared, so `config.wasi_version` must match the sandbox's.
    /// Preview2 has no per-call grants yet and refuses rather than run
    /// with the wrong ones.
    pub async fn execute_with_config(
        &self,
        tool_name: &str,
        payload: ToolPayload,
        config: &SandboxConfig,
    ) -> Result<ToolResult> {
        self.run(tool_name, payload, Some(config)).await.0
    }

    /// [`Self::execute_with_config`], plus which granted directories the
    /// call touched (C5), whether it succeeded or not. Empty on Preview2.
    pub async fn execute_observed(
        &self,
        tool_name: &str,
        payload: ToolPayload,
        config: &SandboxConfig,
    ) -> (Result<ToolResult>, FsObserved) {
        self.run(tool_name, payload, Some(config)).await
    }

    async fn run(&self, tool_name: &str, payload: ToolPayload, call_config: Option<&SandboxConfig>) -> (Result<ToolResult>, FsObserved) {
        let wasm_bytes = {
            let registry = self.tool_registry.read();
            match registry.get_wasm_module(tool_name) {
                Some(bytes) => bytes.to_vec(),
                None => return (Err(CleiMeshError::ToolExecution(format!("tool not found: {}", tool_name))), FsObserved::default()),
            }
        };

        let config = call_config.unwrap_or(&self.config);
        if config.wasi_version != self.config.wasi_version {
            return (Err(CleiMeshError::ToolExecution("call config uses another WASI version than the sandbox".into())), FsObserved::default());
        }
        match (self.config.wasi_version, call_config) {
            (WasiVersion::Preview1, _) => self.execute_preview1(&wasm_bytes, tool_name, payload, config).await,
            (WasiVersion::Preview2, None) => (self.execute_preview2(&wasm_bytes, tool_name, payload).await, FsObserved::default()),
            (WasiVersion::Preview2, Some(_)) => (Err(CleiMeshError::ToolExecution("per-call grants are not supported on WASI Preview2".into())), FsObserved::default()),
        }
    }


    async fn execute_preview1(
        &self,
        wasm_bytes: &[u8],
        tool_name: &str,
        payload: ToolPayload,
        config: &SandboxConfig,
    ) -> (Result<ToolResult>, FsObserved) {
        let start = Instant::now();

        let mut store = match self.create_store(config) {
            Ok(store) => store,
            Err(e) => return (Err(e), FsObserved::default()),
        };
        let pre = match self.prepare(wasm_bytes) {
            Ok(pre) => pre,
            Err(e) => return (Err(e), store.data().fs.observed().clone()),
        };

        // Start the clock after compiling, so host-side compile time never eats the tool's budget.
        let timeout = payload.timeout_ms.map(Duration::from_millis).unwrap_or(config.max_execution_time);
        store.set_epoch_deadline(sandbox::epoch_deadline_ticks(timeout));

        let run = async {
            let mut instance = SandboxInstance::from_pre(&mut store, &pre)
                .await
                .context("failed to instantiate wasm module")?;
            instance.call_tool(&mut store, tool_name, &payload.arguments).await
        };
        let result = run.await.map_err(|e| match e.downcast_ref::<Trap>() {
            Some(Trap::Interrupt) => anyhow::anyhow!("tool '{}' timed out after {} ms", tool_name, timeout.as_millis()),
            Some(Trap::OutOfFuel) => anyhow::anyhow!("tool '{}' exceeded its instruction budget", tool_name),
            _ => e.context("tool execution failed"),
        });
        let observed = store.data().fs.observed().clone();

        let execution_time_ms = start.elapsed().as_millis() as u64;

        let result = result.map(|output| ToolResult {
            success: true,
            output,
            error: None,
            execution_time_ms,
        });
        (result.map_err(Into::into), observed)
    }

    async fn execute_preview2(
        &self,
        wasm_bytes: &[u8],
        tool_name: &str,
        payload: ToolPayload,
    ) -> Result<ToolResult> {
        let start = Instant::now();
        
        let inner_p2 = self.inner_p2.as_ref()
            .ok_or_else(|| CleiMeshError::ToolExecution("WASI Preview2 not configured".to_string()))?;

        let result = wasi_p2::tool::execute_tool_p2(inner_p2, wasm_bytes, tool_name, &payload.arguments).await
            .context("tool execution failed")?;

        let execution_time_ms = start.elapsed().as_millis() as u64;

        Ok(ToolResult {
            success: true,
            output: result,
            error: None,
            execution_time_ms,
        })
    }

    fn create_store(&self, config: &SandboxConfig) -> Result<Store<SandboxData>> {
        let (wasi_p1_ctx, preopened) = sandbox::create_wasi_p1_ctx_with_preopens(config);
        let mut data = SandboxData::new(config.clone(), wasi_p1_ctx);
        data.fs = fs_observe::FsTracker::new(preopened);

        let mut builder = Store::new(&self.inner.engine, data);
        
        builder.limiter(|data| &mut data.limits);
        
        builder.set_fuel(config.limits.max_instructions)
            .map_err(anyhow::Error::from).context("failed to set fuel")?;
        builder.set_epoch_deadline(crate::sandbox::epoch_deadline_ticks(config.max_execution_time));

        Ok(builder)
    }

    pub fn register_tool(&self, tool: BuiltinTool) -> Result<()> {
        let mut registry = self.tool_registry.write();
        registry.register(tool).map_err(|e| CleiMeshError::ToolExecution(e.to_string()))
    }

    /// The module for `wasm_bytes`, compiled and linked to WASI once.
    fn prepare(&self, wasm_bytes: &[u8]) -> Result<InstancePre<SandboxData>> {
        use sha2::{Digest, Sha256};
        let key: [u8; 32] = Sha256::digest(wasm_bytes).into();
        if let Some(pre) = self.prepared.read().get(&key) {
            return Ok(pre.clone());
        }
        let module = Module::new(&self.inner.engine, wasm_bytes).map_err(anyhow::Error::from).context("failed to compile wasm module")?;
        let pre = self.inner.linker.instantiate_pre(&module).map_err(anyhow::Error::from).context("failed to link wasm module")?;
        let mut prepared = self.prepared.write();
        if prepared.len() >= MAX_PREPARED {
            prepared.clear();
        }
        prepared.insert(key, pre.clone());
        Ok(pre)
    }

    pub fn register_wasm_module(&self, name: &str, wasm_bytes: Vec<u8>) -> Result<()> {
        // Compile now so the first call doesn't pay for it; a module that
        // doesn't compile still registers and fails when called, as before.
        if self.config.wasi_version == WasiVersion::Preview1 {
            if let Err(e) = self.prepare(&wasm_bytes) {
                tracing::debug!("{} not precompiled: {}", name, e);
            }
        }
        let mut registry = self.tool_registry.write();
        registry.register_wasm_module(name, wasm_bytes).map_err(|e| CleiMeshError::ToolExecution(e.to_string()))
    }

    /// Get the inner sandbox for hot reload
    pub fn inner(&self) -> Arc<WasmSandboxInner> {
        self.inner.clone()
    }
}

pub async fn execute_in_sandbox(
    sandbox: &WasmSandbox,
    tool_name: &str,
    payload: ToolPayload,
) -> Result<ToolResult> {
    sandbox.execute_in_sandbox(tool_name, payload).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sandbox_creation() {
        let config = SandboxConfig::default();
        let sandbox = WasmSandbox::new(config).unwrap();
        assert!(sandbox.tool_registry.read().tools().is_empty());
    }
}