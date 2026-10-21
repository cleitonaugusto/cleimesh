use anyhow::{Context, Result};
use serde_json::Value;
use wasmtime::*;
use wasmtime_wasi::p1::{self, WasiP1Ctx};

use crate::SandboxConfig;

pub struct SandboxData {
    pub config: SandboxConfig,
    pub wasi_p1_ctx: WasiP1Ctx,
    pub limits: wasmtime::StoreLimits,
    /// Directories the call touched (C5); empty unless the store was
    /// made by `WasmSandbox` with its observing linker.
    pub fs: crate::fs_observe::FsTracker,
}

impl SandboxData {
    pub fn new(config: SandboxConfig, wasi_p1_ctx: WasiP1Ctx) -> Self {
        let limits = wasmtime::StoreLimitsBuilder::new()
            .memory_size(config.max_memory_bytes)
            .table_elements(config.limits.max_table_elements as usize)
            .instances(10)
            .tables(10)
            .memories(10)
            .build();
        
        Self {
            config,
            wasi_p1_ctx,
            limits,
            fs: Default::default(),
        }
    }
}

pub struct SandboxInstance {
    _instance: Instance,
    memory: Memory,
    alloc: TypedFunc<u32, u32>,
    dealloc: Option<TypedFunc<(u32, u32), ()>>,
    execute: TypedFunc<(u32, u32), u64>,
}

/// Host side of guest ABI v1 (guest side: `wasm-tools/builtins/src/lib.rs`).
impl SandboxInstance {
    pub async fn new(
        store: &mut Store<SandboxData>,
        module: &Module,
        _config: &SandboxConfig,
    ) -> Result<Self> {
        let mut linker = Linker::new(store.engine());
        p1::add_to_linker_async(&mut linker, |data: &mut SandboxData| &mut data.wasi_p1_ctx)
            .map_err(anyhow::Error::from).context("failed to add wasi to linker")?;

        let instance = linker.instantiate_async(&mut *store, module).await
            .map_err(anyhow::Error::from).context("failed to instantiate wasm module")?;
        Self::bind(store, instance).await
    }

    /// From a module compiled and linked ahead of time (see `WasmSandbox`'s
    /// cache): no compiling or linking on the call's path.
    pub async fn from_pre(store: &mut Store<SandboxData>, pre: &InstancePre<SandboxData>) -> Result<Self> {
        let instance = pre.instantiate_async(&mut *store).await
            .map_err(anyhow::Error::from).context("failed to instantiate wasm module")?;
        Self::bind(store, instance).await
    }

    async fn bind(store: &mut Store<SandboxData>, instance: Instance) -> Result<Self> {
        // WASI reactors run their constructors (e.g. preopen discovery) in `_initialize`.
        if let Ok(init) = instance.get_typed_func::<(), ()>(&mut *store, "_initialize") {
            init.call_async(&mut *store, ()).await.map_err(anyhow::Error::from).context("_initialize failed")?;
        }

        let memory = instance.get_memory(&mut *store, "memory")
            .context("module does not export 'memory'")?;
        let alloc = instance.get_typed_func::<u32, u32>(&mut *store, "cleimesh_alloc")
            .map_err(anyhow::Error::from).context("module does not export 'cleimesh_alloc(len) -> ptr' (CleiMesh guest ABI v1)")?;
        let execute = instance.get_typed_func::<(u32, u32), u64>(&mut *store, "cleimesh_execute")
            .map_err(anyhow::Error::from).context("module does not export 'cleimesh_execute(ptr, len) -> u64' (CleiMesh guest ABI v1)")?;
        let dealloc = instance.get_typed_func::<(u32, u32), ()>(&mut *store, "cleimesh_dealloc").ok();

        Ok(Self {
            _instance: instance,
            memory,
            alloc,
            dealloc,
            execute,
        })
    }

    /// Runs the tool and returns its output; a guest-reported error becomes `Err`.
    pub async fn call_tool(
        &mut self,
        store: &mut Store<SandboxData>,
        tool_name: &str,
        arguments: &Value,
    ) -> Result<Value> {
        let input = serde_json::to_vec(&serde_json::json!({
            "tool": tool_name,
            "arguments": arguments,
        }))
        .context("failed to serialize tool input")?;
        let input_len = u32::try_from(input.len()).context("tool input too large")?;

        let in_ptr = self.alloc.call_async(&mut *store, input_len).await
            .map_err(anyhow::Error::from).context("guest allocation failed")?;
        self.memory.write(&mut *store, in_ptr as usize, &input)
            .context("guest returned an invalid input buffer")?;

        let packed = self.execute.call_async(&mut *store, (in_ptr, input_len)).await
            .map_err(anyhow::Error::from).context("tool execution failed")?;
        let (out_ptr, out_len) = ((packed >> 32) as u32, packed as u32);

        let mut output = vec![0u8; out_len as usize];
        self.memory.read(&*store, out_ptr as usize, &mut output)
            .context("guest returned an output buffer outside its memory")?;

        if let Some(dealloc) = &self.dealloc {
            dealloc.call_async(&mut *store, (in_ptr, input_len)).await.ok();
            dealloc.call_async(&mut *store, (out_ptr, out_len)).await.ok();
        }

        let mut envelope: Value = serde_json::from_slice(&output)
            .context("failed to deserialize tool output")?;
        if let Some(message) = envelope.get("error") {
            let message = message.as_str().map(str::to_owned).unwrap_or_else(|| message.to_string());
            return Err(anyhow::anyhow!(message));
        }
        Ok(envelope.get_mut("ok").map(Value::take).unwrap_or(Value::Null))
    }
}

pub fn create_wasi_p1_ctx(config: &SandboxConfig) -> WasiP1Ctx {
    crate::sandbox::create_wasi_p1_ctx(config)
}

pub struct EphemeralSandbox {
    engine: Engine,
    config: SandboxConfig,
    linker: Linker<SandboxData>,
}

impl EphemeralSandbox {
    pub fn new(config: SandboxConfig) -> Result<Self> {
        let mut config_builder = Config::new();
        config_builder
            .async_support(true)
            .consume_fuel(true)
            .epoch_interruption(true)
            .max_wasm_stack(512 * 1024);

        let engine = Engine::new(&config_builder)
            .map_err(anyhow::Error::from).context("failed to create wasmtime engine")?;
        crate::sandbox::spawn_epoch_ticker(&engine);

        let mut linker = Linker::new(&engine);
        p1::add_to_linker_async(&mut linker, |data: &mut SandboxData| &mut data.wasi_p1_ctx)
            .map_err(anyhow::Error::from).context("failed to add wasi to linker")?;

        Ok(Self { engine, config, linker })
    }

    pub async fn execute<F, R>(&self, wasm_bytes: &[u8], f: F) -> Result<R>
    where
        F: FnOnce(&mut Store<SandboxData>, Instance) -> Result<R> + Send + 'static,
        R: Send + 'static,
    {
        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(anyhow::Error::from).context("failed to compile module")?;

        let mut store = self.create_store()?;
        let instance = self.linker.instantiate_async(&mut store, &module).await
            .map_err(anyhow::Error::from).context("failed to instantiate module")?;

        let result = f(&mut store, instance)?;

        let _ = instance;
        let _ = store;

        Ok(result)
    }

    fn create_store(&self) -> Result<Store<SandboxData>> {
        let wasi_p1_ctx = create_wasi_p1_ctx(&self.config);
        
        let mut builder = Store::new(
            &self.engine,
            SandboxData::new(self.config.clone(), wasi_p1_ctx)
        );
        
        let _limits = wasmtime::StoreLimitsBuilder::new()
            .memory_size(self.config.max_memory_bytes)
            .table_elements(self.config.limits.max_table_elements as usize)
            .instances(10)
            .tables(10)
            .memories(10)
            .build();
        builder.limiter(|data| &mut data.limits);
        
        builder.set_fuel(self.config.limits.max_instructions)
            .map_err(anyhow::Error::from).context("failed to set fuel")?;
        builder.set_epoch_deadline(crate::sandbox::epoch_deadline_ticks(self.config.max_execution_time));

        Ok(builder)
    }
}