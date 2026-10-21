use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use parking_lot::RwLock;
use wasmtime::*;
use wasmtime_wasi::p1::{self, WasiP1Ctx};

use crate::{SandboxConfig, SandboxData};

/// Granularity of execution timeouts: a background thread bumps each engine's epoch this often.
pub const EPOCH_TICK: Duration = Duration::from_millis(10);

/// Keeps `engine`'s epoch advancing so `set_epoch_deadline` acts as a wall-clock timeout.
/// The thread exits once the engine is dropped.
pub fn spawn_epoch_ticker(engine: &Engine) {
    let weak = engine.weak();
    let _ = std::thread::Builder::new()
        .name("cleimesh-epoch".into())
        .spawn(move || {
            while let Some(engine) = weak.upgrade() {
                engine.increment_epoch();
                drop(engine);
                std::thread::sleep(EPOCH_TICK);
            }
        });
}

/// Number of epoch ticks a store may run before trapping with `Trap::Interrupt`.
pub fn epoch_deadline_ticks(timeout: Duration) -> u64 {
    (timeout.as_millis() / EPOCH_TICK.as_millis()).max(1) as u64
}

pub struct WasmSandboxInner {
    pub engine: Engine,
    pub config: SandboxConfig,
    pub linker: Linker<SandboxData>,
    pub modules: Arc<RwLock<HashMap<String, Module>>>,
}

impl WasmSandboxInner {
    pub fn new(config: SandboxConfig) -> Result<Self> {
        let mut config_builder = Config::new();
        config_builder
            .async_support(true)
            .consume_fuel(true)
            .epoch_interruption(true)
            .max_wasm_stack(512 * 1024)
            .wasm_multi_memory(true)
            .wasm_reference_types(true)
            .wasm_bulk_memory(true)
            .wasm_simd(true);

        let engine = Engine::new(&config_builder)
            .map_err(anyhow::Error::from).context("failed to create wasmtime engine")?;
        crate::sandbox::spawn_epoch_ticker(&engine);

        let mut linker = Linker::new(&engine);
        p1::add_to_linker_async(&mut linker, |data: &mut SandboxData| &mut data.wasi_p1_ctx)
            .map_err(anyhow::Error::from).context("failed to add wasi to linker")?;
        crate::fs_observe::observe_filesystem(&mut linker).context("failed to observe the filesystem")?;

        Ok(Self {
            engine,
            config,
            linker,
            modules: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn compile_module(&self, name: &str, wasm_bytes: &[u8]) -> Result<()> {
        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(anyhow::Error::from).context("failed to compile wasm module")?;
        self.modules.write().insert(name.to_string(), module);
        Ok(())
    }

    pub fn get_module(&self, name: &str) -> Option<Module> {
        self.modules.read().get(name).cloned()
    }

    pub fn remove_module(&self, name: &str) -> Option<Module> {
        self.modules.write().remove(name)
    }

    pub fn create_store(&self) -> Result<Store<SandboxData>> {
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

#[derive(Clone)]
pub struct SandboxHandle {
    inner: Arc<WasmSandboxInner>,
}

impl SandboxHandle {
    pub fn new(inner: Arc<WasmSandboxInner>) -> Self {
        Self { inner }
    }

    pub async fn instantiate(&self, module_name: &str) -> Result<InstanceHandle> {
        let module = self.inner.modules.read().get(module_name).cloned()
            .ok_or_else(|| anyhow::anyhow!("module not found: {}", module_name))?;

        let mut store = self.inner.create_store()?;
        let instance = self.inner.linker.instantiate_async(&mut store, &module).await
            .map_err(anyhow::Error::from).context("failed to instantiate module")?;

        Ok(InstanceHandle { store, instance })
    }
}

pub struct InstanceHandle {
    pub store: Store<SandboxData>,
    pub instance: Instance,
}

impl InstanceHandle {
    pub fn get_export(&mut self, name: &str) -> Option<Extern> {
        self.instance.get_export(&mut self.store, name)
    }

    pub fn get_func(&mut self, name: &str) -> Option<Func> {
        self.get_export(name)?.into_func()
    }

    pub async fn call_func(
        &mut self,
        name: &str,
        args: &[Val],
    ) -> Result<Vec<Val>> {
        let func = self.get_func(name)
            .ok_or_else(|| anyhow::anyhow!("function not found: {}", name))?;

        let mut results = vec![Val::I32(0); func.ty(&self.store).results().len()];
        func.call_async(&mut self.store, args, &mut results).await
            .map_err(anyhow::Error::from).context("function call failed")?;

        Ok(results)
    }

    pub fn store_mut(&mut self) -> &mut Store<SandboxData> {
        &mut self.store
    }

    pub fn store(&self) -> &Store<SandboxData> {
        &self.store
    }
}

/// Directories exposed to the guest, each with its own permissions.
/// `writable_paths` are read-write; `allowed_paths` follow the read/write flags.
pub fn preopens(config: &SandboxConfig) -> Vec<(String, wasmtime_wasi::FsPerms)> {
    use wasmtime_wasi::FsPerms;

    let mut dirs: Vec<_> = config.writable_paths.iter()
        .map(|p| (p.clone(), FsPerms::ReadWrite))
        .collect();

    // Write access implies read; read-only never grants mutation.
    let shared = if config.allow_filesystem_write {
        Some(FsPerms::ReadWrite)
    } else if config.allow_filesystem_read {
        Some(FsPerms::ReadOnly)
    } else {
        None
    };
    if let Some(perms) = shared {
        for path in config.allowed_paths.iter().filter(|p| !config.writable_paths.contains(p)) {
            dirs.push((path.clone(), perms));
        }
    }
    dirs
}

/// A clock that always reads the same instant.
struct FrozenClock(u64);

impl wasmtime_wasi::HostWallClock for FrozenClock {
    fn resolution(&self) -> std::time::Duration {
        std::time::Duration::from_nanos(1)
    }
    fn now(&self) -> std::time::Duration {
        std::time::Duration::from_nanos(self.0)
    }
}

impl wasmtime_wasi::HostMonotonicClock for FrozenClock {
    fn resolution(&self) -> u64 {
        1
    }
    fn now(&self) -> u64 {
        self.0
    }
}

pub fn create_wasi_p1_ctx(config: &SandboxConfig) -> WasiP1Ctx {
    create_wasi_p1_ctx_with_preopens(config).0
}

/// The context and the directories actually preopened, in fd order (a
/// directory that cannot be opened is skipped, and the rest move down).
pub fn create_wasi_p1_ctx_with_preopens(config: &SandboxConfig) -> (WasiP1Ctx, Vec<String>) {
    let mut builder = wasmtime_wasi::WasiCtxBuilder::new();
    if let Some(d) = config.determinism {
        use chacha20::rand_core::SeedableRng;
        // Separate streams for the secure and insecure sources, both from the seed.
        let mut insecure_seed = d.seed;
        insecure_seed[0] ^= 0xff;
        builder
            .wall_clock(FrozenClock(d.clock_ns))
            .monotonic_clock(FrozenClock(d.clock_ns))
            .secure_random(chacha20::ChaCha20Rng::from_seed(d.seed))
            .insecure_random(chacha20::ChaCha20Rng::from_seed(insecure_seed))
            .insecure_random_seed(u128::from_le_bytes(d.seed[..16].try_into().expect("16 bytes")));
    }
    let mut opened = Vec::new();
    for (path, perms) in preopens(config) {
        match builder.preopened_dir(&path, &path, perms) {
            Ok(_) => opened.push(path),
            Err(e) => tracing::warn!("cannot expose '{}' to the sandbox: {}", path, e),
        }
    }
    (builder.build_p1(), opened)
}
