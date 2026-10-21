//! Hot reload support for WASM modules
//!
//! Provides file watching and atomic module swapping for zero-downtime upgrades.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use notify::{Event, EventKind, RecommendedWatcher, Watcher};
use parking_lot::RwLock;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};
use wasmtime::Module;

use crate::{SandboxConfig, ToolRegistry, WasmSandboxInner};

/// Configuration for hot reload
#[derive(Debug, Clone)]
pub struct HotReloadConfig {
    /// Directory to watch for WASM modules
    pub watch_dir: PathBuf,
    /// Debounce duration to avoid multiple rapid reloads
    pub debounce_ms: u64,
    /// Whether to watch recursively
    pub recursive: bool,
    /// File extensions to watch
    pub extensions: Vec<String>,
}

impl Default for HotReloadConfig {
    fn default() -> Self {
        Self {
            watch_dir: PathBuf::from("./wasm-modules"),
            debounce_ms: 500,
            recursive: true,
            extensions: vec!["wasm".to_string()],
        }
    }
}

/// Versioned WASM module
#[derive(Debug, Clone)]
pub struct VersionedModule {
    pub name: String,
    pub version: u64,
    pub wasm_bytes: Vec<u8>,
    pub loaded_at: std::time::SystemTime,
}

/// Hot reload manager
pub struct HotReloadManager {
    config: HotReloadConfig,
    sandbox_inner: Arc<WasmSandboxInner>,
    tool_registry: Arc<RwLock<ToolRegistry>>,
    modules: Arc<RwLock<HashMap<String, VersionedModule>>>,
    watcher: Option<RecommendedWatcher>,
    shutdown_tx: broadcast::Sender<()>,
    reload_tx: broadcast::Sender<String>,
}

impl HotReloadManager {
    /// Create a new hot reload manager
    pub fn new(
        config: HotReloadConfig,
        sandbox_inner: Arc<WasmSandboxInner>,
        tool_registry: Arc<RwLock<ToolRegistry>>,
    ) -> Result<Self> {
        let (shutdown_tx, _) = broadcast::channel(1);
        let (reload_tx, _) = broadcast::channel(16);

        Ok(Self {
            config,
            sandbox_inner,
            tool_registry,
            modules: Arc::new(RwLock::new(HashMap::new())),
            watcher: None,
            shutdown_tx,
            reload_tx,
        })
    }

    /// Start watching for file changes
    pub async fn start(&mut self) -> Result<()> {
        // Initial load
        self.load_modules().await?;

        let (tx, mut rx) = tokio::sync::mpsc::channel(32);
        let watch_dir = self.config.watch_dir.clone();
        let recursive = self.config.recursive;
        let extensions = self.config.extensions.clone();
        let debounce_ms = self.config.debounce_ms;

        // Create file watcher
        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    if Self::should_process_event(&event, &extensions) {
                        let _ = tx.try_send(event);
                    }
                }
            },
            notify::Config::default(),
        )?;

        watcher.watch(&watch_dir, if recursive { notify::RecursiveMode::Recursive } else { notify::RecursiveMode::NonRecursive })?;

        self.watcher = Some(watcher);

        // Spawn event processor
        let modules = self.modules.clone();
        let sandbox_inner = self.sandbox_inner.clone();
        let tool_registry = self.tool_registry.clone();
        let reload_tx = self.reload_tx.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut debounce_timer = tokio::time::interval(Duration::from_millis(debounce_ms));
            debounce_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut pending: Vec<Event> = Vec::new();

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        info!("Hot reload manager shutting down");
                        break;
                    }
                    event = rx.recv() => {
                        if let Some(event) = event {
                            pending.push(event);
                        }
                    }
                    _ = debounce_timer.tick() => {
                        if !pending.is_empty() {
                            let events = std::mem::take(&mut pending);
                            if let Err(e) = Self::process_events(
                                events,
                                &modules,
                                &sandbox_inner,
                                &tool_registry,
                                &reload_tx,
                            ).await {
                                warn!("Hot reload failed: {}", e);
                            }
                        }
                    }
                }
            }
        });

        info!("Hot reload started watching: {:?}", self.config.watch_dir);
        Ok(())
    }

    /// Stop watching
    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(());
    }

    /// Subscribe to reload events
    pub fn subscribe_reloads(&self) -> broadcast::Receiver<String> {
        self.reload_tx.subscribe()
    }

    /// Manually trigger reload for a specific module
    pub async fn reload_module(&self, name: &str) -> Result<()> {
        let path = self.config.watch_dir.join(format!("{}.wasm", name));
        if path.exists() {
            let wasm_bytes = tokio::fs::read(&path).await
                .context("failed to read wasm file")?;
            self.update_module(name, wasm_bytes).await?;
        }
        Ok(())
    }

    /// Load all modules from watch directory
    async fn load_modules(&self) -> Result<()> {
        if !self.config.watch_dir.exists() {
            tokio::fs::create_dir_all(&self.config.watch_dir).await?;
            return Ok(());
        }

        let mut entries = tokio::fs::read_dir(&self.config.watch_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("wasm") {
                if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                    let wasm_bytes = tokio::fs::read(&path).await?;
                    self.update_module(name, wasm_bytes).await?;
                }
            }
        }
        Ok(())
    }

    /// Check if event should trigger reload
    fn should_process_event(event: &Event, extensions: &[String]) -> bool {
        matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_))
            && event.paths.iter().any(|p| {
                p.extension()
                    .and_then(|s| s.to_str())
                    .map(|ext| extensions.iter().any(|e| e == ext))
                    .unwrap_or(false)
            })
    }

    /// Process batched events
    async fn process_events(
        events: Vec<Event>,
        modules: &Arc<RwLock<HashMap<String, VersionedModule>>>,
        sandbox_inner: &Arc<WasmSandboxInner>,
        tool_registry: &Arc<RwLock<ToolRegistry>>,
        reload_tx: &broadcast::Sender<String>,
    ) -> Result<()> {
        for event in events {
            for path in event.paths {
                if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                    match event.kind {
                        EventKind::Create(_) | EventKind::Modify(_) => {
                            if path.exists() {
                                let wasm_bytes = tokio::fs::read(&path).await?;
                                Self::update_module_static(
                                    name,
                                    wasm_bytes,
                                    modules,
                                    sandbox_inner,
                                    tool_registry,
                                ).await?;
                                let _ = reload_tx.send(name.to_string());
                                info!("Hot reloaded module: {}", name);
                            }
                        }
                        EventKind::Remove(_) => {
                            Self::remove_module_static(name, modules, sandbox_inner, tool_registry).await?;
                            let _ = reload_tx.send(format!("{}_removed", name));
                            info!("Removed module: {}", name);
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }

    /// Update a module (instance method)
    async fn update_module(&self, name: &str, wasm_bytes: Vec<u8>) -> Result<()> {
        Self::update_module_static(
            name,
            wasm_bytes,
            &self.modules,
            &self.sandbox_inner,
            &self.tool_registry,
        ).await
    }

    /// Update a module (static method for use in spawned task)
    async fn update_module_static(
        name: &str,
        wasm_bytes: Vec<u8>,
        modules: &Arc<RwLock<HashMap<String, VersionedModule>>>,
        sandbox_inner: &Arc<WasmSandboxInner>,
        tool_registry: &Arc<RwLock<ToolRegistry>>,
    ) -> Result<()> {
        // Compile new module
        let module = sandbox_inner.compile_module(name, &wasm_bytes)?;
        
        // Update registry with new bytes
        {
            let mut registry = tool_registry.write();
            registry.register_wasm_module(name, wasm_bytes.clone())?;
        }

        // Update versioned modules map
        let version = modules.read().get(name).map(|m| m.version + 1).unwrap_or(1);
        let versioned = VersionedModule {
            name: name.to_string(),
            version,
            wasm_bytes,
            loaded_at: std::time::SystemTime::now(),
        };
        
        modules.write().insert(name.to_string(), versioned);

        Ok(())
    }

    /// Remove a module (static method)
    async fn remove_module_static(
        name: &str,
        modules: &Arc<RwLock<HashMap<String, VersionedModule>>>,
        sandbox_inner: &Arc<WasmSandboxInner>,
        tool_registry: &Arc<RwLock<ToolRegistry>>,
    ) -> Result<()> {
        // Remove from sandbox
        sandbox_inner.remove_module(name);
        
        // Remove from registry
        tool_registry.write().remove_wasm_module(name);
        
        // Remove from versioned map
        modules.write().remove(name);

        Ok(())
    }

    /// Get module info
    pub fn get_module_info(&self, name: &str) -> Option<VersionedModule> {
        self.modules.read().get(name).cloned()
    }

    /// List all modules
    pub fn list_modules(&self) -> Vec<VersionedModule> {
        self.modules.read().values().cloned().collect()
    }

    /// Get the watch directory
    pub fn watch_dir(&self) -> &std::path::Path {
        &self.config.watch_dir
    }

    /// Get module count
    pub fn module_count(&self) -> usize {
        self.modules.read().len()
    }
}

/// Extension trait for WasmSandboxInner to add hot reload methods
impl WasmSandboxInner {
    /// Get access to modules for hot reload
    pub fn modules(&self) -> &Arc<RwLock<HashMap<String, Module>>> {
        &self.modules
    }
}