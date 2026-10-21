//! Metrics collection and Prometheus export

use anyhow::Result;
use metrics_exporter_prometheus::PrometheusBuilder;
use std::net::SocketAddr;

/// Handle to metrics recorder for manual metric emission
#[derive(Clone)]
pub struct MetricsHandle {
    service_name: String,
}

impl MetricsHandle {
    /// Record sandbox execution time
    pub fn record_sandbox_execution(&self, tool: &str, duration_ms: u64, success: bool) {
        let labels = [
            ("service", self.service_name.clone()),
            ("tool", tool.to_string()),
            ("success", if success { "true".to_string() } else { "false".to_string() }),
        ];
        metrics::histogram!("sandbox.execution.duration_ms", &labels).record(duration_ms as f64);
        metrics::counter!("sandbox.execution.total", &labels).increment(1);
    }

    /// Record P2P request
    pub fn record_p2p_request(&self, method: &str, peer: &str, duration_ms: u64, success: bool) {
        let labels = [
            ("service", self.service_name.clone()),
            ("method", method.to_string()),
            ("peer", peer.to_string()),
            ("success", if success { "true".to_string() } else { "false".to_string() }),
        ];
        metrics::histogram!("p2p.request.duration_ms", &labels).record(duration_ms as f64);
        metrics::counter!("p2p.request.total", &labels).increment(1);
    }

    /// Record storage operation
    pub fn record_storage_op(&self, op: &str, duration_ms: u64, success: bool) {
        let labels = [
            ("service", self.service_name.clone()),
            ("operation", op.to_string()),
            ("success", if success { "true".to_string() } else { "false".to_string() }),
        ];
        metrics::histogram!("storage.operation.duration_ms", &labels).record(duration_ms as f64);
        metrics::counter!("storage.operation.total", &labels).increment(1);
    }

    /// Record WASM module compilation time
    pub fn record_wasm_compilation(&self, duration_ms: u64, success: bool) {
        let labels = [
            ("service", self.service_name.clone()),
            ("success", if success { "true".to_string() } else { "false".to_string() }),
        ];
        metrics::histogram!("wasm.compilation.duration_ms", &labels).record(duration_ms as f64);
        metrics::counter!("wasm.compilation.total", &labels).increment(1);
    }

    /// Record active connections
    pub fn set_active_connections(&self, count: usize) {
        let labels = [("service", self.service_name.clone())];
        metrics::gauge!("p2p.connections.active", &labels).set(count as f64);
    }

    /// Record memory usage
    pub fn set_memory_usage(&self, bytes: usize) {
        let labels = [("service", self.service_name.clone())];
        metrics::gauge!("process.memory.bytes", &labels).set(bytes as f64);
    }

    /// Record CPU usage
    pub fn set_cpu_usage(&self, percent: f64) {
        let labels = [("service", self.service_name.clone())];
        metrics::gauge!("process.cpu.percent", &labels).set(percent);
    }
}

/// Initialize metrics recorder with Prometheus exporter
pub fn init_metrics(config: &crate::ObservabilityConfig) -> Result<MetricsHandle> {
    let builder = PrometheusBuilder::new()
        .with_http_listener(config.metrics_addr)
        .add_global_label("service", config.service_name.clone());

    builder.install_recorder().map_err(|e| anyhow::anyhow!("Failed to install Prometheus recorder: {}", e))?;

    Ok(MetricsHandle {
        service_name: config.service_name.clone(),
    })
}

/// Spawn Prometheus metrics HTTP server
pub async fn spawn_metrics_server(_addr: SocketAddr) -> Result<tokio::task::JoinHandle<()>> {
    let handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    });
    Ok(handle)
}

/// Pre-defined metric names for consistency
pub mod names {
    pub const SANDBOX_EXECUTION_DURATION_MS: &str = "sandbox.execution.duration_ms";
    pub const SANDBOX_EXECUTION_TOTAL: &str = "sandbox.execution.total";
    pub const P2P_REQUEST_DURATION_MS: &str = "p2p.request.duration_ms";
    pub const P2P_REQUEST_TOTAL: &str = "p2p.request.total";
    pub const STORAGE_OP_DURATION_MS: &str = "storage.operation.duration_ms";
    pub const STORAGE_OP_TOTAL: &str = "storage.operation.total";
    pub const WASM_COMPILATION_DURATION_MS: &str = "wasm.compilation.duration_ms";
    pub const WASM_COMPILATION_TOTAL: &str = "wasm.compilation.total";
    pub const P2P_CONNECTIONS_ACTIVE: &str = "p2p.connections.active";
    pub const PROCESS_MEMORY_BYTES: &str = "process.memory.bytes";
    pub const PROCESS_CPU_PERCENT: &str = "process.cpu.percent";
}