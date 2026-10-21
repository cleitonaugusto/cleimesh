//! CleiMesh Observability - Metrics, Health Checks, Structured Logging, and Distributed Tracing

pub mod metrics;
pub mod health;
pub mod logging;
pub mod tracing;

pub use metrics::*;
pub use health::*;
pub use logging::*;
pub use tracing::*;

use cleimesh_core::Result;
use std::net::SocketAddr;

/// Configuration for observability stack
#[derive(Debug, Clone)]
pub struct ObservabilityConfig {
    /// Enable Prometheus metrics endpoint
    pub enable_metrics: bool,
    /// Address for metrics endpoint (default: 0.0.0.0:9090)
    pub metrics_addr: SocketAddr,
    /// Enable health check endpoint
    pub enable_health: bool,
    /// Address for health endpoint (default: 0.0.0.0:8080)
    pub health_addr: SocketAddr,
    /// Log format: "json" or "pretty"
    pub log_format: String,
    /// Log level (trace, debug, info, warn, error)
    pub log_level: String,
    /// Service name for metrics/labels
    pub service_name: String,
    /// Tracing configuration
    pub tracing: TracingConfig,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            enable_metrics: true,
            metrics_addr: "0.0.0.0:9090".parse().unwrap(),
            enable_health: true,
            health_addr: "0.0.0.0:8080".parse().unwrap(),
            log_format: "json".to_string(),
            log_level: "info".to_string(),
            service_name: "cleimesh".to_string(),
            tracing: TracingConfig::default(),
        }
    }
}

/// Initialize the full observability stack
pub async fn init_observability(config: ObservabilityConfig) -> Result<ObservabilityHandle> {
    // Initialize structured logging
    logging::init_logging(&config)?;

    // Initialize metrics recorder
    let metrics_handle = if config.enable_metrics {
        Some(metrics::init_metrics(&config)?)
    } else {
        None
    };

    // Initialize OpenTelemetry tracing
    tracing::init_tracing(&config.tracing)?;

    // Initialize health check server
    let health_handle = if config.enable_health {
        Some(health::spawn_health_server(config.health_addr).await?)
    } else {
        None
    };

    // Spawn metrics server if enabled
    let metrics_server = if config.enable_metrics {
        Some(metrics::spawn_metrics_server(config.metrics_addr).await?)
    } else {
        None
    };

    Ok(ObservabilityHandle {
        metrics_handle,
        health_handle,
        metrics_server,
    })
}

/// Handle to observability components for graceful shutdown
pub struct ObservabilityHandle {
    metrics_handle: Option<metrics::MetricsHandle>,
    health_handle: Option<health::HealthHandle>,
    metrics_server: Option<tokio::task::JoinHandle<()>>,
}

impl ObservabilityHandle {
    /// Gracefully shutdown all observability components
    pub async fn shutdown(self) {
        if let Some(server) = self.metrics_server {
            server.abort();
        }
        // Health handle drops automatically
    }
}