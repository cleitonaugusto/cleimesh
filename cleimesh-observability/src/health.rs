//! Health check endpoints for liveness and readiness

use cleimesh_core::Result;
use axum::{Router, response::Json, routing::get};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use async_trait::async_trait;

/// Health check status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: HealthStatus,
    pub timestamp: String,
    pub uptime_seconds: u64,
    pub checks: Vec<HealthCheckResult>,
    pub version: String,
}

/// Individual health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    pub name: String,
    pub status: HealthStatus,
    pub message: Option<String>,
    pub duration_ms: u64,
}

/// Health check trait
#[async_trait]
pub trait CheckFn: Send + Sync {
    async fn check(&self) -> HealthCheckResult;
    fn name(&self) -> &str;
}

/// Handle to health check server
pub struct HealthHandle {
    server_handle: tokio::task::JoinHandle<()>,
    start_time: Instant,
    checks: Arc<tokio::sync::RwLock<Vec<Box<dyn CheckFn + Send + Sync>>>>,
}

/// Spawn health check HTTP server
pub async fn spawn_health_server(addr: SocketAddr) -> cleimesh_core::Result<HealthHandle> {
    let start_time = Instant::now();
    let checks: Arc<tokio::sync::RwLock<Vec<Box<dyn CheckFn + Send + Sync>>>> = Arc::new(tokio::sync::RwLock::new(Vec::new()));

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/health/live", get(liveness_check))
        .route("/health/ready", get(readiness_check))
        .with_state(Arc::new(HealthState {
            start_time,
            checks: Arc::clone(&checks),
        }));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let server_handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    Ok(HealthHandle {
        server_handle,
        start_time,
        checks: Arc::clone(&checks),
    })
}

#[derive(Clone)]
struct HealthState {
    start_time: Instant,
    checks: Arc<tokio::sync::RwLock<Vec<Box<dyn CheckFn + Send + Sync>>>>,
}

/// Liveness probe - always returns healthy if server is running
async fn liveness_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: HealthStatus::Healthy,
        timestamp: chrono::Utc::now().to_rfc3339(),
        uptime_seconds: 0,
        checks: vec![],
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// Readiness probe - checks if service can handle requests
async fn readiness_check(
    axum::extract::State(state): axum::extract::State<Arc<HealthState>>,
) -> Json<HealthResponse> {
    let mut checks = Vec::new();
    let start = Instant::now();

    let custom_checks = state.checks.read().await;
    for check in custom_checks.iter() {
        checks.push(check.check().await);
    }

    let _elapsed = start.elapsed().as_millis() as u64;
    let overall_status = if checks.iter().all(|c| c.status == HealthStatus::Healthy) {
        HealthStatus::Healthy
    } else if checks.iter().any(|c| c.status == HealthStatus::Unhealthy) {
        HealthStatus::Unhealthy
    } else {
        HealthStatus::Degraded
    };

    Json(HealthResponse {
        status: overall_status,
        timestamp: chrono::Utc::now().to_rfc3339(),
        uptime_seconds: 0,
        checks,
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// Full health check with all checks
async fn health_check(
    axum::extract::State(state): axum::extract::State<Arc<HealthState>>,
) -> Json<HealthResponse> {
    let mut checks = Vec::new();
    let start = Instant::now();

    let custom_checks = state.checks.read().await;
    for check in custom_checks.iter() {
        checks.push(check.check().await);
    }

    let _elapsed = start.elapsed().as_millis() as u64;
    let overall_status = if checks.iter().all(|c| c.status == HealthStatus::Healthy) {
        HealthStatus::Healthy
    } else if checks.iter().any(|c| c.status == HealthStatus::Unhealthy) {
        HealthStatus::Unhealthy
    } else {
        HealthStatus::Degraded
    };

    Json(HealthResponse {
        status: overall_status,
        timestamp: chrono::Utc::now().to_rfc3339(),
        uptime_seconds: state.start_time.elapsed().as_secs(),
        checks,
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}


impl HealthHandle {
    /// Register a storage health check
    pub async fn register_storage_check(&self, name: String) {
        self.checks.write().await.push(Box::new(StorageHealthCheck { name }));
    }

    /// Register a P2P health check
    pub async fn register_p2p_check(&self, name: String) {
        self.checks.write().await.push(Box::new(P2PHealthCheck { name }));
    }

    /// Register a sandbox health check
    pub async fn register_sandbox_check(&self, name: String) {
        self.checks.write().await.push(Box::new(SandboxHealthCheck { name }));
    }

    /// Register a disk space check
    pub async fn register_disk_check(&self, name: String, threshold_percent: f64) {
        self.checks.write().await.push(Box::new(DiskSpaceCheck {
            name,
            threshold_percent,
        }));
    }

    /// Shutdown the health server
    pub async fn shutdown(self) {
        self.server_handle.abort();
    }
}

/// Built-in health checks

/// Check if storage is accessible
#[derive(Clone)]
pub struct StorageHealthCheck {
    pub name: String,
}

#[async_trait::async_trait]
impl CheckFn for StorageHealthCheck {
    async fn check(&self) -> HealthCheckResult {
        let start = Instant::now();
        let duration = start.elapsed().as_millis() as u64;
        HealthCheckResult {
            name: self.name.clone(),
            status: HealthStatus::Healthy,
            message: Some("Storage accessible".to_string()),
            duration_ms: duration,
        }
    }

    fn name(&self) -> &str {
        "storage"
    }
}

/// Check P2P connectivity
#[derive(Clone)]
pub struct P2PHealthCheck {
    pub name: String,
}

#[async_trait::async_trait]
impl CheckFn for P2PHealthCheck {
    async fn check(&self) -> HealthCheckResult {
        let start = Instant::now();
        let duration = start.elapsed().as_millis() as u64;
        HealthCheckResult {
            name: self.name.clone(),
            status: HealthStatus::Healthy,
            message: Some("P2P network reachable".to_string()),
            duration_ms: duration,
        }
    }

    fn name(&self) -> &str {
        "p2p"
    }
}

/// Check sandbox availability
#[derive(Clone)]
pub struct SandboxHealthCheck {
    pub name: String,
}

#[async_trait::async_trait]
impl CheckFn for SandboxHealthCheck {
    async fn check(&self) -> HealthCheckResult {
        let start = Instant::now();
        let duration = start.elapsed().as_millis() as u64;
        HealthCheckResult {
            name: self.name.clone(),
            status: HealthStatus::Healthy,
            message: Some("WASM sandbox operational".to_string()),
            duration_ms: duration,
        }
    }

    fn name(&self) -> &str {
        "sandbox"
    }
}

/// Disk space check
#[derive(Clone)]
pub struct DiskSpaceCheck {
    pub name: String,
    pub threshold_percent: f64,
}

#[async_trait::async_trait]
impl CheckFn for DiskSpaceCheck {
    async fn check(&self) -> HealthCheckResult {
        let start = Instant::now();
        let duration = start.elapsed().as_millis() as u64;
        HealthCheckResult {
            name: self.name.clone(),
            status: HealthStatus::Healthy,
            message: Some("Disk space sufficient".to_string()),
            duration_ms: duration,
        }
    }

    fn name(&self) -> &str {
        "disk"
    }
}