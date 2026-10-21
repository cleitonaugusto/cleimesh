//! Structured logging configuration

use cleimesh_core::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, fmt, Layer};
use std::net::SocketAddr;

/// Initialize structured logging
pub fn init_logging(config: &crate::ObservabilityConfig) -> Result<()> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    let fmt_layer = if config.log_format == "json" {
        fmt::layer()
            .json()
            .with_current_span(true)
            .with_span_list(true)
            .with_target(true)
            .with_thread_ids(true)
            .with_thread_names(true)
            .boxed()
    } else {
        fmt::layer()
            .pretty()
            .with_thread_ids(true)
            .with_thread_names(true)
            .boxed()
    };

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .init();

    Ok(())
}

/// Create a tracing span for sandbox execution
pub fn sandbox_span(tool: &str, request_id: &str) -> tracing::Span {
    tracing::info_span!(
        "sandbox_execution",
        tool = tool,
        request_id = request_id,
        service = "cleimesh"
    )
}

/// Create a tracing span for P2P request
pub fn p2p_request_span(method: &str, peer: &str, request_id: &str) -> tracing::Span {
    tracing::info_span!(
        "p2p_request",
        method = method,
        peer = peer,
        request_id = request_id,
        service = "cleimesh"
    )
}

/// Create a tracing span for storage operation
pub fn storage_span(operation: &str, key: &str) -> tracing::Span {
    tracing::info_span!(
        "storage_operation",
        operation = operation,
        key = key,
        service = "cleimesh"
    )
}

/// Create a tracing span for WASM compilation
pub fn wasm_compilation_span(module: &str) -> tracing::Span {
    tracing::info_span!(
        "wasm_compilation",
        module = module,
        service = "cleimesh"
    )
}

/// Log sandbox execution result
pub fn log_sandbox_result(tool: &str, duration_ms: u64, success: bool, error: Option<&str>) {
    if success {
        tracing::info!(
            tool = tool,
            duration_ms = duration_ms,
            success = true,
            "Sandbox execution completed"
        );
    } else {
        tracing::error!(
            tool = tool,
            duration_ms = duration_ms,
            success = false,
            error = error.unwrap_or("Unknown error"),
            "Sandbox execution failed"
        );
    }
}

/// Log P2P request result
pub fn log_p2p_result(method: &str, peer: &str, duration_ms: u64, success: bool, error: Option<&str>) {
    if success {
        tracing::info!(
            method = method,
            peer = peer,
            duration_ms = duration_ms,
            success = true,
            "P2P request completed"
        );
    } else {
        tracing::error!(
            method = method,
            peer = peer,
            duration_ms = duration_ms,
            success = false,
            error = error.unwrap_or("Unknown error"),
            "P2P request failed"
        );
    }
}

/// Log storage operation result
pub fn log_storage_result(operation: &str, key: &str, duration_ms: u64, success: bool, error: Option<&str>) {
    if success {
        tracing::info!(
            operation = operation,
            key = key,
            duration_ms = duration_ms,
            success = true,
            "Storage operation completed"
        );
    } else {
        tracing::error!(
            operation = operation,
            key = key,
            duration_ms = duration_ms,
            success = false,
            error = error.unwrap_or("Unknown error"),
            "Storage operation failed"
        );
    }
}