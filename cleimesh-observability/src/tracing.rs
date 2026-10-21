//! OpenTelemetry distributed tracing support
//!
//! This module provides OpenTelemetry integration for distributed tracing.
//! Currently provides basic initialization; full tracing utilities require
//! compatible OpenTelemetry SDK versions.

use anyhow::Result;
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::trace::{RandomIdGenerator, Sampler, SdkTracerProvider};
use opentelemetry_sdk::Resource;
use std::sync::OnceLock;

/// The installed provider, kept so `shutdown_tracing` can flush it.
static PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();

/// Tracing configuration
#[derive(Debug, Clone)]
pub struct TracingConfig {
    /// Enable OpenTelemetry tracing
    pub enabled: bool,
    /// OTLP endpoint (e.g., "http://localhost:4317")
    pub otlp_endpoint: String,
    /// Service name
    pub service_name: String,
    /// Service version
    pub service_version: String,
    /// Deployment environment
    pub environment: String,
    /// Sample rate (0.0 to 1.0)
    pub sample_rate: f64,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            otlp_endpoint: "http://localhost:4317".to_string(),
            service_name: "cleimesh".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            environment: "development".to_string(),
            sample_rate: 1.0,
        }
    }
}

/// Initialize OpenTelemetry tracing
pub fn init_tracing(config: &TracingConfig) -> Result<()> {
    if !config.enabled {
        return Ok(());
    }

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(config.otlp_endpoint.clone())
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build the OTLP exporter: {}", e))?;

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_sampler(Sampler::TraceIdRatioBased(config.sample_rate))
        .with_id_generator(RandomIdGenerator::default())
        .with_resource(
            Resource::builder()
                .with_service_name(config.service_name.clone())
                .with_attributes([
                    KeyValue::new("service.version", config.service_version.clone()),
                    KeyValue::new("deployment.environment", config.environment.clone()),
                ])
                .build(),
        )
        .build();
    global::set_tracer_provider(provider.clone());
    let _ = PROVIDER.set(provider);

    // Note: Full tracing_subscriber integration requires compatible versions
    // For now, the tracer is installed globally and can be used via opentelemetry::global::tracer()
    
    Ok(())
}

/// Shutdown tracing
pub fn shutdown_tracing() {
    if let Some(provider) = PROVIDER.get() {
        let _ = provider.shutdown();
    }
}