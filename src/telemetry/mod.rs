//! Distributed tracing and telemetry for StateSet Sequencer
//!
//! Provides OpenTelemetry-based distributed tracing with span propagation,
//! context injection, and integration with Jaeger/OTLP collectors.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Distributed Tracing                          │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  HTTP Request → Span → DB Query → Span → Response               │
//! │       ↓              ↓              ↓                           │
//! │  trace_id: abc   trace_id: abc  trace_id: abc                   │
//! │  span_id: 001    span_id: 002   span_id: 003                    │
//! │  parent: none    parent: 001    parent: 002                     │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use opentelemetry::global;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    propagation::TraceContextPropagator,
    trace::{self as sdktrace, RandomIdGenerator, Sampler},
    Resource,
};
use std::time::Duration;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Telemetry configuration
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    /// Service name for tracing
    pub service_name: String,
    /// Service version
    pub service_version: String,
    /// OTLP endpoint (e.g., "http://localhost:4317")
    pub otlp_endpoint: Option<String>,
    /// Sample rate (0.0 to 1.0)
    pub sample_rate: f64,
    /// Enable console logging
    pub enable_console: bool,
    /// Enable JSON logging format
    pub json_format: bool,
    /// Log level filter
    pub log_level: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            service_name: "stateset-sequencer".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            otlp_endpoint: None,
            sample_rate: 1.0,
            enable_console: true,
            json_format: false,
            log_level: "info".to_string(),
        }
    }
}

impl TelemetryConfig {
    pub fn from_env() -> Self {
        Self {
            service_name: std::env::var("OTEL_SERVICE_NAME")
                .unwrap_or_else(|_| "stateset-sequencer".to_string()),
            service_version: std::env::var("OTEL_SERVICE_VERSION")
                .unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string()),
            otlp_endpoint: std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok(),
            sample_rate: std::env::var("OTEL_SAMPLE_RATE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1.0),
            enable_console: std::env::var("LOG_CONSOLE")
                .map(|v| v != "false" && v != "0")
                .unwrap_or(true),
            json_format: std::env::var("LOG_JSON")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
            log_level: std::env::var("LOG_LEVEL")
                .or_else(|_| std::env::var("RUST_LOG"))
                .unwrap_or_else(|_| "info".to_string()),
        }
    }
}

/// Initialize telemetry with the given configuration
pub fn init_telemetry(config: &TelemetryConfig) -> Result<(), Box<dyn std::error::Error>> {
    // Set up trace context propagation
    global::set_text_map_propagator(TraceContextPropagator::new());

    // Build the subscriber
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&config.log_level))
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let subscriber = tracing_subscriber::registry().with(env_filter);

    // Add console layer if enabled
    if config.enable_console {
        if config.json_format {
            let fmt_layer = tracing_subscriber::fmt::layer()
                .json()
                .with_target(true)
                .with_thread_ids(true)
                .with_file(true)
                .with_line_number(true);

            if let Some(endpoint) = &config.otlp_endpoint {
                let tracer_provider = init_tracer_provider(config, endpoint)?;
                let tracer = tracer_provider.tracer("stateset-sequencer");
                let otel_layer = OpenTelemetryLayer::new(tracer);
                subscriber.with(fmt_layer).with(otel_layer).init();
            } else {
                subscriber.with(fmt_layer).init();
            }
        } else {
            let fmt_layer = tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(false)
                .with_file(false)
                .with_line_number(false)
                .compact();

            if let Some(endpoint) = &config.otlp_endpoint {
                let tracer_provider = init_tracer_provider(config, endpoint)?;
                let tracer = tracer_provider.tracer("stateset-sequencer");
                let otel_layer = OpenTelemetryLayer::new(tracer);
                subscriber.with(fmt_layer).with(otel_layer).init();
            } else {
                subscriber.with(fmt_layer).init();
            }
        }
    } else if let Some(endpoint) = &config.otlp_endpoint {
        let tracer_provider = init_tracer_provider(config, endpoint)?;
        let tracer = tracer_provider.tracer("stateset-sequencer");
        let otel_layer = OpenTelemetryLayer::new(tracer);
        subscriber.with(otel_layer).init();
    } else {
        subscriber.init();
    }

    Ok(())
}

fn init_tracer_provider(
    config: &TelemetryConfig,
    endpoint: &str,
) -> Result<sdktrace::TracerProvider, Box<dyn std::error::Error>> {
    let resource = Resource::new(vec![
        KeyValue::new("service.name", config.service_name.clone()),
        KeyValue::new("service.version", config.service_version.clone()),
        KeyValue::new("deployment.environment",
            std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string())),
    ]);

    let sampler = if config.sample_rate >= 1.0 {
        Sampler::AlwaysOn
    } else if config.sample_rate <= 0.0 {
        Sampler::AlwaysOff
    } else {
        Sampler::TraceIdRatioBased(config.sample_rate)
    };

    let tracer_provider = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(endpoint)
                .with_timeout(Duration::from_secs(5)),
        )
        .with_trace_config(
            sdktrace::Config::default()
                .with_sampler(sampler)
                .with_id_generator(RandomIdGenerator::default())
                .with_resource(resource),
        )
        .install_batch(opentelemetry_sdk::runtime::Tokio)?;

    Ok(tracer_provider)
}

/// Shutdown telemetry (flush pending spans)
pub fn shutdown_telemetry() {
    global::shutdown_tracer_provider();
}

/// Span attribute keys for consistent instrumentation
pub mod attributes {
    pub const TENANT_ID: &str = "tenant.id";
    pub const STORE_ID: &str = "store.id";
    pub const EVENT_ID: &str = "event.id";
    pub const EVENT_TYPE: &str = "event.type";
    pub const SEQUENCE_NUMBER: &str = "sequence.number";
    pub const BATCH_SIZE: &str = "batch.size";
    pub const COMMITMENT_ID: &str = "commitment.id";
    pub const AGENT_ID: &str = "agent.id";
    pub const API_KEY_ID: &str = "api_key.id";
    pub const ERROR_TYPE: &str = "error.type";
    pub const ERROR_MESSAGE: &str = "error.message";
    pub const DB_OPERATION: &str = "db.operation";
    pub const DB_TABLE: &str = "db.table";
    pub const CACHE_HIT: &str = "cache.hit";
    pub const GRPC_METHOD: &str = "rpc.method";
    pub const HTTP_METHOD: &str = "http.method";
    pub const HTTP_PATH: &str = "http.path";
    pub const HTTP_STATUS_CODE: &str = "http.status_code";
}

/// Span names for common operations
pub mod spans {
    // API operations
    pub const INGEST_EVENT: &str = "ingest_event";
    pub const INGEST_BATCH: &str = "ingest_batch";
    pub const GET_EVENT: &str = "get_event";
    pub const LIST_EVENTS: &str = "list_events";
    pub const CREATE_COMMITMENT: &str = "create_commitment";
    pub const GET_COMMITMENT: &str = "get_commitment";
    pub const VERIFY_PROOF: &str = "verify_proof";
    pub const GENERATE_PROOF: &str = "generate_proof";

    // VES operations
    pub const VES_RECEIVE_EVENT: &str = "ves.receive_event";
    pub const VES_VERIFY_SIGNATURE: &str = "ves.verify_signature";
    pub const VES_ASSIGN_SEQUENCE: &str = "ves.assign_sequence";
    pub const VES_STORE_EVENT: &str = "ves.store_event";
    pub const VES_BUILD_MERKLE_TREE: &str = "ves.build_merkle_tree";
    pub const VES_ANCHOR_BATCH: &str = "ves.anchor_batch";

    // Database operations
    pub const DB_QUERY: &str = "db.query";
    pub const DB_INSERT: &str = "db.insert";
    pub const DB_UPDATE: &str = "db.update";
    pub const DB_TRANSACTION: &str = "db.transaction";

    // Cache operations
    pub const CACHE_GET: &str = "cache.get";
    pub const CACHE_SET: &str = "cache.set";
    pub const CACHE_DELETE: &str = "cache.delete";

    // Auth operations
    pub const AUTH_VALIDATE_TOKEN: &str = "auth.validate_token";
    pub const AUTH_VERIFY_SIGNATURE: &str = "auth.verify_signature";
    pub const AUTH_CHECK_RATE_LIMIT: &str = "auth.check_rate_limit";

    // Projection operations
    pub const PROJECTION_RUN: &str = "projection.run";
    pub const PROJECTION_APPLY: &str = "projection.apply";
}

/// Extract trace context from HTTP headers for propagation
pub fn extract_context_from_headers(
    headers: &axum::http::HeaderMap,
) -> opentelemetry::Context {
    use opentelemetry::propagation::TextMapPropagator;

    struct HeaderExtractor<'a>(&'a axum::http::HeaderMap);

    impl<'a> opentelemetry::propagation::Extractor for HeaderExtractor<'a> {
        fn get(&self, key: &str) -> Option<&str> {
            self.0.get(key).and_then(|v| v.to_str().ok())
        }

        fn keys(&self) -> Vec<&str> {
            self.0.keys().map(|k| k.as_str()).collect()
        }
    }

    let propagator = TraceContextPropagator::new();
    propagator.extract(&HeaderExtractor(headers))
}

/// Inject trace context into HTTP headers for outgoing requests
pub fn inject_context_into_headers(
    headers: &mut axum::http::HeaderMap,
    ctx: &opentelemetry::Context,
) {
    use opentelemetry::propagation::TextMapPropagator;

    struct HeaderInjector<'a>(&'a mut axum::http::HeaderMap);

    impl<'a> opentelemetry::propagation::Injector for HeaderInjector<'a> {
        fn set(&mut self, key: &str, value: String) {
            if let Ok(header_name) = axum::http::header::HeaderName::try_from(key) {
                if let Ok(header_value) = axum::http::header::HeaderValue::from_str(&value) {
                    self.0.insert(header_name, header_value);
                }
            }
        }
    }

    let propagator = TraceContextPropagator::new();
    propagator.inject_context(ctx, &mut HeaderInjector(headers));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_config_default() {
        let config = TelemetryConfig::default();
        assert_eq!(config.service_name, "stateset-sequencer");
        assert_eq!(config.sample_rate, 1.0);
        assert!(config.enable_console);
        assert!(!config.json_format);
    }
}
