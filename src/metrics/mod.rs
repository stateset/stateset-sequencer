//! Metrics and observability for StateSet Sequencer
//!
//! Provides metrics collection, health checks, and debugging endpoints.
//!
//! # Metrics Categories
//!
//! - **Counters**: Monotonically increasing values (events ingested, errors)
//! - **Gauges**: Point-in-time values (active connections, queue depth)
//! - **Histograms**: Distribution of values (latencies, sizes)
//! - **Labels**: Dimensional metrics for tenant/store breakdowns

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// Label set for dimensional metrics
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Labels(Vec<(String, String)>);

impl Labels {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn with(mut self, key: &str, value: &str) -> Self {
        self.0.push((key.to_string(), value.to_string()));
        self
    }

    pub fn tenant(self, tenant_id: &str) -> Self {
        self.with("tenant_id", tenant_id)
    }

    pub fn store(self, store_id: &str) -> Self {
        self.with("store_id", store_id)
    }

    pub fn method(self, method: &str) -> Self {
        self.with("method", method)
    }

    pub fn status(self, status: &str) -> Self {
        self.with("status", status)
    }

    pub fn error_type(self, error_type: &str) -> Self {
        self.with("error_type", error_type)
    }

    pub fn cache_name(self, name: &str) -> Self {
        self.with("cache", name)
    }

    pub fn circuit(self, name: &str) -> Self {
        self.with("circuit", name)
    }

    fn to_suffix(&self) -> String {
        if self.0.is_empty() {
            return String::new();
        }
        let parts: Vec<String> = self.0.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
        format!("{{{}}}", parts.join(","))
    }

    fn to_prometheus_labels(&self) -> String {
        if self.0.is_empty() {
            return String::new();
        }
        let parts: Vec<String> = self
            .0
            .iter()
            .map(|(k, v)| format!("{}=\"{}\"", k, v))
            .collect();
        format!("{{{}}}", parts.join(","))
    }
}

impl Default for Labels {
    fn default() -> Self {
        Self::new()
    }
}

/// Global metrics registry
pub struct MetricsRegistry {
    /// Counter metrics
    counters: RwLock<HashMap<String, Arc<AtomicU64>>>,

    /// Labeled counter metrics
    labeled_counters: RwLock<HashMap<String, HashMap<Labels, Arc<AtomicU64>>>>,

    /// Gauge metrics (current values)
    gauges: RwLock<HashMap<String, Arc<AtomicU64>>>,

    /// Labeled gauge metrics
    labeled_gauges: RwLock<HashMap<String, HashMap<Labels, Arc<AtomicU64>>>>,

    /// Histogram metrics (bucketed)
    histograms: RwLock<HashMap<String, Arc<Histogram>>>,

    /// Labeled histogram metrics
    labeled_histograms: RwLock<HashMap<String, HashMap<Labels, Arc<Histogram>>>>,

    /// Service start time
    start_time: Instant,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self {
            counters: RwLock::new(HashMap::new()),
            labeled_counters: RwLock::new(HashMap::new()),
            gauges: RwLock::new(HashMap::new()),
            labeled_gauges: RwLock::new(HashMap::new()),
            histograms: RwLock::new(HashMap::new()),
            labeled_histograms: RwLock::new(HashMap::new()),
            start_time: Instant::now(),
        }
    }

    /// Increment a counter
    pub async fn inc_counter(&self, name: &str) {
        self.add_counter(name, 1).await;
    }

    /// Add to a counter
    pub async fn add_counter(&self, name: &str, value: u64) {
        let counters = self.counters.read().await;
        if let Some(counter) = counters.get(name) {
            counter.fetch_add(value, Ordering::Relaxed);
            return;
        }
        drop(counters);

        // Create new counter
        let mut counters = self.counters.write().await;
        let counter = counters
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(AtomicU64::new(0)));
        counter.fetch_add(value, Ordering::Relaxed);
    }

    /// Set a gauge value
    pub async fn set_gauge(&self, name: &str, value: u64) {
        let gauges = self.gauges.read().await;
        if let Some(gauge) = gauges.get(name) {
            gauge.store(value, Ordering::Relaxed);
            return;
        }
        drop(gauges);

        // Create new gauge
        let mut gauges = self.gauges.write().await;
        gauges.insert(name.to_string(), Arc::new(AtomicU64::new(value)));
    }

    /// Get a counter value
    pub async fn get_counter(&self, name: &str) -> u64 {
        let counters = self.counters.read().await;
        counters
            .get(name)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Get a gauge value
    pub async fn get_gauge(&self, name: &str) -> u64 {
        let gauges = self.gauges.read().await;
        gauges
            .get(name)
            .map(|g| g.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Record a histogram observation
    pub async fn observe_histogram(&self, name: &str, value: f64) {
        let histograms = self.histograms.read().await;
        if let Some(histogram) = histograms.get(name) {
            histogram.observe(value).await;
            return;
        }
        drop(histograms);

        // Create new histogram with default buckets
        let mut histograms = self.histograms.write().await;
        let histogram = histograms
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(Histogram::default()));
        histogram.observe(value).await;
    }

    // =========================================================================
    // Labeled metrics methods
    // =========================================================================

    /// Increment a labeled counter
    pub async fn inc_counter_labeled(&self, name: &str, labels: Labels) {
        self.add_counter_labeled(name, labels, 1).await;
    }

    /// Add to a labeled counter
    pub async fn add_counter_labeled(&self, name: &str, labels: Labels, value: u64) {
        let counters = self.labeled_counters.read().await;
        if let Some(label_map) = counters.get(name) {
            if let Some(counter) = label_map.get(&labels) {
                counter.fetch_add(value, Ordering::Relaxed);
                return;
            }
        }
        drop(counters);

        // Create new counter
        let mut counters = self.labeled_counters.write().await;
        let label_map = counters.entry(name.to_string()).or_default();
        let counter = label_map
            .entry(labels)
            .or_insert_with(|| Arc::new(AtomicU64::new(0)));
        counter.fetch_add(value, Ordering::Relaxed);
    }

    /// Set a labeled gauge value
    pub async fn set_gauge_labeled(&self, name: &str, labels: Labels, value: u64) {
        let gauges = self.labeled_gauges.read().await;
        if let Some(label_map) = gauges.get(name) {
            if let Some(gauge) = label_map.get(&labels) {
                gauge.store(value, Ordering::Relaxed);
                return;
            }
        }
        drop(gauges);

        // Create new gauge
        let mut gauges = self.labeled_gauges.write().await;
        let label_map = gauges.entry(name.to_string()).or_default();
        label_map.insert(labels, Arc::new(AtomicU64::new(value)));
    }

    /// Record a labeled histogram observation
    pub async fn observe_histogram_labeled(&self, name: &str, labels: Labels, value: f64) {
        let histograms = self.labeled_histograms.read().await;
        if let Some(label_map) = histograms.get(name) {
            if let Some(histogram) = label_map.get(&labels) {
                histogram.observe(value).await;
                return;
            }
        }
        drop(histograms);

        // Create new histogram with default buckets
        let mut histograms = self.labeled_histograms.write().await;
        let label_map = histograms.entry(name.to_string()).or_default();
        let histogram = label_map
            .entry(labels)
            .or_insert_with(|| Arc::new(Histogram::default()));
        histogram.observe(value).await;
    }

    /// Get a labeled counter value
    pub async fn get_counter_labeled(&self, name: &str, labels: &Labels) -> u64 {
        let counters = self.labeled_counters.read().await;
        counters
            .get(name)
            .and_then(|m| m.get(labels))
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Get a labeled gauge value
    pub async fn get_gauge_labeled(&self, name: &str, labels: &Labels) -> u64 {
        let gauges = self.labeled_gauges.read().await;
        gauges
            .get(name)
            .and_then(|m| m.get(labels))
            .map(|g| g.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Get uptime in seconds
    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Get all metrics as JSON
    pub async fn to_json(&self) -> serde_json::Value {
        let counters = self.counters.read().await;
        let gauges = self.gauges.read().await;
        let histograms = self.histograms.read().await;

        let counter_values: HashMap<String, u64> = counters
            .iter()
            .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
            .collect();

        let gauge_values: HashMap<String, u64> = gauges
            .iter()
            .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
            .collect();

        let mut histogram_values: HashMap<String, serde_json::Value> = HashMap::new();
        for (name, histogram) in histograms.iter() {
            histogram_values.insert(name.clone(), histogram.to_json().await);
        }

        serde_json::json!({
            "uptime_seconds": self.uptime_seconds(),
            "counters": counter_values,
            "gauges": gauge_values,
            "histograms": histogram_values,
        })
    }

    /// Export metrics in Prometheus format
    pub async fn to_prometheus(&self) -> String {
        let counters = self.counters.read().await;
        let labeled_counters = self.labeled_counters.read().await;
        let gauges = self.gauges.read().await;
        let labeled_gauges = self.labeled_gauges.read().await;
        let histograms = self.histograms.read().await;
        let labeled_histograms = self.labeled_histograms.read().await;

        let mut output = String::new();

        // Uptime
        output.push_str("# HELP sequencer_uptime_seconds Time since service start\n");
        output.push_str("# TYPE sequencer_uptime_seconds gauge\n");
        output.push_str(&format!(
            "sequencer_uptime_seconds {}\n\n",
            self.uptime_seconds()
        ));

        // Counters
        for (name, counter) in counters.iter() {
            let prometheus_name = name.replace(['.', '-'], "_");
            output.push_str(&format!("# TYPE {} counter\n", prometheus_name));
            output.push_str(&format!(
                "{} {}\n",
                prometheus_name,
                counter.load(Ordering::Relaxed)
            ));
        }

        // Labeled counters
        for (name, label_map) in labeled_counters.iter() {
            let prometheus_name = name.replace(['.', '-'], "_");
            output.push_str(&format!("# TYPE {} counter\n", prometheus_name));
            for (labels, counter) in label_map.iter() {
                output.push_str(&format!(
                    "{}{} {}\n",
                    prometheus_name,
                    labels.to_prometheus_labels(),
                    counter.load(Ordering::Relaxed)
                ));
            }
        }

        // Gauges
        for (name, gauge) in gauges.iter() {
            let prometheus_name = name.replace(['.', '-'], "_");
            output.push_str(&format!("# TYPE {} gauge\n", prometheus_name));
            output.push_str(&format!(
                "{} {}\n",
                prometheus_name,
                gauge.load(Ordering::Relaxed)
            ));
        }

        // Labeled gauges
        for (name, label_map) in labeled_gauges.iter() {
            let prometheus_name = name.replace(['.', '-'], "_");
            output.push_str(&format!("# TYPE {} gauge\n", prometheus_name));
            for (labels, gauge) in label_map.iter() {
                output.push_str(&format!(
                    "{}{} {}\n",
                    prometheus_name,
                    labels.to_prometheus_labels(),
                    gauge.load(Ordering::Relaxed)
                ));
            }
        }

        // Histograms
        for (name, histogram) in histograms.iter() {
            output.push_str(&histogram.to_prometheus(name).await);
        }

        // Labeled histograms
        for (name, label_map) in labeled_histograms.iter() {
            for (labels, histogram) in label_map.iter() {
                let labeled_name = format!("{}{}", name, labels.to_suffix());
                output.push_str(&histogram.to_prometheus(&labeled_name).await);
            }
        }

        output
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple histogram implementation
pub struct Histogram {
    /// Bucket boundaries
    buckets: Vec<f64>,

    /// Count per bucket
    counts: RwLock<Vec<AtomicU64>>,

    /// Sum of all observations
    sum: AtomicU64,

    /// Total count of observations
    count: AtomicU64,
}

impl Histogram {
    pub fn new(buckets: Vec<f64>) -> Self {
        let counts = buckets.iter().map(|_| AtomicU64::new(0)).collect();
        Self {
            buckets,
            counts: RwLock::new(counts),
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Record an observation
    pub async fn observe(&self, value: f64) {
        // Add to sum (store as bits)
        let bits = (value * 1000.0) as u64; // Store with millisecond precision
        self.sum.fetch_add(bits, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);

        // Increment appropriate bucket
        let counts = self.counts.read().await;
        for (i, bucket) in self.buckets.iter().enumerate() {
            if value <= *bucket {
                counts[i].fetch_add(1, Ordering::Relaxed);
                break;
            }
        }
    }

    /// Get histogram as JSON
    pub async fn to_json(&self) -> serde_json::Value {
        let counts = self.counts.read().await;
        let bucket_counts: Vec<u64> = counts.iter().map(|c| c.load(Ordering::Relaxed)).collect();

        serde_json::json!({
            "buckets": self.buckets,
            "counts": bucket_counts,
            "sum": self.sum.load(Ordering::Relaxed) as f64 / 1000.0,
            "count": self.count.load(Ordering::Relaxed),
        })
    }

    /// Export as Prometheus format
    pub async fn to_prometheus(&self, name: &str) -> String {
        let prometheus_name = name.replace(['.', '-'], "_");
        let mut output = String::new();

        output.push_str(&format!("# TYPE {} histogram\n", prometheus_name));

        let counts = self.counts.read().await;
        let mut cumulative = 0u64;

        for (i, bucket) in self.buckets.iter().enumerate() {
            cumulative += counts[i].load(Ordering::Relaxed);
            output.push_str(&format!(
                "{}_bucket{{le=\"{}\"}} {}\n",
                prometheus_name, bucket, cumulative
            ));
        }

        output.push_str(&format!(
            "{}_bucket{{le=\"+Inf\"}} {}\n",
            prometheus_name,
            self.count.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "{}_sum {}\n",
            prometheus_name,
            self.sum.load(Ordering::Relaxed) as f64 / 1000.0
        ));
        output.push_str(&format!(
            "{}_count {}\n",
            prometheus_name,
            self.count.load(Ordering::Relaxed)
        ));

        output
    }
}

impl Default for Histogram {
    fn default() -> Self {
        // Default buckets for latency in seconds
        Self::new(vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ])
    }
}

/// Predefined metric names
pub mod metric_names {
    // Event processing
    pub const EVENTS_INGESTED: &str = "sequencer.events.ingested";
    pub const EVENTS_REJECTED: &str = "sequencer.events.rejected";
    pub const EVENTS_SEQUENCED: &str = "sequencer.events.sequenced";
    pub const EVENTS_PROJECTED: &str = "sequencer.events.projected";

    // Batch processing
    pub const BATCHES_RECEIVED: &str = "sequencer.batches.received";
    pub const BATCHES_PROCESSED: &str = "sequencer.batches.processed";

    // Commitments
    pub const COMMITMENTS_CREATED: &str = "sequencer.commitments.created";
    pub const COMMITMENTS_ANCHORED: &str = "sequencer.commitments.anchored";
    pub const COMMITMENTS_VERIFIED: &str = "sequencer.commitments.verified";

    // Latency histograms
    pub const INGEST_LATENCY: &str = "sequencer.ingest.latency_seconds";
    pub const SEQUENCE_LATENCY: &str = "sequencer.sequence.latency_seconds";
    pub const PROJECT_LATENCY: &str = "sequencer.project.latency_seconds";
    pub const COMMIT_LATENCY: &str = "sequencer.commit.latency_seconds";
    pub const ANCHOR_LATENCY: &str = "sequencer.anchor.latency_seconds";
    pub const PROOF_LATENCY: &str = "sequencer.proof.latency_seconds";
    pub const DB_QUERY_LATENCY: &str = "sequencer.db.query_latency_seconds";

    // Error counters
    pub const VALIDATION_ERRORS: &str = "sequencer.errors.validation";
    pub const DATABASE_ERRORS: &str = "sequencer.errors.database";
    pub const SCHEMA_VALIDATION_ERRORS: &str = "sequencer.errors.schema_validation";
    pub const SIGNATURE_ERRORS: &str = "sequencer.errors.signature";
    pub const AUTH_ERRORS: &str = "sequencer.errors.auth";

    // Connection gauges
    pub const ACTIVE_CONNECTIONS: &str = "sequencer.connections.active";
    pub const DB_POOL_SIZE: &str = "sequencer.db.pool_size";
    pub const DB_POOL_IDLE: &str = "sequencer.db.pool_idle";
    pub const DB_POOL_WAITING: &str = "sequencer.db.pool_waiting";

    // Head sequence
    pub const HEAD_SEQUENCE: &str = "sequencer.head_sequence";

    // Rate limiting
    pub const RATE_LIMIT_ALLOWED: &str = "sequencer.ratelimit.allowed";
    pub const RATE_LIMIT_REJECTED: &str = "sequencer.ratelimit.rejected";
    pub const RATE_LIMIT_ENTRIES: &str = "sequencer.ratelimit.entries";
    pub const RATE_LIMIT_EVICTED: &str = "sequencer.ratelimit.evicted";

    // Request sizes
    pub const REQUEST_BODY_SIZE: &str = "sequencer.request.body_size_bytes";
    pub const EVENTS_PER_BATCH: &str = "sequencer.request.events_per_batch";

    // Cache metrics
    pub const CACHE_HITS: &str = "sequencer.cache.hits";
    pub const CACHE_MISSES: &str = "sequencer.cache.misses";
    pub const CACHE_SIZE: &str = "sequencer.cache.size";
    pub const CACHE_EVICTIONS: &str = "sequencer.cache.evictions";

    // Circuit breaker metrics
    pub const CIRCUIT_BREAKER_STATE: &str = "sequencer.circuit_breaker.state";
    pub const CIRCUIT_BREAKER_FAILURES: &str = "sequencer.circuit_breaker.failures";
    pub const CIRCUIT_BREAKER_SUCCESSES: &str = "sequencer.circuit_breaker.successes";
    pub const CIRCUIT_BREAKER_REJECTIONS: &str = "sequencer.circuit_breaker.rejections";

    // VES-specific metrics
    pub const VES_EVENTS_RECEIVED: &str = "sequencer.ves.events_received";
    pub const VES_EVENTS_VERIFIED: &str = "sequencer.ves.events_verified";
    pub const VES_MERKLE_TREE_DEPTH: &str = "sequencer.ves.merkle_tree_depth";
    pub const VES_PROOF_SIZE_BYTES: &str = "sequencer.ves.proof_size_bytes";

    // Anchor service metrics
    pub const ANCHOR_BATCHES_SUBMITTED: &str = "sequencer.anchor.batches_submitted";
    pub const ANCHOR_BATCHES_CONFIRMED: &str = "sequencer.anchor.batches_confirmed";
    pub const ANCHOR_GAS_USED: &str = "sequencer.anchor.gas_used";
    pub const ANCHOR_RETRIES: &str = "sequencer.anchor.retries";

    // Dead letter queue metrics
    pub const DLQ_SIZE: &str = "sequencer.dlq.size";
    pub const DLQ_ADDED: &str = "sequencer.dlq.added";
    pub const DLQ_RETRIED: &str = "sequencer.dlq.retried";
    pub const DLQ_DISCARDED: &str = "sequencer.dlq.discarded";
    pub const DLQ_PENDING: &str = "sequencer.dlq.pending";
    pub const DLQ_FAILED: &str = "sequencer.dlq.failed";
    pub const DLQ_DUE_FOR_RETRY: &str = "sequencer.dlq.due_for_retry";

    // Retry metrics
    pub const RETRY_ATTEMPTS: &str = "sequencer.retry.attempts";
    pub const RETRY_SUCCESSES: &str = "sequencer.retry.successes";
    pub const RETRY_FAILURES: &str = "sequencer.retry.failures";
    pub const RETRY_EXHAUSTED: &str = "sequencer.retry.exhausted";
    pub const RETRY_LATENCY: &str = "sequencer.retry.latency_seconds";

    // Pool monitoring metrics
    pub const POOL_ACTIVE_CONNECTIONS: &str = "sequencer.pool.active_connections";
    pub const POOL_IDLE_CONNECTIONS: &str = "sequencer.pool.idle_connections";
    pub const POOL_TOTAL_CONNECTIONS: &str = "sequencer.pool.total_connections";
    pub const POOL_MAX_CONNECTIONS: &str = "sequencer.pool.max_connections";
    pub const POOL_ACQUISITION_LATENCY: &str = "sequencer.pool.acquisition_latency_ms";
    pub const POOL_SLOW_ACQUISITIONS: &str = "sequencer.pool.slow_acquisitions";
    pub const POOL_TIMED_OUT_ACQUISITIONS: &str = "sequencer.pool.timed_out_acquisitions";
    pub const POOL_UTILIZATION: &str = "sequencer.pool.utilization";

    // Audit metrics
    pub const AUDIT_EVENTS_LOGGED: &str = "sequencer.audit.events_logged";

    // gRPC metrics
    pub const GRPC_REQUESTS_TOTAL: &str = "sequencer.grpc.requests_total";
    pub const GRPC_REQUEST_LATENCY: &str = "sequencer.grpc.request_latency_seconds";
    pub const GRPC_STREAM_MESSAGES: &str = "sequencer.grpc.stream_messages";

    // HTTP metrics
    pub const HTTP_REQUESTS_TOTAL: &str = "sequencer.http.requests_total";
    pub const HTTP_REQUEST_LATENCY: &str = "sequencer.http.request_latency_seconds";
    pub const HTTP_RESPONSE_SIZE: &str = "sequencer.http.response_size_bytes";
}

/// Timer guard for measuring operation duration
pub struct TimerGuard {
    metrics: Arc<MetricsRegistry>,
    metric_name: String,
    start: Instant,
}

impl TimerGuard {
    pub fn new(metrics: Arc<MetricsRegistry>, metric_name: &str) -> Self {
        Self {
            metrics,
            metric_name: metric_name.to_string(),
            start: Instant::now(),
        }
    }
}

impl Drop for TimerGuard {
    fn drop(&mut self) {
        let duration = self.start.elapsed().as_secs_f64();
        let metrics = self.metrics.clone();
        let metric_name = self.metric_name.clone();

        // Spawn a task to record the metric since we can't await in Drop
        tokio::spawn(async move {
            metrics.observe_histogram(&metric_name, duration).await;
        });
    }
}

/// Helper function to time an async operation
pub async fn timed<F, T>(metrics: &MetricsRegistry, metric_name: &str, f: F) -> T
where
    F: std::future::Future<Output = T>,
{
    let start = Instant::now();
    let result = f.await;
    let duration = start.elapsed().as_secs_f64();
    metrics.observe_histogram(metric_name, duration).await;
    result
}

// ============================================================================
// Component Metrics Collection
// ============================================================================

use crate::infra::{CircuitBreakerRegistry, PoolMonitor, PoolStats};

/// Collector for infrastructure component metrics
pub struct ComponentMetrics {
    metrics: Arc<MetricsRegistry>,
    pool_monitor: Option<Arc<PoolMonitor>>,
    circuit_breaker_registry: Option<Arc<CircuitBreakerRegistry>>,
}

impl ComponentMetrics {
    /// Create a new component metrics collector
    pub fn new(
        metrics: Arc<MetricsRegistry>,
        pool_monitor: Option<Arc<PoolMonitor>>,
        circuit_breaker_registry: Option<Arc<CircuitBreakerRegistry>>,
    ) -> Self {
        Self {
            metrics,
            pool_monitor,
            circuit_breaker_registry,
        }
    }

    /// Update all component metrics
    pub async fn update(&self) {
        self.update_pool_metrics().await;
        self.update_circuit_breaker_metrics().await;
    }

    /// Update pool monitoring metrics
    pub async fn update_pool_metrics(&self) {
        if let Some(ref monitor) = self.pool_monitor {
            let stats = monitor.stats().await;

            self.metrics
                .set_gauge(metric_names::POOL_ACTIVE_CONNECTIONS, stats.active_connections as u64)
                .await;
            self.metrics
                .set_gauge(metric_names::POOL_IDLE_CONNECTIONS, stats.idle_connections as u64)
                .await;
            self.metrics
                .set_gauge(metric_names::POOL_TOTAL_CONNECTIONS, stats.total_connections as u64)
                .await;
            self.metrics
                .set_gauge(metric_names::POOL_MAX_CONNECTIONS, stats.max_connections as u64)
                .await;
            self.metrics
                .set_gauge(
                    metric_names::POOL_UTILIZATION,
                    (stats.utilization() * 100.0) as u64,
                )
                .await;

            // Counters for acquisition stats
            self.metrics
                .add_counter(
                    metric_names::POOL_SLOW_ACQUISITIONS,
                    stats.slow_acquisitions,
                )
                .await;
            self.metrics
                .add_counter(
                    metric_names::POOL_TIMED_OUT_ACQUISITIONS,
                    stats.timed_out_acquisitions,
                )
                .await;

            // Record acquisition latency histogram if we have data
            if stats.avg_acquisition_latency_ms > 0.0 {
                self.metrics
                    .observe_histogram(
                        metric_names::POOL_ACQUISITION_LATENCY,
                        stats.avg_acquisition_latency_ms / 1000.0, // Convert to seconds
                    )
                    .await;
            }
        }
    }

    /// Update circuit breaker metrics
    pub async fn update_circuit_breaker_metrics(&self) {
        if let Some(ref registry) = self.circuit_breaker_registry {
            let status = registry.status().await;

            if let Some(obj) = status.as_object() {
                for (name, value) in obj {
                    let labels = Labels::new().circuit(name);

                    // State gauge (0=closed, 1=half-open, 2=open)
                    let state_value = match value.get("state").and_then(|v| v.as_str()) {
                        Some("closed") => 0u64,
                        Some("half_open") => 1u64,
                        Some("open") => 2u64,
                        _ => 0u64,
                    };
                    self.metrics
                        .set_gauge_labeled(metric_names::CIRCUIT_BREAKER_STATE, labels.clone(), state_value)
                        .await;

                    // Stats from the circuit breaker
                    if let Some(stats) = value.get("stats") {
                        if let Some(successes) = stats.get("successes").and_then(|v| v.as_u64()) {
                            self.metrics
                                .add_counter_labeled(
                                    metric_names::CIRCUIT_BREAKER_SUCCESSES,
                                    labels.clone(),
                                    successes,
                                )
                                .await;
                        }
                        if let Some(failures) = stats.get("failures").and_then(|v| v.as_u64()) {
                            self.metrics
                                .add_counter_labeled(
                                    metric_names::CIRCUIT_BREAKER_FAILURES,
                                    labels.clone(),
                                    failures,
                                )
                                .await;
                        }
                        if let Some(rejected) = stats.get("rejected").and_then(|v| v.as_u64()) {
                            self.metrics
                                .add_counter_labeled(
                                    metric_names::CIRCUIT_BREAKER_REJECTIONS,
                                    labels,
                                    rejected,
                                )
                                .await;
                        }
                    }
                }
            }
        }
    }

    /// Start a background task that periodically updates metrics
    pub fn start_collection_task(
        self: Arc<Self>,
        interval: std::time::Duration,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            loop {
                tick.tick().await;
                self.update().await;
            }
        })
    }
}

/// Record pool stats directly to metrics registry
pub async fn record_pool_stats(metrics: &MetricsRegistry, stats: &PoolStats) {
    metrics
        .set_gauge(metric_names::POOL_ACTIVE_CONNECTIONS, stats.active_connections as u64)
        .await;
    metrics
        .set_gauge(metric_names::POOL_IDLE_CONNECTIONS, stats.idle_connections as u64)
        .await;
    metrics
        .set_gauge(metric_names::POOL_TOTAL_CONNECTIONS, stats.total_connections as u64)
        .await;
    metrics
        .set_gauge(metric_names::POOL_MAX_CONNECTIONS, stats.max_connections as u64)
        .await;
    metrics
        .set_gauge(
            metric_names::POOL_UTILIZATION,
            (stats.utilization() * 100.0) as u64,
        )
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_counter() {
        let registry = MetricsRegistry::new();

        registry.inc_counter("test.counter").await;
        registry.inc_counter("test.counter").await;
        registry.add_counter("test.counter", 5).await;

        assert_eq!(registry.get_counter("test.counter").await, 7);
    }

    #[tokio::test]
    async fn test_gauge() {
        let registry = MetricsRegistry::new();

        registry.set_gauge("test.gauge", 100).await;
        assert_eq!(registry.get_gauge("test.gauge").await, 100);

        registry.set_gauge("test.gauge", 50).await;
        assert_eq!(registry.get_gauge("test.gauge").await, 50);
    }

    #[tokio::test]
    async fn test_histogram() {
        let registry = MetricsRegistry::new();

        registry.observe_histogram("test.latency", 0.005).await;
        registry.observe_histogram("test.latency", 0.05).await;
        registry.observe_histogram("test.latency", 0.5).await;

        let json = registry.to_json().await;
        let histograms = json.get("histograms").unwrap();
        let latency = histograms.get("test.latency").unwrap();

        assert_eq!(latency.get("count").unwrap().as_u64().unwrap(), 3);
    }

    #[tokio::test]
    async fn test_prometheus_format() {
        let registry = MetricsRegistry::new();

        registry.inc_counter("test_counter").await;
        registry.set_gauge("test_gauge", 42).await;

        let prometheus = registry.to_prometheus().await;
        assert!(prometheus.contains("test_counter 1"));
        assert!(prometheus.contains("test_gauge 42"));
    }
}
