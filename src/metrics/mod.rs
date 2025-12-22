//! Metrics and observability for StateSet Sequencer
//!
//! Provides metrics collection, health checks, and debugging endpoints.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// Global metrics registry
pub struct MetricsRegistry {
    /// Counter metrics
    counters: RwLock<HashMap<String, Arc<AtomicU64>>>,

    /// Gauge metrics (current values)
    gauges: RwLock<HashMap<String, Arc<AtomicU64>>>,

    /// Histogram metrics (bucketed)
    histograms: RwLock<HashMap<String, Arc<Histogram>>>,

    /// Service start time
    start_time: Instant,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self {
            counters: RwLock::new(HashMap::new()),
            gauges: RwLock::new(HashMap::new()),
            histograms: RwLock::new(HashMap::new()),
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
        let gauges = self.gauges.read().await;
        let histograms = self.histograms.read().await;

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

        // Histograms
        for (name, histogram) in histograms.iter() {
            output.push_str(&histogram.to_prometheus(name).await);
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

    // Latency histograms
    pub const INGEST_LATENCY: &str = "sequencer.ingest.latency_seconds";
    pub const SEQUENCE_LATENCY: &str = "sequencer.sequence.latency_seconds";
    pub const PROJECT_LATENCY: &str = "sequencer.project.latency_seconds";

    // Error counters
    pub const VALIDATION_ERRORS: &str = "sequencer.errors.validation";
    pub const DATABASE_ERRORS: &str = "sequencer.errors.database";

    // Connection gauges
    pub const ACTIVE_CONNECTIONS: &str = "sequencer.connections.active";
    pub const DB_POOL_SIZE: &str = "sequencer.db.pool_size";

    // Head sequence
    pub const HEAD_SEQUENCE: &str = "sequencer.head_sequence";
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
