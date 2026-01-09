//! Connection pool health monitoring
//!
//! Provides real-time monitoring of database connection pool health:
//! - Active/idle connection counts
//! - Wait queue depth
//! - Connection acquisition latency
//! - Pool saturation alerts
//! - Automatic health degradation detection

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Pool health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PoolHealthStatus {
    /// Pool is healthy with plenty of capacity
    #[default]
    Healthy,
    /// Pool is under moderate load but functioning
    Moderate,
    /// Pool is under heavy load, may experience delays
    Stressed,
    /// Pool is saturated, connections are being rejected
    Critical,
}

impl std::fmt::Display for PoolHealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PoolHealthStatus::Healthy => write!(f, "healthy"),
            PoolHealthStatus::Moderate => write!(f, "moderate"),
            PoolHealthStatus::Stressed => write!(f, "stressed"),
            PoolHealthStatus::Critical => write!(f, "critical"),
        }
    }
}

/// Configuration for pool health monitoring
#[derive(Debug, Clone)]
pub struct PoolMonitorConfig {
    /// Threshold for moderate status (% of pool in use)
    pub moderate_threshold: f64,
    /// Threshold for stressed status (% of pool in use)
    pub stressed_threshold: f64,
    /// Threshold for critical status (% of pool in use)
    pub critical_threshold: f64,
    /// Latency threshold for slow connection acquisition (ms)
    pub slow_acquisition_ms: u64,
    /// Number of slow acquisitions to trigger warning
    pub slow_acquisition_threshold: u32,
    /// Window for tracking slow acquisitions
    pub monitoring_window: Duration,
}

impl Default for PoolMonitorConfig {
    fn default() -> Self {
        Self {
            moderate_threshold: 0.5, // 50% utilization
            stressed_threshold: 0.8, // 80% utilization
            critical_threshold: 0.95, // 95% utilization
            slow_acquisition_ms: 100,
            slow_acquisition_threshold: 10,
            monitoring_window: Duration::from_secs(60),
        }
    }
}

/// Statistics for connection pool monitoring
#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    /// Total connections (active + idle)
    pub total_connections: u32,
    /// Maximum pool size
    pub max_connections: u32,
    /// Currently active (in-use) connections
    pub active_connections: u32,
    /// Idle connections available
    pub idle_connections: u32,
    /// Connections waiting in queue
    pub pending_connections: u32,
    /// Total connection acquisitions
    pub total_acquisitions: u64,
    /// Slow connection acquisitions
    pub slow_acquisitions: u64,
    /// Timed out connection acquisitions
    pub timed_out_acquisitions: u64,
    /// Average acquisition latency (ms)
    pub avg_acquisition_latency_ms: f64,
    /// Maximum acquisition latency (ms)
    pub max_acquisition_latency_ms: u64,
    /// Current health status
    pub status: PoolHealthStatus,
}

impl PoolStats {
    /// Get pool utilization as a percentage
    pub fn utilization(&self) -> f64 {
        if self.max_connections == 0 {
            return 0.0;
        }
        self.active_connections as f64 / self.max_connections as f64
    }

    /// Check if pool is under stress
    pub fn is_stressed(&self) -> bool {
        matches!(self.status, PoolHealthStatus::Stressed | PoolHealthStatus::Critical)
    }

    /// Check if pool is critical
    pub fn is_critical(&self) -> bool {
        matches!(self.status, PoolHealthStatus::Critical)
    }

    /// Convert to JSON for metrics export
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "total_connections": self.total_connections,
            "max_connections": self.max_connections,
            "active_connections": self.active_connections,
            "idle_connections": self.idle_connections,
            "pending_connections": self.pending_connections,
            "utilization": self.utilization(),
            "status": self.status.to_string(),
            "total_acquisitions": self.total_acquisitions,
            "slow_acquisitions": self.slow_acquisitions,
            "timed_out_acquisitions": self.timed_out_acquisitions,
            "avg_acquisition_latency_ms": self.avg_acquisition_latency_ms,
            "max_acquisition_latency_ms": self.max_acquisition_latency_ms,
        })
    }
}

/// Internal metrics collector
struct MetricsCollector {
    total_acquisitions: AtomicU64,
    slow_acquisitions: AtomicU64,
    timed_out_acquisitions: AtomicU64,
    total_latency_us: AtomicU64,
    max_latency_us: AtomicU64,
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self {
            total_acquisitions: AtomicU64::new(0),
            slow_acquisitions: AtomicU64::new(0),
            timed_out_acquisitions: AtomicU64::new(0),
            total_latency_us: AtomicU64::new(0),
            max_latency_us: AtomicU64::new(0),
        }
    }
}

/// Connection pool health monitor
pub struct PoolMonitor {
    config: PoolMonitorConfig,
    max_connections: u32,
    metrics: Arc<MetricsCollector>,
    last_status: RwLock<PoolHealthStatus>,
    last_stats: RwLock<PoolStats>,
}

impl PoolMonitor {
    /// Create a new pool monitor
    pub fn new(max_connections: u32) -> Self {
        Self {
            config: PoolMonitorConfig::default(),
            max_connections,
            metrics: Arc::new(MetricsCollector::default()),
            last_status: RwLock::new(PoolHealthStatus::Healthy),
            last_stats: RwLock::new(PoolStats::default()),
        }
    }

    /// Create with custom configuration
    pub fn with_config(max_connections: u32, config: PoolMonitorConfig) -> Self {
        Self {
            config,
            max_connections,
            metrics: Arc::new(MetricsCollector::default()),
            last_status: RwLock::new(PoolHealthStatus::Healthy),
            last_stats: RwLock::new(PoolStats::default()),
        }
    }

    /// Record a connection acquisition attempt
    pub fn record_acquisition(&self, latency: Duration, success: bool) {
        let latency_us = latency.as_micros() as u64;

        self.metrics.total_acquisitions.fetch_add(1, Ordering::Relaxed);
        self.metrics.total_latency_us.fetch_add(latency_us, Ordering::Relaxed);

        // Update max latency
        let mut current_max = self.metrics.max_latency_us.load(Ordering::Relaxed);
        while latency_us > current_max {
            match self.metrics.max_latency_us.compare_exchange_weak(
                current_max,
                latency_us,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(x) => current_max = x,
            }
        }

        // Track slow acquisitions
        if latency.as_millis() as u64 > self.config.slow_acquisition_ms {
            self.metrics.slow_acquisitions.fetch_add(1, Ordering::Relaxed);
        }

        if !success {
            self.metrics.timed_out_acquisitions.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Create a guard that records acquisition latency when dropped
    pub fn start_acquisition(&self) -> AcquisitionGuard<'_> {
        AcquisitionGuard {
            start: Instant::now(),
            monitor: self,
            completed: false,
        }
    }

    /// Update pool statistics from sqlx pool state
    pub async fn update_from_pool(&self, pool: &sqlx::PgPool) {
        let size = pool.size();
        let num_idle = pool.num_idle();

        let active = size - num_idle as u32;
        let utilization = if self.max_connections > 0 {
            active as f64 / self.max_connections as f64
        } else {
            0.0
        };

        // Determine health status
        let status = if utilization >= self.config.critical_threshold {
            PoolHealthStatus::Critical
        } else if utilization >= self.config.stressed_threshold {
            PoolHealthStatus::Stressed
        } else if utilization >= self.config.moderate_threshold {
            PoolHealthStatus::Moderate
        } else {
            PoolHealthStatus::Healthy
        };

        // Log status changes
        {
            let last = *self.last_status.read().await;
            if status != last {
                match status {
                    PoolHealthStatus::Critical => {
                        tracing::error!(
                            utilization = %utilization,
                            active = active,
                            max = self.max_connections,
                            "Pool health critical - connection pool saturated"
                        );
                    }
                    PoolHealthStatus::Stressed => {
                        tracing::warn!(
                            utilization = %utilization,
                            active = active,
                            max = self.max_connections,
                            "Pool health stressed - approaching capacity"
                        );
                    }
                    PoolHealthStatus::Healthy if last.is_stressed() => {
                        tracing::info!(
                            utilization = %utilization,
                            "Pool health recovered to healthy"
                        );
                    }
                    _ => {}
                }
            }
        }

        // Update stored stats
        let total_acquisitions = self.metrics.total_acquisitions.load(Ordering::Relaxed);
        let total_latency_us = self.metrics.total_latency_us.load(Ordering::Relaxed);
        let avg_latency_ms = if total_acquisitions > 0 {
            (total_latency_us as f64 / total_acquisitions as f64) / 1000.0
        } else {
            0.0
        };

        let stats = PoolStats {
            total_connections: size,
            max_connections: self.max_connections,
            active_connections: active,
            idle_connections: num_idle as u32,
            pending_connections: 0, // sqlx doesn't expose this directly
            total_acquisitions,
            slow_acquisitions: self.metrics.slow_acquisitions.load(Ordering::Relaxed),
            timed_out_acquisitions: self.metrics.timed_out_acquisitions.load(Ordering::Relaxed),
            avg_acquisition_latency_ms: avg_latency_ms,
            max_acquisition_latency_ms: self.metrics.max_latency_us.load(Ordering::Relaxed) / 1000,
            status,
        };

        *self.last_status.write().await = status;
        *self.last_stats.write().await = stats;
    }

    /// Get current pool status
    pub async fn status(&self) -> PoolHealthStatus {
        *self.last_status.read().await
    }

    /// Get current pool statistics
    pub async fn stats(&self) -> PoolStats {
        self.last_stats.read().await.clone()
    }

    /// Check if pool is healthy for accepting new requests
    pub async fn is_healthy(&self) -> bool {
        let status = *self.last_status.read().await;
        !matches!(status, PoolHealthStatus::Critical)
    }

    /// Get metrics as JSON
    pub async fn metrics_json(&self) -> serde_json::Value {
        self.last_stats.read().await.to_json()
    }

    /// Reset metrics (typically called periodically)
    pub fn reset_metrics(&self) {
        self.metrics.total_acquisitions.store(0, Ordering::Relaxed);
        self.metrics.slow_acquisitions.store(0, Ordering::Relaxed);
        self.metrics.timed_out_acquisitions.store(0, Ordering::Relaxed);
        self.metrics.total_latency_us.store(0, Ordering::Relaxed);
        self.metrics.max_latency_us.store(0, Ordering::Relaxed);
    }
}

impl PoolHealthStatus {
    fn is_stressed(&self) -> bool {
        matches!(self, PoolHealthStatus::Stressed | PoolHealthStatus::Critical)
    }
}

/// Guard for measuring connection acquisition latency
pub struct AcquisitionGuard<'a> {
    start: Instant,
    monitor: &'a PoolMonitor,
    completed: bool,
}

impl<'a> AcquisitionGuard<'a> {
    /// Mark acquisition as successful
    pub fn success(mut self) {
        self.completed = true;
        self.monitor.record_acquisition(self.start.elapsed(), true);
    }

    /// Mark acquisition as failed (timeout)
    pub fn timeout(mut self) {
        self.completed = true;
        self.monitor.record_acquisition(self.start.elapsed(), false);
    }
}

impl<'a> Drop for AcquisitionGuard<'a> {
    fn drop(&mut self) {
        if !self.completed {
            // Acquisition was dropped without explicit success/failure, treat as success
            self.monitor.record_acquisition(self.start.elapsed(), true);
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_health_status_display() {
        assert_eq!(PoolHealthStatus::Healthy.to_string(), "healthy");
        assert_eq!(PoolHealthStatus::Critical.to_string(), "critical");
    }

    #[test]
    fn test_pool_stats_utilization() {
        let stats = PoolStats {
            active_connections: 50,
            max_connections: 100,
            ..Default::default()
        };
        assert!((stats.utilization() - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_pool_stats_is_stressed() {
        let mut stats = PoolStats::default();
        stats.status = PoolHealthStatus::Healthy;
        assert!(!stats.is_stressed());

        stats.status = PoolHealthStatus::Stressed;
        assert!(stats.is_stressed());

        stats.status = PoolHealthStatus::Critical;
        assert!(stats.is_stressed());
        assert!(stats.is_critical());
    }

    #[test]
    fn test_pool_monitor_creation() {
        let monitor = PoolMonitor::new(100);
        assert_eq!(monitor.max_connections, 100);
    }

    #[test]
    fn test_acquisition_recording() {
        let monitor = PoolMonitor::new(100);

        monitor.record_acquisition(Duration::from_millis(50), true);
        monitor.record_acquisition(Duration::from_millis(150), true); // slow

        let metrics = &monitor.metrics;
        assert_eq!(metrics.total_acquisitions.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.slow_acquisitions.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_acquisition_guard() {
        let monitor = PoolMonitor::new(100);

        {
            let guard = monitor.start_acquisition();
            std::thread::sleep(Duration::from_millis(10));
            guard.success();
        }

        let metrics = &monitor.metrics;
        assert_eq!(metrics.total_acquisitions.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_metrics_reset() {
        let monitor = PoolMonitor::new(100);
        monitor.record_acquisition(Duration::from_millis(50), true);

        assert_eq!(monitor.metrics.total_acquisitions.load(Ordering::Relaxed), 1);

        monitor.reset_metrics();
        assert_eq!(monitor.metrics.total_acquisitions.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_config_thresholds() {
        let config = PoolMonitorConfig {
            moderate_threshold: 0.4,
            stressed_threshold: 0.7,
            critical_threshold: 0.9,
            ..Default::default()
        };

        let monitor = PoolMonitor::with_config(100, config);
        assert_eq!(monitor.config.moderate_threshold, 0.4);
    }
}
