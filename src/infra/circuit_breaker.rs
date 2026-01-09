//! Circuit breaker for external service calls
//!
//! Implements the circuit breaker pattern to prevent cascading failures
//! when external services (like L2 anchoring) are unavailable.
//!
//! # States
//!
//! - **Closed**: Normal operation, requests pass through
//! - **Open**: Service unavailable, requests fail fast
//! - **HalfOpen**: Testing if service recovered

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation - requests pass through
    Closed,
    /// Service unavailable - requests fail fast
    Open,
    /// Testing recovery - limited requests allowed
    HalfOpen,
}

impl std::fmt::Display for CircuitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitState::Closed => write!(f, "closed"),
            CircuitState::Open => write!(f, "open"),
            CircuitState::HalfOpen => write!(f, "half_open"),
        }
    }
}

/// Configuration for circuit breaker
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening circuit
    pub failure_threshold: u32,
    /// Number of successes in half-open state to close circuit
    pub success_threshold: u32,
    /// Initial duration to wait before transitioning from open to half-open
    pub open_timeout: Duration,
    /// Duration window for counting failures
    pub failure_window: Duration,
    /// Maximum requests allowed in half-open state
    pub half_open_max_requests: u32,
    /// Exponential backoff multiplier for consecutive failures (e.g., 2.0 = double timeout each time)
    pub backoff_multiplier: f64,
    /// Maximum backoff duration (caps exponential growth)
    pub max_backoff: Duration,
    /// Jitter factor (0.0-1.0) to add randomness to backoff timing
    pub jitter_factor: f64,
    /// Threshold for slow calls (calls slower than this are counted as degraded)
    pub slow_call_threshold: Option<Duration>,
    /// Number of slow calls to trigger circuit open
    pub slow_call_rate_threshold: Option<f64>,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 3,
            open_timeout: Duration::from_secs(30),
            failure_window: Duration::from_secs(60),
            half_open_max_requests: 3,
            backoff_multiplier: 2.0,
            max_backoff: Duration::from_secs(300), // 5 minutes max
            jitter_factor: 0.1,
            slow_call_threshold: None,
            slow_call_rate_threshold: None,
        }
    }
}

/// Circuit breaker statistics
#[derive(Debug, Default)]
pub struct CircuitBreakerStats {
    /// Total successful calls
    pub successes: AtomicU64,
    /// Total failed calls
    pub failures: AtomicU64,
    /// Calls rejected due to open circuit
    pub rejected: AtomicU64,
    /// Number of times circuit opened
    pub times_opened: AtomicU64,
    /// Number of times circuit closed
    pub times_closed: AtomicU64,
    /// Number of slow calls detected
    pub slow_calls: AtomicU64,
    /// Total call duration in milliseconds (for average calculation)
    pub total_duration_ms: AtomicU64,
    /// Number of calls with duration recorded
    pub calls_with_duration: AtomicU64,
}

impl CircuitBreakerStats {
    pub fn to_json(&self) -> serde_json::Value {
        let calls_with_duration = self.calls_with_duration.load(Ordering::Relaxed);
        let avg_duration_ms = if calls_with_duration > 0 {
            self.total_duration_ms.load(Ordering::Relaxed) / calls_with_duration
        } else {
            0
        };

        serde_json::json!({
            "successes": self.successes.load(Ordering::Relaxed),
            "failures": self.failures.load(Ordering::Relaxed),
            "rejected": self.rejected.load(Ordering::Relaxed),
            "times_opened": self.times_opened.load(Ordering::Relaxed),
            "times_closed": self.times_closed.load(Ordering::Relaxed),
            "slow_calls": self.slow_calls.load(Ordering::Relaxed),
            "avg_duration_ms": avg_duration_ms,
        })
    }

    /// Record call duration
    pub fn record_duration(&self, duration: Duration) {
        self.total_duration_ms.fetch_add(duration.as_millis() as u64, Ordering::Relaxed);
        self.calls_with_duration.fetch_add(1, Ordering::Relaxed);
    }
}

/// Internal state tracking
struct InternalState {
    state: CircuitState,
    failure_count: u32,
    success_count: u32,
    last_failure_time: Option<Instant>,
    opened_at: Option<Instant>,
    half_open_requests: u32,
    /// Number of consecutive times circuit opened (for exponential backoff)
    consecutive_opens: u32,
    /// Current backoff duration (increases with consecutive opens)
    current_backoff: Duration,
    /// Slow call count in current window
    slow_call_count: u32,
    /// Total calls in current window (for slow call rate calculation)
    window_call_count: u32,
}

impl Default for InternalState {
    fn default() -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: 0,
            success_count: 0,
            last_failure_time: None,
            opened_at: None,
            half_open_requests: 0,
            consecutive_opens: 0,
            current_backoff: Duration::from_secs(30),
            slow_call_count: 0,
            window_call_count: 0,
        }
    }
}

/// Circuit breaker for protecting external service calls
pub struct CircuitBreaker {
    name: String,
    config: CircuitBreakerConfig,
    state: RwLock<InternalState>,
    stats: CircuitBreakerStats,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given name
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            config: CircuitBreakerConfig::default(),
            state: RwLock::new(InternalState::default()),
            stats: CircuitBreakerStats::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(name: impl Into<String>, config: CircuitBreakerConfig) -> Self {
        Self {
            name: name.into(),
            config,
            state: RwLock::new(InternalState::default()),
            stats: CircuitBreakerStats::default(),
        }
    }

    /// Get the circuit breaker name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get current state
    pub async fn state(&self) -> CircuitState {
        let mut state = self.state.write().await;
        self.maybe_transition(&mut state);
        state.state
    }

    /// Check if the circuit allows requests
    pub async fn is_allowed(&self) -> bool {
        let mut state = self.state.write().await;
        self.maybe_transition(&mut state);

        match state.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                self.stats.rejected.fetch_add(1, Ordering::Relaxed);
                false
            }
            CircuitState::HalfOpen => {
                if state.half_open_requests < self.config.half_open_max_requests {
                    state.half_open_requests += 1;
                    true
                } else {
                    self.stats.rejected.fetch_add(1, Ordering::Relaxed);
                    false
                }
            }
        }
    }

    /// Record a successful call
    pub async fn record_success(&self) {
        self.stats.successes.fetch_add(1, Ordering::Relaxed);

        let mut state = self.state.write().await;

        match state.state {
            CircuitState::Closed => {
                // Reset failure count on success
                state.failure_count = 0;
            }
            CircuitState::HalfOpen => {
                state.success_count += 1;
                if state.success_count >= self.config.success_threshold {
                    self.transition_to_closed(&mut state);
                }
            }
            CircuitState::Open => {
                // Shouldn't happen, but handle gracefully
            }
        }
    }

    /// Record a failed call
    pub async fn record_failure(&self) {
        self.stats.failures.fetch_add(1, Ordering::Relaxed);

        let mut state = self.state.write().await;
        state.last_failure_time = Some(Instant::now());

        match state.state {
            CircuitState::Closed => {
                // Check if we should reset failure count due to window expiry
                if let Some(last_failure) = state.last_failure_time {
                    if last_failure.elapsed() > self.config.failure_window {
                        state.failure_count = 0;
                    }
                }

                state.failure_count += 1;
                if state.failure_count >= self.config.failure_threshold {
                    self.transition_to_open(&mut state);
                }
            }
            CircuitState::HalfOpen => {
                // Any failure in half-open state opens the circuit
                self.transition_to_open(&mut state);
            }
            CircuitState::Open => {
                // Already open, nothing to do
            }
        }
    }

    /// Execute a function with circuit breaker protection
    pub async fn call<F, T, E>(&self, f: F) -> Result<T, CircuitBreakerError<E>>
    where
        F: std::future::Future<Output = Result<T, E>>,
    {
        if !self.is_allowed().await {
            return Err(CircuitBreakerError::CircuitOpen);
        }

        let start = Instant::now();
        let result = f.await;
        let duration = start.elapsed();

        // Record duration for stats
        self.stats.record_duration(duration);

        // Check for slow call
        if let Some(threshold) = self.config.slow_call_threshold {
            if duration > threshold {
                self.record_slow_call().await;
            }
        }

        match result {
            Ok(result) => {
                self.record_success().await;
                Ok(result)
            }
            Err(e) => {
                self.record_failure().await;
                Err(CircuitBreakerError::ServiceError(e))
            }
        }
    }

    /// Execute a function with circuit breaker protection and timeout
    pub async fn call_with_timeout<F, T, E>(
        &self,
        f: F,
        timeout: Duration,
    ) -> Result<T, CircuitBreakerError<E>>
    where
        F: std::future::Future<Output = Result<T, E>>,
        E: From<std::io::Error>,
    {
        if !self.is_allowed().await {
            return Err(CircuitBreakerError::CircuitOpen);
        }

        let start = Instant::now();

        match tokio::time::timeout(timeout, f).await {
            Ok(result) => {
                let duration = start.elapsed();
                self.stats.record_duration(duration);

                if let Some(threshold) = self.config.slow_call_threshold {
                    if duration > threshold {
                        self.record_slow_call().await;
                    }
                }

                match result {
                    Ok(value) => {
                        self.record_success().await;
                        Ok(value)
                    }
                    Err(e) => {
                        self.record_failure().await;
                        Err(CircuitBreakerError::ServiceError(e))
                    }
                }
            }
            Err(_) => {
                self.record_failure().await;
                Err(CircuitBreakerError::Timeout)
            }
        }
    }

    /// Record a slow call
    async fn record_slow_call(&self) {
        self.stats.slow_calls.fetch_add(1, Ordering::Relaxed);

        let mut state = self.state.write().await;
        state.slow_call_count += 1;
        state.window_call_count += 1;

        // Check if slow call rate exceeds threshold
        if let Some(rate_threshold) = self.config.slow_call_rate_threshold {
            if state.window_call_count >= 10 {
                // Minimum sample size
                let rate = state.slow_call_count as f64 / state.window_call_count as f64;
                if rate >= rate_threshold {
                    tracing::warn!(
                        circuit = %self.name,
                        slow_call_rate = %rate,
                        threshold = %rate_threshold,
                        "Slow call rate exceeded threshold, opening circuit"
                    );
                    self.transition_to_open(&mut state);
                }
            }
        }
    }

    /// Get statistics
    pub fn stats(&self) -> &CircuitBreakerStats {
        &self.stats
    }

    /// Force the circuit to open
    pub async fn force_open(&self) {
        let mut state = self.state.write().await;
        self.transition_to_open(&mut state);
    }

    /// Force the circuit to close
    pub async fn force_close(&self) {
        let mut state = self.state.write().await;
        self.transition_to_closed(&mut state);
    }

    /// Reset the circuit breaker
    pub async fn reset(&self) {
        let mut state = self.state.write().await;
        *state = InternalState::default();
    }

    // Internal state transition methods

    fn maybe_transition(&self, state: &mut InternalState) {
        if state.state == CircuitState::Open {
            if let Some(opened_at) = state.opened_at {
                // Use dynamic backoff duration instead of fixed open_timeout
                if opened_at.elapsed() >= state.current_backoff {
                    self.transition_to_half_open(state);
                }
            }
        }
    }

    fn transition_to_open(&self, state: &mut InternalState) {
        state.consecutive_opens += 1;

        // Calculate exponential backoff with jitter
        let base_backoff = self.config.open_timeout.as_secs_f64();
        let multiplier = self.config.backoff_multiplier.powi(state.consecutive_opens.saturating_sub(1) as i32);
        let backoff_secs = base_backoff * multiplier;

        // Cap at max backoff
        let capped_backoff = backoff_secs.min(self.config.max_backoff.as_secs_f64());

        // Add jitter to prevent thundering herd
        let jitter = if self.config.jitter_factor > 0.0 {
            let jitter_range = capped_backoff * self.config.jitter_factor;
            // Use a simple pseudo-random based on current time
            let now_nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos() as f64
                / 1_000_000_000.0;
            jitter_range * now_nanos
        } else {
            0.0
        };

        let final_backoff = Duration::from_secs_f64(capped_backoff + jitter);
        state.current_backoff = final_backoff;

        tracing::warn!(
            circuit = %self.name,
            failures = state.failure_count,
            consecutive_opens = state.consecutive_opens,
            backoff_secs = ?final_backoff,
            "Circuit breaker opened with exponential backoff"
        );

        state.state = CircuitState::Open;
        state.opened_at = Some(Instant::now());
        state.success_count = 0;
        state.half_open_requests = 0;
        state.slow_call_count = 0;
        state.window_call_count = 0;
        self.stats.times_opened.fetch_add(1, Ordering::Relaxed);
    }

    fn transition_to_half_open(&self, state: &mut InternalState) {
        tracing::info!(
            circuit = %self.name,
            consecutive_opens = state.consecutive_opens,
            "Circuit breaker transitioning to half-open"
        );

        state.state = CircuitState::HalfOpen;
        state.success_count = 0;
        state.half_open_requests = 0;
    }

    fn transition_to_closed(&self, state: &mut InternalState) {
        tracing::info!(
            circuit = %self.name,
            consecutive_opens = state.consecutive_opens,
            "Circuit breaker closed, resetting backoff"
        );

        state.state = CircuitState::Closed;
        state.failure_count = 0;
        state.success_count = 0;
        state.opened_at = None;
        state.half_open_requests = 0;
        state.consecutive_opens = 0; // Reset on successful close
        state.current_backoff = self.config.open_timeout;
        state.slow_call_count = 0;
        state.window_call_count = 0;
        self.stats.times_closed.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the current backoff duration
    pub async fn current_backoff(&self) -> Duration {
        let state = self.state.read().await;
        state.current_backoff
    }

    /// Get the number of consecutive times the circuit has opened
    pub async fn consecutive_opens(&self) -> u32 {
        let state = self.state.read().await;
        state.consecutive_opens
    }
}

/// Error type for circuit breaker protected calls
#[derive(Debug)]
pub enum CircuitBreakerError<E> {
    /// Circuit is open, request rejected
    CircuitOpen,
    /// Underlying service error
    ServiceError(E),
    /// Operation timed out
    Timeout,
}

impl<E: std::fmt::Display> std::fmt::Display for CircuitBreakerError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitBreakerError::CircuitOpen => write!(f, "circuit breaker is open"),
            CircuitBreakerError::ServiceError(e) => write!(f, "service error: {}", e),
            CircuitBreakerError::Timeout => write!(f, "operation timed out"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for CircuitBreakerError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CircuitBreakerError::CircuitOpen => None,
            CircuitBreakerError::ServiceError(e) => Some(e),
            CircuitBreakerError::Timeout => None,
        }
    }
}

// ============================================================================
// Circuit Breaker Registry
// ============================================================================

/// Registry for managing multiple circuit breakers
pub struct CircuitBreakerRegistry {
    breakers: RwLock<std::collections::HashMap<String, Arc<CircuitBreaker>>>,
}

impl CircuitBreakerRegistry {
    /// Create a new registry
    pub fn new() -> Self {
        Self {
            breakers: RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Get or create a circuit breaker
    pub async fn get_or_create(&self, name: &str) -> Arc<CircuitBreaker> {
        {
            let breakers = self.breakers.read().await;
            if let Some(cb) = breakers.get(name) {
                return cb.clone();
            }
        }

        let mut breakers = self.breakers.write().await;
        breakers
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(CircuitBreaker::new(name)))
            .clone()
    }

    /// Get a circuit breaker by name
    pub async fn get(&self, name: &str) -> Option<Arc<CircuitBreaker>> {
        let breakers = self.breakers.read().await;
        breakers.get(name).cloned()
    }

    /// Register a circuit breaker with custom config
    pub async fn register(&self, name: &str, config: CircuitBreakerConfig) -> Arc<CircuitBreaker> {
        let mut breakers = self.breakers.write().await;
        let cb = Arc::new(CircuitBreaker::with_config(name, config));
        breakers.insert(name.to_string(), cb.clone());
        cb
    }

    /// Get status of all circuit breakers
    pub async fn status(&self) -> serde_json::Value {
        let breakers = self.breakers.read().await;
        let mut status = serde_json::Map::new();

        for (name, cb) in breakers.iter() {
            status.insert(
                name.clone(),
                serde_json::json!({
                    "state": cb.state().await.to_string(),
                    "stats": cb.stats().to_json(),
                }),
            );
        }

        serde_json::Value::Object(status)
    }
}

impl Default for CircuitBreakerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_circuit_breaker_closed() {
        let cb = CircuitBreaker::new("test");
        assert_eq!(cb.state().await, CircuitState::Closed);
        assert!(cb.is_allowed().await);
    }

    #[tokio::test]
    async fn test_circuit_breaker_opens_on_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let cb = CircuitBreaker::with_config("test", config);

        // Record failures
        cb.record_failure().await;
        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Closed);

        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Open);
        assert!(!cb.is_allowed().await);
    }

    #[tokio::test]
    async fn test_circuit_breaker_half_open() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            open_timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let cb = CircuitBreaker::with_config("test", config);

        // Open the circuit
        cb.record_failure().await;
        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Open);

        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Should transition to half-open
        assert_eq!(cb.state().await, CircuitState::HalfOpen);
        assert!(cb.is_allowed().await);
    }

    #[tokio::test]
    async fn test_circuit_breaker_closes_on_success() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            open_timeout: Duration::from_millis(10),
            ..Default::default()
        };
        let cb = CircuitBreaker::with_config("test", config);

        // Open the circuit
        cb.record_failure().await;
        cb.record_failure().await;

        // Wait for half-open
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(cb.state().await, CircuitState::HalfOpen);

        // Record successes
        cb.record_success().await;
        cb.record_success().await;

        assert_eq!(cb.state().await, CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_circuit_breaker_call() {
        let cb = CircuitBreaker::new("test");

        // Successful call
        let result: Result<i32, CircuitBreakerError<&str>> =
            cb.call(async { Ok::<i32, &str>(42) }).await;
        assert_eq!(result.unwrap(), 42);

        // Failed call
        let result: Result<i32, CircuitBreakerError<&str>> =
            cb.call(async { Err::<i32, &str>("error") }).await;
        assert!(matches!(result, Err(CircuitBreakerError::ServiceError(_))));
    }

    #[tokio::test]
    async fn test_circuit_breaker_stats() {
        let cb = CircuitBreaker::new("test");

        cb.record_success().await;
        cb.record_success().await;
        cb.record_failure().await;

        assert_eq!(cb.stats().successes.load(Ordering::Relaxed), 2);
        assert_eq!(cb.stats().failures.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_circuit_breaker_registry() {
        let registry = CircuitBreakerRegistry::new();

        let cb1 = registry.get_or_create("anchor").await;
        let cb2 = registry.get_or_create("anchor").await;

        // Should return the same instance
        assert!(Arc::ptr_eq(&cb1, &cb2));

        let status = registry.status().await;
        assert!(status.get("anchor").is_some());
    }
}
