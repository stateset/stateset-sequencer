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
    /// Duration to wait before transitioning from open to half-open
    pub open_timeout: Duration,
    /// Duration window for counting failures
    pub failure_window: Duration,
    /// Maximum requests allowed in half-open state
    pub half_open_max_requests: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 3,
            open_timeout: Duration::from_secs(30),
            failure_window: Duration::from_secs(60),
            half_open_max_requests: 3,
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
}

impl CircuitBreakerStats {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "successes": self.successes.load(Ordering::Relaxed),
            "failures": self.failures.load(Ordering::Relaxed),
            "rejected": self.rejected.load(Ordering::Relaxed),
            "times_opened": self.times_opened.load(Ordering::Relaxed),
            "times_closed": self.times_closed.load(Ordering::Relaxed),
        })
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

        match f.await {
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
                if opened_at.elapsed() >= self.config.open_timeout {
                    self.transition_to_half_open(state);
                }
            }
        }
    }

    fn transition_to_open(&self, state: &mut InternalState) {
        tracing::warn!(
            circuit = %self.name,
            failures = state.failure_count,
            "Circuit breaker opened"
        );

        state.state = CircuitState::Open;
        state.opened_at = Some(Instant::now());
        state.success_count = 0;
        state.half_open_requests = 0;
        self.stats.times_opened.fetch_add(1, Ordering::Relaxed);
    }

    fn transition_to_half_open(&self, state: &mut InternalState) {
        tracing::info!(
            circuit = %self.name,
            "Circuit breaker transitioning to half-open"
        );

        state.state = CircuitState::HalfOpen;
        state.success_count = 0;
        state.half_open_requests = 0;
    }

    fn transition_to_closed(&self, state: &mut InternalState) {
        tracing::info!(
            circuit = %self.name,
            "Circuit breaker closed"
        );

        state.state = CircuitState::Closed;
        state.failure_count = 0;
        state.success_count = 0;
        state.opened_at = None;
        state.half_open_requests = 0;
        self.stats.times_closed.fetch_add(1, Ordering::Relaxed);
    }
}

/// Error type for circuit breaker protected calls
#[derive(Debug)]
pub enum CircuitBreakerError<E> {
    /// Circuit is open, request rejected
    CircuitOpen,
    /// Underlying service error
    ServiceError(E),
}

impl<E: std::fmt::Display> std::fmt::Display for CircuitBreakerError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitBreakerError::CircuitOpen => write!(f, "circuit breaker is open"),
            CircuitBreakerError::ServiceError(e) => write!(f, "service error: {}", e),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for CircuitBreakerError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CircuitBreakerError::CircuitOpen => None,
            CircuitBreakerError::ServiceError(e) => Some(e),
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
