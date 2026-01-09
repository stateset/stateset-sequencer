//! Retry utilities with exponential backoff and jitter
//!
//! Provides robust retry logic for transient failures with:
//! - Exponential backoff to prevent thundering herd
//! - Configurable jitter to spread out retries
//! - Maximum retry limits
//! - Custom retry predicates
//! - Async-friendly design

use std::future::Future;
use std::time::Duration;

use rand::Rng;

/// Configuration for retry behavior
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts (0 = no retries, just the initial attempt)
    pub max_retries: u32,
    /// Initial delay before first retry
    pub initial_delay: Duration,
    /// Maximum delay between retries (caps exponential growth)
    pub max_delay: Duration,
    /// Multiplier for exponential backoff (e.g., 2.0 = double each time)
    pub multiplier: f64,
    /// Jitter factor (0.0-1.0) - randomness to spread retries
    /// 0.0 = no jitter, 1.0 = full jitter (delay can be 0 to 2x calculated)
    pub jitter: f64,
    /// Whether to use decorrelated jitter (recommended for high concurrency)
    pub decorrelated_jitter: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            multiplier: 2.0,
            jitter: 0.5, // 50% jitter by default
            decorrelated_jitter: true,
        }
    }
}

impl RetryConfig {
    /// Create a config for fast retries (good for local/in-memory operations)
    pub fn fast() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(500),
            multiplier: 2.0,
            jitter: 0.3,
            decorrelated_jitter: false,
        }
    }

    /// Create a config for database operations
    pub fn database() -> Self {
        Self {
            max_retries: 5,
            initial_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(5),
            multiplier: 2.0,
            jitter: 0.5,
            decorrelated_jitter: true,
        }
    }

    /// Create a config for external service calls (more patient)
    pub fn external_service() -> Self {
        Self {
            max_retries: 5,
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(60),
            multiplier: 2.0,
            jitter: 0.5,
            decorrelated_jitter: true,
        }
    }

    /// Create a config for anchor/blockchain operations (most patient)
    pub fn blockchain() -> Self {
        Self {
            max_retries: 10,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(300), // 5 minutes max
            multiplier: 1.5,
            jitter: 0.5,
            decorrelated_jitter: true,
        }
    }

    /// Set the maximum number of retries
    pub fn with_max_retries(mut self, max: u32) -> Self {
        self.max_retries = max;
        self
    }

    /// Set the initial delay
    pub fn with_initial_delay(mut self, delay: Duration) -> Self {
        self.initial_delay = delay;
        self
    }

    /// Set the maximum delay
    pub fn with_max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    /// Set the multiplier
    pub fn with_multiplier(mut self, multiplier: f64) -> Self {
        self.multiplier = multiplier;
        self
    }

    /// Set the jitter factor
    pub fn with_jitter(mut self, jitter: f64) -> Self {
        self.jitter = jitter.clamp(0.0, 1.0);
        self
    }

    /// Calculate delay for a given attempt (0-indexed)
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let base_delay = self.initial_delay.as_secs_f64() * self.multiplier.powi(attempt as i32);
        let capped_delay = base_delay.min(self.max_delay.as_secs_f64());

        let final_delay = if self.jitter > 0.0 {
            if self.decorrelated_jitter {
                // Decorrelated jitter: delay = random(initial_delay, previous_delay * 3)
                // This provides better spread for high-concurrency scenarios
                let min_delay = self.initial_delay.as_secs_f64();
                let max_delay = (capped_delay * 3.0).min(self.max_delay.as_secs_f64());
                let mut rng = rand::thread_rng();
                rng.gen_range(min_delay..=max_delay)
            } else {
                // Standard jitter: add/subtract random portion of delay
                let jitter_range = capped_delay * self.jitter;
                let mut rng = rand::thread_rng();
                let jitter_offset = rng.gen_range(-jitter_range..=jitter_range);
                (capped_delay + jitter_offset).max(0.0)
            }
        } else {
            capped_delay
        };

        Duration::from_secs_f64(final_delay)
    }
}

/// Result of a retry operation
#[derive(Debug)]
pub struct RetryResult<T, E> {
    /// The final result (success or last error)
    pub result: Result<T, E>,
    /// Number of attempts made (1 = succeeded on first try)
    pub attempts: u32,
    /// Total time spent on retries (including delays)
    pub total_duration: Duration,
}

impl<T, E> RetryResult<T, E> {
    /// Check if the operation succeeded
    pub fn is_success(&self) -> bool {
        self.result.is_ok()
    }

    /// Get the result, consuming self
    pub fn into_result(self) -> Result<T, E> {
        self.result
    }
}

/// A retry executor that can run operations with retry logic
pub struct Retry {
    config: RetryConfig,
}

impl Retry {
    /// Create a new retry executor with the given config
    pub fn new(config: RetryConfig) -> Self {
        Self { config }
    }

    /// Create a retry executor with default config
    pub fn default_config() -> Self {
        Self::new(RetryConfig::default())
    }

    /// Run an operation with retry logic
    ///
    /// The operation will be retried on failure up to `max_retries` times.
    pub async fn run<F, Fut, T, E>(&self, operation: F) -> RetryResult<T, E>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        self.run_with_predicate(operation, |_| true).await
    }

    /// Run an operation with retry logic and a custom retry predicate
    ///
    /// The `should_retry` predicate receives the error and returns true if
    /// the operation should be retried.
    pub async fn run_with_predicate<F, Fut, T, E, P>(
        &self,
        operation: F,
        should_retry: P,
    ) -> RetryResult<T, E>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        P: Fn(&E) -> bool,
    {
        let start = std::time::Instant::now();
        let mut attempts = 0;

        loop {
            attempts += 1;

            match operation().await {
                Ok(value) => {
                    return RetryResult {
                        result: Ok(value),
                        attempts,
                        total_duration: start.elapsed(),
                    };
                }
                Err(e) => {
                    // Check if we should retry
                    if attempts > self.config.max_retries || !should_retry(&e) {
                        return RetryResult {
                            result: Err(e),
                            attempts,
                            total_duration: start.elapsed(),
                        };
                    }

                    // Calculate delay and wait
                    let delay = self.config.delay_for_attempt(attempts - 1);

                    tracing::debug!(
                        attempt = attempts,
                        max_retries = self.config.max_retries,
                        delay_ms = delay.as_millis(),
                        "Retrying operation after failure"
                    );

                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    /// Run an operation with retry logic and context logging
    pub async fn run_with_context<F, Fut, T, E>(
        &self,
        context: &str,
        operation: F,
    ) -> RetryResult<T, E>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        E: std::fmt::Display,
    {
        let start = std::time::Instant::now();
        let mut attempts = 0;

        loop {
            attempts += 1;

            match operation().await {
                Ok(value) => {
                    if attempts > 1 {
                        tracing::info!(
                            context = context,
                            attempts = attempts,
                            duration_ms = start.elapsed().as_millis(),
                            "Operation succeeded after retries"
                        );
                    }
                    return RetryResult {
                        result: Ok(value),
                        attempts,
                        total_duration: start.elapsed(),
                    };
                }
                Err(e) => {
                    if attempts > self.config.max_retries {
                        tracing::warn!(
                            context = context,
                            attempts = attempts,
                            error = %e,
                            duration_ms = start.elapsed().as_millis(),
                            "Operation failed after all retries exhausted"
                        );
                        return RetryResult {
                            result: Err(e),
                            attempts,
                            total_duration: start.elapsed(),
                        };
                    }

                    let delay = self.config.delay_for_attempt(attempts - 1);

                    tracing::warn!(
                        context = context,
                        attempt = attempts,
                        max_retries = self.config.max_retries,
                        delay_ms = delay.as_millis(),
                        error = %e,
                        "Operation failed, will retry"
                    );

                    tokio::time::sleep(delay).await;
                }
            }
        }
    }
}

/// Convenience function to retry an operation with default config
pub async fn retry<F, Fut, T, E>(operation: F) -> Result<T, E>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    Retry::default_config().run(operation).await.into_result()
}

/// Convenience function to retry an operation with custom config
pub async fn retry_with_config<F, Fut, T, E>(config: RetryConfig, operation: F) -> Result<T, E>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    Retry::new(config).run(operation).await.into_result()
}

/// Check if an error is retryable (for database errors)
pub fn is_retryable_db_error(err: &sqlx::Error) -> bool {
    match err {
        // Connection errors are usually transient
        sqlx::Error::Io(_) => true,
        sqlx::Error::PoolTimedOut => true,
        sqlx::Error::PoolClosed => false, // Pool is intentionally closed
        // Serialization failures in transactions can be retried
        sqlx::Error::Database(db_err) => {
            let code = db_err.code().unwrap_or_default();
            // PostgreSQL serialization failure
            code == "40001"
                // PostgreSQL deadlock detected
                || code == "40P01"
                // Connection exceptions
                || code.starts_with("08")
                // Operator intervention (admin disconnected, crash recovery)
                || code.starts_with("57")
        }
        _ => false,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_retry_config_delay_calculation() {
        let config = RetryConfig {
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            multiplier: 2.0,
            jitter: 0.0, // No jitter for predictable testing
            decorrelated_jitter: false,
            max_retries: 5,
        };

        assert_eq!(config.delay_for_attempt(0), Duration::from_millis(100));
        assert_eq!(config.delay_for_attempt(1), Duration::from_millis(200));
        assert_eq!(config.delay_for_attempt(2), Duration::from_millis(400));
        assert_eq!(config.delay_for_attempt(3), Duration::from_millis(800));
        // Should cap at max_delay
        assert_eq!(config.delay_for_attempt(10), Duration::from_secs(10));
    }

    #[test]
    fn test_retry_config_with_jitter() {
        let config = RetryConfig::default().with_jitter(0.5);

        // With jitter, delays should vary
        let delays: Vec<_> = (0..10).map(|_| config.delay_for_attempt(2)).collect();

        // Not all delays should be the same (with high probability)
        let first = delays[0];
        let all_same = delays.iter().all(|d| *d == first);
        // This might occasionally fail due to randomness, but very unlikely
        assert!(!all_same || delays.len() < 5);
    }

    #[tokio::test]
    async fn test_retry_succeeds_first_try() {
        let retry = Retry::default_config();

        let result = retry.run(|| async { Ok::<_, &str>(42) }).await;

        assert!(result.is_success());
        assert_eq!(result.attempts, 1);
        assert_eq!(result.into_result().unwrap(), 42);
    }

    #[tokio::test]
    async fn test_retry_succeeds_after_failures() {
        let attempt_count = Arc::new(AtomicU32::new(0));
        let retry = Retry::new(RetryConfig::fast().with_max_retries(5));

        let count = attempt_count.clone();
        let result = retry
            .run(|| {
                let count = count.clone();
                async move {
                    let attempt = count.fetch_add(1, Ordering::SeqCst);
                    if attempt < 2 {
                        Err("not yet")
                    } else {
                        Ok(42)
                    }
                }
            })
            .await;

        assert!(result.is_success());
        assert_eq!(result.attempts, 3); // Failed twice, succeeded on third
        assert_eq!(result.into_result().unwrap(), 42);
    }

    #[tokio::test]
    async fn test_retry_exhausts_retries() {
        let retry = Retry::new(RetryConfig::fast().with_max_retries(2));

        let result = retry.run(|| async { Err::<i32, _>("always fails") }).await;

        assert!(!result.is_success());
        assert_eq!(result.attempts, 3); // Initial + 2 retries
        assert_eq!(result.into_result().unwrap_err(), "always fails");
    }

    #[tokio::test]
    async fn test_retry_with_predicate() {
        let attempt_count = Arc::new(AtomicU32::new(0));
        let retry = Retry::new(RetryConfig::fast().with_max_retries(5));

        #[derive(Debug, PartialEq)]
        enum TestError {
            Retryable,
            Fatal,
        }

        let count = attempt_count.clone();
        let result: RetryResult<i32, TestError> = retry
            .run_with_predicate(
                || {
                    let count = count.clone();
                    async move {
                        let attempt = count.fetch_add(1, Ordering::SeqCst);
                        if attempt == 0 {
                            Err(TestError::Retryable)
                        } else {
                            Err(TestError::Fatal)
                        }
                    }
                },
                |e| *e == TestError::Retryable,
            )
            .await;

        assert!(!result.is_success());
        assert_eq!(result.attempts, 2); // Stopped on fatal error
        assert_eq!(result.into_result().unwrap_err(), TestError::Fatal);
    }

    #[test]
    fn test_preset_configs() {
        let fast = RetryConfig::fast();
        assert!(fast.initial_delay < Duration::from_millis(50));

        let db = RetryConfig::database();
        assert!(db.max_retries >= 3);

        let external = RetryConfig::external_service();
        assert!(external.initial_delay >= Duration::from_millis(100));

        let blockchain = RetryConfig::blockchain();
        assert!(blockchain.max_retries >= 5);
        assert!(blockchain.max_delay >= Duration::from_secs(60));
    }

    #[tokio::test]
    async fn test_convenience_function() {
        let result = retry(|| async { Ok::<_, &str>(123) }).await;
        assert_eq!(result.unwrap(), 123);
    }
}
