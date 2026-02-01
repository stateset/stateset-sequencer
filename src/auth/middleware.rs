//! Authentication middleware for Axum
//!
//! Extracts authentication from requests and enforces authorization.

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use uuid::Uuid;

use super::{ApiKeyStore, ApiKeyValidator, AuthContext, AuthError, JwtValidator, Permissions, API_KEY_PREFIX};

/// Combined authenticator supporting both API keys and JWT
pub struct Authenticator {
    api_key_validator: Arc<ApiKeyValidator>,
    api_key_store: Option<Arc<dyn ApiKeyStore>>,
    jwt_validator: Option<Arc<JwtValidator>>,
}

impl Authenticator {
    pub fn new(api_key_validator: Arc<ApiKeyValidator>) -> Self {
        Self {
            api_key_validator,
            api_key_store: None,
            jwt_validator: None,
        }
    }

    pub fn with_api_key_store(mut self, store: Arc<dyn ApiKeyStore>) -> Self {
        self.api_key_store = Some(store);
        self
    }

    pub fn with_jwt(mut self, jwt_validator: Arc<JwtValidator>) -> Self {
        self.jwt_validator = Some(jwt_validator);
        self
    }

    /// Get the JWT validator (if configured)
    pub fn jwt_validator(&self) -> Option<&Arc<JwtValidator>> {
        self.jwt_validator.as_ref()
    }

    /// Validate an API key synchronously (in-memory only)
    ///
    /// This is used by the gRPC interceptor which needs sync validation.
    /// Only checks the in-memory key store, not the database.
    pub fn validate_api_key(&self, key: &str) -> Result<AuthContext, AuthError> {
        if !key.starts_with(API_KEY_PREFIX) {
            return Err(AuthError::InvalidApiKey);
        }
        self.api_key_validator.validate(key)
    }

    /// Authenticate a request
    pub async fn authenticate(&self, auth_header: Option<&str>) -> Result<AuthContext, AuthError> {
        let header = auth_header.ok_or(AuthError::MissingAuth)?;

        // Check for Bearer token (JWT)
        if let Some(token) = header.strip_prefix("Bearer ") {
            if let Some(jwt) = &self.jwt_validator {
                return jwt.validate(token);
            }
            return Err(AuthError::InvalidJwt("JWT not configured".to_string()));
        }

        // Check for API key
        if let Some(key) = header.strip_prefix("ApiKey ") {
            return self.authenticate_api_key(key).await;
        }

        // Try as raw API key
        if header.starts_with(API_KEY_PREFIX) {
            return self.authenticate_api_key(header).await;
        }

        Err(AuthError::MissingAuth)
    }

    async fn authenticate_api_key(&self, key: &str) -> Result<AuthContext, AuthError> {
        if !key.starts_with(API_KEY_PREFIX) {
            return Err(AuthError::InvalidApiKey);
        }

        let Some(store) = &self.api_key_store else {
            return self.api_key_validator.validate(key);
        };

        let key_hash = ApiKeyValidator::hash_key(key);
        let record = store.get_by_hash(&key_hash).await?;
        let Some(record) = record else {
            return Err(AuthError::InvalidApiKey);
        };

        if !record.active {
            return Err(AuthError::InvalidApiKey);
        }

        Ok(record.to_auth_context())
    }
}

/// Auth context extension for request
#[derive(Clone)]
pub struct AuthContextExt(pub AuthContext);

/// Authentication middleware configuration/state.
#[derive(Clone)]
pub struct AuthMiddlewareState {
    pub authenticator: Arc<Authenticator>,
    /// If false, requests are treated as fully authorized (dev mode).
    pub require_auth: bool,
    /// Optional global rate limiter.
    pub rate_limiter: Option<Arc<RateLimiter>>,
}

/// Authentication middleware
pub async fn auth_middleware(
    State(state): State<AuthMiddlewareState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    // Extract auth header
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let context = match state.authenticator.authenticate(auth_header).await {
        Ok(context) => context,
        Err(e) if state.require_auth => return auth_error_response(e),
        Err(_) => AuthContext {
            tenant_id: Uuid::nil(),
            store_ids: Vec::new(),
            agent_id: None,
            permissions: Permissions::admin(),
        },
    };

    if let Some(ref limiter) = state.rate_limiter {
        let key = if context.tenant_id.is_nil() {
            "bootstrap".to_string()
        } else {
            format!("tenant:{}", context.tenant_id)
        };
        if let Err(e) = limiter.check(&key) {
            return auth_error_response(e);
        }
    }

    // Add auth context to request extensions
    request.extensions_mut().insert(AuthContextExt(context));
    next.run(request).await
}

/// Convert auth error to HTTP response
fn auth_error_response(error: AuthError) -> Response {
    let (status, message) = match error {
        AuthError::MissingAuth => (StatusCode::UNAUTHORIZED, "Missing authentication"),
        AuthError::InvalidApiKey => (StatusCode::UNAUTHORIZED, "Invalid API key"),
        AuthError::InvalidJwt(_) => (StatusCode::UNAUTHORIZED, "Invalid JWT"),
        AuthError::TokenExpired => (StatusCode::UNAUTHORIZED, "Token expired"),
        AuthError::InsufficientPermissions => (StatusCode::FORBIDDEN, "Insufficient permissions"),
        AuthError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded"),
        AuthError::TenantNotFound => (StatusCode::NOT_FOUND, "Tenant not found"),
        AuthError::StoreAccessDenied => (StatusCode::FORBIDDEN, "Store access denied"),
    };

    (
        status,
        axum::Json(serde_json::json!({
            "error": message,
            "code": format!("{:?}", error).to_lowercase()
        })),
    )
        .into_response()
}

/// Rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    /// Requests per minute per key
    pub requests_per_minute: u32,
    /// Maximum number of keys to track (bounded storage to prevent memory exhaustion)
    pub max_entries: usize,
    /// Window duration in seconds (default: 60)
    pub window_seconds: u64,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 100,
            max_entries: 10_000, // Bound memory usage
            window_seconds: 60,
        }
    }
}

impl RateLimiterConfig {
    /// Load from environment variables
    pub fn from_env() -> Self {
        let requests_per_minute = std::env::var("RATE_LIMIT_PER_MINUTE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);

        let max_entries = std::env::var("RATE_LIMIT_MAX_ENTRIES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10_000);

        let window_seconds = std::env::var("RATE_LIMIT_WINDOW_SECONDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);

        Self {
            requests_per_minute,
            max_entries,
            window_seconds,
        }
    }
}

/// Rate limit entry with timestamp and count
struct RateLimitEntry {
    count: u32,
    window_start: std::time::Instant,
}

/// Rate limiter for API requests with bounded storage
///
/// Features:
/// - Per-key rate limiting with sliding window
/// - Bounded storage to prevent memory exhaustion (LRU-like eviction)
/// - Metrics integration for observability
/// - Configurable window duration
pub struct RateLimiter {
    config: RateLimiterConfig,
    /// In-memory request counts with bounded size
    /// Keys: hash of (tenant_id or API key)
    /// Values: (count, window_start_time)
    entries: std::sync::RwLock<std::collections::HashMap<String, RateLimitEntry>>,
    /// Metrics counters
    requests_allowed: std::sync::atomic::AtomicU64,
    requests_rejected: std::sync::atomic::AtomicU64,
    entries_evicted: std::sync::atomic::AtomicU64,
}

impl RateLimiter {
    /// Create a new rate limiter with the given requests per minute limit
    pub fn new(requests_per_minute: u32) -> Self {
        Self::with_config(RateLimiterConfig {
            requests_per_minute,
            ..Default::default()
        })
    }

    /// Create a new rate limiter with full configuration
    pub fn with_config(config: RateLimiterConfig) -> Self {
        Self {
            config,
            entries: std::sync::RwLock::new(std::collections::HashMap::new()),
            requests_allowed: std::sync::atomic::AtomicU64::new(0),
            requests_rejected: std::sync::atomic::AtomicU64::new(0),
            entries_evicted: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Check if request is allowed
    pub fn check(&self, key: &str) -> Result<(), AuthError> {
        let mut entries = self.entries.write().unwrap();
        let now = std::time::Instant::now();
        let window_duration = std::time::Duration::from_secs(self.config.window_seconds);

        // Evict expired entries and enforce max_entries limit
        if entries.len() >= self.config.max_entries {
            self.evict_expired_entries(&mut entries, now, window_duration);

            // If still at capacity, evict oldest entries (at least 10% or 1)
            if entries.len() >= self.config.max_entries {
                let evict_count = std::cmp::max(self.config.max_entries / 10, 1);
                self.evict_oldest_entries(&mut entries, evict_count);
            }
        }

        let entry = entries.entry(key.to_string()).or_insert(RateLimitEntry {
            count: 0,
            window_start: now,
        });

        // Reset counter if window has passed
        if now.duration_since(entry.window_start) >= window_duration {
            entry.count = 0;
            entry.window_start = now;
        }

        // Check limit
        if entry.count >= self.config.requests_per_minute {
            self.requests_rejected
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(AuthError::RateLimited);
        }

        // Increment counter
        entry.count += 1;
        self.requests_allowed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        Ok(())
    }

    /// Evict expired entries (older than window)
    fn evict_expired_entries(
        &self,
        entries: &mut std::collections::HashMap<String, RateLimitEntry>,
        now: std::time::Instant,
        window_duration: std::time::Duration,
    ) {
        let before = entries.len();
        entries.retain(|_, entry| now.duration_since(entry.window_start) < window_duration);
        let evicted = before - entries.len();
        if evicted > 0 {
            self.entries_evicted
                .fetch_add(evicted as u64, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Evict oldest entries to make room (simple LRU-like behavior)
    fn evict_oldest_entries(
        &self,
        entries: &mut std::collections::HashMap<String, RateLimitEntry>,
        count: usize,
    ) {
        // Find oldest entries by window_start time
        let mut entries_vec: Vec<_> = entries.iter().collect();
        entries_vec.sort_by_key(|(_, entry)| entry.window_start);

        let keys_to_remove: Vec<String> = entries_vec
            .iter()
            .take(count)
            .map(|(k, _)| (*k).clone())
            .collect();

        for key in &keys_to_remove {
            entries.remove(key);
        }

        self.entries_evicted
            .fetch_add(keys_to_remove.len() as u64, std::sync::atomic::Ordering::Relaxed);
    }

    /// Get remaining requests for a key
    pub fn remaining(&self, key: &str) -> u32 {
        let entries = self.entries.read().unwrap();
        let now = std::time::Instant::now();
        let window_duration = std::time::Duration::from_secs(self.config.window_seconds);

        match entries.get(key) {
            Some(entry) => {
                if now.duration_since(entry.window_start) >= window_duration {
                    self.config.requests_per_minute
                } else {
                    self.config.requests_per_minute.saturating_sub(entry.count)
                }
            }
            None => self.config.requests_per_minute,
        }
    }

    /// Get time until rate limit resets for a key (in seconds)
    pub fn reset_after(&self, key: &str) -> u64 {
        let entries = self.entries.read().unwrap();
        let now = std::time::Instant::now();
        let window_duration = std::time::Duration::from_secs(self.config.window_seconds);

        match entries.get(key) {
            Some(entry) => {
                let elapsed = now.duration_since(entry.window_start);
                if elapsed >= window_duration {
                    0
                } else {
                    (window_duration - elapsed).as_secs()
                }
            }
            None => 0,
        }
    }

    /// Get metrics for this rate limiter
    pub fn metrics(&self) -> RateLimiterMetrics {
        RateLimiterMetrics {
            requests_allowed: self
                .requests_allowed
                .load(std::sync::atomic::Ordering::Relaxed),
            requests_rejected: self
                .requests_rejected
                .load(std::sync::atomic::Ordering::Relaxed),
            entries_evicted: self
                .entries_evicted
                .load(std::sync::atomic::Ordering::Relaxed),
            current_entries: self.entries.read().unwrap().len(),
            max_entries: self.config.max_entries,
            requests_per_minute: self.config.requests_per_minute,
        }
    }

    /// Get current number of tracked keys
    pub fn entry_count(&self) -> usize {
        self.entries.read().unwrap().len()
    }
}

/// Rate limiter metrics for observability
#[derive(Debug, Clone)]
pub struct RateLimiterMetrics {
    /// Total requests that were allowed
    pub requests_allowed: u64,
    /// Total requests that were rejected (rate limited)
    pub requests_rejected: u64,
    /// Total entries that were evicted
    pub entries_evicted: u64,
    /// Current number of tracked entries
    pub current_entries: usize,
    /// Maximum allowed entries
    pub max_entries: usize,
    /// Configured requests per minute
    pub requests_per_minute: u32,
}

/// Request body size limits for abuse protection
#[derive(Debug, Clone)]
pub struct RequestLimits {
    /// Maximum request body size in bytes (default: 10MB)
    pub max_body_size: usize,
    /// Maximum events per ingest batch (default: 1000)
    pub max_events_per_batch: usize,
    /// Maximum payload size per event in bytes (default: 1MB)
    pub max_event_payload_size: usize,
}

impl Default for RequestLimits {
    fn default() -> Self {
        Self {
            max_body_size: 10 * 1024 * 1024,       // 10MB
            max_events_per_batch: 1000,            // 1000 events
            max_event_payload_size: 1024 * 1024,   // 1MB
        }
    }
}

impl RequestLimits {
    /// Load from environment variables
    pub fn from_env() -> Self {
        let max_body_size = std::env::var("MAX_BODY_SIZE_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10 * 1024 * 1024);

        let max_events_per_batch = std::env::var("MAX_EVENTS_PER_BATCH")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1000);

        let max_event_payload_size = std::env::var("MAX_EVENT_PAYLOAD_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1024 * 1024);

        Self {
            max_body_size,
            max_events_per_batch,
            max_event_payload_size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(5);
        let key = "test-key";

        // First 5 requests should succeed
        for _ in 0..5 {
            assert!(limiter.check(key).is_ok());
        }

        // 6th request should fail
        assert!(matches!(limiter.check(key), Err(AuthError::RateLimited)));
    }

    #[test]
    fn test_remaining_requests() {
        let limiter = RateLimiter::new(10);
        let key = "test-key";

        assert_eq!(limiter.remaining(key), 10);

        limiter.check(key).unwrap();
        assert_eq!(limiter.remaining(key), 9);

        for _ in 0..4 {
            limiter.check(key).unwrap();
        }
        assert_eq!(limiter.remaining(key), 5);
    }

    #[test]
    fn test_rate_limiter_metrics() {
        let limiter = RateLimiter::new(3);
        let key = "test-key";

        // Make some successful requests
        for _ in 0..3 {
            assert!(limiter.check(key).is_ok());
        }

        // This should fail
        assert!(limiter.check(key).is_err());
        assert!(limiter.check(key).is_err());

        let metrics = limiter.metrics();
        assert_eq!(metrics.requests_allowed, 3);
        assert_eq!(metrics.requests_rejected, 2);
        assert_eq!(metrics.current_entries, 1);
    }

    #[test]
    fn test_rate_limiter_bounded_storage() {
        let config = RateLimiterConfig {
            requests_per_minute: 100,
            max_entries: 5,
            window_seconds: 60,
        };
        let limiter = RateLimiter::with_config(config);

        // Create entries up to the limit and beyond
        // Eviction happens when len >= max_entries before inserting
        for i in 0..20 {
            let key = format!("key-{}", i);
            assert!(limiter.check(&key).is_ok());
        }

        // Should have evicted entries to stay bounded
        // After eviction, we may have slightly more than max_entries
        // because eviction happens before insert, not after
        let entry_count = limiter.entry_count();
        assert!(
            entry_count <= 6, // max_entries + 1 (just inserted)
            "Entry count {} exceeds expected bound",
            entry_count
        );

        let metrics = limiter.metrics();
        // Should have evicted at least some entries (we created 20, max is 5)
        assert!(
            metrics.entries_evicted > 0,
            "Expected some evictions, got 0"
        );
    }

    #[test]
    fn test_rate_limiter_multiple_keys() {
        let limiter = RateLimiter::new(3);

        // Different keys should have separate limits
        for _ in 0..3 {
            assert!(limiter.check("key-a").is_ok());
            assert!(limiter.check("key-b").is_ok());
        }

        // Both should be at their limits now
        assert!(limiter.check("key-a").is_err());
        assert!(limiter.check("key-b").is_err());

        // But a new key should still work
        assert!(limiter.check("key-c").is_ok());
    }

    #[test]
    fn test_rate_limiter_config_from_default() {
        let config = RateLimiterConfig::default();
        assert_eq!(config.requests_per_minute, 100);
        assert_eq!(config.max_entries, 10_000);
        assert_eq!(config.window_seconds, 60);
    }

    #[test]
    fn test_request_limits_default() {
        let limits = RequestLimits::default();
        assert_eq!(limits.max_body_size, 10 * 1024 * 1024);
        assert_eq!(limits.max_events_per_batch, 1000);
        assert_eq!(limits.max_event_payload_size, 1024 * 1024);
    }
}
