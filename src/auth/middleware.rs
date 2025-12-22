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

use super::{ApiKeyValidator, AuthContext, AuthError, JwtValidator, Permissions};

/// Combined authenticator supporting both API keys and JWT
pub struct Authenticator {
    api_key_validator: Arc<ApiKeyValidator>,
    jwt_validator: Option<Arc<JwtValidator>>,
}

impl Authenticator {
    pub fn new(api_key_validator: Arc<ApiKeyValidator>) -> Self {
        Self {
            api_key_validator,
            jwt_validator: None,
        }
    }

    pub fn with_jwt(mut self, jwt_validator: Arc<JwtValidator>) -> Self {
        self.jwt_validator = Some(jwt_validator);
        self
    }

    /// Authenticate a request
    pub fn authenticate(&self, auth_header: Option<&str>) -> Result<AuthContext, AuthError> {
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
            return self.api_key_validator.validate(key);
        }

        // Try as raw API key
        if header.starts_with("ss_") {
            return self.api_key_validator.validate(header);
        }

        Err(AuthError::MissingAuth)
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

    let context = match state.authenticator.authenticate(auth_header) {
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

/// Rate limiter for API requests
pub struct RateLimiter {
    /// Requests per minute per key
    requests_per_minute: u32,
    /// In-memory request counts (for development)
    /// Production should use Redis
    counts: std::sync::RwLock<std::collections::HashMap<String, (u32, std::time::Instant)>>,
}

impl RateLimiter {
    pub fn new(requests_per_minute: u32) -> Self {
        Self {
            requests_per_minute,
            counts: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Check if request is allowed
    pub fn check(&self, key: &str) -> Result<(), AuthError> {
        let mut counts = self.counts.write().unwrap();
        let now = std::time::Instant::now();

        let entry = counts.entry(key.to_string()).or_insert((0, now));

        // Reset counter if minute has passed
        if now.duration_since(entry.1).as_secs() >= 60 {
            *entry = (0, now);
        }

        // Check limit
        if entry.0 >= self.requests_per_minute {
            return Err(AuthError::RateLimited);
        }

        // Increment counter
        entry.0 += 1;

        Ok(())
    }

    /// Get remaining requests for a key
    pub fn remaining(&self, key: &str) -> u32 {
        let counts = self.counts.read().unwrap();
        let now = std::time::Instant::now();

        match counts.get(key) {
            Some((count, started)) => {
                if now.duration_since(*started).as_secs() >= 60 {
                    self.requests_per_minute
                } else {
                    self.requests_per_minute.saturating_sub(*count)
                }
            }
            None => self.requests_per_minute,
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
}
