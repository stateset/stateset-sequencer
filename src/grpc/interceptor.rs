//! gRPC authentication interceptor
//!
//! Validates API keys and JWT tokens from gRPC metadata.

use std::sync::Arc;

use tonic::{Request, Status};
use tracing::{debug, warn};

use crate::auth::{AuthContext, AuthError, Authenticator, Permissions};
use uuid::Uuid;

/// gRPC authentication interceptor
///
/// Extracts and validates credentials from gRPC request metadata.
///
/// Supported metadata keys:
/// - `authorization`: Bearer token (JWT) or API key
/// - `x-api-key`: API key (alternative)
/// - `x-tenant-id`: Tenant ID (for store-scoped keys)
#[derive(Clone)]
pub struct GrpcAuthInterceptor {
    authenticator: Arc<Authenticator>,
    require_auth: bool,
}

impl GrpcAuthInterceptor {
    pub fn new(authenticator: Arc<Authenticator>, require_auth: bool) -> Self {
        Self {
            authenticator,
            require_auth,
        }
    }

    /// Validate request and extract auth context
    pub fn authenticate<T>(&self, request: &Request<T>) -> Result<Option<AuthContext>, Status> {
        let metadata = request.metadata();

        // Try Authorization header first (Bearer token or raw API key)
        if let Some(auth_value) = metadata.get("authorization") {
            let auth_str = auth_value
                .to_str()
                .map_err(|_| Status::unauthenticated("invalid authorization header encoding"))?;

            // Check for Bearer prefix
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                return self.validate_bearer_token(token);
            }

            // Treat as raw API key
            return self.validate_api_key(auth_str);
        }

        // Try x-api-key header
        if let Some(api_key) = metadata.get("x-api-key") {
            let key_str = api_key
                .to_str()
                .map_err(|_| Status::unauthenticated("invalid api key header encoding"))?;
            return self.validate_api_key(key_str);
        }

        // No credentials found
        if self.require_auth {
            Err(Status::unauthenticated("authentication required"))
        } else {
            debug!("No auth credentials, auth not required - proceeding");
            Ok(Some(AuthContext {
                tenant_id: Uuid::nil(),
                store_ids: Vec::new(),
                agent_id: None,
                permissions: Permissions::admin(),
            }))
        }
    }

    fn validate_bearer_token(&self, token: &str) -> Result<Option<AuthContext>, Status> {
        // Try JWT first
        if let Some(jwt_validator) = self.authenticator.jwt_validator() {
            match jwt_validator.validate(token) {
                Ok(ctx) => {
                    debug!(tenant_id = %ctx.tenant_id, "JWT authenticated");
                    return Ok(Some(ctx));
                }
                Err(e) => {
                    debug!("JWT validation failed: {}, trying as API key", e);
                }
            }
        }

        // Fall back to API key
        self.validate_api_key(token)
    }

    fn validate_api_key(&self, key: &str) -> Result<Option<AuthContext>, Status> {
        match self.authenticator.validate_api_key(key) {
            Ok(ctx) => {
                debug!(tenant_id = %ctx.tenant_id, "API key authenticated");
                Ok(Some(ctx))
            }
            Err(AuthError::InvalidApiKey) => {
                warn!("Invalid API key provided");
                Err(Status::unauthenticated("invalid api key"))
            }
            Err(AuthError::RateLimited) => {
                warn!("Rate limit exceeded");
                Err(Status::resource_exhausted("rate limit exceeded"))
            }
            Err(e) => {
                warn!("Auth error: {}", e);
                Err(Status::unauthenticated(e.to_string()))
            }
        }
    }
}

/// Tonic interceptor implementation for auth
impl tonic::service::Interceptor for GrpcAuthInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let auth_ctx = self.authenticate(&request)?;

        if let Some(ctx) = auth_ctx {
            // Store auth context in request extensions for use in handlers
            request.extensions_mut().insert(ctx);
        }

        Ok(request)
    }
}

/// Extension trait to get auth context from gRPC request
pub trait AuthContextExt {
    fn auth_context(&self) -> Option<&AuthContext>;
}

impl<T> AuthContextExt for Request<T> {
    fn auth_context(&self) -> Option<&AuthContext> {
        self.extensions().get::<AuthContext>()
    }
}
