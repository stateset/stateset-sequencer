//! gRPC authentication interceptor
//!
//! Validates API keys and JWT tokens from gRPC metadata.
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use tonic::{Request, Status};
use tracing::{debug, warn};

use crate::auth::{credential_rate_limit_key, AuthContext, AuthError, Authenticator, RateLimiter};

/// gRPC authentication interceptor with optional rate limiting
///
/// Extracts and validates credentials from gRPC request metadata,
/// then applies rate limiting per tenant if configured.
///
/// Supported metadata keys:
/// - `authorization`: Bearer token (JWT) or API key
/// - `x-api-key`: API key (alternative)
/// - `x-tenant-id`: Tenant ID (for store-scoped keys)
#[derive(Clone)]
pub struct GrpcAuthInterceptor {
    authenticator: Arc<Authenticator>,
    require_auth: bool,
    rate_limiter: Option<Arc<RateLimiter>>,
    credential_rate_limiter: Arc<RateLimiter>,
}

impl GrpcAuthInterceptor {
    pub fn new(
        authenticator: Arc<Authenticator>,
        require_auth: bool,
        rate_limiter: Option<Arc<RateLimiter>>,
        credential_rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        Self {
            authenticator,
            require_auth,
            rate_limiter,
            credential_rate_limiter,
        }
    }

    /// Validate request, extract auth context, and enforce rate limits
    pub fn authenticate<T>(&self, request: &Request<T>) -> Result<Option<AuthContext>, Status> {
        let metadata = request.metadata();
        let bootstrap_ctx = AuthContext::bootstrap_admin();
        let mut credential_key = None;

        // Try Authorization header first (Bearer token or raw API key)
        let auth_ctx = if let Some(auth_value) = metadata.get("authorization") {
            let auth_str = match auth_value.to_str() {
                Ok(value) => value,
                Err(_) if self.require_auth => {
                    return Err(Status::unauthenticated(
                        "invalid authorization header encoding",
                    ));
                }
                Err(_) => {
                    debug!("Invalid authorization metadata encoding, auth not required; injecting bootstrap context");
                    return Ok(Some(bootstrap_ctx));
                }
            };
            credential_key = credential_rate_limit_key(auth_str);

            match self.authenticate_header(auth_str) {
                Ok(ctx) => ctx,
                Err(_) if !self.require_auth => {
                    debug!("Invalid authorization metadata, auth not required; injecting bootstrap context");
                    Some(bootstrap_ctx.clone())
                }
                Err(error) => return Err(error),
            }
        } else if let Some(api_key) = metadata.get("x-api-key") {
            // Try x-api-key header
            let key_str = match api_key.to_str() {
                Ok(value) => value,
                Err(_) if self.require_auth => {
                    return Err(Status::unauthenticated("invalid api key header encoding"));
                }
                Err(_) => {
                    debug!("Invalid x-api-key metadata encoding, auth not required; injecting bootstrap context");
                    return Ok(Some(bootstrap_ctx));
                }
            };
            credential_key = credential_rate_limit_key(key_str);

            match self.authenticate_header(key_str) {
                Ok(ctx) => ctx,
                Err(_) if !self.require_auth => {
                    debug!("Invalid x-api-key metadata, auth not required; injecting bootstrap context");
                    Some(bootstrap_ctx.clone())
                }
                Err(error) => return Err(error),
            }
        } else if self.require_auth {
            // No credentials found
            return Err(Status::unauthenticated("authentication required"));
        } else {
            debug!("No auth credentials, auth not required - injecting bootstrap context");
            Some(bootstrap_ctx)
        };

        // Apply rate limiting after successful authentication
        if let (Some(limiter), Some(ref ctx)) = (&self.rate_limiter, &auth_ctx) {
            let key = format!("grpc:tenant:{}", ctx.tenant_id);
            if let Err(AuthError::RateLimited) = limiter.check(&key) {
                warn!(tenant_id = %ctx.tenant_id, "gRPC rate limit exceeded");
                return Err(Status::resource_exhausted("rate limit exceeded"));
            }
        }

        if let (Some(ctx), Some(limit), Some(key)) = (
            &auth_ctx,
            auth_ctx.as_ref().and_then(|ctx| ctx.rate_limit),
            credential_key.as_ref(),
        ) {
            if let Err(AuthError::RateLimited) =
                self.credential_rate_limiter.check_with_limit(key, limit)
            {
                warn!(tenant_id = %ctx.tenant_id, "gRPC credential rate limit exceeded");
                return Err(Status::resource_exhausted("rate limit exceeded"));
            }
        }

        Ok(auth_ctx)
    }

    fn authenticate_header(&self, header: &str) -> Result<Option<AuthContext>, Status> {
        match self.authenticate_blocking(Some(header)) {
            Ok(ctx) => {
                debug!(tenant_id = %ctx.tenant_id, "gRPC authenticated");
                Ok(Some(ctx))
            }
            Err(AuthError::InvalidApiKey) => {
                warn!("Invalid API key provided");
                Err(Status::unauthenticated("invalid api key"))
            }
            Err(AuthError::InvalidJwt(_)) => {
                warn!("Invalid JWT provided");
                Err(Status::unauthenticated("invalid jwt"))
            }
            Err(AuthError::TokenExpired) => {
                warn!("JWT token expired");
                Err(Status::unauthenticated("token expired"))
            }
            Err(AuthError::RateLimited) => {
                warn!("Rate limit exceeded");
                Err(Status::resource_exhausted("rate limit exceeded"))
            }
            Err(AuthError::BackendUnavailable(_)) => {
                warn!("Authentication backend unavailable");
                Err(Status::unavailable("authentication backend unavailable"))
            }
            Err(AuthError::MissingAuth) => Err(Status::unauthenticated("authentication required")),
            Err(e) => {
                warn!("Auth error: {}", e);
                Err(Status::unauthenticated(e.to_string()))
            }
        }
    }

    fn authenticate_blocking(&self, auth_header: Option<&str>) -> Result<AuthContext, AuthError> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.authenticator.authenticate(auth_header))
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Code;

    use crate::auth::{ApiKeyRecord, ApiKeyValidator, Permissions};

    #[tokio::test(flavor = "multi_thread")]
    async fn grpc_interceptor_enforces_per_credential_rate_limit() {
        let api_key = "ss_test_grpc_limit_12345";
        let validator = Arc::new(ApiKeyValidator::new());
        validator.register_key(ApiKeyRecord {
            key_hash: ApiKeyValidator::hash_key(api_key),
            tenant_id: uuid::Uuid::new_v4(),
            store_ids: Vec::new(),
            permissions: Permissions::read_only(),
            agent_id: None,
            active: true,
            rate_limit: Some(1),
        });

        let interceptor = GrpcAuthInterceptor::new(
            Arc::new(Authenticator::new(validator)),
            true,
            None,
            Arc::new(RateLimiter::new(100)),
        );

        let mut first = Request::new(());
        first.metadata_mut().insert(
            "authorization",
            format!("ApiKey {api_key}").parse().unwrap(),
        );
        assert!(interceptor.authenticate(&first).is_ok());

        let mut second = Request::new(());
        second.metadata_mut().insert(
            "authorization",
            format!("ApiKey {api_key}").parse().unwrap(),
        );
        let err = interceptor.authenticate(&second).unwrap_err();
        assert_eq!(err.code(), Code::ResourceExhausted);
    }
}
