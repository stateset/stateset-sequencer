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

            return self.authenticate_header(auth_str);
        }

        // Try x-api-key header
        if let Some(api_key) = metadata.get("x-api-key") {
            let key_str = api_key
                .to_str()
                .map_err(|_| Status::unauthenticated("invalid api key header encoding"))?;
            return self.authenticate_header(key_str);
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
