//! JWT authentication
//!
//! JWT tokens with tenant/store claims for API authentication.

use super::{AuthContext, AuthError, Permissions};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// JWT claims for StateSet Sequencer
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (tenant_id)
    pub sub: String,

    /// Issuer
    pub iss: String,

    /// Audience
    pub aud: String,

    /// Expiration time (Unix timestamp)
    pub exp: i64,

    /// Issued at (Unix timestamp)
    pub iat: i64,

    /// Not before (Unix timestamp)
    pub nbf: i64,

    /// JWT ID
    pub jti: String,

    /// Store IDs (comma-separated or empty for all)
    #[serde(default)]
    pub stores: String,

    /// Agent ID (optional)
    #[serde(default)]
    pub agent: Option<String>,

    /// Permissions (comma-separated: read,write,admin)
    #[serde(default)]
    pub perms: String,
}

/// JWT validator and issuer
pub struct JwtValidator {
    /// Secret key for signing/verifying
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,

    /// Issuer string
    issuer: String,

    /// Audience string
    audience: String,
}

impl JwtValidator {
    /// Create a new JWT validator with a secret key
    pub fn new(secret: &[u8], issuer: &str, audience: &str) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            issuer: issuer.to_string(),
            audience: audience.to_string(),
        }
    }

    /// Issue a new JWT token
    pub fn issue(
        &self,
        tenant_id: &Uuid,
        store_ids: &[Uuid],
        agent_id: Option<&Uuid>,
        permissions: &Permissions,
        ttl: Duration,
    ) -> Result<String, AuthError> {
        let now = Utc::now();
        let exp = now + ttl;

        let stores = store_ids
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(",");

        let mut perms = Vec::new();
        if permissions.read {
            perms.push("read");
        }
        if permissions.write {
            perms.push("write");
        }
        if permissions.admin {
            perms.push("admin");
        }

        let claims = Claims {
            sub: tenant_id.to_string(),
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            jti: Uuid::new_v4().to_string(),
            stores,
            agent: agent_id.map(|id| id.to_string()),
            perms: perms.join(","),
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| AuthError::InvalidJwt(e.to_string()))
    }

    /// Validate a JWT token and return auth context
    pub fn validate(&self, token: &str) -> Result<AuthContext, AuthError> {
        let mut validation = Validation::default();
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);

        let token_data = decode::<Claims>(token, &self.decoding_key, &validation).map_err(|e| {
            match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                _ => AuthError::InvalidJwt(e.to_string()),
            }
        })?;

        let claims = token_data.claims;

        // Parse tenant ID
        let tenant_id = Uuid::parse_str(&claims.sub)
            .map_err(|_| AuthError::InvalidJwt("invalid tenant ID".to_string()))?;

        // Parse store IDs
        let store_ids: Vec<Uuid> = if claims.stores.is_empty() {
            vec![]
        } else {
            claims
                .stores
                .split(',')
                .filter_map(|s| Uuid::parse_str(s.trim()).ok())
                .collect()
        };

        // Parse agent ID
        let agent_id = claims.agent.as_ref().and_then(|s| Uuid::parse_str(s).ok());

        // Parse permissions
        let perms_list: Vec<&str> = claims.perms.split(',').collect();
        let permissions = Permissions {
            read: perms_list.contains(&"read"),
            write: perms_list.contains(&"write"),
            admin: perms_list.contains(&"admin"),
        };

        Ok(AuthContext {
            tenant_id,
            store_ids,
            agent_id,
            permissions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_validator() -> JwtValidator {
        JwtValidator::new(
            b"test-secret-key-for-testing-only",
            "stateset-sequencer",
            "stateset-api",
        )
    }

    #[test]
    fn test_issue_and_validate() {
        let validator = create_validator();
        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();

        let token = validator
            .issue(
                &tenant_id,
                &[store_id],
                None,
                &Permissions::read_write(),
                Duration::hours(1),
            )
            .unwrap();

        let context = validator.validate(&token).unwrap();

        assert_eq!(context.tenant_id, tenant_id);
        assert_eq!(context.store_ids, vec![store_id]);
        assert!(context.can_read());
        assert!(context.can_write());
        assert!(!context.is_admin());
    }

    #[test]
    fn test_all_stores_access() {
        let validator = create_validator();
        let tenant_id = Uuid::new_v4();

        let token = validator
            .issue(
                &tenant_id,
                &[], // Empty = all stores
                None,
                &Permissions::read_only(),
                Duration::hours(1),
            )
            .unwrap();

        let context = validator.validate(&token).unwrap();

        assert!(context.store_ids.is_empty());
        // Empty store_ids means access to all stores
        assert!(context.can_access_store(&Uuid::new_v4()));
    }

    #[test]
    fn test_agent_token() {
        let validator = create_validator();
        let tenant_id = Uuid::new_v4();
        let agent_id = Uuid::new_v4();

        let token = validator
            .issue(
                &tenant_id,
                &[],
                Some(&agent_id),
                &Permissions::read_write(),
                Duration::hours(1),
            )
            .unwrap();

        let context = validator.validate(&token).unwrap();

        assert_eq!(context.agent_id, Some(agent_id));
    }

    #[test]
    fn test_expired_token() {
        let validator = create_validator();
        let tenant_id = Uuid::new_v4();

        // Use -120 seconds to exceed the default 60-second leeway in jsonwebtoken
        let token = validator
            .issue(
                &tenant_id,
                &[],
                None,
                &Permissions::read_only(),
                Duration::seconds(-120), // Clearly expired past any leeway
            )
            .unwrap();

        let result = validator.validate(&token);
        assert!(matches!(result, Err(AuthError::TokenExpired)));
    }
}
