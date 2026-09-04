//! JWT authentication
//!
//! JWT tokens with tenant/store claims for API authentication.

use super::{AuthContext, AuthError, Permissions};
use chrono::{Duration, Utc};
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet, KeyAlgorithm};
use jsonwebtoken::{
    decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
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

enum JwtKeys {
    Hmac {
        encoding: EncodingKey,
        decoding: DecodingKey,
    },
    Jwks(HashMap<String, (DecodingKey, Algorithm)>),
}

/// JWT validator and optional local issuer.
pub struct JwtValidator {
    keys: RwLock<JwtKeys>,

    /// Issuer string
    issuer: String,

    /// Audience string
    audience: String,
}

impl JwtValidator {
    /// Create a new JWT validator with a secret key
    pub fn new(secret: &[u8], issuer: &str, audience: &str) -> Self {
        Self {
            keys: RwLock::new(JwtKeys::Hmac {
                encoding: EncodingKey::from_secret(secret),
                decoding: DecodingKey::from_secret(secret),
            }),
            issuer: issuer.to_string(),
            audience: audience.to_string(),
        }
    }

    /// Create a validator for an externally managed OIDC/JWKS key set.
    ///
    /// Only asymmetric signature keys with an explicit `kid` and `alg` are
    /// accepted. This prevents algorithm confusion and makes key rotation
    /// deterministic. Static documents rotate through a rolling restart; use
    /// [`Self::from_jwks_url`] for automatic refresh.
    pub fn from_jwks_json(
        jwks_json: &str,
        issuer: &str,
        audience: &str,
    ) -> Result<Self, AuthError> {
        let keys = parse_jwks(jwks_json)?;

        Ok(Self {
            keys: RwLock::new(JwtKeys::Jwks(keys)),
            issuer: issuer.to_string(),
            audience: audience.to_string(),
        })
    }

    /// Fetch an initial key set from an OIDC/JWKS endpoint.
    pub async fn from_jwks_url(url: &str, issuer: &str, audience: &str) -> Result<Self, AuthError> {
        let document = fetch_jwks_document(url).await?;
        Self::from_jwks_json(&document, issuer, audience)
    }

    /// Atomically replace externally managed keys after a successful refresh.
    /// A malformed or unreachable refresh never destroys the last-known-good set.
    pub async fn refresh_jwks_url(&self, url: &str) -> Result<(), AuthError> {
        let document = fetch_jwks_document(url).await?;
        self.replace_jwks_json(&document)
    }

    /// Atomically install a refreshed JWKS document.
    pub fn replace_jwks_json(&self, document: &str) -> Result<(), AuthError> {
        let keys = parse_jwks(document)?;
        let mut current = self
            .keys
            .write()
            .map_err(|_| AuthError::BackendUnavailable("JWT key lock poisoned".to_string()))?;
        if matches!(&*current, JwtKeys::Hmac { .. }) {
            return Err(AuthError::InvalidJwt(
                "cannot replace locally managed HMAC keys with JWKS".to_string(),
            ));
        }
        *current = JwtKeys::Jwks(keys);
        Ok(())
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

        let keys = self
            .keys
            .read()
            .map_err(|_| AuthError::BackendUnavailable("JWT key lock poisoned".to_string()))?;
        let JwtKeys::Hmac { encoding, .. } = &*keys else {
            return Err(AuthError::InvalidJwt(
                "token issuance is disabled for externally managed JWKS authentication".to_string(),
            ));
        };
        encode(&Header::default(), &claims, encoding)
            .map_err(|e| AuthError::InvalidJwt(e.to_string()))
    }

    /// Validate a JWT token and return auth context
    pub fn validate(&self, token: &str) -> Result<AuthContext, AuthError> {
        let keys = self
            .keys
            .read()
            .map_err(|_| AuthError::BackendUnavailable("JWT key lock poisoned".to_string()))?;
        let (decoding_key, algorithm) = match &*keys {
            JwtKeys::Hmac { decoding, .. } => (decoding, Algorithm::HS256),
            JwtKeys::Jwks(keys) => {
                let header =
                    decode_header(token).map_err(|e| AuthError::InvalidJwt(e.to_string()))?;
                let kid = header.kid.ok_or_else(|| {
                    AuthError::InvalidJwt("JWT signed with JWKS must include kid".to_string())
                })?;
                let (key, algorithm) = keys.get(&kid).ok_or_else(|| {
                    AuthError::InvalidJwt(format!("unknown JWT signing key: {kid}"))
                })?;
                if header.alg != *algorithm {
                    return Err(AuthError::InvalidJwt(format!(
                        "JWT algorithm does not match JWKS key {kid}"
                    )));
                }
                (key, *algorithm)
            }
        };

        let mut validation = Validation::new(algorithm);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);

        let token_data =
            decode::<Claims>(token, decoding_key, &validation).map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                _ => AuthError::InvalidJwt(e.to_string()),
            })?;

        let claims = token_data.claims;

        // Parse tenant ID
        let tenant_id = Uuid::parse_str(&claims.sub)
            .map_err(|_| AuthError::InvalidJwt("invalid tenant ID".to_string()))?;

        // Parse store IDs - fail if any store ID is invalid to prevent
        // privilege escalation (empty store_ids = access to all stores)
        let store_ids: Vec<Uuid> = if claims.stores.is_empty() {
            vec![]
        } else {
            claims
                .stores
                .split(',')
                .map(|s| {
                    Uuid::parse_str(s.trim()).map_err(|_| {
                        AuthError::InvalidJwt(format!("invalid store ID: {}", s.trim()))
                    })
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        // Parse agent ID - fail closed on malformed values so agent-scoped
        // authorization cannot silently degrade to an unscoped principal.
        let agent_id = claims
            .agent
            .as_ref()
            .map(|s| {
                Uuid::parse_str(s)
                    .map_err(|_| AuthError::InvalidJwt(format!("invalid agent ID: {}", s)))
            })
            .transpose()?;

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
            rate_limit: None,
            permissions,
        })
    }
}

fn parse_jwks(jwks_json: &str) -> Result<HashMap<String, (DecodingKey, Algorithm)>, AuthError> {
    let jwks: JwkSet = serde_json::from_str(jwks_json)
        .map_err(|e| AuthError::InvalidJwt(format!("invalid JWT_JWKS_JSON: {e}")))?;
    if jwks.keys.is_empty() {
        return Err(AuthError::InvalidJwt(
            "JWT_JWKS_JSON must contain at least one key".to_string(),
        ));
    }

    let mut keys = HashMap::with_capacity(jwks.keys.len());
    for jwk in jwks.keys {
        if matches!(&jwk.algorithm, AlgorithmParameters::OctetKey(_)) {
            return Err(AuthError::InvalidJwt(
                "JWT_JWKS_JSON must contain asymmetric keys only".to_string(),
            ));
        }
        let kid =
            jwk.common.key_id.clone().ok_or_else(|| {
                AuthError::InvalidJwt("every JWKS key must have a kid".to_string())
            })?;
        let key_algorithm = jwk
            .common
            .key_algorithm
            .ok_or_else(|| AuthError::InvalidJwt(format!("JWKS key {kid} must declare alg")))?;
        let algorithm = jwk_algorithm(key_algorithm).ok_or_else(|| {
            AuthError::InvalidJwt(format!("JWKS key {kid} uses a non-signing algorithm"))
        })?;
        let decoding = DecodingKey::from_jwk(&jwk)
            .map_err(|e| AuthError::InvalidJwt(format!("invalid JWKS key {kid}: {e}")))?;
        if keys.insert(kid.clone(), (decoding, algorithm)).is_some() {
            return Err(AuthError::InvalidJwt(format!(
                "duplicate JWKS key id: {kid}"
            )));
        }
    }

    Ok(keys)
}

async fn fetch_jwks_document(url: &str) -> Result<String, AuthError> {
    const MAX_JWKS_BYTES: usize = 2 * 1024 * 1024;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| AuthError::BackendUnavailable(format!("build JWKS client: {e}")))?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| AuthError::BackendUnavailable(format!("fetch JWKS: {e}")))?
        .error_for_status()
        .map_err(|e| AuthError::BackendUnavailable(format!("fetch JWKS: {e}")))?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_JWKS_BYTES as u64)
    {
        return Err(AuthError::InvalidJwt(
            "JWKS response exceeds 2 MiB".to_string(),
        ));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|e| AuthError::BackendUnavailable(format!("read JWKS: {e}")))?;
    if bytes.len() > MAX_JWKS_BYTES {
        return Err(AuthError::InvalidJwt(
            "JWKS response exceeds 2 MiB".to_string(),
        ));
    }
    String::from_utf8(bytes.to_vec())
        .map_err(|e| AuthError::InvalidJwt(format!("JWKS response is not UTF-8: {e}")))
}

fn jwk_algorithm(algorithm: KeyAlgorithm) -> Option<Algorithm> {
    match algorithm {
        KeyAlgorithm::ES256 => Some(Algorithm::ES256),
        KeyAlgorithm::ES384 => Some(Algorithm::ES384),
        KeyAlgorithm::RS256 => Some(Algorithm::RS256),
        KeyAlgorithm::RS384 => Some(Algorithm::RS384),
        KeyAlgorithm::RS512 => Some(Algorithm::RS512),
        KeyAlgorithm::PS256 => Some(Algorithm::PS256),
        KeyAlgorithm::PS384 => Some(Algorithm::PS384),
        KeyAlgorithm::PS512 => Some(Algorithm::PS512),
        KeyAlgorithm::EdDSA => Some(Algorithm::EdDSA),
        KeyAlgorithm::HS256
        | KeyAlgorithm::HS384
        | KeyAlgorithm::HS512
        | KeyAlgorithm::RSA1_5
        | KeyAlgorithm::RSA_OAEP
        | KeyAlgorithm::RSA_OAEP_256
        | KeyAlgorithm::UNKNOWN_ALGORITHM => None,
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
    fn jwks_rejects_symmetric_keys() {
        let document = r#"{"keys":[{"kty":"oct","k":"c2VjcmV0","kid":"one","alg":"HS256"}]}"#;
        let error = JwtValidator::from_jwks_json(document, "issuer", "audience")
            .err()
            .expect("symmetric JWKS must be rejected");
        assert!(error.to_string().contains("asymmetric"));
    }

    #[test]
    fn jwks_requires_unique_key_ids_and_algorithms() {
        let missing_kid = r#"{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB","alg":"RS256"}]}"#;
        assert!(JwtValidator::from_jwks_json(missing_kid, "issuer", "audience").is_err());

        let missing_algorithm = r#"{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB","kid":"one"}]}"#;
        assert!(JwtValidator::from_jwks_json(missing_algorithm, "issuer", "audience").is_err());
    }

    #[test]
    fn jwks_mode_configures_asymmetric_validation_and_disables_issuance() {
        let document = r#"{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB","kid":"one","alg":"RS256","use":"sig"}]}"#;
        let validator = JwtValidator::from_jwks_json(document, "issuer", "audience").unwrap();
        let issue = validator.issue(
            &Uuid::new_v4(),
            &[],
            None,
            &Permissions::read_only(),
            Duration::minutes(5),
        );
        assert!(
            matches!(&issue, Err(AuthError::InvalidJwt(message)) if message.contains("disabled"))
        );
    }

    #[test]
    fn jwks_rotation_is_atomic_and_rejects_hmac_conversion() {
        let first = r#"{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB","kid":"one","alg":"RS256"}]}"#;
        let second = r#"{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB","kid":"two","alg":"RS256"}]}"#;
        let validator = JwtValidator::from_jwks_json(first, "issuer", "audience").unwrap();
        assert!(validator.replace_jwks_json("not-json").is_err());
        validator.replace_jwks_json(second).unwrap();
        let keys = validator.keys.read().unwrap();
        assert!(
            matches!(&*keys, JwtKeys::Jwks(keys) if keys.contains_key("two") && !keys.contains_key("one"))
        );

        let hmac = create_validator();
        assert!(hmac.replace_jwks_json(second).is_err());
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

    #[test]
    fn test_invalid_store_id_fails_validation() {
        // This test verifies that invalid store IDs in the JWT cause
        // a hard auth failure rather than silently granting all-stores access.
        // Previously, invalid UUIDs were dropped via filter_map, so a claim
        // like "invalid-uuid" would become an empty Vec, granting access to all stores.
        let validator = create_validator();
        let tenant_id = Uuid::new_v4();

        // Create a token with valid structure, then manually craft one with invalid stores
        let now = Utc::now();
        let exp = now + Duration::hours(1);

        let claims = Claims {
            sub: tenant_id.to_string(),
            iss: "stateset-sequencer".to_string(),
            aud: "stateset-api".to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            jti: Uuid::new_v4().to_string(),
            stores: "not-a-valid-uuid,also-invalid".to_string(), // Invalid store IDs
            agent: None,
            perms: "read".to_string(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"test-secret-key-for-testing-only"),
        )
        .unwrap();

        let result = validator.validate(&token);
        assert!(
            matches!(&result, Err(AuthError::InvalidJwt(msg)) if msg.contains("invalid store ID")),
            "Expected InvalidJwt error for invalid store IDs, got: {:?}",
            result
        );
    }

    #[test]
    fn test_invalid_agent_id_fails_validation() {
        let validator = create_validator();
        let tenant_id = Uuid::new_v4();

        let now = Utc::now();
        let exp = now + Duration::hours(1);

        let claims = Claims {
            sub: tenant_id.to_string(),
            iss: "stateset-sequencer".to_string(),
            aud: "stateset-api".to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            jti: Uuid::new_v4().to_string(),
            stores: String::new(),
            agent: Some("not-a-valid-agent-uuid".to_string()),
            perms: "read,write".to_string(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"test-secret-key-for-testing-only"),
        )
        .unwrap();

        let result = validator.validate(&token);
        assert!(
            matches!(&result, Err(AuthError::InvalidJwt(msg)) if msg.contains("invalid agent ID")),
            "Expected InvalidJwt error for invalid agent ID, got: {:?}",
            result
        );
    }
}
