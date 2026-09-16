//! gRPC key-management v2 service: agent key lifecycle.
//!
//! Register, list, and revoke agent signing keys (including PQC bundles).
#![allow(clippy::result_large_err)]

use crate::auth::{
    AgentKeyEntry, AgentKeyError, AgentKeyLookup, AgentKeyRegistry, AuthContext,
    KeyStatus as DomainKeyStatus,
};
use crate::crypto::pqc_signing::{
    verify_proof_of_possession, KeyAlgorithm as DomainKeyAlgorithm, ParsedSignatureBundle,
    PublicKeyBundle as DomainPublicKeyBundle,
};
use crate::domain::TenantId;
use crate::infra::PgAgentKeyRegistry;
use crate::proto::v2::{
    self, key_management_server::KeyManagement as KeyManagementTrait, GetAgentKeysRequest,
    GetAgentKeysResponse, KeyType, PublicKeyBundle as ProtoPublicKeyBundle, RegisterKeyRequest,
    RegisterKeyResponse, RevokeKeyRequest, RevokeKeyResponse,
};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::info;
use uuid::Uuid;

/// Key Management service implementation
pub struct KeyManagementServiceV2 {
    registry: Arc<PgAgentKeyRegistry>,
}

impl KeyManagementServiceV2 {
    pub fn new(registry: Arc<PgAgentKeyRegistry>) -> Self {
        Self { registry }
    }

    fn auth_context<T>(request: &Request<T>) -> Result<AuthContext, Status> {
        request
            .extensions()
            .get::<AuthContext>()
            .cloned()
            .ok_or_else(|| Status::unauthenticated("missing auth context"))
    }

    fn require_admin(ctx: &AuthContext) -> Result<(), Status> {
        if ctx.is_admin() {
            Ok(())
        } else {
            Err(Status::permission_denied("admin permission required"))
        }
    }

    fn authorize_tenant(ctx: &AuthContext, tenant_id: &TenantId) -> Result<(), Status> {
        if !ctx.tenant_id.is_nil() && ctx.tenant_id != tenant_id.0 {
            return Err(Status::permission_denied("tenant access denied"));
        }
        Ok(())
    }

    fn timestamp_to_datetime(
        ts: &prost_types::Timestamp,
        field: &str,
    ) -> Result<DateTime<Utc>, Status> {
        if ts.nanos < 0 || ts.nanos > 999_999_999 {
            return Err(Status::invalid_argument(format!("invalid {} nanos", field)));
        }
        DateTime::<Utc>::from_timestamp(ts.seconds, ts.nanos as u32)
            .ok_or_else(|| Status::invalid_argument(format!("invalid {} timestamp", field)))
    }

    fn datetime_to_timestamp(dt: &DateTime<Utc>) -> prost_types::Timestamp {
        prost_types::Timestamp {
            seconds: dt.timestamp(),
            nanos: dt.timestamp_subsec_nanos() as i32,
        }
    }
}

#[tonic::async_trait]
impl KeyManagementTrait for KeyManagementServiceV2 {
    async fn register_agent_key(
        &self,
        request: Request<RegisterKeyRequest>,
    ) -> Result<Response<RegisterKeyResponse>, Status> {
        let auth_ctx = Self::auth_context(&request)?;
        let req = request.into_inner();

        info!(
            tenant_id = %req.tenant_id,
            agent_id = %req.agent_id,
            key_id = req.key_id,
            key_type = ?KeyType::try_from(req.key_type).unwrap_or(KeyType::Unspecified),
            "Registering agent key"
        );

        Self::require_admin(&auth_ctx)?;

        let tenant_id = Uuid::parse_str(&req.tenant_id)
            .map_err(|e| Status::invalid_argument(format!("invalid tenant_id: {}", e)))?;
        let agent_id = Uuid::parse_str(&req.agent_id)
            .map_err(|e| Status::invalid_argument(format!("invalid agent_id: {}", e)))?;

        let tenant_id = TenantId(tenant_id);
        Self::authorize_tenant(&auth_ctx, &tenant_id)?;

        let key_type = KeyType::try_from(req.key_type).unwrap_or(KeyType::Unspecified);
        if key_type != KeyType::Signing {
            return Err(Status::unimplemented("only signing keys are supported"));
        }

        // Parse key algorithm (VES-PQC-1)
        let key_algorithm = DomainKeyAlgorithm::from_i32(req.key_algorithm);

        // Parse public key (legacy Ed25519 field)
        let public_key: [u8; 32] = if req.public_key.len() == 32 {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&req.public_key);
            pk
        } else if key_algorithm.has_ml_dsa() && !key_algorithm.has_ed25519() {
            // PQC-strict (ML-DSA-65 only): legacy field may be empty
            [0u8; 32]
        } else {
            return Err(Status::invalid_argument("public_key must be 32 bytes"));
        };

        // Parse PQC public key bundle
        let public_key_bundle =
            req.public_key_bundle
                .as_ref()
                .map(|bundle| DomainPublicKeyBundle {
                    ed25519_public_key: if bundle.ed25519_public_key.len() == 32 {
                        let mut pk = [0u8; 32];
                        pk.copy_from_slice(&bundle.ed25519_public_key);
                        Some(pk)
                    } else {
                        None
                    },
                    ml_dsa_65_public_key: if bundle.ml_dsa_65_public_key.is_empty() {
                        None
                    } else {
                        Some(bundle.ml_dsa_65_public_key.clone())
                    },
                    x25519_public_key: if bundle.x25519_public_key.is_empty() {
                        None
                    } else {
                        Some(bundle.x25519_public_key.clone())
                    },
                    ml_kem_768_public_key: if bundle.ml_kem_768_public_key.is_empty() {
                        None
                    } else {
                        Some(bundle.ml_kem_768_public_key.clone())
                    },
                });

        // Parse PQC proof-of-possession bundle
        let pop_bundle =
            req.proof_of_possession_bundle
                .as_ref()
                .map(|bundle| ParsedSignatureBundle {
                    ed25519_signature: if bundle.ed25519_pop.is_empty() {
                        None
                    } else {
                        Some(bundle.ed25519_pop.clone())
                    },
                    ml_dsa_65_signature: if bundle.ml_dsa_65_pop.is_empty() {
                        None
                    } else {
                        Some(bundle.ml_dsa_65_pop.clone())
                    },
                });

        // SECURITY: PoP is MANDATORY for hybrid and strict key algorithms.
        let pop_required = matches!(
            key_algorithm,
            DomainKeyAlgorithm::Ed25519MlDsa65 | DomainKeyAlgorithm::MlDsa65
        );
        if pop_required && pop_bundle.is_none() && req.proof_of_possession.is_empty() {
            return Err(Status::invalid_argument(
                "proof_of_possession_bundle is required for hybrid and pqc-strict key registrations",
            ));
        }

        if pop_bundle.is_some() || !req.proof_of_possession.is_empty() {
            verify_proof_of_possession(
                key_algorithm,
                &public_key,
                public_key_bundle.as_ref(),
                &req.proof_of_possession,
                pop_bundle.as_ref(),
            )
            .map_err(|e| {
                Status::invalid_argument(format!("proof of possession verification failed: {e}"))
            })?;
        }

        let valid_from = match req.valid_from.as_ref() {
            Some(ts) => Some(Self::timestamp_to_datetime(ts, "valid_from")?),
            None => None,
        };
        let valid_to = match req.valid_to.as_ref() {
            Some(ts) => Some(Self::timestamp_to_datetime(ts, "valid_to")?),
            None => None,
        };
        if let (Some(from), Some(to)) = (valid_from.as_ref(), valid_to.as_ref()) {
            if from > to {
                return Err(Status::invalid_argument(
                    "valid_from must be less than or equal to valid_to",
                ));
            }
        }

        // Create key entry — PQC-aware when algorithm is specified
        let mut entry = if key_algorithm != DomainKeyAlgorithm::Unspecified {
            AgentKeyEntry::new_with_algorithm(public_key, key_algorithm, public_key_bundle)
        } else {
            AgentKeyEntry::new(public_key)
        };
        entry.valid_from = valid_from;
        entry.valid_to = valid_to;

        let lookup = AgentKeyLookup {
            tenant_id: tenant_id.0,
            agent_id,
            key_id: req.key_id,
        };

        self.registry
            .register_key(&lookup, entry)
            .await
            .map_err(|e| match e {
                AgentKeyError::KeyAlreadyExists => Status::already_exists("key already exists"),
                _ => super::grpc_internal_error(e),
            })?;

        Ok(Response::new(RegisterKeyResponse {
            success: true,
            message: "Key registered successfully".to_string(),
            registered_at: Some(prost_types::Timestamp {
                seconds: Utc::now().timestamp(),
                nanos: 0,
            }),
        }))
    }

    async fn get_agent_keys(
        &self,
        request: Request<GetAgentKeysRequest>,
    ) -> Result<Response<GetAgentKeysResponse>, Status> {
        let auth_ctx = Self::auth_context(&request)?;
        let req = request.into_inner();

        info!(
            tenant_id = %req.tenant_id,
            agent_id = %req.agent_id,
            "Getting agent keys"
        );

        Self::require_admin(&auth_ctx)?;

        let tenant_id = Uuid::parse_str(&req.tenant_id)
            .map_err(|e| Status::invalid_argument(format!("invalid tenant_id: {}", e)))?;
        let agent_id = Uuid::parse_str(&req.agent_id)
            .map_err(|e| Status::invalid_argument(format!("invalid agent_id: {}", e)))?;
        let tenant_id = TenantId(tenant_id);
        Self::authorize_tenant(&auth_ctx, &tenant_id)?;

        let key_type_filter =
            KeyType::try_from(req.key_type_filter).unwrap_or(KeyType::Unspecified);
        if key_type_filter == KeyType::Encryption {
            return Ok(Response::new(GetAgentKeysResponse { keys: vec![] }));
        }

        let now = Utc::now();
        let entries = self
            .registry
            .list_agent_keys(&tenant_id.0, &agent_id)
            .await
            .map_err(super::grpc_internal_error)?;

        let mut keys = Vec::with_capacity(entries.len());
        for (key_id, entry) in entries {
            let status = entry.status_at(now);
            if !req.include_revoked && status == DomainKeyStatus::Revoked {
                continue;
            }
            let proto_status = match status {
                DomainKeyStatus::Active => v2::KeyStatus::Active,
                DomainKeyStatus::Expired => v2::KeyStatus::Expired,
                DomainKeyStatus::Revoked => v2::KeyStatus::Revoked,
                DomainKeyStatus::NotYetValid => v2::KeyStatus::Unspecified,
            };

            // Serialize PQC key metadata
            let proto_key_algorithm = entry.key_algorithm as i32;
            let proto_public_key_bundle =
                entry
                    .public_key_bundle
                    .as_ref()
                    .map(|bundle| ProtoPublicKeyBundle {
                        ed25519_public_key: bundle
                            .ed25519_public_key
                            .map(|pk| pk.to_vec())
                            .unwrap_or_default(),
                        ml_dsa_65_public_key: bundle
                            .ml_dsa_65_public_key
                            .clone()
                            .unwrap_or_default(),
                        x25519_public_key: bundle.x25519_public_key.clone().unwrap_or_default(),
                        ml_kem_768_public_key: bundle
                            .ml_kem_768_public_key
                            .clone()
                            .unwrap_or_default(),
                    });

            keys.push(v2::AgentKey {
                key_id,
                key_type: KeyType::Signing as i32,
                public_key: entry.public_key.to_vec(),
                status: proto_status as i32,
                created_at: Some(Self::datetime_to_timestamp(&entry.created_at)),
                valid_from: entry.valid_from.as_ref().map(Self::datetime_to_timestamp),
                valid_to: entry.valid_to.as_ref().map(Self::datetime_to_timestamp),
                revoked_at: entry.revoked_at.as_ref().map(Self::datetime_to_timestamp),
                key_algorithm: proto_key_algorithm,
                public_key_bundle: proto_public_key_bundle,
            });
        }

        Ok(Response::new(GetAgentKeysResponse { keys }))
    }

    async fn revoke_agent_key(
        &self,
        request: Request<RevokeKeyRequest>,
    ) -> Result<Response<RevokeKeyResponse>, Status> {
        let auth_ctx = Self::auth_context(&request)?;
        let req = request.into_inner();

        info!(
            tenant_id = %req.tenant_id,
            agent_id = %req.agent_id,
            key_id = req.key_id,
            reason = %req.reason,
            "Revoking agent key"
        );

        Self::require_admin(&auth_ctx)?;

        let tenant_id = Uuid::parse_str(&req.tenant_id)
            .map_err(|e| Status::invalid_argument(format!("invalid tenant_id: {}", e)))?;
        let agent_id = Uuid::parse_str(&req.agent_id)
            .map_err(|e| Status::invalid_argument(format!("invalid agent_id: {}", e)))?;

        let tenant_id = TenantId(tenant_id);
        Self::authorize_tenant(&auth_ctx, &tenant_id)?;

        let lookup = AgentKeyLookup {
            tenant_id: tenant_id.0,
            agent_id,
            key_id: req.key_id,
        };

        self.registry
            .revoke_key(&lookup)
            .await
            .map_err(|e| match e {
                AgentKeyError::KeyNotFound { .. } => Status::not_found("key not found"),
                _ => super::grpc_internal_error(e),
            })?;

        Ok(Response::new(RevokeKeyResponse {
            success: true,
            revoked_at: Some(prost_types::Timestamp {
                seconds: Utc::now().timestamp(),
                nanos: 0,
            }),
        }))
    }
}
