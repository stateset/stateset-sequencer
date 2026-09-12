//! Agent key management handlers.

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use tracing::{info, instrument};
use uuid::Uuid;

use crate::api::auth_helpers::{ensure_admin, ensure_read};
use crate::api::types::{
    AgentSigningKeyEntry, AgentSigningKeysBody, AgentSigningKeysQuery, AgentSigningKeysResponse,
    RegisterAgentKeyRequest,
};
use crate::api::utils::internal_error;
use crate::auth::{AgentKeyEntry, AgentKeyLookup, AgentKeyRegistry, AuthContextExt};
use crate::crypto::pqc_signing::{
    validate_key_algorithm_for_profile, verify_proof_of_possession, KeyAlgorithm,
    ParsedSignatureBundle, PublicKeyBundle,
};
use crate::crypto::{canonicalize_json, compute_key_directory_hash, public_key_to_hex};
use crate::server::AppState;

/// Decode a hex string (with optional "0x" prefix) into bytes.
fn decode_hex(hex_str: &str, field_name: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode(stripped).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid {} hex: {}", field_name, e),
        )
    })
}

/// POST /api/v1/agents/keys - Register an agent public key.
#[instrument(skip(state, auth, request), fields(
    tenant_id = %request.tenant_id,
    agent_id = %request.agent_id,
    key_id = %request.key_id
))]
pub async fn register_agent_key(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Json(request): Json<RegisterAgentKeyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    info!("Registering agent key");
    // Admin-only operation (manages signing keys).
    ensure_admin(&auth, request.tenant_id, Uuid::nil())?;

    // Parse key algorithm (VES-PQC-1)
    let key_algorithm = KeyAlgorithm::from_i32(request.key_algorithm.unwrap_or(0));
    let security_profile = state.ves_sequencer.security_profile();
    validate_key_algorithm_for_profile(key_algorithm, security_profile).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            format!(
                "key_algorithm {:?} is not allowed under the {} profile",
                key_algorithm, security_profile
            ),
        )
    })?;

    // Parse the hex-encoded public key (legacy Ed25519 field)
    let public_key_bytes = decode_hex(&request.public_key, "public_key")?;

    let public_key: [u8; 32] = if public_key_bytes.len() == 32 {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&public_key_bytes);
        pk
    } else if key_algorithm.has_ml_dsa() && !key_algorithm.has_ed25519() {
        // PQC-strict (ML-DSA-65 only): legacy Ed25519 field may be empty
        [0u8; 32]
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            "Public key must be 32 bytes".to_string(),
        ));
    };

    // Parse PQC public key bundle if provided
    let public_key_bundle = if let Some(ref bundle_req) = request.public_key_bundle {
        let ed25519_pk = if let Some(ref hex) = bundle_req.ed25519_public_key {
            let bytes = decode_hex(hex, "ed25519_public_key")?;
            if bytes.len() != 32 {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "ed25519_public_key must be 32 bytes".to_string(),
                ));
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&bytes);
            Some(pk)
        } else {
            None
        };
        let ml_dsa_pk = if let Some(ref hex) = bundle_req.ml_dsa_65_public_key {
            Some(decode_hex(hex, "ml_dsa_65_public_key")?)
        } else {
            None
        };
        let x25519_pk = if let Some(ref hex) = bundle_req.x25519_public_key {
            Some(decode_hex(hex, "x25519_public_key")?)
        } else {
            None
        };
        let ml_kem_pk = if let Some(ref hex) = bundle_req.ml_kem_768_public_key {
            Some(decode_hex(hex, "ml_kem_768_public_key")?)
        } else {
            None
        };
        Some(PublicKeyBundle {
            ed25519_public_key: ed25519_pk,
            ml_dsa_65_public_key: ml_dsa_pk,
            x25519_public_key: x25519_pk,
            ml_kem_768_public_key: ml_kem_pk,
        })
    } else {
        None
    };

    // Parse PQC proof-of-possession bundle if provided
    let pop_bundle = if let Some(ref pop_req) = request.proof_of_possession_bundle {
        let ed_pop = if let Some(ref hex) = pop_req.ed25519_pop {
            let bytes = decode_hex(hex, "ed25519_pop")?;
            if bytes.len() != 64 {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "ed25519_pop must be 64 bytes".to_string(),
                ));
            }
            Some(bytes)
        } else {
            None
        };
        let ml_dsa_pop = if let Some(ref hex) = pop_req.ml_dsa_65_pop {
            Some(decode_hex(hex, "ml_dsa_65_pop")?)
        } else {
            None
        };
        Some(ParsedSignatureBundle {
            ed25519_signature: ed_pop,
            ml_dsa_65_signature: ml_dsa_pop,
        })
    } else {
        None
    };

    // SECURITY: PoP is MANDATORY for hybrid and strict key algorithms.
    // Without PoP, an attacker could register a key with arbitrary ML-DSA-65
    // material without proving possession of the private key.
    let pop_required = matches!(
        key_algorithm,
        KeyAlgorithm::Ed25519MlDsa65 | KeyAlgorithm::MlDsa65
    );
    if pop_required && pop_bundle.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Proof of possession is required for hybrid and pqc-strict key registrations"
                .to_string(),
        ));
    }

    if let Some(ref pop) = pop_bundle {
        verify_proof_of_possession(
            key_algorithm,
            &public_key,
            public_key_bundle.as_ref(),
            &[],
            Some(pop),
        )
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Proof of possession verification failed: {e}"),
            )
        })?;
    }

    // Parse validity timestamps if provided
    let valid_from = if let Some(ref ts) = request.valid_from {
        Some(
            chrono::DateTime::parse_from_rfc3339(ts)
                .map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Invalid valid_from timestamp: {}", e),
                    )
                })?
                .with_timezone(&chrono::Utc),
        )
    } else {
        None
    };

    let valid_to = if let Some(ref ts) = request.valid_to {
        Some(
            chrono::DateTime::parse_from_rfc3339(ts)
                .map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Invalid valid_to timestamp: {}", e),
                    )
                })?
                .with_timezone(&chrono::Utc),
        )
    } else {
        None
    };

    // Create lookup and entry
    let lookup = AgentKeyLookup {
        tenant_id: request.tenant_id,
        agent_id: request.agent_id,
        key_id: request.key_id,
    };

    // Create key entry — PQC-aware when algorithm is specified
    let mut entry = if key_algorithm != KeyAlgorithm::Unspecified {
        AgentKeyEntry::new_with_algorithm(public_key, key_algorithm, public_key_bundle)
    } else {
        AgentKeyEntry::new(public_key)
    };
    entry.valid_from = valid_from;
    entry.valid_to = valid_to;

    // Register the key
    state
        .agent_key_registry
        .register_key(&lookup, entry)
        .await
        .map_err(internal_error)?;

    Ok(Json(serde_json::json!({
        "success": true,
        "tenantId": request.tenant_id,
        "agentId": request.agent_id,
        "keyId": request.key_id,
        "keyAlgorithm": request.key_algorithm.unwrap_or(0),
        "message": "Agent key registered successfully"
    })))
}

/// GET /api/v1/agents/:agent_id/signing-keys - Signed peer key directory.
///
/// Readable by any authenticated agent within the same tenant. Serves the
/// agent's full key history — including revoked and expired keys, each with
/// its validity window — so that peers can verify events signed by a key that
/// has since rotated. The client, not the server, decides whether a given
/// event falls inside its key's window.
#[instrument(skip(state, auth), fields(tenant_id = %query.tenant_id, agent_id = %agent_id))]
pub async fn list_agent_signing_keys(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
    Path(agent_id): Path<Uuid>,
    Query(query): Query<AgentSigningKeysQuery>,
) -> Result<Json<AgentSigningKeysResponse>, (StatusCode, String)> {
    // Tenant membership, not self-or-admin: peers must read each other's keys.
    //
    // `ensure_read` is the crate-wide convention for a tenant-scoped,
    // store-agnostic read (see `schemas::list_schemas`): it checks the read bit
    // and waives the tenant check only for the bootstrap admin (admin
    // permissions AND a nil tenant). A hand-rolled `!auth.is_admin()` escape
    // hatch would let a tenant-scoped admin read another tenant's directory,
    // since `is_admin()` is only the permission bit and carries no tenant.
    // The nil store id is deliberate: a key directory is agent-scoped, so a
    // store-restricted key inside the tenant must still be able to read it.
    ensure_read(&auth, query.tenant_id, Uuid::nil())?;

    // Fail closed: an unsigned key directory invites clients to trust key
    // material with no provenance, which is worse than having no directory.
    let signing_config = state.ves_sequencer.signing_config().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Key directory unavailable: sequencer signing key not configured".to_string(),
    ))?;

    let entries = state
        .agent_key_registry
        .list_agent_keys(&query.tenant_id, &agent_id)
        .await
        .map_err(internal_error)?;

    let mut keys: Vec<AgentSigningKeyEntry> = entries
        .into_iter()
        .map(|(key_id, entry)| AgentSigningKeyEntry {
            key_id,
            algorithm: format!("{:?}", entry.key_algorithm).to_lowercase(),
            public_key: public_key_to_hex(&entry.public_key),
            public_key_bundle: entry
                .public_key_bundle
                .as_ref()
                .map(|b| serde_json::to_value(b).unwrap_or(serde_json::Value::Null)),
            valid_from: entry.valid_from,
            valid_to: entry.valid_to,
            revoked_at: entry.revoked_at,
        })
        .collect();
    // Deterministic order so the signed preimage is reproducible.
    keys.sort_by_key(|k| k.key_id);

    // Sign the response body itself, not a restatement of it: the preimage is
    // `serde_json::to_value` of the very struct that is served, so the two
    // cannot drift.
    let body = AgentSigningKeysBody {
        agent_id,
        tenant_id: query.tenant_id,
        keys,
        signed_at: Utc::now(),
    };
    let canonical = canonicalize_json(&serde_json::to_value(&body).map_err(internal_error)?);
    let hash = compute_key_directory_hash(canonical.as_bytes());
    let (_scheme, signature, _bundle) =
        signing_config.sign_receipt(&hash).map_err(internal_error)?;

    // `sign_receipt` returns an empty legacy signature under the PQC-strict
    // profile, where the signature lives in the bundle instead. Serving that as
    // `"0x"` would be an unsigned directory wearing a signature field, so fail
    // closed here too rather than emit one.
    if signature.is_empty() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "Key directory unavailable: sequencer signing scheme produces no directory signature"
                .to_string(),
        ));
    }

    Ok(Json(AgentSigningKeysResponse {
        body,
        directory_signature: format!("0x{}", hex::encode(signature)),
    }))
}
