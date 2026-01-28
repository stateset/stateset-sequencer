//! VES (Verifiable Event Sequencing) v1.0 handlers.

pub mod anchoring;
pub mod commitments;
pub mod compliance_proofs;
pub mod inclusion_proofs;
pub mod validity_proofs;

// Re-export all handlers for convenience
pub use anchoring::*;
pub use commitments::*;
pub use compliance_proofs::*;
pub use inclusion_proofs::*;
pub use validity_proofs::*;

use axum::http::StatusCode;
use std::time::Duration;
use uuid::Uuid;

use crate::domain::{Hash256, VesBatchCommitment};
use crate::infra::VesComplianceEventInputs;
use crate::server::AppState;

/// Generate canonical public inputs for VES validity proofs.
pub fn ves_validity_public_inputs(commitment: &VesBatchCommitment) -> serde_json::Value {
    serde_json::json!({
        "batchId": commitment.batch_id,
        "tenantId": commitment.tenant_id.0,
        "storeId": commitment.store_id.0,
        "vesVersion": commitment.ves_version,
        "treeDepth": commitment.tree_depth,
        "leafCount": commitment.leaf_count,
        "paddedLeafCount": commitment.padded_leaf_count,
        "merkleRoot": hex::encode(commitment.merkle_root),
        "prevStateRoot": hex::encode(commitment.prev_state_root),
        "newStateRoot": hex::encode(commitment.new_state_root),
        "sequenceStart": commitment.sequence_range.0,
        "sequenceEnd": commitment.sequence_range.1,
    })
}

/// Generate canonical public inputs for VES compliance proofs.
pub fn ves_compliance_public_inputs(
    inputs: &VesComplianceEventInputs,
    policy_id: &str,
    policy_params: &serde_json::Value,
    policy_hash: &Hash256,
) -> serde_json::Value {
    serde_json::json!({
        "eventId": inputs.event_id,
        "tenantId": inputs.tenant_id.0,
        "storeId": inputs.store_id.0,
        "sequenceNumber": inputs.sequence_number,
        "payloadKind": inputs.payload_kind,
        "payloadPlainHash": hex::encode(inputs.payload_plain_hash),
        "payloadCipherHash": hex::encode(inputs.payload_cipher_hash),
        "eventSigningHash": hex::encode(inputs.event_signing_hash),
        "policyId": policy_id,
        "policyParams": policy_params,
        "policyHash": hex::encode(policy_hash),
    })
}

/// Fetch a VES commitment with cache and replica fallback.
pub async fn get_ves_commitment_cached(
    state: &AppState,
    batch_id: Uuid,
) -> Result<VesBatchCommitment, (StatusCode, String)> {
    let cache = &state.cache_manager.ves_commitments;
    if let Some(commitment) = cache.get_by_batch_id(&batch_id).await {
        return Ok(commitment);
    }

    let (cached, lock_acquired) = cache.get_by_batch_id_with_lock(&batch_id).await;
    if let Some(commitment) = cached {
        return Ok(commitment);
    }

    if !lock_acquired {
        tokio::time::sleep(Duration::from_millis(25)).await;
        if let Some(commitment) = cache.get_by_batch_id(&batch_id).await {
            return Ok(commitment);
        }
    }

    let commitment = match state.ves_commitment_reader.get_commitment(batch_id).await {
        Ok(Some(commitment)) => Some(commitment),
        Ok(None) => match state.ves_commitment_engine.get_commitment(batch_id).await {
            Ok(commitment) => commitment,
            Err(e) => {
                if lock_acquired {
                    cache.release_batch_id_lock(&batch_id).await;
                }
                return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
            }
        },
        Err(_) => match state.ves_commitment_engine.get_commitment(batch_id).await {
            Ok(commitment) => commitment,
            Err(e) => {
                if lock_acquired {
                    cache.release_batch_id_lock(&batch_id).await;
                }
                return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
            }
        },
    };

    let Some(commitment) = commitment else {
        if lock_acquired {
            cache.release_batch_id_lock(&batch_id).await;
        }
        return Err((StatusCode::NOT_FOUND, "Commitment not found".to_string()));
    };

    cache.insert(commitment.clone()).await;
    if lock_acquired {
        cache.release_batch_id_lock(&batch_id).await;
    }

    Ok(commitment)
}
