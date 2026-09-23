//! VES (Verifiable Event Sequencing) v1.0 handlers.

pub mod anchoring;
pub mod commitments;
pub mod cursors;
pub mod events;
pub mod inclusion_proofs;

// STARK proof endpoints depend on the private stateset-stark workspace.
#[cfg(feature = "stark")]
pub(crate) mod amount_binding;
#[cfg(feature = "stark")]
pub mod compliance_proofs;
#[cfg(feature = "stark")]
pub mod validity_proofs;

// Re-export all handlers for convenience
pub use anchoring::*;
pub use commitments::*;
pub use cursors::*;
pub use events::*;
pub use inclusion_proofs::*;

#[cfg(feature = "stark")]
pub use compliance_proofs::*;
#[cfg(feature = "stark")]
pub use validity_proofs::*;

use axum::http::StatusCode;
use tracing::instrument;
use uuid::Uuid;

use crate::api::utils::internal_error;
use crate::domain::{Hash256, VesBatchCommitment};
use crate::infra::VesComplianceEventInputs;
use crate::server::AppState;

/// Generate canonical public inputs for VES validity proofs.
pub fn ves_validity_public_inputs(commitment: &VesBatchCommitment) -> serde_json::Value {
    const ZERO_HASH: [u8; 32] = [0u8; 32];

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
        "allCompliant": true,
        "policyHash": hex::encode(ZERO_HASH),
        "policyLimit": 0,
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

/// Fetch mutable anchoring state from the primary. A cached commitment can
/// retain a finalized chain status after a reorg on another replica.
#[instrument(skip(state), fields(batch_id = %batch_id))]
pub async fn get_ves_commitment_cached(
    state: &AppState,
    batch_id: Uuid,
) -> Result<VesBatchCommitment, (StatusCode, String)> {
    state
        .ves_commitment_engine
        .get_commitment(batch_id)
        .await
        .map_err(internal_error)?
        .ok_or((StatusCode::NOT_FOUND, "Commitment not found".to_string()))
}
