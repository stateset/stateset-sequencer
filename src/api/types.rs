//! Shared request and response types for REST API handlers.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::{EventEnvelope, VesEventEnvelope};

// ============================================================================
// Ingest types
// ============================================================================

/// Request body for legacy event ingestion.
#[derive(Debug, Deserialize)]
pub struct IngestRequest {
    pub agent_id: Uuid,
    pub events: Vec<EventEnvelope>,
}

/// Response for legacy event ingestion.
#[derive(Debug, Serialize)]
pub struct IngestResponse {
    pub batch_id: Uuid,
    pub events_accepted: u32,
    pub events_rejected: u32,
    pub assigned_sequence_start: Option<u64>,
    pub assigned_sequence_end: Option<u64>,
    pub head_sequence: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rejections: Vec<RejectionInfo>,
}

/// Information about a rejected event.
#[derive(Debug, Serialize)]
pub struct RejectionInfo {
    pub event_id: Uuid,
    pub reason: String,
    pub message: String,
}

/// Request body for VES event ingestion.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VesIngestRequest {
    pub agent_id: Uuid,
    pub events: Vec<VesEventEnvelope>,
}

/// Response receipt for a single VES event.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VesReceiptResponse {
    pub sequencer_id: Uuid,
    pub event_id: Uuid,
    pub sequence_number: u64,
    pub sequenced_at: String,
    pub receipt_hash: String,
    pub signature_alg: String,
    pub sequencer_signature: String,
}

/// Response for VES event ingestion.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VesIngestResponse {
    pub batch_id: Uuid,
    pub events_accepted: u32,
    pub events_rejected: u32,
    pub sequence_start: Option<u64>,
    pub sequence_end: Option<u64>,
    pub head_sequence: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rejections: Vec<RejectionInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<VesReceiptResponse>,
}

// ============================================================================
// Agent key types
// ============================================================================

/// Request body for agent key registration.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterAgentKeyRequest {
    pub tenant_id: Uuid,
    pub agent_id: Uuid,
    pub key_id: u32,
    /// Hex-encoded Ed25519 public key.
    pub public_key: String,
    /// ISO timestamp.
    pub valid_from: Option<String>,
    /// ISO timestamp.
    pub valid_to: Option<String>,
}

// ============================================================================
// Query types
// ============================================================================

/// Query parameters for listing events.
#[derive(Debug, Deserialize)]
pub struct ListEventsQuery {
    pub tenant_id: Uuid,
    pub store_id: Uuid,
    pub from: Option<u64>,
    pub limit: Option<u32>,
}

/// Query parameters for getting head sequence.
#[derive(Debug, Deserialize)]
pub struct HeadQuery {
    pub tenant_id: Uuid,
    pub store_id: Uuid,
}

/// Query parameters for proof requests.
#[derive(Debug, Deserialize)]
pub struct ProofQuery {
    pub tenant_id: Uuid,
    pub store_id: Uuid,
    pub batch_id: Uuid,
}

/// Query parameters for pending commitments.
#[derive(Debug, Deserialize)]
pub struct PendingCommitmentsQuery {
    pub limit: Option<u32>,
}

// ============================================================================
// Commitment types
// ============================================================================

/// Request body for creating a commitment.
#[derive(Debug, Deserialize)]
pub struct CreateCommitmentRequest {
    pub tenant_id: Uuid,
    pub store_id: Uuid,
    pub sequence_start: u64,
    pub sequence_end: u64,
}

/// Request body for commit and anchor in one operation.
#[derive(Debug, Deserialize)]
pub struct CommitAndAnchorVesRequest {
    pub tenant_id: Uuid,
    pub store_id: Uuid,
    pub sequence_start: Option<u64>,
    pub sequence_end: Option<u64>,
    pub max_events: Option<u64>,
}

// ============================================================================
// Proof types
// ============================================================================

/// Request body for proof verification.
#[derive(Debug, Deserialize)]
pub struct VerifyProofRequest {
    pub leaf_hash: String,
    pub events_root: String,
    pub proof_path: Vec<String>,
    pub leaf_index: usize,
}

/// Request body for VES proof verification.
#[derive(Debug, Deserialize)]
pub struct VerifyVesProofRequest {
    pub leaf_hash: String,
    pub merkle_root: String,
    pub proof_path: Vec<String>,
    pub leaf_index: usize,
}

/// Request body for submitting a VES validity proof.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitVesValidityProofRequest {
    pub proof_type: String,
    #[serde(default = "default_proof_version")]
    pub proof_version: u32,
    pub proof_b64: String,
    pub public_inputs: Option<serde_json::Value>,
}

/// Request body for VES compliance public inputs.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VesComplianceInputsRequest {
    pub policy_id: String,
    #[serde(default = "default_policy_params")]
    pub policy_params: serde_json::Value,
}

/// Request body for submitting a VES compliance proof.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitVesComplianceProofRequest {
    pub proof_type: String,
    #[serde(default = "default_proof_version")]
    pub proof_version: u32,
    pub policy_id: String,
    #[serde(default = "default_policy_params")]
    pub policy_params: serde_json::Value,
    pub proof_b64: String,
    pub public_inputs: Option<serde_json::Value>,
}

// ============================================================================
// Anchor types
// ============================================================================

/// Request body for anchoring a commitment.
#[derive(Debug, Deserialize)]
pub struct AnchorRequest {
    pub batch_id: Uuid,
}

/// Request body for notifying anchor completion.
#[derive(Debug, Deserialize)]
pub struct AnchorNotificationRequest {
    pub chain_tx_hash: String,
    pub chain_id: u64,
    pub block_number: Option<u64>,
    pub gas_used: Option<u64>,
}

// ============================================================================
// Default value functions
// ============================================================================

pub fn default_proof_version() -> u32 {
    1
}

pub fn default_policy_params() -> serde_json::Value {
    serde_json::json!({})
}
