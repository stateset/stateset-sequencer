//! Shared request and response types for REST API handlers.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::EventEnvelope;
pub use crate::domain::VesEventEnvelope;

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
// Agent registration types
// ============================================================================

/// Request body for agent registration.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentRegistrationRequest {
    /// Human-readable name for the agent.
    pub name: String,
    /// Optional description of the agent's purpose.
    pub description: Option<String>,
    /// Tenant ID is not allowed for self-service registration.
    pub tenant_id: Option<Uuid>,
    /// Optional store IDs this agent can access.
    pub store_ids: Option<Vec<Uuid>>,
    /// Whether this is a read-only agent (default: false).
    pub read_only: Option<bool>,
    /// Admin is not allowed for self-service registration.
    pub admin: Option<bool>,
    /// Optional rate limit (requests per minute).
    pub rate_limit: Option<u32>,
}

/// Response for agent registration.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentRegistrationResponse {
    pub success: bool,
    pub agent_id: Uuid,
    pub tenant_id: Uuid,
    /// The API key - only returned once, store securely!
    pub api_key: String,
    pub permissions: String,
    pub message: String,
}

/// Response for agent details.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentResponse {
    pub agent_id: Uuid,
    pub tenant_id: Uuid,
    pub active: bool,
    pub permissions: String,
    pub store_ids: Vec<Uuid>,
    pub rate_limit: Option<u32>,
}

/// Request body for creating a new API key.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateApiKeyRequest {
    /// Optional store IDs this key can access.
    pub store_ids: Option<Vec<Uuid>>,
    /// Whether this is a read-only key (default: false).
    pub read_only: Option<bool>,
    /// Whether this is an admin key (default: false, requires admin auth).
    pub admin: Option<bool>,
    /// Optional rate limit (requests per minute).
    pub rate_limit: Option<u32>,
}

/// Response for API key creation.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyResponse {
    pub success: bool,
    /// The API key - only returned once, store securely!
    pub api_key: String,
    /// First 16 chars of key hash for identification.
    pub key_hash_prefix: String,
    pub permissions: String,
    pub message: String,
}

/// Summary info for an API key (without the actual key).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyInfo {
    /// First 16 chars of key hash for identification.
    pub key_hash_prefix: String,
    pub active: bool,
    pub permissions: String,
    pub rate_limit: Option<u32>,
}

/// Response for listing API keys.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListApiKeysResponse {
    pub keys: Vec<ApiKeyInfo>,
    pub count: usize,
}

// ============================================================================
// Agent signing key types
// ============================================================================

/// Request body for agent signing key registration.
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
// Schema registry types
// ============================================================================

/// Query parameters for schema operations.
#[derive(Debug, Deserialize)]
pub struct SchemaQuery {
    pub tenant_id: Uuid,
}

/// Query parameters for schema by event type.
#[derive(Debug, Deserialize)]
pub struct SchemaByEventTypeQuery {
    pub tenant_id: Uuid,
    pub event_type: String,
}

/// Query parameters for schema version.
#[derive(Debug, Deserialize)]
pub struct SchemaVersionQuery {
    pub tenant_id: Uuid,
    pub event_type: String,
    pub version: Option<u32>,
}

/// Request body for registering a schema.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterSchemaRequest {
    pub tenant_id: Uuid,
    pub event_type: String,
    pub schema_json: serde_json::Value,
    pub description: Option<String>,
    pub compatibility: Option<String>,
}

/// Request body for validating a payload against a schema.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatePayloadRequest {
    pub tenant_id: Uuid,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub schema_version: Option<u32>,
}

/// Request body for updating schema status.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSchemaStatusRequest {
    pub status: String,
}

/// Response for schema registration.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterSchemaResponse {
    pub id: Uuid,
    pub event_type: String,
    pub version: u32,
    pub created_at: String,
}

/// Response for schema details.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub event_type: String,
    pub version: u32,
    pub schema_json: serde_json::Value,
    pub status: String,
    pub compatibility: String,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub created_by: Option<String>,
}

/// Response for schema list.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaListResponse {
    pub schemas: Vec<SchemaResponse>,
    pub count: usize,
}

/// Response for payload validation.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationResponse {
    pub valid: bool,
    pub schema_id: Option<Uuid>,
    pub schema_version: Option<u32>,
    pub errors: Vec<ValidationErrorResponse>,
}

/// A single validation error.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationErrorResponse {
    pub path: String,
    pub message: String,
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
