//! VES compliance proof registry types.
//!
//! Compliance proofs are externally-generated artifacts (e.g., STARKs/zkVM receipts)
//! that attest to properties of encrypted event payloads without revealing the payload.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Hash256, StoreId, TenantId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VesComplianceProof {
    pub proof_id: Uuid,
    pub event_id: Uuid,
    pub tenant_id: TenantId,
    pub store_id: StoreId,
    pub proof_type: String,
    pub proof_version: u32,
    pub policy_id: String,
    pub policy_params: serde_json::Value,
    pub policy_hash: Hash256,
    pub proof: Vec<u8>,
    pub proof_hash: Hash256,
    pub public_inputs: Option<serde_json::Value>,
    pub submitted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VesComplianceProofSummary {
    pub proof_id: Uuid,
    pub event_id: Uuid,
    pub tenant_id: TenantId,
    pub store_id: StoreId,
    pub proof_type: String,
    pub proof_version: u32,
    pub policy_id: String,
    pub policy_params: serde_json::Value,
    pub policy_hash: Hash256,
    pub proof_hash: Hash256,
    pub public_inputs: Option<serde_json::Value>,
    pub submitted_at: DateTime<Utc>,
}
