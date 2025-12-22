//! VES validity proof registry types.
//!
//! Validity proofs are externally-generated artifacts (e.g., SNARKs) that attest
//! to properties of a `ves_commitments` batch. The sequencer stores them for
//! downstream verification and anchoring workflows.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Hash256, StoreId, TenantId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VesValidityProof {
    pub proof_id: Uuid,
    pub batch_id: Uuid,
    pub tenant_id: TenantId,
    pub store_id: StoreId,
    pub proof_type: String,
    pub proof_version: u32,
    pub proof: Vec<u8>,
    pub proof_hash: Hash256,
    pub public_inputs: Option<serde_json::Value>,
    pub submitted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VesValidityProofSummary {
    pub proof_id: Uuid,
    pub batch_id: Uuid,
    pub tenant_id: TenantId,
    pub store_id: StoreId,
    pub proof_type: String,
    pub proof_version: u32,
    pub proof_hash: Hash256,
    pub public_inputs: Option<serde_json::Value>,
    pub submitted_at: DateTime<Utc>,
}
