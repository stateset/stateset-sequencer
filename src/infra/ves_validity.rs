//! VES validity proof storage.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::crypto::{compute_ves_validity_proof_at_rest_aad, compute_ves_validity_proof_hash};
use crate::domain::{Hash256, StoreId, TenantId, VesValidityProof, VesValidityProofSummary};
use crate::infra::{PayloadEncryption, Result, SequencerError};

pub struct PgVesValidityProofStore {
    pool: PgPool,
    payload_encryption: Arc<PayloadEncryption>,
}

impl PgVesValidityProofStore {
    pub fn new(pool: PgPool, payload_encryption: Arc<PayloadEncryption>) -> Self {
        Self {
            pool,
            payload_encryption,
        }
    }

    /// Submit a validity proof for a batch commitment.
    ///
    /// Note: Parameters represent distinct proof components per VES specification.
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_proof(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        batch_id: Uuid,
        proof_type: &str,
        proof_version: u32,
        proof: Vec<u8>,
        public_inputs: Option<serde_json::Value>,
    ) -> Result<VesValidityProofSummary> {
        let commitment_stream: Option<(Uuid, Uuid)> = sqlx::query_as(
            r#"
            SELECT tenant_id, store_id
            FROM ves_commitments
            WHERE batch_id = $1
            "#,
        )
        .bind(batch_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some((commitment_tenant_id, commitment_store_id)) = commitment_stream else {
            return Err(SequencerError::BatchNotFound(batch_id));
        };

        if commitment_tenant_id != tenant_id.0 || commitment_store_id != store_id.0 {
            return Err(SequencerError::Unauthorized(
                "tenant/store mismatch for batch commitment".to_string(),
            ));
        }

        let proof_hash = compute_ves_validity_proof_hash(&proof);
        let proof_id = Uuid::new_v4();
        let aad = compute_ves_validity_proof_at_rest_aad(
            &tenant_id.0,
            &store_id.0,
            &batch_id,
            &proof_id,
            proof_type,
            proof_version,
            &proof_hash,
        );

        let ciphertext = self
            .payload_encryption
            .encrypt_payload(&tenant_id.0, &aad, &proof)
            .await?;

        let inserted: Option<VesValidityProofSummaryRow> = sqlx::query_as(
            r#"
            INSERT INTO ves_validity_proofs (
                proof_id,
                batch_id,
                tenant_id,
                store_id,
                proof_type,
                proof_version,
                proof,
                proof_hash,
                public_inputs
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
            ON CONFLICT (batch_id, proof_type, proof_version) DO NOTHING
            RETURNING
                proof_id,
                batch_id,
                tenant_id,
                store_id,
                proof_type,
                proof_version,
                proof_hash,
                public_inputs,
                submitted_at
            "#,
        )
        .bind(proof_id)
        .bind(batch_id)
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(proof_type)
        .bind(proof_version as i32)
        .bind(ciphertext)
        .bind(&proof_hash[..])
        .bind(public_inputs.clone())
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = inserted {
            return row.try_into();
        }

        let mut existing: VesValidityProofSummaryRow = sqlx::query_as(
            r#"
            SELECT
                proof_id,
                batch_id,
                tenant_id,
                store_id,
                proof_type,
                proof_version,
                proof_hash,
                public_inputs,
                submitted_at
            FROM ves_validity_proofs
            WHERE batch_id = $1 AND proof_type = $2 AND proof_version = $3
            "#,
        )
        .bind(batch_id)
        .bind(proof_type)
        .bind(proof_version as i32)
        .fetch_one(&self.pool)
        .await?;

        let existing_hash: Hash256 = existing
            .proof_hash
            .clone()
            .try_into()
            .map_err(|_| SequencerError::Internal("invalid proof_hash length".to_string()))?;
        if existing_hash != proof_hash {
            return Err(SequencerError::InvariantViolation {
                invariant: "ves_validity_proof_conflict".to_string(),
                message: format!(
                    "proof already exists for batch_id={batch_id}, proof_type={proof_type}, proof_version={proof_version}"
                ),
            });
        }

        if let Some(new_inputs) = public_inputs {
            match &existing.public_inputs {
                Some(existing_inputs) if existing_inputs != &new_inputs => {
                    return Err(SequencerError::InvariantViolation {
                        invariant: "ves_validity_proof_public_inputs_conflict".to_string(),
                        message: format!(
                            "public_inputs mismatch for existing proof_id={} (batch_id={batch_id}, proof_type={proof_type}, proof_version={proof_version})",
                            existing.proof_id
                        ),
                    });
                }
                None => {
                    sqlx::query(
                        r#"
                        UPDATE ves_validity_proofs
                        SET public_inputs = $1
                        WHERE proof_id = $2
                        "#,
                    )
                    .bind(new_inputs.clone())
                    .bind(existing.proof_id)
                    .execute(&self.pool)
                    .await?;
                    existing.public_inputs = Some(new_inputs);
                }
                Some(_) => {}
            }
        }

        existing.try_into()
    }

    pub async fn list_proofs_for_batch(
        &self,
        batch_id: Uuid,
    ) -> Result<Vec<VesValidityProofSummary>> {
        let rows: Vec<VesValidityProofSummaryRow> = sqlx::query_as(
            r#"
            SELECT
                proof_id,
                batch_id,
                tenant_id,
                store_id,
                proof_type,
                proof_version,
                proof_hash,
                public_inputs,
                submitted_at
            FROM ves_validity_proofs
            WHERE batch_id = $1
            ORDER BY submitted_at ASC
            "#,
        )
        .bind(batch_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    pub async fn get_proof(&self, proof_id: Uuid) -> Result<Option<VesValidityProof>> {
        let row: Option<VesValidityProofRow> = sqlx::query_as(
            r#"
            SELECT
                proof_id,
                batch_id,
                tenant_id,
                store_id,
                proof_type,
                proof_version,
                proof,
                proof_hash,
                public_inputs,
                submitted_at
            FROM ves_validity_proofs
            WHERE proof_id = $1
            "#,
        )
        .bind(proof_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let proof_hash: Hash256 = row
            .proof_hash
            .try_into()
            .map_err(|_| SequencerError::Internal("invalid proof_hash length".to_string()))?;

        let aad = compute_ves_validity_proof_at_rest_aad(
            &row.tenant_id,
            &row.store_id,
            &row.batch_id,
            &row.proof_id,
            &row.proof_type,
            row.proof_version as u32,
            &proof_hash,
        );

        let plaintext = self
            .payload_encryption
            .decrypt_payload(&row.tenant_id, &aad, &row.proof)
            .await?;

        let recomputed = compute_ves_validity_proof_hash(&plaintext);
        if recomputed != proof_hash {
            return Err(SequencerError::Internal(
                "validity proof hash mismatch".to_string(),
            ));
        }

        Ok(Some(VesValidityProof {
            proof_id: row.proof_id,
            batch_id: row.batch_id,
            tenant_id: TenantId::from_uuid(row.tenant_id),
            store_id: StoreId::from_uuid(row.store_id),
            proof_type: row.proof_type,
            proof_version: row.proof_version as u32,
            proof: plaintext,
            proof_hash,
            public_inputs: row.public_inputs,
            submitted_at: row.submitted_at,
        }))
    }
}

#[derive(Debug, sqlx::FromRow)]
struct VesValidityProofRow {
    proof_id: Uuid,
    batch_id: Uuid,
    tenant_id: Uuid,
    store_id: Uuid,
    proof_type: String,
    proof_version: i32,
    proof: Vec<u8>,
    proof_hash: Vec<u8>,
    public_inputs: Option<serde_json::Value>,
    submitted_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
struct VesValidityProofSummaryRow {
    proof_id: Uuid,
    batch_id: Uuid,
    tenant_id: Uuid,
    store_id: Uuid,
    proof_type: String,
    proof_version: i32,
    proof_hash: Vec<u8>,
    public_inputs: Option<serde_json::Value>,
    submitted_at: DateTime<Utc>,
}

impl TryFrom<VesValidityProofSummaryRow> for VesValidityProofSummary {
    type Error = SequencerError;

    fn try_from(row: VesValidityProofSummaryRow) -> Result<Self> {
        let proof_hash: Hash256 = row
            .proof_hash
            .try_into()
            .map_err(|_| SequencerError::Internal("invalid proof_hash length".to_string()))?;

        Ok(Self {
            proof_id: row.proof_id,
            batch_id: row.batch_id,
            tenant_id: TenantId::from_uuid(row.tenant_id),
            store_id: StoreId::from_uuid(row.store_id),
            proof_type: row.proof_type,
            proof_version: row.proof_version as u32,
            proof_hash,
            public_inputs: row.public_inputs,
            submitted_at: row.submitted_at,
        })
    }
}
