//! VES compliance proof storage.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::crypto::{
    compute_ves_compliance_policy_hash, compute_ves_compliance_proof_at_rest_aad,
    compute_ves_compliance_proof_hash, ComplianceProofAadParams,
};
use crate::domain::{Hash256, StoreId, TenantId, VesComplianceProof, VesComplianceProofSummary};
use crate::infra::{PayloadEncryption, Result, SequencerError};

#[derive(Debug, Clone)]
pub struct VesComplianceEventInputs {
    pub event_id: Uuid,
    pub tenant_id: TenantId,
    pub store_id: StoreId,
    pub sequence_number: u64,
    pub event_type: String,
    pub payload_kind: u32,
    /// Stored plaintext payload (present when payload_kind = 0).
    ///
    /// Used to re-extract the canonical amount when verifying payload amount
    /// bindings for STARK compliance proofs.
    pub payload: Option<serde_json::Value>,
    pub payload_plain_hash: Hash256,
    pub payload_cipher_hash: Hash256,
    pub event_signing_hash: Hash256,
}

pub struct PgVesComplianceProofStore {
    pool: PgPool,
    payload_encryption: Arc<PayloadEncryption>,
}

impl PgVesComplianceProofStore {
    pub fn new(pool: PgPool, payload_encryption: Arc<PayloadEncryption>) -> Self {
        Self {
            pool,
            payload_encryption,
        }
    }

    pub async fn get_event_inputs(
        &self,
        event_id: Uuid,
    ) -> Result<Option<VesComplianceEventInputs>> {
        let row: Option<VesEventInputsRow> = sqlx::query_as(
            r#"
            SELECT
                event_id,
                tenant_id,
                store_id,
                sequence_number,
                event_type,
                payload_kind,
                payload,
                payload_plain_hash,
                payload_cipher_hash,
                event_signing_hash
            FROM ves_events
            WHERE event_id = $1
            "#,
        )
        .bind(event_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else { return Ok(None) };

        let payload_plain_hash: Hash256 = row.payload_plain_hash.try_into().map_err(|_| {
            SequencerError::Internal("invalid payload_plain_hash length".to_string())
        })?;
        let payload_cipher_hash: Hash256 = row.payload_cipher_hash.try_into().map_err(|_| {
            SequencerError::Internal("invalid payload_cipher_hash length".to_string())
        })?;
        let event_signing_hash: Hash256 = row.event_signing_hash.try_into().map_err(|_| {
            SequencerError::Internal("invalid event_signing_hash length".to_string())
        })?;

        Ok(Some(VesComplianceEventInputs {
            event_id: row.event_id,
            tenant_id: TenantId::from_uuid(row.tenant_id),
            store_id: StoreId::from_uuid(row.store_id),
            sequence_number: row.sequence_number as u64,
            event_type: row.event_type,
            payload_kind: row.payload_kind as u32,
            payload: row.payload,
            payload_plain_hash,
            payload_cipher_hash,
            event_signing_hash,
        }))
    }

    /// Return plaintext VES events that do not yet have the requested proof.
    /// Used by the optional in-process prover; encrypted payloads are excluded
    /// because the sequencer cannot soundly derive their private amount.
    pub async fn list_unproved_plaintext_events(
        &self,
        proof_type: &str,
        proof_version: u32,
        policy_hash: &Hash256,
        limit: usize,
    ) -> Result<Vec<VesComplianceEventInputs>> {
        let limit = i64::try_from(limit).map_err(|_| {
            SequencerError::Configuration("proof worker batch size does not fit BIGINT".to_string())
        })?;
        let rows: Vec<VesEventInputsRow> = sqlx::query_as(
            r#"
            SELECT
                e.event_id, e.tenant_id, e.store_id, e.sequence_number,
                e.event_type, e.payload_kind, e.payload, e.payload_plain_hash,
                e.payload_cipher_hash, e.event_signing_hash
            FROM ves_events e
            WHERE e.payload_kind = 0
              AND e.payload IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1
                  FROM ves_proof_jobs j
                  WHERE j.event_id = e.event_id
                    AND j.policy_hash = $3
                    AND (
                        j.status IN ('proved', 'not_compliant', 'skipped', 'failed')
                        OR (j.status = 'retryable' AND j.next_attempt_at > NOW())
                    )
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM ves_compliance_proofs p
                  WHERE p.event_id = e.event_id
                    AND p.proof_type = $1
                    AND p.proof_version = $2
                    AND p.policy_hash = $3
              )
            ORDER BY e.sequenced_at ASC, e.sequence_number ASC
            LIMIT $4
            "#,
        )
        .bind(proof_type)
        .bind(i32::try_from(proof_version).map_err(|_| {
            SequencerError::Configuration("proof version does not fit INTEGER".to_string())
        })?)
        .bind(&policy_hash[..])
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(VesComplianceEventInputs::try_from)
            .collect()
    }

    pub async fn record_worker_proved(&self, event_id: Uuid, policy_hash: &Hash256) -> Result<()> {
        self.upsert_worker_job(event_id, policy_hash, "proved", None, None)
            .await
    }

    pub async fn record_worker_not_compliant(
        &self,
        event_id: Uuid,
        policy_hash: &Hash256,
        reason: &str,
    ) -> Result<()> {
        self.upsert_worker_job(event_id, policy_hash, "not_compliant", Some(reason), None)
            .await
    }

    pub async fn record_worker_skipped(
        &self,
        event_id: Uuid,
        policy_hash: &Hash256,
        reason: &str,
    ) -> Result<()> {
        self.upsert_worker_job(event_id, policy_hash, "skipped", Some(reason), None)
            .await
    }

    pub async fn record_worker_failure(
        &self,
        event_id: Uuid,
        policy_hash: &Hash256,
        reason: &str,
        max_attempts: u32,
        retry_delay: std::time::Duration,
    ) -> Result<()> {
        let delay_seconds = i64::try_from(retry_delay.as_secs()).unwrap_or(i64::MAX);
        let max_attempts = i32::try_from(max_attempts).unwrap_or(i32::MAX);
        let reason = truncate_error(reason);
        sqlx::query(
            r#"
            INSERT INTO ves_proof_jobs
                (event_id, policy_hash, status, attempts, last_error, next_attempt_at, updated_at)
            VALUES ($1, $2,
                    CASE WHEN 1 >= $4 THEN 'failed' ELSE 'retryable' END,
                    1, $3, NOW() + make_interval(secs => $5), NOW())
            ON CONFLICT (event_id, policy_hash) DO UPDATE SET
                attempts = ves_proof_jobs.attempts + 1,
                status = CASE
                    WHEN ves_proof_jobs.attempts + 1 >= $4 THEN 'failed'
                    ELSE 'retryable'
                END,
                last_error = $3,
                next_attempt_at = NOW() + make_interval(secs => $5),
                updated_at = NOW()
            "#,
        )
        .bind(event_id)
        .bind(&policy_hash[..])
        .bind(reason)
        .bind(max_attempts)
        .bind(delay_seconds as f64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn upsert_worker_job(
        &self,
        event_id: Uuid,
        policy_hash: &Hash256,
        status: &str,
        error: Option<&str>,
        next_attempt_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        let error = error.map(truncate_error);
        sqlx::query(
            r#"
            INSERT INTO ves_proof_jobs
                (event_id, policy_hash, status, attempts, last_error, next_attempt_at, updated_at)
            VALUES ($1, $2, $3, 1, $4, $5, NOW())
            ON CONFLICT (event_id, policy_hash) DO UPDATE SET
                status = EXCLUDED.status,
                attempts = ves_proof_jobs.attempts + 1,
                last_error = EXCLUDED.last_error,
                next_attempt_at = EXCLUDED.next_attempt_at,
                updated_at = NOW()
            "#,
        )
        .bind(event_id)
        .bind(&policy_hash[..])
        .bind(status)
        .bind(error)
        .bind(next_attempt_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Submit a compliance proof for an event.
    ///
    /// Note: Parameters represent distinct proof components per VES specification.
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_proof(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        event_id: Uuid,
        proof_type: &str,
        proof_version: u32,
        policy_id: &str,
        policy_params: serde_json::Value,
        witness_commitment: Option<Hash256>,
        proof: Vec<u8>,
        public_inputs: Option<serde_json::Value>,
    ) -> Result<VesComplianceProofSummary> {
        let event_stream: Option<(Uuid, Uuid)> = sqlx::query_as(
            r#"
            SELECT tenant_id, store_id
            FROM ves_events
            WHERE event_id = $1
            "#,
        )
        .bind(event_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some((event_tenant_id, event_store_id)) = event_stream else {
            return Err(SequencerError::EventNotFound(event_id));
        };

        if event_tenant_id != tenant_id.0 || event_store_id != store_id.0 {
            return Err(SequencerError::Unauthorized(
                "tenant/store mismatch for event".to_string(),
            ));
        }

        let policy_hash = compute_ves_compliance_policy_hash(policy_id, &policy_params);
        let proof_hash = compute_ves_compliance_proof_hash(&proof);
        let proof_id = Uuid::new_v4();

        let aad = compute_ves_compliance_proof_at_rest_aad(&ComplianceProofAadParams {
            tenant_id: &tenant_id.0,
            store_id: &store_id.0,
            event_id: &event_id,
            proof_id: &proof_id,
            policy_hash: &policy_hash,
            proof_type,
            proof_version,
            proof_hash: &proof_hash,
        });

        let ciphertext = self
            .payload_encryption
            .encrypt_payload(&tenant_id.0, &aad, &proof)
            .await?;

        let inserted: Option<VesComplianceProofSummaryRow> = sqlx::query_as(
            r#"
            INSERT INTO ves_compliance_proofs (
                proof_id,
                event_id,
                tenant_id,
                store_id,
                proof_type,
                proof_version,
                policy_id,
                policy_params,
                policy_hash,
                witness_commitment,
                proof,
                proof_hash,
                public_inputs
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
            ON CONFLICT (event_id, proof_type, proof_version, policy_hash) DO NOTHING
            RETURNING
                proof_id,
                event_id,
                tenant_id,
                store_id,
                proof_type,
                proof_version,
                policy_id,
                policy_params,
                policy_hash,
                proof_hash,
                witness_commitment,
                public_inputs,
                submitted_at
            "#,
        )
        .bind(proof_id)
        .bind(event_id)
        .bind(tenant_id.0)
        .bind(store_id.0)
        .bind(proof_type)
        .bind(proof_version as i32)
        .bind(policy_id)
        .bind(policy_params.clone())
        .bind(&policy_hash[..])
        .bind(witness_commitment.as_ref().map(|v| v.to_vec()))
        .bind(ciphertext)
        .bind(&proof_hash[..])
        .bind(public_inputs.clone())
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = inserted {
            return row.try_into();
        }

        let mut existing: VesComplianceProofSummaryRow = sqlx::query_as(
            r#"
            SELECT
                proof_id,
                event_id,
                tenant_id,
                store_id,
                proof_type,
                proof_version,
                policy_id,
                policy_params,
                policy_hash,
                proof_hash,
                witness_commitment,
                public_inputs,
                submitted_at
            FROM ves_compliance_proofs
            WHERE event_id = $1 AND proof_type = $2 AND proof_version = $3 AND policy_hash = $4
            "#,
        )
        .bind(event_id)
        .bind(proof_type)
        .bind(proof_version as i32)
        .bind(&policy_hash[..])
        .fetch_one(&self.pool)
        .await?;

        let existing_proof_hash: Hash256 = existing
            .proof_hash
            .clone()
            .try_into()
            .map_err(|_| SequencerError::Internal("invalid proof_hash length".to_string()))?;
        if existing_proof_hash != proof_hash {
            return Err(SequencerError::InvariantViolation {
                invariant: "ves_compliance_proof_conflict".to_string(),
                message: format!(
                    "proof already exists for event_id={event_id}, policy_id={policy_id}, proof_type={proof_type}, proof_version={proof_version}"
                ),
            });
        }

        if let Some(new_inputs) = public_inputs {
            match &existing.public_inputs {
                Some(existing_inputs) if existing_inputs != &new_inputs => {
                    return Err(SequencerError::InvariantViolation {
                        invariant: "ves_compliance_proof_public_inputs_conflict".to_string(),
                        message: format!(
                            "public_inputs mismatch for existing proof_id={} (event_id={event_id})",
                            existing.proof_id
                        ),
                    });
                }
                None => {
                    sqlx::query(
                        r#"
                        UPDATE ves_compliance_proofs
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

        if let Some(new_commitment) = witness_commitment {
            match &existing.witness_commitment {
                Some(existing_commitment) if existing_commitment != &new_commitment.to_vec() => {
                    return Err(SequencerError::InvariantViolation {
                        invariant: "ves_compliance_proof_witness_commitment_conflict".to_string(),
                        message: format!(
                            "witness_commitment mismatch for existing proof_id={} (event_id={event_id})",
                            existing.proof_id
                        ),
                    });
                }
                None => {
                    sqlx::query(
                        r#"
                        UPDATE ves_compliance_proofs
                        SET witness_commitment = $1
                        WHERE proof_id = $2
                        "#,
                    )
                    .bind(new_commitment.to_vec())
                    .bind(existing.proof_id)
                    .execute(&self.pool)
                    .await?;
                    existing.witness_commitment = Some(new_commitment.to_vec());
                }
                Some(_) => {}
            }
        }

        existing.try_into()
    }

    pub async fn list_proofs_for_event(
        &self,
        event_id: Uuid,
    ) -> Result<Vec<VesComplianceProofSummary>> {
        let rows: Vec<VesComplianceProofSummaryRow> = sqlx::query_as(
            r#"
            SELECT
                proof_id,
                event_id,
                tenant_id,
                store_id,
                proof_type,
                proof_version,
                policy_id,
                policy_params,
                policy_hash,
                proof_hash,
                witness_commitment,
                public_inputs,
                submitted_at
            FROM ves_compliance_proofs
            WHERE event_id = $1
            ORDER BY submitted_at ASC
            "#,
        )
        .bind(event_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    pub async fn get_proof(&self, proof_id: Uuid) -> Result<Option<VesComplianceProof>> {
        let row: Option<VesComplianceProofRow> = sqlx::query_as(
            r#"
            SELECT
                proof_id,
                event_id,
                tenant_id,
                store_id,
                proof_type,
                proof_version,
                policy_id,
                policy_params,
                policy_hash,
                witness_commitment,
                proof,
                proof_hash,
                public_inputs,
                submitted_at
            FROM ves_compliance_proofs
            WHERE proof_id = $1
            "#,
        )
        .bind(proof_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let policy_hash: Hash256 = row
            .policy_hash
            .try_into()
            .map_err(|_| SequencerError::Internal("invalid policy_hash length".to_string()))?;
        let proof_hash: Hash256 = row
            .proof_hash
            .try_into()
            .map_err(|_| SequencerError::Internal("invalid proof_hash length".to_string()))?;

        let aad = compute_ves_compliance_proof_at_rest_aad(&ComplianceProofAadParams {
            tenant_id: &row.tenant_id,
            store_id: &row.store_id,
            event_id: &row.event_id,
            proof_id: &row.proof_id,
            policy_hash: &policy_hash,
            proof_type: &row.proof_type,
            proof_version: row.proof_version as u32,
            proof_hash: &proof_hash,
        });

        let plaintext = self
            .payload_encryption
            .decrypt_payload(&row.tenant_id, &aad, &row.proof)
            .await?;

        let recomputed = compute_ves_compliance_proof_hash(&plaintext);
        if recomputed != proof_hash {
            return Err(SequencerError::Internal(
                "compliance proof hash mismatch".to_string(),
            ));
        }

        Ok(Some(VesComplianceProof {
            proof_id: row.proof_id,
            event_id: row.event_id,
            tenant_id: TenantId::from_uuid(row.tenant_id),
            store_id: StoreId::from_uuid(row.store_id),
            proof_type: row.proof_type,
            proof_version: row.proof_version as u32,
            policy_id: row.policy_id,
            policy_params: row.policy_params,
            policy_hash,
            witness_commitment: row
                .witness_commitment
                .as_ref()
                .map(|v| v.clone().try_into())
                .transpose()
                .map_err(|_| {
                    SequencerError::Internal("invalid witness_commitment length".to_string())
                })?,
            proof: plaintext,
            proof_hash,
            public_inputs: row.public_inputs,
            submitted_at: row.submitted_at,
        }))
    }
}

fn truncate_error(reason: &str) -> &str {
    let end = reason
        .char_indices()
        .map(|(index, _)| index)
        .take_while(|index| *index <= 4000)
        .last()
        .unwrap_or(0);
    if reason.len() <= 4000 {
        reason
    } else {
        &reason[..end]
    }
}

#[derive(Debug, sqlx::FromRow)]
struct VesEventInputsRow {
    event_id: Uuid,
    tenant_id: Uuid,
    store_id: Uuid,
    sequence_number: i64,
    event_type: String,
    payload_kind: i32,
    payload: Option<serde_json::Value>,
    payload_plain_hash: Vec<u8>,
    payload_cipher_hash: Vec<u8>,
    event_signing_hash: Vec<u8>,
}

impl TryFrom<VesEventInputsRow> for VesComplianceEventInputs {
    type Error = SequencerError;

    fn try_from(row: VesEventInputsRow) -> Result<Self> {
        Ok(Self {
            event_id: row.event_id,
            tenant_id: TenantId::from_uuid(row.tenant_id),
            store_id: StoreId::from_uuid(row.store_id),
            sequence_number: u64::try_from(row.sequence_number).map_err(|_| {
                SequencerError::Internal("invalid negative VES sequence number".to_string())
            })?,
            event_type: row.event_type,
            payload_kind: u32::try_from(row.payload_kind).map_err(|_| {
                SequencerError::Internal("invalid negative VES payload kind".to_string())
            })?,
            payload: row.payload,
            payload_plain_hash: row.payload_plain_hash.try_into().map_err(|_| {
                SequencerError::Internal("invalid payload_plain_hash length".to_string())
            })?,
            payload_cipher_hash: row.payload_cipher_hash.try_into().map_err(|_| {
                SequencerError::Internal("invalid payload_cipher_hash length".to_string())
            })?,
            event_signing_hash: row.event_signing_hash.try_into().map_err(|_| {
                SequencerError::Internal("invalid event_signing_hash length".to_string())
            })?,
        })
    }
}

#[derive(Debug, sqlx::FromRow)]
struct VesComplianceProofRow {
    proof_id: Uuid,
    event_id: Uuid,
    tenant_id: Uuid,
    store_id: Uuid,
    proof_type: String,
    proof_version: i32,
    policy_id: String,
    policy_params: serde_json::Value,
    policy_hash: Vec<u8>,
    witness_commitment: Option<Vec<u8>>,
    proof: Vec<u8>,
    proof_hash: Vec<u8>,
    public_inputs: Option<serde_json::Value>,
    submitted_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
struct VesComplianceProofSummaryRow {
    proof_id: Uuid,
    event_id: Uuid,
    tenant_id: Uuid,
    store_id: Uuid,
    proof_type: String,
    proof_version: i32,
    policy_id: String,
    policy_params: serde_json::Value,
    policy_hash: Vec<u8>,
    proof_hash: Vec<u8>,
    witness_commitment: Option<Vec<u8>>,
    public_inputs: Option<serde_json::Value>,
    submitted_at: DateTime<Utc>,
}

impl TryFrom<VesComplianceProofSummaryRow> for VesComplianceProofSummary {
    type Error = SequencerError;

    fn try_from(row: VesComplianceProofSummaryRow) -> Result<Self> {
        let policy_hash: Hash256 = row
            .policy_hash
            .try_into()
            .map_err(|_| SequencerError::Internal("invalid policy_hash length".to_string()))?;
        let proof_hash: Hash256 = row
            .proof_hash
            .try_into()
            .map_err(|_| SequencerError::Internal("invalid proof_hash length".to_string()))?;
        let witness_commitment: Option<Hash256> = row
            .witness_commitment
            .as_ref()
            .map(|v| v.clone().try_into())
            .transpose()
            .map_err(|_| {
                SequencerError::Internal("invalid witness_commitment length".to_string())
            })?;

        Ok(Self {
            proof_id: row.proof_id,
            event_id: row.event_id,
            tenant_id: TenantId::from_uuid(row.tenant_id),
            store_id: StoreId::from_uuid(row.store_id),
            proof_type: row.proof_type,
            proof_version: row.proof_version as u32,
            policy_id: row.policy_id,
            policy_params: row.policy_params,
            policy_hash,
            proof_hash,
            witness_commitment,
            public_inputs: row.public_inputs,
            submitted_at: row.submitted_at,
        })
    }
}
