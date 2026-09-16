//! Stateless proto/domain conversions for the gRPC v2 API.
//!
//! Pure mapping between v2 protobuf messages and domain types, shared by the
//! sequencer and key-management services. Kept free of I/O and auth so the
//! logic stays unit-testable.
#![allow(clippy::result_large_err)]

use crate::crypto::pqc_signing::{ParsedSignatureBundle, SignatureScheme as DomainSignatureScheme};
use crate::crypto::{
    base64_url_decode, base64_url_encode, compute_cipher_hash_from_encrypted, compute_payload_aad,
    compute_receipt_hash, payload_plain_hash, HpkeParams, PayloadAadParams, PayloadEncrypted,
    Recipient, NONCE_SIZE, TAG_SIZE,
};
use crate::domain::{
    AgentId, AgentKeyId, EntityType, EventType, PayloadKind, SequencedVesEvent, StoreId, TenantId,
    VesBatchCommitment, VesEventEnvelope, VES_VERSION, ZERO_HASH,
};
use crate::infra::postgres::VesRejectionReason;
use crate::proto::v2::{
    self, BatchCommitment, EventEnvelope, RejectionReason, SequencedEvent, SignatureBundle,
};
use chrono::{DateTime, Utc};
use tonic::Status;
use uuid::Uuid;

pub(crate) fn map_rejection_reason(reason: &VesRejectionReason) -> RejectionReason {
    match reason {
        VesRejectionReason::DuplicateEventId => RejectionReason::DuplicateEvent,
        VesRejectionReason::DuplicateCommandId => RejectionReason::DuplicateCommand,
        VesRejectionReason::InvalidPayloadHash | VesRejectionReason::InvalidCipherHash => {
            RejectionReason::InvalidHash
        }
        VesRejectionReason::InvalidSignature => RejectionReason::InvalidSignature,
        VesRejectionReason::AgentKeyInvalid(message) => {
            if message.to_ascii_lowercase().contains("revoked") {
                RejectionReason::RevokedKey
            } else {
                RejectionReason::UnknownKey
            }
        }
        VesRejectionReason::UnsupportedVersion | VesRejectionReason::SchemaValidation(_) => {
            RejectionReason::InvalidFormat
        }
        VesRejectionReason::PolicyViolation(_) => RejectionReason::PolicyViolation,
        VesRejectionReason::VersionConflict { .. } => RejectionReason::VersionConflict,
    }
}

/// Validate an acknowledgement without confusing individually completed
/// events with the highest contiguous durable checkpoint.
pub(crate) fn durable_ack_sequence(ack: &v2::EventAck, head: u64) -> Result<u64, Status> {
    let highest_referenced_sequence = ack
        .sequence_numbers
        .iter()
        .copied()
        .chain(std::iter::once(ack.agent_head_sequence))
        .max()
        .unwrap_or(0);
    if highest_referenced_sequence > head {
        return Err(Status::invalid_argument(
            "acknowledged sequences cannot exceed the stream head",
        ));
    }
    Ok(ack.agent_head_sequence)
}

pub(crate) fn timestamp_to_rfc3339(ts: &prost_types::Timestamp) -> Result<String, Status> {
    if ts.nanos < 0 || ts.nanos > 999_999_999 {
        return Err(Status::invalid_argument("invalid created_at nanos"));
    }
    let dt = DateTime::<Utc>::from_timestamp(ts.seconds, ts.nanos as u32)
        .ok_or_else(|| Status::invalid_argument("invalid created_at timestamp"))?;
    Ok(dt.to_rfc3339())
}

pub(crate) fn rfc3339_to_timestamp(value: &str) -> Result<prost_types::Timestamp, Status> {
    let dt = DateTime::parse_from_rfc3339(value).map_err(|e| {
        tracing::error!("invalid created_at: {e}");
        Status::internal("internal error")
    })?;
    let dt = dt.with_timezone(&Utc);
    Ok(prost_types::Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    })
}

pub(crate) fn payload_kind_from_proto(value: i32) -> Result<PayloadKind, Status> {
    match v2::PayloadKind::try_from(value).unwrap_or(v2::PayloadKind::Unspecified) {
        v2::PayloadKind::Plaintext => Ok(PayloadKind::Plaintext),
        v2::PayloadKind::Encrypted => Ok(PayloadKind::Encrypted),
        v2::PayloadKind::Unspecified => Err(Status::invalid_argument("payload_kind required")),
    }
}

pub(crate) fn encrypted_from_proto(
    payload: &v2::EncryptedPayload,
) -> Result<PayloadEncrypted, Status> {
    let enc_version = if payload.enc_version == 0 {
        1
    } else {
        payload.enc_version
    };
    if enc_version != 1 {
        return Err(Status::invalid_argument("enc_version must be 1"));
    }
    if payload.nonce.len() != NONCE_SIZE {
        return Err(Status::invalid_argument("nonce must be 12 bytes"));
    }
    if payload.tag.len() != TAG_SIZE {
        return Err(Status::invalid_argument("tag must be 16 bytes"));
    }

    let hpke = payload
        .hpke
        .as_ref()
        .map(|params| HpkeParams {
            mode: params.mode.clone(),
            kem: params.kem.clone(),
            kdf: params.kdf.clone(),
            aead: params.aead.clone(),
        })
        .unwrap_or_default();

    let recipients = payload
        .recipients
        .iter()
        .map(|recipient| Recipient {
            recipient_kid: recipient.recipient_kid,
            enc_b64u: base64_url_encode(&recipient.ephemeral_public_key),
            ct_b64u: base64_url_encode(&recipient.wrapped_dek),
        })
        .collect();

    Ok(PayloadEncrypted {
        enc_version,
        aead: payload.aead.clone(),
        nonce_b64u: base64_url_encode(&payload.nonce),
        ciphertext_b64u: base64_url_encode(&payload.ciphertext),
        tag_b64u: base64_url_encode(&payload.tag),
        hpke,
        recipients,
    })
}

pub(crate) fn encrypted_to_proto(
    payload: &PayloadEncrypted,
) -> Result<v2::EncryptedPayload, Status> {
    let nonce = base64_url_decode(&payload.nonce_b64u)
        .map_err(|_| Status::internal("invalid encrypted nonce"))?;
    if nonce.len() != NONCE_SIZE {
        return Err(Status::internal("invalid encrypted nonce length"));
    }
    let tag = base64_url_decode(&payload.tag_b64u)
        .map_err(|_| Status::internal("invalid encrypted tag"))?;
    if tag.len() != TAG_SIZE {
        return Err(Status::internal("invalid encrypted tag length"));
    }
    let ciphertext = base64_url_decode(&payload.ciphertext_b64u)
        .map_err(|_| Status::internal("invalid encrypted ciphertext"))?;

    let mut recipients = Vec::with_capacity(payload.recipients.len());
    for recipient in &payload.recipients {
        let enc = base64_url_decode(&recipient.enc_b64u)
            .map_err(|_| Status::internal("invalid recipient enc"))?;
        let wrapped = base64_url_decode(&recipient.ct_b64u)
            .map_err(|_| Status::internal("invalid recipient wrapped_dek"))?;
        recipients.push(v2::RecipientKey {
            recipient_kid: recipient.recipient_kid,
            ephemeral_public_key: enc,
            wrapped_dek: wrapped,
        });
    }

    Ok(v2::EncryptedPayload {
        enc_version: payload.enc_version,
        aead: payload.aead.clone(),
        nonce,
        ciphertext,
        tag,
        hpke: Some(v2::HpkeParams {
            mode: payload.hpke.mode.clone(),
            kem: payload.hpke.kem.clone(),
            kdf: payload.hpke.kdf.clone(),
            aead: payload.hpke.aead.clone(),
        }),
        recipients,
        key_wrap_params: None,
        recipient_wraps: Vec::new(),
    })
}

/// Convert domain event to v2 proto event
pub(crate) fn to_proto_event(event: &SequencedVesEvent) -> Result<SequencedEvent, Status> {
    let envelope = &event.envelope;
    let payload_kind = match envelope.payload_kind {
        PayloadKind::Plaintext => v2::PayloadKind::Plaintext as i32,
        PayloadKind::Encrypted => v2::PayloadKind::Encrypted as i32,
    };

    let (payload, payload_encrypted) = match envelope.payload_kind {
        PayloadKind::Plaintext => {
            let payload = envelope
                .payload
                .as_ref()
                .ok_or_else(|| Status::internal("missing plaintext payload"))?;
            (
                serde_json::to_vec(payload).map_err(super::grpc_internal_error)?,
                None,
            )
        }
        PayloadKind::Encrypted => {
            let encrypted = envelope
                .payload_encrypted
                .as_ref()
                .ok_or_else(|| Status::internal("missing encrypted payload"))?;
            (Vec::new(), Some(encrypted_to_proto(encrypted)?))
        }
    };

    let created_at = rfc3339_to_timestamp(&envelope.created_at)?;
    let sequenced_at = envelope.sequenced_at.unwrap_or_else(Utc::now);
    let receipt_hash = compute_receipt_hash(
        &envelope.tenant_id.0,
        &envelope.store_id.0,
        &envelope.event_id,
        event.sequence_number(),
        &event.compute_signing_hash(),
    );

    // Serialize PQC signature bundle for the EventEnvelope
    let agent_signature_scheme = envelope.agent_signature_scheme.unwrap_or(0);
    let agent_signature_bundle =
        envelope
            .agent_signature_bundle
            .as_ref()
            .map(|bundle| SignatureBundle {
                ed25519_signature: bundle.ed25519_signature.clone().unwrap_or_default(),
                ml_dsa_65_signature: bundle.ml_dsa_65_signature.clone().unwrap_or_default(),
            });

    // Receipt PQC signature fields — populated when apply_receipt_signature is called
    let receipt_sig_scheme = 0i32;
    let receipt_sig_bundle = None::<SignatureBundle>;

    Ok(SequencedEvent {
        envelope: Some(EventEnvelope {
            event_id: envelope.event_id.to_string(),
            command_id: envelope
                .command_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
            tenant_id: envelope.tenant_id.0.to_string(),
            store_id: envelope.store_id.0.to_string(),
            entity_type: envelope.entity_type.0.clone(),
            entity_id: envelope.entity_id.clone(),
            event_type: envelope.event_type.0.clone(),
            source_agent: envelope.source_agent_id.0.to_string(),
            ves_version: envelope.ves_version,
            payload_kind,
            payload,
            payload_encrypted,
            payload_plain_hash: envelope.payload_plain_hash.to_vec(),
            payload_cipher_hash: envelope.payload_cipher_hash.to_vec(),
            agent_key_id: envelope.agent_key_id.as_u32(),
            agent_signature: envelope.agent_signature.to_vec(),
            base_version: envelope.base_version.unwrap_or(0),
            created_at: Some(created_at),
            agent_signature_scheme,
            agent_signature_bundle,
        }),
        sequence_number: event.sequence_number(),
        sequenced_at: Some(prost_types::Timestamp {
            seconds: sequenced_at.timestamp(),
            nanos: sequenced_at.timestamp_subsec_nanos() as i32,
        }),
        receipt_hash: receipt_hash.to_vec(),
        receipt_signature_scheme: receipt_sig_scheme,
        receipt_signature_bundle: receipt_sig_bundle,
    })
}

/// Apply PQC receipt signature fields to a proto SequencedEvent.
///
/// Called when a receipt with PQC signature data is available (e.g., after
/// ingestion). For pull/stream paths, receipt signatures are stored separately
/// and applied when the receipt is joined with the event.
#[allow(dead_code)]
pub(crate) fn apply_receipt_signature(
    event: &mut SequencedEvent,
    receipt: &crate::infra::postgres::VesSequencerReceipt,
) {
    event.receipt_signature_scheme = receipt.receipt_signature_scheme;
    if let Some(ref bundle) = receipt.receipt_signature_bundle {
        event.receipt_signature_bundle = Some(SignatureBundle {
            ed25519_signature: bundle.ed25519_signature.clone().unwrap_or_default(),
            ml_dsa_65_signature: bundle.ml_dsa_65_signature.clone().unwrap_or_default(),
        });
    }
}

/// Convert v2 proto event to VES event envelope
#[allow(clippy::result_large_err)]
pub(crate) fn from_proto_event(proto: &EventEnvelope) -> Result<VesEventEnvelope, Status> {
    let ves_version = if proto.ves_version == 0 {
        VES_VERSION
    } else {
        proto.ves_version
    };
    if !matches!(ves_version, 1 | 2) {
        return Err(Status::invalid_argument("unsupported ves_version"));
    }

    let event_id = Uuid::parse_str(&proto.event_id)
        .map_err(|e| Status::invalid_argument(format!("invalid event_id: {}", e)))?;
    let tenant_id = Uuid::parse_str(&proto.tenant_id)
        .map_err(|e| Status::invalid_argument(format!("invalid tenant_id: {}", e)))?;
    let store_id = Uuid::parse_str(&proto.store_id)
        .map_err(|e| Status::invalid_argument(format!("invalid store_id: {}", e)))?;
    let source_agent = Uuid::parse_str(&proto.source_agent)
        .map_err(|e| Status::invalid_argument(format!("invalid source_agent: {}", e)))?;

    let payload_kind = payload_kind_from_proto(proto.payload_kind)?;

    let created_at = match proto.created_at.as_ref() {
        Some(ts) => timestamp_to_rfc3339(ts)?,
        None => return Err(Status::invalid_argument("created_at required")),
    };

    let command_id = if proto.command_id.is_empty() {
        None
    } else {
        Some(
            Uuid::parse_str(&proto.command_id)
                .map_err(|e| Status::invalid_argument(format!("invalid command_id: {}", e)))?,
        )
    };

    let payload = match payload_kind {
        PayloadKind::Plaintext => {
            let payload: serde_json::Value = serde_json::from_slice(&proto.payload)
                .map_err(|e| Status::invalid_argument(format!("invalid payload JSON: {}", e)))?;
            Some(payload)
        }
        PayloadKind::Encrypted => None,
    };

    if payload_kind == PayloadKind::Plaintext && proto.payload_encrypted.is_some() {
        return Err(Status::invalid_argument(
            "payload_encrypted must be omitted for plaintext events",
        ));
    }
    if payload_kind == PayloadKind::Encrypted && !proto.payload.is_empty() {
        return Err(Status::invalid_argument(
            "payload must be omitted for encrypted events",
        ));
    }

    let payload_encrypted = match payload_kind {
        PayloadKind::Encrypted => {
            let encrypted = proto.payload_encrypted.as_ref().ok_or_else(|| {
                Status::invalid_argument("payload_encrypted required for encrypted events")
            })?;
            Some(encrypted_from_proto(encrypted)?)
        }
        PayloadKind::Plaintext => None,
    };

    let payload_plain_hash: [u8; 32] = match proto.payload_plain_hash.len() {
        0 => {
            if let Some(ref payload) = payload {
                payload_plain_hash(payload)
            } else {
                return Err(Status::invalid_argument(
                    "payload_plain_hash required for encrypted events",
                ));
            }
        }
        32 => proto
            .payload_plain_hash
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("payload_plain_hash must be 32 bytes"))?,
        _ => {
            return Err(Status::invalid_argument(
                "payload_plain_hash must be 32 bytes",
            ))
        }
    };

    // Validate string field lengths (matching HTTP-side limits)
    if proto.entity_type.is_empty() || proto.entity_type.len() > 128 {
        return Err(Status::invalid_argument(
            "entity_type must be between 1 and 128 characters",
        ));
    }
    if proto.entity_id.is_empty() || proto.entity_id.len() > 512 {
        return Err(Status::invalid_argument(
            "entity_id must be between 1 and 512 characters",
        ));
    }
    if proto.event_type.is_empty() || proto.event_type.len() > 256 {
        return Err(Status::invalid_argument(
            "event_type must be between 1 and 256 characters",
        ));
    }

    let payload_aad = payload_encrypted.as_ref().map(|_| {
        compute_payload_aad(&PayloadAadParams {
            tenant_id: &tenant_id,
            store_id: &store_id,
            event_id: &event_id,
            source_agent_id: &source_agent,
            agent_key_id: proto.agent_key_id,
            entity_type: proto.entity_type.as_str(),
            entity_id: &proto.entity_id,
            event_type: proto.event_type.as_str(),
            created_at: &created_at,
            payload_plain_hash: &payload_plain_hash,
        })
    });

    let payload_cipher_hash: [u8; 32] = match proto.payload_cipher_hash.len() {
        0 => {
            if let Some(ref encrypted) = payload_encrypted {
                let payload_aad = payload_aad
                    .as_ref()
                    .ok_or_else(|| Status::invalid_argument("invalid payload_encrypted"))?;
                compute_cipher_hash_from_encrypted(encrypted, payload_aad)
                    .map_err(|_| Status::invalid_argument("invalid payload_encrypted"))?
            } else {
                ZERO_HASH
            }
        }
        32 => proto
            .payload_cipher_hash
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("payload_cipher_hash must be 32 bytes"))?,
        _ => {
            return Err(Status::invalid_argument(
                "payload_cipher_hash must be 32 bytes",
            ))
        }
    };

    // Parse PQC signature scheme and bundle
    let sig_scheme = DomainSignatureScheme::from_i32(proto.agent_signature_scheme);

    let agent_signature: [u8; 64] = match sig_scheme {
        // For PQC-strict (ML-DSA-65 only), the legacy field may be empty
        DomainSignatureScheme::MlDsa65 => {
            if proto.agent_signature.is_empty() {
                [0u8; 64]
            } else {
                proto.agent_signature.as_slice().try_into().map_err(|_| {
                    Status::invalid_argument("agent_signature must be 64 bytes when present")
                })?
            }
        }
        // Legacy and hybrid: Ed25519 signature is required in the legacy field
        _ => proto
            .agent_signature
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("agent_signature must be 64 bytes"))?,
    };

    let agent_signature_scheme = if proto.agent_signature_scheme != 0 {
        Some(proto.agent_signature_scheme)
    } else {
        None
    };

    let agent_signature_bundle =
        proto
            .agent_signature_bundle
            .as_ref()
            .map(|bundle| ParsedSignatureBundle {
                ed25519_signature: if bundle.ed25519_signature.is_empty() {
                    None
                } else {
                    Some(bundle.ed25519_signature.clone())
                },
                ml_dsa_65_signature: if bundle.ml_dsa_65_signature.is_empty() {
                    None
                } else {
                    Some(bundle.ml_dsa_65_signature.clone())
                },
            });

    Ok(VesEventEnvelope {
        ves_version,
        event_id,
        tenant_id: TenantId(tenant_id),
        store_id: StoreId(store_id),
        source_agent_id: AgentId(source_agent),
        agent_key_id: AgentKeyId::new(proto.agent_key_id),
        entity_type: EntityType::from(proto.entity_type.as_str()),
        entity_id: proto.entity_id.clone(),
        event_type: EventType(proto.event_type.clone()),
        created_at,
        payload_kind,
        payload,
        payload_encrypted,
        payload_plain_hash,
        payload_cipher_hash,
        agent_signature,
        agent_signature_scheme,
        agent_signature_bundle,
        sequence_number: None,
        sequenced_at: None,
        command_id,
        base_version: if proto.base_version > 0 {
            Some(proto.base_version)
        } else {
            None
        },
    })
}

/// Convert VES commitment to v2 proto commitment
pub(crate) fn to_proto_commitment(commitment: &VesBatchCommitment) -> BatchCommitment {
    let previous_root = if commitment.prev_state_root == [0u8; 32] {
        Vec::new()
    } else {
        commitment.prev_state_root.to_vec()
    };

    BatchCommitment {
        batch_id: commitment.batch_id.to_string(),
        merkle_root: commitment.merkle_root.to_vec(),
        start_sequence: commitment.sequence_range.0,
        end_sequence: commitment.sequence_range.1,
        event_count: commitment.leaf_count,
        committed_at: Some(prost_types::Timestamp {
            seconds: commitment.committed_at.timestamp(),
            nanos: commitment.committed_at.timestamp_subsec_nanos() as i32,
        }),
        previous_root,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ack(sequence_numbers: Vec<u64>, agent_head_sequence: u64) -> v2::EventAck {
        v2::EventAck {
            sequence_numbers,
            agent_head_sequence,
            tenant_id: Uuid::new_v4().to_string(),
            store_id: Uuid::new_v4().to_string(),
        }
    }

    #[test]
    fn durable_ack_never_skips_a_gap() {
        let ack = ack(vec![8, 10], 7);
        assert_eq!(durable_ack_sequence(&ack, 10).unwrap(), 7);
    }

    #[test]
    fn durable_ack_rejects_any_future_sequence() {
        let ack = ack(vec![8, 11], 8);
        let error = durable_ack_sequence(&ack, 10).unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn durable_ack_accepts_empty_receipt_list() {
        let ack = ack(Vec::new(), 10);
        assert_eq!(durable_ack_sequence(&ack, 10).unwrap(), 10);
    }
}
