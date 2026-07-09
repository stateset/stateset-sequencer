//! Verifier-side payload amount re-extraction for STARK compliance proofs.
//!
//! # Why this exists
//!
//! The STARK compliance circuits prove range predicates (`amount < threshold`,
//! `amount <= cap`, ...) over a *committed* amount: the proof binds a Rescue
//! witness commitment of the amount, and the `PayloadAmountBinding` artifact
//! hashes that amount next to the event's payload hashes. Nothing inside the
//! circuit parses the payload, so a malicious prover could commit a false low
//! amount that hashes self-consistently while the real payload amount violates
//! the policy. Left unchecked, proof soundness reduces to trusting the
//! prover's extraction.
//!
//! # What is enforced, and where
//!
//! The sequencer closes the gap at *verification time* wherever it can see the
//! payload:
//!
//! - **Plaintext events** (`payload_kind = 0`): the sequencer stores the
//!   payload JSON and verified its `payload_plain_hash` at ingest. On proof
//!   submission and re-verification we re-extract the amount with the shared
//!   canonical extractor (`ves_stark_primitives::payload_amount`), recompute
//!   the witness commitment and canonical binding hash, and REJECT the proof
//!   if the committed amount differs from the payload amount.
//! - **Encrypted events** (`payload_kind = 1`): the sequencer never sees the
//!   plaintext — payloads are HPKE-encrypted end-to-end and the plain hash is
//!   salted, so there is *no* point (ingest included) at which the sequencer
//!   can observe both the amount and the payload. Such proofs are rejected by
//!   default; operators may explicitly opt into accepting prover-attested
//!   amounts with `VES_STARK_ALLOW_UNVERIFIED_AMOUNT_BINDING=1`, in which case
//!   responses carry `amount_binding_verified: false` so downstream consumers
//!   know the binding rests on prover honesty.

use std::sync::OnceLock;

use ves_stark_primitives::payload_amount::{amount_witness_commitment, extract_payload_amount};
use ves_stark_primitives::PayloadAmountBinding;

use crate::crypto::payload_plain_hash;
use crate::domain::PayloadKind;
use crate::infra::VesComplianceEventInputs;

/// Environment variable that opts into accepting STARK compliance proofs whose
/// committed amount cannot be re-extracted from the event payload (encrypted
/// payloads, or plaintext payloads without a canonical integer amount field).
pub const ALLOW_UNVERIFIED_AMOUNT_BINDING_ENV: &str = "VES_STARK_ALLOW_UNVERIFIED_AMOUNT_BINDING";

/// Whether unverifiable amount bindings are accepted (default: no).
pub(crate) fn allow_unverified_amount_binding() -> bool {
    static ALLOWED: OnceLock<bool> = OnceLock::new();
    *ALLOWED.get_or_init(|| {
        std::env::var(ALLOW_UNVERIFIED_AMOUNT_BINDING_ENV)
            .ok()
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "on" | "yes"
                )
            })
            .unwrap_or(false)
    })
}

/// Outcome of a successful payload amount binding check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AmountBindingCheck {
    /// Whether the committed amount was re-extracted from the stored payload
    /// and verified against the witness commitment. `false` only when the
    /// operator explicitly allows unverified bindings.
    pub verified: bool,
    /// Canonical binding hash (hex64) recomputed from the payload-extracted
    /// amount; present iff `verified`.
    pub amount_binding_hash: Option<String>,
}

impl AmountBindingCheck {
    fn unverified() -> Self {
        Self {
            verified: false,
            amount_binding_hash: None,
        }
    }
}

/// Verify that a STARK proof's witness commitment commits to the amount
/// actually contained in the event payload.
///
/// Returns `Err(reason)` when the proof must be rejected. Pure function: the
/// `allow_unverified` policy is passed in so it can be unit-tested without
/// process-global environment state.
pub(crate) fn check_payload_amount_binding(
    inputs: &VesComplianceEventInputs,
    witness_commitment: &[u64; 4],
    allow_unverified: bool,
) -> Result<AmountBindingCheck, String> {
    match PayloadKind::from_u32(inputs.payload_kind) {
        Some(PayloadKind::Plaintext) => {}
        Some(PayloadKind::Encrypted) => {
            if allow_unverified {
                return Ok(AmountBindingCheck::unverified());
            }
            return Err(format!(
                "payload amount binding cannot be verified for encrypted payloads: the sequencer \
                 cannot re-extract the amount from the ciphertext (the plain hash is salted). \
                 Set {ALLOW_UNVERIFIED_AMOUNT_BINDING_ENV}=1 to accept prover-attested amounts \
                 (this weakens proof soundness to prover honesty)"
            ));
        }
        None => {
            return Err(format!(
                "unsupported payload_kind {} for payload amount binding",
                inputs.payload_kind
            ));
        }
    }

    let Some(payload) = inputs.payload.as_ref() else {
        return Err(
            "plaintext event payload is unavailable; cannot verify payload amount binding"
                .to_string(),
        );
    };

    // Defense in depth: only trust the stored payload if it still matches the
    // plain hash committed in the signed envelope and the public inputs.
    if payload_plain_hash(payload) != inputs.payload_plain_hash {
        return Err(
            "stored event payload does not match payload_plain_hash; refusing to verify the \
             amount binding against an inconsistent payload"
                .to_string(),
        );
    }

    let amount = match extract_payload_amount(&inputs.event_type, payload) {
        Ok(amount) => amount,
        Err(_) if allow_unverified => return Ok(AmountBindingCheck::unverified()),
        Err(e) => {
            return Err(format!(
                "cannot re-extract a canonical amount from the event payload: {e}. Amount-range \
                 compliance proofs require a canonical integer minor-unit amount field in the \
                 payload; set {ALLOW_UNVERIFIED_AMOUNT_BINDING_ENV}=1 to accept prover-attested \
                 amounts instead"
            ));
        }
    };

    if amount_witness_commitment(amount) != *witness_commitment {
        return Err(format!(
            "witnessCommitment does not match the amount extracted from the event payload: the \
             proof commits to a different amount than the canonical payload amount {amount} for \
             event type \"{}\"",
            inputs.event_type
        ));
    }

    // Recompute the canonical binding hash for the payload-derived amount so
    // callers can persist/expose the attested binding.
    let mut binding = PayloadAmountBinding {
        event_id: inputs.event_id,
        tenant_id: inputs.tenant_id.0,
        store_id: inputs.store_id.0,
        sequence_number: inputs.sequence_number,
        payload_kind: inputs.payload_kind,
        payload_plain_hash: hex::encode(inputs.payload_plain_hash),
        payload_cipher_hash: hex::encode(inputs.payload_cipher_hash),
        event_signing_hash: hex::encode(inputs.event_signing_hash),
        amount,
        binding_hash: String::new(),
    };
    binding.binding_hash = binding
        .compute_hash_hex()
        .map_err(|e| format!("failed to compute canonical amount binding hash: {e}"))?;

    Ok(AmountBindingCheck {
        verified: true,
        amount_binding_hash: Some(binding.binding_hash),
    })
}

/// One event's amount-relevant view for batch validity policy re-checking.
#[derive(Debug, Clone)]
pub(crate) struct BatchAmountEvent<'a> {
    pub event_id: uuid::Uuid,
    pub event_type: &'a str,
    pub payload_kind: u32,
    pub payload: Option<&'a serde_json::Value>,
}

/// Summary of a batch amount re-check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BatchAmountCheckSummary {
    /// Events whose payload amount was re-extracted and checked.
    pub checked: usize,
    /// Events that could not be checked (encrypted, or no canonical amount).
    pub skipped: usize,
}

/// Re-check a batch validity proof's `allCompliant` claim against the stored
/// event payloads.
///
/// The batch STARK proves the policy predicate over *prover-supplied* amounts,
/// so wherever the sequencer holds the plaintext payload it re-extracts the
/// amount and checks the claimed predicate directly. Events whose amount is
/// not recoverable (encrypted payloads, payloads without a canonical amount
/// field) are skipped and only counted; the batch proof for those events
/// remains prover-attested.
///
/// `policy_kind` uses the wire encoding of the batch public inputs
/// (`1` = `order_total.cap`, i.e. `amount <= limit`; anything else =
/// `aml.threshold`, i.e. `amount < limit`), mirroring
/// `parse_batch_public_inputs`.
pub(crate) fn check_batch_amounts_against_policy(
    events: &[BatchAmountEvent<'_>],
    policy_kind: u64,
    policy_limit: u64,
) -> Result<BatchAmountCheckSummary, String> {
    let mut summary = BatchAmountCheckSummary {
        checked: 0,
        skipped: 0,
    };

    for event in events {
        let payload = match (PayloadKind::from_u32(event.payload_kind), event.payload) {
            (Some(PayloadKind::Plaintext), Some(payload)) => payload,
            _ => {
                summary.skipped += 1;
                continue;
            }
        };
        let amount = match extract_payload_amount(event.event_type, payload) {
            Ok(amount) => amount,
            Err(_) => {
                summary.skipped += 1;
                continue;
            }
        };

        let compliant = if policy_kind == 1 {
            amount <= policy_limit
        } else {
            amount < policy_limit
        };
        if !compliant {
            let relation = if policy_kind == 1 { "<=" } else { "<" };
            return Err(format!(
                "event {} has payload amount {amount}, which violates the claimed policy \
                 (amount {relation} {policy_limit}); the batch cannot be allCompliant",
                event.event_id
            ));
        }
        summary.checked += 1;
    }

    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::payload_plain_hash;
    use crate::domain::{StoreId, TenantId};
    use serde_json::json;
    use uuid::Uuid;

    fn plaintext_inputs(event_type: &str, payload: serde_json::Value) -> VesComplianceEventInputs {
        VesComplianceEventInputs {
            event_id: Uuid::from_u128(1),
            tenant_id: TenantId::from_uuid(Uuid::from_u128(2)),
            store_id: StoreId::from_uuid(Uuid::from_u128(3)),
            sequence_number: 42,
            event_type: event_type.to_string(),
            payload_kind: 0,
            payload_plain_hash: payload_plain_hash(&payload),
            payload: Some(payload),
            payload_cipher_hash: [0u8; 32],
            event_signing_hash: [7u8; 32],
        }
    }

    fn encrypted_inputs() -> VesComplianceEventInputs {
        VesComplianceEventInputs {
            event_id: Uuid::from_u128(1),
            tenant_id: TenantId::from_uuid(Uuid::from_u128(2)),
            store_id: StoreId::from_uuid(Uuid::from_u128(3)),
            sequence_number: 42,
            event_type: "order.payment_received".to_string(),
            payload_kind: 1,
            payload: None,
            payload_plain_hash: [1u8; 32],
            payload_cipher_hash: [2u8; 32],
            event_signing_hash: [7u8; 32],
        }
    }

    #[test]
    fn accepts_matching_committed_amount() {
        let inputs = plaintext_inputs(
            "order.payment_received",
            json!({ "paymentId": "PAY-1", "amount": 5_000u64 }),
        );
        let commitment = amount_witness_commitment(5_000);

        let check = check_payload_amount_binding(&inputs, &commitment, false).unwrap();
        assert!(check.verified);
        let hash = check.amount_binding_hash.expect("binding hash");
        assert_eq!(hash.len(), 64);
        assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn rejects_committed_amount_that_differs_from_payload() {
        // Payload says 50_000 (over a 10_000 threshold); the prover commits
        // 5_000 to sneak under it. Must be rejected with a clear error.
        let inputs = plaintext_inputs(
            "order.payment_received",
            json!({ "paymentId": "PAY-1", "amount": 50_000u64 }),
        );
        let lying_commitment = amount_witness_commitment(5_000);

        let err = check_payload_amount_binding(&inputs, &lying_commitment, false).unwrap_err();
        assert!(
            err.contains("witnessCommitment does not match the amount extracted"),
            "unexpected error: {err}"
        );
        assert!(
            err.contains("50000"),
            "error should name the payload amount: {err}"
        );
    }

    #[test]
    fn rejects_tampered_stored_payload() {
        let mut inputs = plaintext_inputs(
            "order.payment_received",
            json!({ "paymentId": "PAY-1", "amount": 5_000u64 }),
        );
        // Simulate stored-payload/plain-hash divergence.
        inputs.payload = Some(json!({ "paymentId": "PAY-1", "amount": 1u64 }));
        let commitment = amount_witness_commitment(1);

        let err = check_payload_amount_binding(&inputs, &commitment, false).unwrap_err();
        assert!(
            err.contains("payload_plain_hash"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_missing_plaintext_payload() {
        let mut inputs = plaintext_inputs("order.payment_received", json!({ "amount": 5_000u64 }));
        inputs.payload = None;
        let commitment = amount_witness_commitment(5_000);

        let err = check_payload_amount_binding(&inputs, &commitment, false).unwrap_err();
        assert!(
            err.contains("payload is unavailable"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_encrypted_payload_by_default() {
        let inputs = encrypted_inputs();
        let commitment = amount_witness_commitment(5_000);

        let err = check_payload_amount_binding(&inputs, &commitment, false).unwrap_err();
        assert!(
            err.contains("encrypted payloads"),
            "unexpected error: {err}"
        );
        assert!(
            err.contains(ALLOW_UNVERIFIED_AMOUNT_BINDING_ENV),
            "error should mention the opt-out: {err}"
        );
    }

    #[test]
    fn allows_encrypted_payload_when_opted_in_but_marks_unverified() {
        let inputs = encrypted_inputs();
        let commitment = amount_witness_commitment(5_000);

        let check = check_payload_amount_binding(&inputs, &commitment, true).unwrap();
        assert!(!check.verified);
        assert!(check.amount_binding_hash.is_none());
    }

    #[test]
    fn rejects_payload_without_canonical_amount_by_default() {
        // A float amount has no canonical integer minor-unit value.
        let inputs = plaintext_inputs("order.created", json!({ "total": 1482.37 }));
        let commitment = amount_witness_commitment(1482);

        let err = check_payload_amount_binding(&inputs, &commitment, false).unwrap_err();
        assert!(
            err.contains("cannot re-extract a canonical amount"),
            "unexpected error: {err}"
        );

        // With the explicit opt-in it is accepted but marked unverified.
        let check = check_payload_amount_binding(&inputs, &commitment, true).unwrap();
        assert!(!check.verified);
    }

    // ------------------------------------------------------------------
    // Batch re-check
    // ------------------------------------------------------------------

    #[test]
    fn batch_recheck_flags_policy_violation() {
        let over = json!({ "amount": 50_000u64 });
        let under = json!({ "amount": 5_000u64 });
        let events = [
            BatchAmountEvent {
                event_id: Uuid::from_u128(10),
                event_type: "order.payment_received",
                payload_kind: 0,
                payload: Some(&under),
            },
            BatchAmountEvent {
                event_id: Uuid::from_u128(11),
                event_type: "order.payment_received",
                payload_kind: 0,
                payload: Some(&over),
            },
        ];

        // aml.threshold (policy_kind 0): amount < 10_000.
        let err = check_batch_amounts_against_policy(&events, 0, 10_000).unwrap_err();
        assert!(
            err.contains(&Uuid::from_u128(11).to_string()),
            "unexpected error: {err}"
        );
        assert!(err.contains("50000"), "unexpected error: {err}");
    }

    #[test]
    fn batch_recheck_respects_cap_semantics() {
        let at_cap = json!({ "amount": 10_000u64 });
        let events = [BatchAmountEvent {
            event_id: Uuid::from_u128(10),
            event_type: "order.payment_received",
            payload_kind: 0,
            payload: Some(&at_cap),
        }];

        // order_total.cap (policy_kind 1): amount <= 10_000 passes...
        let summary = check_batch_amounts_against_policy(&events, 1, 10_000).unwrap();
        assert_eq!(summary.checked, 1);
        // ...but aml.threshold (strict <) fails at the boundary.
        assert!(check_batch_amounts_against_policy(&events, 0, 10_000).is_err());
    }

    #[test]
    fn batch_recheck_skips_unrecoverable_events() {
        let good = json!({ "amount": 1_000u64 });
        let no_amount = json!({ "trackingNumber": "1Z" });
        let events = [
            BatchAmountEvent {
                event_id: Uuid::from_u128(10),
                event_type: "order.payment_received",
                payload_kind: 0,
                payload: Some(&good),
            },
            BatchAmountEvent {
                event_id: Uuid::from_u128(11),
                event_type: "order.shipped",
                payload_kind: 0,
                payload: Some(&no_amount),
            },
            BatchAmountEvent {
                event_id: Uuid::from_u128(12),
                event_type: "order.payment_received",
                payload_kind: 1,
                payload: None,
            },
        ];

        let summary = check_batch_amounts_against_policy(&events, 0, 10_000).unwrap();
        assert_eq!(summary.checked, 1);
        assert_eq!(summary.skipped, 2);
    }
}
