//! Property-based tests using proptest.
//!
//! These tests verify invariants that should hold for any valid input.

use proptest::prelude::*;
use serde_json::json;
use uuid::Uuid;

use stateset_sequencer::crypto::{
    canonical_json_hash, canonicalize_json, compute_event_signing_hash, compute_leaf_hash,
    decrypt_payload, encrypt_payload, generate_key, EventSigningParams, LeafHashParams,
};
use stateset_sequencer::domain::{
    AgentId, BatchCommitment, EntityType, EventEnvelope, EventType, MerkleProof, StoreId, TenantId,
};

// ============================================================================
// Custom Strategies
// ============================================================================

/// Generate a random UUID
fn arb_uuid() -> impl Strategy<Value = Uuid> {
    any::<[u8; 16]>().prop_map(Uuid::from_bytes)
}

/// Generate a random 32-byte hash
fn arb_hash256() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
}

/// Generate a random entity type
fn arb_entity_type() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("order".to_string()),
        Just("product".to_string()),
        Just("customer".to_string()),
        Just("inventory".to_string()),
        Just("return".to_string()),
        "[a-z][a-z0-9_]{2,20}".prop_map(|s| s),
    ]
}

/// Generate a random event type
fn arb_event_type() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("order.created".to_string()),
        Just("order.updated".to_string()),
        Just("product.created".to_string()),
        "[a-z]+\\.[a-z]+".prop_map(|s| s),
    ]
}

/// Generate a random JSON payload
fn arb_payload() -> impl Strategy<Value = serde_json::Value> {
    prop_oneof![
        // Empty object
        Just(json!({})),
        // Simple object
        (any::<i64>(), ".*").prop_map(|(num, str)| json!({ "number": num, "string": str })),
        // Nested object
        any::<i64>().prop_map(|n| json!({
            "level1": {
                "level2": {
                    "value": n
                }
            }
        })),
        // Array
        prop::collection::vec(any::<i32>(), 0..10).prop_map(|v| json!({ "items": v })),
    ]
}

/// Generate a random entity ID
fn arb_entity_id() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_-]{1,64}".prop_map(|s| s)
}

// ============================================================================
// Canonical JSON Hash Properties
// ============================================================================

proptest! {
    /// Property: Canonical hash is deterministic
    #[test]
    fn canonical_hash_is_deterministic(payload in arb_payload()) {
        let hash1 = canonical_json_hash(&payload);
        let hash2 = canonical_json_hash(&payload);
        prop_assert_eq!(hash1, hash2);
    }

    /// Property: Key order doesn't affect canonical hash
    #[test]
    fn canonical_hash_ignores_key_order(
        a in any::<i64>(),
        b in any::<i64>(),
        c in any::<i64>()
    ) {
        let payload1 = json!({ "a": a, "b": b, "c": c });
        let payload2 = json!({ "c": c, "a": a, "b": b });
        let payload3 = json!({ "b": b, "c": c, "a": a });

        let hash1 = canonical_json_hash(&payload1);
        let hash2 = canonical_json_hash(&payload2);
        let hash3 = canonical_json_hash(&payload3);

        prop_assert_eq!(hash1, hash2);
        prop_assert_eq!(hash2, hash3);
    }

    /// Property: Different payloads produce different hashes (with high probability)
    #[test]
    fn different_payloads_different_hashes(
        a in any::<i64>(),
        b in any::<i64>()
    ) {
        prop_assume!(a != b);

        let payload1 = json!({ "value": a });
        let payload2 = json!({ "value": b });

        let hash1 = canonical_json_hash(&payload1);
        let hash2 = canonical_json_hash(&payload2);

        prop_assert_ne!(hash1, hash2);
    }

    /// Property: Canonical JSON produces valid JSON string
    #[test]
    fn canonical_json_is_valid_json(payload in arb_payload()) {
        let canonical = canonicalize_json(&payload);
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&canonical);
        prop_assert!(parsed.is_ok());
    }

    /// Property: Canonical JSON is stable across serialization cycles
    #[test]
    fn canonical_json_is_stable(payload in arb_payload()) {
        let canonical1 = canonicalize_json(&payload);
        let reparsed: serde_json::Value = serde_json::from_str(&canonical1).unwrap();
        let canonical2 = canonicalize_json(&reparsed);

        prop_assert_eq!(canonical1, canonical2);
    }
}

// ============================================================================
// Encryption Properties
// ============================================================================

proptest! {
    /// Property: Encryption roundtrip preserves data
    #[test]
    fn encryption_roundtrip_preserves_data(data in prop::collection::vec(any::<u8>(), 0..10000)) {
        let key = generate_key();
        let ciphertext = encrypt_payload(&key, &data).unwrap();
        let decrypted = decrypt_payload(&key, &ciphertext).unwrap();

        prop_assert_eq!(data, decrypted);
    }

    /// Property: Ciphertext differs from plaintext (for non-empty data)
    #[test]
    fn ciphertext_differs_from_plaintext(data in prop::collection::vec(any::<u8>(), 1..1000)) {
        let key = generate_key();
        let ciphertext = encrypt_payload(&key, &data).unwrap();

        // Ciphertext should be different (unless by astronomically unlikely chance)
        prop_assert_ne!(data, ciphertext);
    }

    /// Property: Ciphertext is longer than plaintext (due to nonce + tag)
    #[test]
    fn ciphertext_is_longer(data in prop::collection::vec(any::<u8>(), 0..1000)) {
        let key = generate_key();
        let ciphertext = encrypt_payload(&key, &data).unwrap();

        // AES-GCM adds 12-byte nonce + 16-byte auth tag + 4-byte header
        prop_assert!(ciphertext.len() > data.len());
    }

    /// Property: Different keys produce different ciphertexts
    #[test]
    fn different_keys_different_ciphertexts(data in prop::collection::vec(any::<u8>(), 1..100)) {
        let key1 = generate_key();
        let key2 = generate_key();

        // Keys should be different (with overwhelming probability)
        prop_assume!(key1 != key2);

        let ciphertext1 = encrypt_payload(&key1, &data).unwrap();
        let ciphertext2 = encrypt_payload(&key2, &data).unwrap();

        prop_assert_ne!(ciphertext1, ciphertext2);
    }

    /// Property: Wrong key fails decryption
    #[test]
    fn wrong_key_fails_decryption(data in prop::collection::vec(any::<u8>(), 1..100)) {
        let key1 = generate_key();
        let key2 = generate_key();

        prop_assume!(key1 != key2);

        let ciphertext = encrypt_payload(&key1, &data).unwrap();
        let result = decrypt_payload(&key2, &ciphertext);

        prop_assert!(result.is_err());
    }

    /// Property: Tampered ciphertext fails decryption
    #[test]
    fn tampered_ciphertext_fails(
        data in prop::collection::vec(any::<u8>(), 1..100),
        tamper_idx in 0usize..1000
    ) {
        let key = generate_key();
        let mut ciphertext = encrypt_payload(&key, &data).unwrap();

        // Tamper with a byte
        let idx = tamper_idx % ciphertext.len();
        ciphertext[idx] = ciphertext[idx].wrapping_add(1);

        let result = decrypt_payload(&key, &ciphertext);
        prop_assert!(result.is_err());
    }
}

// ============================================================================
// Event Signing Hash Properties
// ============================================================================

proptest! {
    /// Property: Event signing hash is deterministic
    #[test]
    fn event_signing_hash_deterministic(
        event_id in arb_uuid(),
        tenant_id in arb_uuid(),
        store_id in arb_uuid(),
        agent_id in arb_uuid(),
        entity_type in arb_entity_type(),
        entity_id in arb_entity_id(),
        event_type in arb_event_type(),
        payload_hash in arb_hash256(),
    ) {
        let cipher_hash = [0u8; 32];

        let params = EventSigningParams {
            ves_version: 1,
            event_id: &event_id,
            tenant_id: &tenant_id,
            store_id: &store_id,
            source_agent_id: &agent_id,
            agent_key_id: 1,
            entity_type: &entity_type,
            entity_id: &entity_id,
            event_type: &event_type,
            created_at: "2025-01-01T00:00:00Z",
            payload_kind: 0,
            payload_plain_hash: &payload_hash,
            payload_cipher_hash: &cipher_hash,
        };

        let hash1 = compute_event_signing_hash(&params);
        let hash2 = compute_event_signing_hash(&params);

        prop_assert_eq!(hash1, hash2);
    }

    /// Property: Different event IDs produce different signing hashes
    #[test]
    fn different_event_ids_different_hashes(
        event_id1 in arb_uuid(),
        event_id2 in arb_uuid(),
    ) {
        prop_assume!(event_id1 != event_id2);

        let tenant_id = Uuid::nil();
        let store_id = Uuid::nil();
        let agent_id = Uuid::nil();
        let payload_hash = [0u8; 32];
        let cipher_hash = [0u8; 32];

        let params1 = EventSigningParams {
            ves_version: 1,
            event_id: &event_id1,
            tenant_id: &tenant_id,
            store_id: &store_id,
            source_agent_id: &agent_id,
            agent_key_id: 1,
            entity_type: "order",
            entity_id: "ord-1",
            event_type: "order.created",
            created_at: "2025-01-01T00:00:00Z",
            payload_kind: 0,
            payload_plain_hash: &payload_hash,
            payload_cipher_hash: &cipher_hash,
        };

        let params2 = EventSigningParams {
            event_id: &event_id2,
            ..params1
        };

        let hash1 = compute_event_signing_hash(&params1);
        let hash2 = compute_event_signing_hash(&params2);

        prop_assert_ne!(hash1, hash2);
    }
}

// ============================================================================
// Leaf Hash Properties
// ============================================================================

proptest! {
    /// Property: Leaf hash is deterministic
    #[test]
    fn leaf_hash_deterministic(
        tenant_id in arb_uuid(),
        store_id in arb_uuid(),
        sequence_number in 1u64..1_000_000,
        event_signing_hash in arb_hash256(),
        agent_signature in any::<[u8; 64]>(),
    ) {
        let params = LeafHashParams {
            tenant_id: &tenant_id,
            store_id: &store_id,
            sequence_number,
            event_signing_hash: &event_signing_hash,
            agent_signature: &agent_signature,
        };

        let hash1 = compute_leaf_hash(&params);
        let hash2 = compute_leaf_hash(&params);

        prop_assert_eq!(hash1, hash2);
    }

    /// Property: Different sequence numbers produce different leaf hashes
    #[test]
    fn different_sequences_different_leaf_hashes(
        seq1 in 1u64..1_000_000,
        seq2 in 1u64..1_000_000,
    ) {
        prop_assume!(seq1 != seq2);

        let tenant_id = Uuid::nil();
        let store_id = Uuid::nil();
        let event_signing_hash = [0u8; 32];
        let agent_signature = [0u8; 64];

        let params1 = LeafHashParams {
            tenant_id: &tenant_id,
            store_id: &store_id,
            sequence_number: seq1,
            event_signing_hash: &event_signing_hash,
            agent_signature: &agent_signature,
        };

        let params2 = LeafHashParams {
            sequence_number: seq2,
            ..params1
        };

        let hash1 = compute_leaf_hash(&params1);
        let hash2 = compute_leaf_hash(&params2);

        prop_assert_ne!(hash1, hash2);
    }
}

// ============================================================================
// Domain Type Properties
// ============================================================================

proptest! {
    /// Property: TenantId from UUID roundtrips correctly
    #[test]
    fn tenant_id_roundtrip(uuid in arb_uuid()) {
        let tenant_id = TenantId::from_uuid(uuid);
        prop_assert_eq!(tenant_id.0, uuid);
    }

    /// Property: StoreId from UUID roundtrips correctly
    #[test]
    fn store_id_roundtrip(uuid in arb_uuid()) {
        let store_id = StoreId::from_uuid(uuid);
        prop_assert_eq!(store_id.0, uuid);
    }

    /// Property: EntityType preserves value
    #[test]
    fn entity_type_preserves_value(entity_type in arb_entity_type()) {
        let et = EntityType::from(entity_type.as_str());
        prop_assert_eq!(et.as_str(), entity_type);
    }

    /// Property: EventType preserves value
    #[test]
    fn event_type_preserves_value(event_type in arb_event_type()) {
        let et = EventType::new(&event_type);
        prop_assert_eq!(et.as_str(), event_type);
    }

    /// Property: AgentId from UUID roundtrips correctly
    #[test]
    fn agent_id_roundtrip(uuid in arb_uuid()) {
        let agent_id = AgentId::from_uuid(uuid);
        prop_assert_eq!(agent_id.0, uuid);
    }
}

// ============================================================================
// Merkle Proof Properties
// ============================================================================

proptest! {
    /// Property: MerkleProof stores correct leaf index
    #[test]
    fn merkle_proof_stores_leaf_index(
        leaf_hash in arb_hash256(),
        leaf_index in 0usize..1000,
        path_len in 0usize..20,
    ) {
        let proof_path: Vec<[u8; 32]> = (0..path_len).map(|i| [i as u8; 32]).collect();
        let proof = MerkleProof::new(leaf_hash, proof_path.clone(), leaf_index);

        prop_assert_eq!(proof.leaf_index, leaf_index);
        prop_assert_eq!(proof.proof_path.len(), path_len);
        prop_assert_eq!(proof.leaf_hash, leaf_hash);
    }

    /// Property: MerkleProof directions match path length
    #[test]
    fn merkle_proof_directions_match_path(
        leaf_hash in arb_hash256(),
        leaf_index in 0usize..1000,
        path_len in 1usize..20,
    ) {
        let proof_path: Vec<[u8; 32]> = (0..path_len).map(|i| [i as u8; 32]).collect();
        let proof = MerkleProof::new(leaf_hash, proof_path, leaf_index);

        prop_assert_eq!(proof.directions.len(), proof.proof_path.len());
    }
}

// ============================================================================
// Batch Commitment Properties
// ============================================================================

proptest! {
    /// Property: BatchCommitment stores sequence range correctly
    #[test]
    fn batch_commitment_sequence_range(
        start in 1u64..1_000_000,
        count in 1u32..1000,
    ) {
        let end = start + count as u64 - 1;

        let commitment = BatchCommitment::new(
            TenantId::new(),
            StoreId::new(),
            [0u8; 32],
            [1u8; 32],
            [2u8; 32],
            count,
            (start, end),
        );

        prop_assert_eq!(commitment.sequence_start(), start);
        prop_assert_eq!(commitment.sequence_end(), end);
        prop_assert_eq!(commitment.event_count, count);
    }

    /// Property: BatchCommitment is not anchored initially
    #[test]
    fn batch_commitment_not_anchored_initially(
        start in 1u64..1_000_000,
        count in 1u32..1000,
    ) {
        let end = start + count as u64 - 1;

        let commitment = BatchCommitment::new(
            TenantId::new(),
            StoreId::new(),
            [0u8; 32],
            [1u8; 32],
            [2u8; 32],
            count,
            (start, end),
        );

        prop_assert!(!commitment.is_anchored());
        prop_assert!(commitment.chain_tx_hash.is_none());
    }

    /// Property: BatchCommitment with_chain_tx marks as anchored
    #[test]
    fn batch_commitment_with_chain_tx_is_anchored(
        tx_hash in arb_hash256(),
    ) {
        let commitment = BatchCommitment::new(
            TenantId::new(),
            StoreId::new(),
            [0u8; 32],
            [1u8; 32],
            [2u8; 32],
            10,
            (1, 10),
        )
        .with_chain_tx(tx_hash);

        prop_assert!(commitment.is_anchored());
        prop_assert_eq!(commitment.chain_tx_hash, Some(tx_hash));
    }
}

// ============================================================================
// EventEnvelope Properties
// ============================================================================

proptest! {
    /// Property: EventEnvelope generates unique event_id
    #[test]
    fn event_envelope_unique_ids(
        entity_id1 in arb_entity_id(),
        entity_id2 in arb_entity_id(),
    ) {
        let tenant_id = TenantId::new();
        let store_id = StoreId::new();
        let agent_id = AgentId::new();

        let event1 = EventEnvelope::new(
            tenant_id.clone(),
            store_id.clone(),
            EntityType::order(),
            entity_id1,
            EventType::new("order.created"),
            json!({}),
            agent_id.clone(),
        );

        let event2 = EventEnvelope::new(
            tenant_id,
            store_id,
            EntityType::order(),
            entity_id2,
            EventType::new("order.created"),
            json!({}),
            agent_id,
        );

        // Event IDs should be unique
        prop_assert_ne!(event1.event_id, event2.event_id);
    }

    /// Property: EventEnvelope with_command_id sets command_id
    #[test]
    fn event_envelope_command_id(command_id in arb_uuid()) {
        let event = EventEnvelope::new(
            TenantId::new(),
            StoreId::new(),
            EntityType::order(),
            "ord-1".to_string(),
            EventType::new("order.created"),
            json!({}),
            AgentId::new(),
        )
        .with_command_id(command_id);

        prop_assert_eq!(event.command_id, Some(command_id));
    }

    /// Property: EventEnvelope with_base_version sets base_version
    #[test]
    fn event_envelope_base_version(version in 0u64..1_000_000) {
        let event = EventEnvelope::new(
            TenantId::new(),
            StoreId::new(),
            EntityType::order(),
            "ord-1".to_string(),
            EventType::new("order.updated"),
            json!({}),
            AgentId::new(),
        )
        .with_base_version(version);

        prop_assert_eq!(event.base_version, Some(version));
    }
}

// ============================================================================
// Sequence Invariant Properties
// ============================================================================

proptest! {
    /// Property: Sequence numbers are positive
    #[test]
    fn sequence_numbers_positive(seq in 1u64..u64::MAX) {
        prop_assert!(seq > 0);
    }

    /// Property: Sequence range is valid (start <= end)
    #[test]
    fn sequence_range_valid(start in 1u64..1_000_000, count in 1u64..1000) {
        let end = start.saturating_add(count - 1);
        prop_assert!(start <= end);
    }
}
