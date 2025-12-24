//! Comprehensive unit tests for crypto modules
//!
//! This module provides extensive test coverage for:
//! - Hash functions with domain separation
//! - Ed25519 signing and verification
//! - Merkle tree construction and proofs
//! - Property-based testing for cryptographic invariants

use super::hash::*;
use super::signing::*;
use proptest::prelude::*;
use uuid::Uuid;

// ============================================================================
// Property-Based Tests for Hash Functions
// ============================================================================

proptest! {
    /// Property: Same input always produces same hash (determinism)
    #[test]
    fn prop_hash_deterministic(data in any::<Vec<u8>>()) {
        let hash1 = sha256(&data);
        let hash2 = sha256(&data);
        prop_assert_eq!(hash1, hash2);
    }

    /// Property: Different inputs produce different hashes (collision resistance)
    #[test]
    fn prop_hash_collision_resistance(
        data1 in any::<Vec<u8>>(),
        data2 in any::<Vec<u8>>()
    ) {
        if data1 != data2 {
            let hash1 = sha256(&data1);
            let hash2 = sha256(&data2);
            prop_assert_ne!(hash1, hash2, "Hash collision detected!");
        }
    }

    /// Property: Hash output is always 32 bytes
    #[test]
    fn prop_hash_length(data in any::<Vec<u8>>()) {
        let hash = sha256(&data);
        prop_assert_eq!(hash.len(), 32);
    }

    /// Property: Domain separation produces different hashes for same data
    #[test]
    fn prop_domain_separation(payload in "[a-zA-Z0-9]{1,100}") {
        let json = serde_json::json!({ "data": payload });

        let ves_hash = payload_plain_hash(&json);
        let legacy_hash = canonical_json_hash(&json);

        prop_assert_ne!(ves_hash, legacy_hash,
            "Domain separation failed: VES and legacy hashes should differ");
    }

    /// Property: Canonical JSON produces same hash regardless of key order
    #[test]
    fn prop_canonical_json_key_order_invariant(
        key1 in "[a-z]{1,10}",
        key2 in "[a-z]{1,10}",
        val1 in any::<i32>(),
        val2 in any::<i32>()
    ) {
        // Skip if keys are the same (JSON can't have duplicate keys)
        prop_assume!(key1 != key2);

        let json1 = serde_json::json!({ &key1: val1, &key2: val2 });
        let json2 = serde_json::json!({ &key2: val2, &key1: val1 });

        let hash1 = payload_plain_hash(&json1);
        let hash2 = payload_plain_hash(&json2);

        prop_assert_eq!(hash1, hash2,
            "Canonical JSON should produce identical hashes for same data with different key order");
    }

    /// Property: String encoding is reversible and consistent
    #[test]
    fn prop_encode_string_length(s in ".*") {
        let encoded = encode_string(&s);
        let expected_len = 4 + s.len(); // 4 bytes length prefix + string bytes
        prop_assert_eq!(encoded.len(), expected_len);

        // Verify length prefix
        let len_prefix = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
        prop_assert_eq!(len_prefix as usize, s.len());
    }

    /// Property: Big-endian encoding is correct
    #[test]
    fn prop_u32_be_roundtrip(n in any::<u32>()) {
        let bytes = u32_be(n);
        let reconstructed = u32::from_be_bytes(bytes);
        prop_assert_eq!(n, reconstructed);
    }

    #[test]
    fn prop_u64_be_roundtrip(n in any::<u64>()) {
        let bytes = u64_be(n);
        let reconstructed = u64::from_be_bytes(bytes);
        prop_assert_eq!(n, reconstructed);
    }
}

// ============================================================================
// Property-Based Tests for Signing
// ============================================================================

proptest! {
    /// Property: Signatures are deterministic (Ed25519 is deterministic)
    #[test]
    fn prop_signature_deterministic(message in any::<[u8; 32]>()) {
        let key = AgentSigningKey::generate();
        let sig1 = key.sign(&message);
        let sig2 = key.sign(&message);
        prop_assert_eq!(sig1, sig2);
    }

    /// Property: Valid signatures always verify
    #[test]
    fn prop_valid_signature_verifies(message in any::<[u8; 32]>()) {
        let signing_key = AgentSigningKey::generate();
        let verifying_key = signing_key.public_key();

        let signature = signing_key.sign(&message);
        let result = verifying_key.verify(&message, &signature);

        prop_assert!(result.is_ok(), "Valid signature should verify");
    }

    /// Property: Signatures from different keys don't verify
    #[test]
    fn prop_wrong_key_fails(message in any::<[u8; 32]>()) {
        let key1 = AgentSigningKey::generate();
        let key2 = AgentSigningKey::generate();

        let signature = key1.sign(&message);
        let result = key2.public_key().verify(&message, &signature);

        prop_assert!(result.is_err(), "Signature should not verify with wrong key");
    }

    /// Property: Tampered messages don't verify
    #[test]
    fn prop_tampered_message_fails(message in any::<[u8; 32]>(), tamper_idx in 0usize..32) {
        let signing_key = AgentSigningKey::generate();
        let verifying_key = signing_key.public_key();

        let signature = signing_key.sign(&message);

        // Tamper with the message
        let mut tampered = message;
        tampered[tamper_idx] ^= 0xFF;

        let result = verifying_key.verify(&tampered, &signature);
        prop_assert!(result.is_err(), "Tampered message should not verify");
    }

    /// Property: Tampered signatures don't verify
    #[test]
    fn prop_tampered_signature_fails(message in any::<[u8; 32]>(), tamper_idx in 0usize..64) {
        let signing_key = AgentSigningKey::generate();
        let verifying_key = signing_key.public_key();

        let mut signature = signing_key.sign(&message);

        // Tamper with the signature
        signature[tamper_idx] ^= 0xFF;

        let result = verifying_key.verify(&message, &signature);
        prop_assert!(result.is_err(), "Tampered signature should not verify");
    }

    /// Property: Public key roundtrip through bytes
    #[test]
    fn prop_public_key_roundtrip(_seed in any::<u64>()) {
        let signing_key = AgentSigningKey::generate();
        let public_bytes = signing_key.public_key_bytes();

        let restored = AgentVerifyingKey::from_bytes(&public_bytes);
        prop_assert!(restored.is_ok(), "Valid public key bytes should parse");

        let restored = restored.unwrap();
        prop_assert_eq!(restored.to_bytes(), public_bytes);
    }

    /// Property: Secret key roundtrip through bytes
    #[test]
    fn prop_secret_key_roundtrip(_seed in any::<u64>()) {
        let original = AgentSigningKey::generate();
        let secret_bytes = original.to_bytes();

        let restored = AgentSigningKey::from_bytes(&secret_bytes);
        prop_assert!(restored.is_ok(), "Valid secret key bytes should parse");

        let restored = restored.unwrap();
        prop_assert_eq!(restored.public_key_bytes(), original.public_key_bytes());
    }
}

// ============================================================================
// Property-Based Tests for Merkle Trees
// ============================================================================

proptest! {
    /// Property: Merkle node hash is different from its children
    #[test]
    fn prop_node_hash_differs_from_children(
        left in any::<[u8; 32]>(),
        right in any::<[u8; 32]>()
    ) {
        let node = compute_node_hash(&left, &right);
        prop_assert_ne!(node, left);
        prop_assert_ne!(node, right);
    }

    /// Property: Merkle node hash is order-dependent
    #[test]
    fn prop_node_hash_order_dependent(
        left in any::<[u8; 32]>(),
        right in any::<[u8; 32]>()
    ) {
        prop_assume!(left != right);

        let hash1 = compute_node_hash(&left, &right);
        let hash2 = compute_node_hash(&right, &left);

        prop_assert_ne!(hash1, hash2, "Node hash should be order-dependent");
    }

    /// Property: Leaf hash includes all parameters
    #[test]
    fn prop_leaf_hash_includes_all_params(
        seq1 in any::<u64>(),
        seq2 in any::<u64>()
    ) {
        prop_assume!(seq1 != seq2);

        let tenant = Uuid::new_v4();
        let store = Uuid::new_v4();
        let signing_hash = [1u8; 32];
        let signature = [2u8; 64];

        let leaf1 = compute_leaf_hash(&LeafHashParams {
            tenant_id: &tenant,
            store_id: &store,
            sequence_number: seq1,
            event_signing_hash: &signing_hash,
            agent_signature: &signature,
        });

        let leaf2 = compute_leaf_hash(&LeafHashParams {
            tenant_id: &tenant,
            store_id: &store,
            sequence_number: seq2,
            event_signing_hash: &signing_hash,
            agent_signature: &signature,
        });

        prop_assert_ne!(leaf1, leaf2, "Different sequence numbers should produce different leaf hashes");
    }

    /// Property: Pad leaf is constant
    #[test]
    fn prop_pad_leaf_constant(_seed in any::<u64>()) {
        let pad1 = pad_leaf();
        let pad2 = pad_leaf();
        let direct = compute_pad_leaf();

        prop_assert_eq!(pad1, pad2);
        prop_assert_eq!(pad1, direct);
    }

    /// Property: Stream ID is deterministic for same inputs
    #[test]
    fn prop_stream_id_deterministic(_seed in any::<u64>()) {
        let tenant = Uuid::new_v4();
        let store = Uuid::new_v4();

        let id1 = compute_stream_id(&tenant, &store);
        let id2 = compute_stream_id(&tenant, &store);

        prop_assert_eq!(id1, id2);
    }

    /// Property: Different tenant/store pairs produce different stream IDs
    #[test]
    fn prop_stream_id_unique(_seed in any::<u64>()) {
        let tenant1 = Uuid::new_v4();
        let tenant2 = Uuid::new_v4();
        let store1 = Uuid::new_v4();
        let store2 = Uuid::new_v4();

        let id1 = compute_stream_id(&tenant1, &store1);
        let id2 = compute_stream_id(&tenant2, &store2);

        // Very high probability these are different (unless UUID collision)
        if tenant1 != tenant2 || store1 != store2 {
            prop_assert_ne!(id1, id2);
        }
    }
}

// ============================================================================
// Property-Based Tests for Event Signing Hash
// ============================================================================

proptest! {
    /// Property: Event signing hash is deterministic
    #[test]
    fn prop_event_signing_hash_deterministic(
        entity_type in "[a-z]{1,20}",
        entity_id in "[a-zA-Z0-9]{1,50}",
        event_type in "[a-z.]{1,30}"
    ) {
        let tenant = Uuid::new_v4();
        let store = Uuid::new_v4();
        let event = Uuid::new_v4();
        let agent = Uuid::new_v4();
        let plain_hash = [0u8; 32];
        let cipher_hash = [0u8; 32];

        let params = EventSigningParams {
            ves_version: 1,
            tenant_id: &tenant,
            store_id: &store,
            event_id: &event,
            source_agent_id: &agent,
            agent_key_id: 1,
            entity_type: &entity_type,
            entity_id: &entity_id,
            event_type: &event_type,
            created_at: "2025-12-24T00:00:00Z",
            payload_kind: 0,
            payload_plain_hash: &plain_hash,
            payload_cipher_hash: &cipher_hash,
        };

        let hash1 = compute_event_signing_hash(&params);
        let hash2 = compute_event_signing_hash(&params);

        prop_assert_eq!(hash1, hash2);
    }

    /// Property: Different VES versions produce different hashes
    #[test]
    fn prop_ves_version_affects_hash(
        v1 in 1u32..100,
        v2 in 1u32..100
    ) {
        prop_assume!(v1 != v2);

        let tenant = Uuid::new_v4();
        let store = Uuid::new_v4();
        let event = Uuid::new_v4();
        let agent = Uuid::new_v4();
        let plain_hash = [0u8; 32];
        let cipher_hash = [0u8; 32];

        let hash1 = compute_event_signing_hash(&EventSigningParams {
            ves_version: v1,
            tenant_id: &tenant,
            store_id: &store,
            event_id: &event,
            source_agent_id: &agent,
            agent_key_id: 1,
            entity_type: "order",
            entity_id: "order-123",
            event_type: "order.created",
            created_at: "2025-12-24T00:00:00Z",
            payload_kind: 0,
            payload_plain_hash: &plain_hash,
            payload_cipher_hash: &cipher_hash,
        });

        let hash2 = compute_event_signing_hash(&EventSigningParams {
            ves_version: v2,
            tenant_id: &tenant,
            store_id: &store,
            event_id: &event,
            source_agent_id: &agent,
            agent_key_id: 1,
            entity_type: "order",
            entity_id: "order-123",
            event_type: "order.created",
            created_at: "2025-12-24T00:00:00Z",
            payload_kind: 0,
            payload_plain_hash: &plain_hash,
            payload_cipher_hash: &cipher_hash,
        });

        prop_assert_ne!(hash1, hash2);
    }
}

// ============================================================================
// Additional Unit Tests for Edge Cases
// ============================================================================

#[cfg(test)]
mod edge_case_tests {
    use super::*;

    #[test]
    fn test_empty_string_encoding() {
        let encoded = encode_string("");
        assert_eq!(encoded, vec![0, 0, 0, 0]);
    }

    #[test]
    fn test_unicode_string_encoding() {
        let s = "Hello, 世界! 🎉";
        let encoded = encode_string(s);

        // Length should be byte length, not char count
        let expected_len = s.len();
        let len_prefix = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
        assert_eq!(len_prefix as usize, expected_len);
    }

    #[test]
    fn test_max_u32_encoding() {
        let bytes = u32_be(u32::MAX);
        assert_eq!(bytes, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_max_u64_encoding() {
        let bytes = u64_be(u64::MAX);
        assert_eq!(bytes, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_zero_encoding() {
        assert_eq!(u32_be(0), [0, 0, 0, 0]);
        assert_eq!(u64_be(0), [0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_empty_json_object_hash() {
        let json = serde_json::json!({});
        let hash = payload_plain_hash(&json);
        assert_eq!(hash.len(), 32);

        // Same empty object should produce same hash
        let json2 = serde_json::json!({});
        let hash2 = payload_plain_hash(&json2);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_empty_json_array_hash() {
        let json = serde_json::json!([]);
        let hash = payload_plain_hash(&json);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_null_json_hash() {
        let json = serde_json::json!(null);
        let hash = payload_plain_hash(&json);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_deeply_nested_json() {
        let json = serde_json::json!({
            "level1": {
                "level2": {
                    "level3": {
                        "level4": {
                            "level5": "deep value"
                        }
                    }
                }
            }
        });

        let hash = payload_plain_hash(&json);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_large_json_array() {
        let arr: Vec<i32> = (0..1000).collect();
        let json = serde_json::json!(arr);
        let hash = payload_plain_hash(&json);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_salted_hash_differs_from_unsalted() {
        let json = serde_json::json!({"test": "data"});
        let salt = [0u8; 16];

        let unsalted = payload_plain_hash(&json);
        let salted = payload_plain_hash_salted(&json, &salt);

        assert_ne!(unsalted, salted);
    }

    #[test]
    fn test_different_salts_produce_different_hashes() {
        let json = serde_json::json!({"test": "data"});
        let salt1 = [0u8; 16];
        let salt2 = [1u8; 16];

        let hash1 = payload_plain_hash_salted(&json, &salt1);
        let hash2 = payload_plain_hash_salted(&json, &salt2);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_receipt_hash_includes_all_fields() {
        let tenant = Uuid::new_v4();
        let store = Uuid::new_v4();
        let event = Uuid::new_v4();
        let signing_hash = [1u8; 32];

        let hash1 = compute_receipt_hash(&tenant, &store, &event, 1, &signing_hash);
        let hash2 = compute_receipt_hash(&tenant, &store, &event, 2, &signing_hash);

        // Different sequence numbers should produce different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_state_root_chaining() {
        let tenant = Uuid::new_v4();
        let store = Uuid::new_v4();
        let prev_root = [0u8; 32];
        let merkle_root = sha256(b"events");

        let root1 = compute_ves_state_root(
            &tenant, &store, &prev_root, &merkle_root, 1, 10, 10
        );

        // Chaining: use root1 as prev_root
        let root2 = compute_ves_state_root(
            &tenant, &store, &root1, &merkle_root, 11, 20, 10
        );

        assert_ne!(root1, root2);
        assert_ne!(root1, prev_root);
    }

    #[test]
    fn test_validity_proof_hash() {
        let proof = b"some proof data";
        let hash = compute_ves_validity_proof_hash(proof);
        assert_eq!(hash.len(), 32);

        // Different proofs should produce different hashes
        let proof2 = b"different proof";
        let hash2 = compute_ves_validity_proof_hash(proof2);
        assert_ne!(hash, hash2);
    }

    #[test]
    fn test_compliance_proof_hash() {
        let proof = b"compliance proof data";
        let hash = compute_ves_compliance_proof_hash(proof);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_compliance_policy_hash() {
        let policy_id = "max_value_check";
        let params = serde_json::json!({"max_value": 1000});

        let hash = compute_ves_compliance_policy_hash(policy_id, &params);
        assert_eq!(hash.len(), 32);

        // Different params should produce different hashes
        let params2 = serde_json::json!({"max_value": 2000});
        let hash2 = compute_ves_compliance_policy_hash(policy_id, &params2);
        assert_ne!(hash, hash2);
    }

    #[test]
    fn test_next_power_of_two_edge_cases() {
        assert_eq!(next_power_of_two(0), 1);
        assert_eq!(next_power_of_two(1), 1);
        assert_eq!(next_power_of_two(2), 2);
        assert_eq!(next_power_of_two(3), 4);
        assert_eq!(next_power_of_two(4), 4);
        assert_eq!(next_power_of_two(5), 8);
        assert_eq!(next_power_of_two(1023), 1024);
        assert_eq!(next_power_of_two(1024), 1024);
        assert_eq!(next_power_of_two(1025), 2048);
    }
}

// ============================================================================
// Signing Edge Case Tests
// ============================================================================

#[cfg(test)]
mod signing_edge_cases {
    use super::*;

    #[test]
    fn test_signature_hex_with_leading_zeros() {
        // Create a signature that might have leading zeros
        let signing_key = AgentSigningKey::generate();
        let message = [0u8; 32]; // All zeros message
        let signature = signing_key.sign(&message);

        let hex_str = signature_to_hex(&signature);
        assert!(hex_str.starts_with("0x"));
        assert_eq!(hex_str.len(), 2 + 128);

        let parsed = signature_from_hex(&hex_str).unwrap();
        assert_eq!(signature, parsed);
    }

    #[test]
    fn test_public_key_hex_formats() {
        let key = AgentSigningKey::generate();
        let public_key = key.public_key_bytes();

        let hex_with_prefix = public_key_to_hex(&public_key);
        let hex_without_prefix = &hex_with_prefix[2..];

        // Both formats should parse
        let parsed1 = public_key_from_hex(&hex_with_prefix).unwrap();
        let parsed2 = public_key_from_hex(hex_without_prefix).unwrap();

        assert_eq!(parsed1, parsed2);
        assert_eq!(parsed1, public_key);
    }

    #[test]
    fn test_secret_key_from_hex() {
        let key = AgentSigningKey::generate();
        let secret_bytes = key.to_bytes();
        let hex_str = format!("0x{}", hex::encode(secret_bytes));

        let parsed = secret_key_from_str(&hex_str).unwrap();
        assert_eq!(parsed, secret_bytes);
    }

    #[test]
    fn test_secret_key_from_base64() {
        let key = AgentSigningKey::generate();
        let secret_bytes = key.to_bytes();
        let base64_str = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            secret_bytes
        );

        let parsed = secret_key_from_str(&base64_str).unwrap();
        assert_eq!(parsed, secret_bytes);
    }

    #[test]
    fn test_secret_key_from_base64_url_safe() {
        let key = AgentSigningKey::generate();
        let secret_bytes = key.to_bytes();
        let base64_str = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            secret_bytes
        );

        let parsed = secret_key_from_str(&base64_str).unwrap();
        assert_eq!(parsed, secret_bytes);
    }

    #[test]
    fn test_invalid_signature_lengths() {
        // Too short
        assert!(signature_from_hex("0x1234").is_err());

        // Too long
        let long = "0x".to_string() + &"ab".repeat(65);
        assert!(signature_from_hex(&long).is_err());

        // Exactly 64 bytes (128 hex chars) should work
        let valid = "0x".to_string() + &"ab".repeat(64);
        assert!(signature_from_hex(&valid).is_ok());
    }

    #[test]
    fn test_invalid_public_key_lengths() {
        // Too short
        assert!(public_key_from_hex("0x1234").is_err());

        // Too long
        let long = "0x".to_string() + &"ab".repeat(33);
        assert!(public_key_from_hex(&long).is_err());

        // Exactly 32 bytes (64 hex chars) - but may fail validation
        // (not all 32-byte sequences are valid Ed25519 public keys)
    }

    #[test]
    fn test_sign_and_verify_all_zeros() {
        let key = AgentSigningKey::generate();
        let message = [0u8; 32];

        let signature = key.sign(&message);
        let result = key.public_key().verify(&message, &signature);

        assert!(result.is_ok());
    }

    #[test]
    fn test_sign_and_verify_all_ones() {
        let key = AgentSigningKey::generate();
        let message = [0xFF; 32];

        let signature = key.sign(&message);
        let result = key.public_key().verify(&message, &signature);

        assert!(result.is_ok());
    }

    #[test]
    fn test_debug_hides_secret_key() {
        let key = AgentSigningKey::generate();
        let debug_output = format!("{:?}", key);

        // Should contain public key info
        assert!(debug_output.contains("AgentSigningKey"));
        assert!(debug_output.contains("public_key"));

        // Should NOT contain the full secret key
        let secret_hex = hex::encode(key.to_bytes());
        assert!(!debug_output.contains(&secret_hex));
    }

    #[test]
    fn test_verifying_key_debug() {
        let key = AgentSigningKey::generate();
        let verifying_key = key.public_key();
        let debug_output = format!("{:?}", verifying_key);

        assert!(debug_output.contains("AgentVerifyingKey"));
        assert!(debug_output.contains("public_key"));
    }
}

// ============================================================================
// Cross-Implementation Compatibility Tests
// ============================================================================

#[cfg(test)]
mod compatibility_tests {
    use super::*;

    /// Test vector for cross-platform verification
    /// This hash should be identical across all VES implementations
    #[test]
    fn test_known_payload_hash_vector() {
        let json = serde_json::json!({
            "orderId": "ORD-001",
            "amount": 100,
            "currency": "USD"
        });

        // Canonical form should be:
        // {"amount":100,"currency":"USD","orderId":"ORD-001"}
        let canonical = canonicalize_json(&json);
        assert_eq!(canonical, r#"{"amount":100,"currency":"USD","orderId":"ORD-001"}"#);

        // The hash should be deterministic
        let hash = payload_plain_hash(&json);
        assert_eq!(hash.len(), 32);

        // Log for cross-implementation testing
        println!("Canonical: {}", canonical);
        println!("Hash: {}", hex::encode(hash));
    }

    /// Verify domain prefixes match VES spec
    #[test]
    fn test_domain_prefix_values() {
        assert_eq!(DOMAIN_PAYLOAD_PLAIN, b"VES_PAYLOAD_PLAIN_V1");
        assert_eq!(DOMAIN_PAYLOAD_AAD, b"VES_PAYLOAD_AAD_V1");
        assert_eq!(DOMAIN_PAYLOAD_CIPHER, b"VES_PAYLOAD_CIPHER_V1");
        assert_eq!(DOMAIN_RECIPIENTS, b"VES_RECIPIENTS_V1");
        assert_eq!(DOMAIN_EVENTSIG, b"VES_EVENTSIG_V1");
        assert_eq!(DOMAIN_LEAF, b"VES_LEAF_V1");
        assert_eq!(DOMAIN_PAD_LEAF, b"VES_PAD_LEAF_V1");
        assert_eq!(DOMAIN_NODE, b"VES_NODE_V1");
        assert_eq!(DOMAIN_STREAM, b"VES_STREAM_V1");
        assert_eq!(DOMAIN_RECEIPT, b"VES_RECEIPT_V1");
        assert_eq!(DOMAIN_STATE_ROOT, b"VES_STATE_ROOT_V1");
    }
}
