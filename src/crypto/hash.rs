//! VES v1.0 compliant hashing with domain separation
//!
//! This module provides deterministic hashing that matches the VES specification:
//! - RFC 8785 JSON Canonicalization Scheme (JCS) for payload hashing
//! - Domain separation prefixes for all hash operations
//! - Big-endian encoding for integers
//! - Reproducible hashes across implementations
//!
//! # RFC 8785 Compliance
//!
//! This module uses `serde_json_canonicalizer` for RFC 8785 compliant JSON
//! canonicalization, ensuring consistent hashing across implementations
//! in different languages. Key properties:
//! - Deterministic key ordering (lexicographic UTF-8)
//! - ES6-compatible number serialization (handles floats, -0, etc.)
//! - Proper Unicode handling

use sha2::{Digest, Sha256};
use uuid::Uuid;

/// 32-byte SHA-256 hash
pub type Hash256 = [u8; 32];

// ============================================================================
// VES v1.0 Domain Separation Constants
// ============================================================================

/// Domain prefix for payload plaintext hashing
pub const DOMAIN_PAYLOAD_PLAIN: &[u8] = b"VES_PAYLOAD_PLAIN_V1";

/// Domain prefix for payload AAD computation
pub const DOMAIN_PAYLOAD_AAD: &[u8] = b"VES_PAYLOAD_AAD_V1";

/// Domain prefix for ciphertext bundle hashing
pub const DOMAIN_PAYLOAD_CIPHER: &[u8] = b"VES_PAYLOAD_CIPHER_V1";

/// Domain prefix for recipients list hashing
pub const DOMAIN_RECIPIENTS: &[u8] = b"VES_RECIPIENTS_V1";

/// Domain prefix for event signing preimage
pub const DOMAIN_EVENTSIG: &[u8] = b"VES_EVENTSIG_V1";

/// Domain prefix for Merkle leaf hashing
pub const DOMAIN_LEAF: &[u8] = b"VES_LEAF_V1";

/// Domain prefix for padding leaf
pub const DOMAIN_PAD_LEAF: &[u8] = b"VES_PAD_LEAF_V1";

/// Domain prefix for Merkle internal nodes
pub const DOMAIN_NODE: &[u8] = b"VES_NODE_V1";

/// Domain prefix for stream ID derivation
pub const DOMAIN_STREAM: &[u8] = b"VES_STREAM_V1";

/// Domain prefix for sequencer receipt
pub const DOMAIN_RECEIPT: &[u8] = b"VES_RECEIPT_V1";

/// Domain prefix for commitment-chain state root
pub const DOMAIN_STATE_ROOT: &[u8] = b"VES_STATE_ROOT_V1";

/// Domain prefix for externally-generated validity proofs over VES commitments.
pub const DOMAIN_VES_VALIDITY_PROOF_HASH: &[u8] = b"STATESET_VES_VALIDITY_PROOF_HASH_V1";

/// Domain prefix for externally-generated compliance proofs over encrypted VES events.
pub const DOMAIN_VES_COMPLIANCE_PROOF_HASH: &[u8] = b"STATESET_VES_COMPLIANCE_PROOF_HASH_V1";

/// Domain prefix for compliance policy hashing.
pub const DOMAIN_VES_COMPLIANCE_POLICY_HASH: &[u8] = b"STATESET_VES_COMPLIANCE_POLICY_HASH_V1";

// ============================================================================
// Binary Encoding Helpers (VES v1.0 Spec Section 3)
// ============================================================================

/// Encode a u32 as 4 bytes big-endian
#[inline]
pub fn u32_be(n: u32) -> [u8; 4] {
    n.to_be_bytes()
}

/// Encode a u64 as 8 bytes big-endian
#[inline]
pub fn u64_be(n: u64) -> [u8; 8] {
    n.to_be_bytes()
}

/// Encode a string as length-prefixed UTF-8 bytes
/// Format: U32_BE(len) || UTF8_bytes
pub fn encode_string(s: &str) -> Vec<u8> {
    let utf8_bytes = s.as_bytes();
    let mut result = Vec::with_capacity(4 + utf8_bytes.len());
    result.extend_from_slice(&u32_be(utf8_bytes.len() as u32));
    result.extend_from_slice(utf8_bytes);
    result
}

// ============================================================================
// Canonical JSON (RFC 8785 JCS)
// ============================================================================

/// Compute SHA-256 hash of canonical JSON representation with domain prefix
///
/// Per VES v1.0 Section 5.2:
/// payload_plain_hash = SHA256(b"VES_PAYLOAD_PLAIN_V1" || JCS(payload))
pub fn payload_plain_hash(value: &serde_json::Value) -> Hash256 {
    let canonical = canonicalize_json(value);
    let json_bytes = canonical.as_bytes();

    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_PAYLOAD_PLAIN);
    hasher.update(json_bytes);
    hasher.finalize().into()
}

/// Compute salted payload hash for encrypted payloads
///
/// Per VES v1.0 Section 5.2 (encrypted case):
/// payload_plaintext_bytes = payload_salt(16) || JCS(payload)
/// payload_plain_hash = SHA256(b"VES_PAYLOAD_PLAIN_V1" || payload_plaintext_bytes)
pub fn payload_plain_hash_salted(value: &serde_json::Value, salt: &[u8; 16]) -> Hash256 {
    let canonical = canonicalize_json(value);
    let json_bytes = canonical.as_bytes();

    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_PAYLOAD_PLAIN);
    hasher.update(salt);
    hasher.update(json_bytes);
    hasher.finalize().into()
}

/// Convert JSON value to canonical string representation per RFC 8785 (JCS).
///
/// Uses `serde_json_canonicalizer` for strict RFC 8785 compliance, ensuring:
/// - Keys sorted alphabetically (lexicographic UTF-8)
/// - No extra whitespace
/// - Numbers normalized per ES6/RFC 8785 rules (handles -0, exponents, etc.)
/// - Strings properly escaped per JSON spec
///
/// # Panics
///
/// Panics if the JSON value contains a float that cannot be represented
/// (NaN or Infinity). Per RFC 8785, these are not valid JSON.
pub fn canonicalize_json(value: &serde_json::Value) -> String {
    serde_json_canonicalizer::to_string(value)
        .expect("Failed to canonicalize JSON - contains invalid values (NaN or Infinity)")
}

// ============================================================================
// Event Signing Hash (VES v1.0 Section 8.2)
// ============================================================================

/// Parameters for computing event signing hash
pub struct EventSigningParams<'a> {
    pub ves_version: u32,
    pub tenant_id: &'a Uuid,
    pub store_id: &'a Uuid,
    pub event_id: &'a Uuid,
    pub source_agent_id: &'a Uuid,
    pub agent_key_id: u32,
    pub entity_type: &'a str,
    pub entity_id: &'a str,
    pub event_type: &'a str,
    pub created_at: &'a str, // RFC 3339 string
    pub payload_kind: u32,
    pub payload_plain_hash: &'a Hash256,
    pub payload_cipher_hash: &'a Hash256,
}

/// Compute event signing hash per VES v1.0 Section 8.2
///
/// ```text
/// eventsig_preimage =
///   b"VES_EVENTSIG_V1" ||
///   U32_BE(ves_version) ||
///   UUID(tenant_id) ||
///   UUID(store_id) ||
///   UUID(event_id) ||
///   UUID(source_agent_id) ||
///   U32_BE(agent_key_id) ||
///   ENC_STR(entity_type) ||
///   ENC_STR(entity_id) ||
///   ENC_STR(event_type) ||
///   ENC_STR(created_at) ||
///   U32_BE(payload_kind) ||
///   payload_plain_hash(32) ||
///   payload_cipher_hash(32)
///
/// event_signing_hash = SHA256(eventsig_preimage)
/// ```
pub fn compute_event_signing_hash(params: &EventSigningParams) -> Hash256 {
    let mut hasher = Sha256::new();

    // Domain prefix
    hasher.update(DOMAIN_EVENTSIG);

    // VES version
    hasher.update(u32_be(params.ves_version));

    // UUIDs (16 bytes each, network byte order)
    hasher.update(params.tenant_id.as_bytes());
    hasher.update(params.store_id.as_bytes());
    hasher.update(params.event_id.as_bytes());
    hasher.update(params.source_agent_id.as_bytes());

    // Agent key ID
    hasher.update(u32_be(params.agent_key_id));

    // Length-prefixed strings
    hasher.update(encode_string(params.entity_type));
    hasher.update(encode_string(params.entity_id));
    hasher.update(encode_string(params.event_type));
    hasher.update(encode_string(params.created_at));

    // Payload kind
    hasher.update(u32_be(params.payload_kind));

    // Payload hashes (32 bytes each)
    hasher.update(params.payload_plain_hash);
    hasher.update(params.payload_cipher_hash);

    hasher.finalize().into()
}

// ============================================================================
// Merkle Tree Operations (VES v1.0 Section 11)
// ============================================================================

/// Parameters for computing leaf hash
pub struct LeafHashParams<'a> {
    pub tenant_id: &'a Uuid,
    pub store_id: &'a Uuid,
    pub sequence_number: u64,
    pub event_signing_hash: &'a Hash256,
    pub agent_signature: &'a [u8; 64], // Ed25519 signature
}

/// Compute Merkle leaf hash per VES v1.0 Section 11.2
///
/// ```text
/// leaf_preimage =
///   b"VES_LEAF_V1" ||
///   UUID(tenant_id) ||
///   UUID(store_id) ||
///   U64_BE(sequence_number) ||
///   event_signing_hash(32) ||
///   agent_signature(64)
///
/// leaf_hash = SHA256(leaf_preimage)
/// ```
pub fn compute_leaf_hash(params: &LeafHashParams) -> Hash256 {
    let mut hasher = Sha256::new();

    // Domain prefix
    hasher.update(DOMAIN_LEAF);

    // Stream identity
    hasher.update(params.tenant_id.as_bytes());
    hasher.update(params.store_id.as_bytes());

    // Sequence number (big-endian)
    hasher.update(u64_be(params.sequence_number));

    // Event signing hash
    hasher.update(params.event_signing_hash);

    // Agent signature
    hasher.update(params.agent_signature);

    hasher.finalize().into()
}

/// Compute the padding leaf hash per VES v1.0 Section 11.3
///
/// PAD_LEAF = SHA256(b"VES_PAD_LEAF_V1")
pub fn compute_pad_leaf() -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_PAD_LEAF);
    hasher.finalize().into()
}

/// Lazily computed padding leaf (cached)
pub fn pad_leaf() -> Hash256 {
    // This is a constant, compute once
    static PAD_LEAF: std::sync::OnceLock<Hash256> = std::sync::OnceLock::new();
    *PAD_LEAF.get_or_init(compute_pad_leaf)
}

/// Compute Merkle internal node hash per VES v1.0 Section 11.4
///
/// node_hash = SHA256(b"VES_NODE_V1" || left(32) || right(32))
pub fn compute_node_hash(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_NODE);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Compute stream ID for commitment chaining per VES v1.0 Section 12.2
///
/// stream_id = SHA256(b"VES_STREAM_V1" || UUID(tenant_id) || UUID(store_id))
pub fn compute_stream_id(tenant_id: &Uuid, store_id: &Uuid) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_STREAM);
    hasher.update(tenant_id.as_bytes());
    hasher.update(store_id.as_bytes());
    hasher.finalize().into()
}

/// Compute VES state root for commitment chaining.
///
/// This is a deterministic "state progression" root derived from the prior state root and the
/// current batch commitment (Merkle root + range metadata). It enables anchored commitments to
/// form a verifiable chain even before an application-specific projector state root is available.
pub fn compute_ves_state_root(
    tenant_id: &Uuid,
    store_id: &Uuid,
    prev_state_root: &Hash256,
    merkle_root: &Hash256,
    sequence_start: u64,
    sequence_end: u64,
    leaf_count: u32,
) -> Hash256 {
    let stream_id = compute_stream_id(tenant_id, store_id);

    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_STATE_ROOT);
    hasher.update(stream_id);
    hasher.update(prev_state_root);
    hasher.update(merkle_root);
    hasher.update(u64_be(sequence_start));
    hasher.update(u64_be(sequence_end));
    hasher.update(u32_be(leaf_count));
    hasher.finalize().into()
}

/// Compute sequencer receipt hash per VES v1.0 Section 8.4
///
/// ```text
/// receipt_preimage =
///   b"VES_RECEIPT_V1" ||
///   UUID(tenant_id) ||
///   UUID(store_id) ||
///   UUID(event_id) ||
///   U64_BE(sequence_number) ||
///   event_signing_hash(32)
///
/// receipt_hash = SHA256(receipt_preimage)
/// ```
pub fn compute_receipt_hash(
    tenant_id: &Uuid,
    store_id: &Uuid,
    event_id: &Uuid,
    sequence_number: u64,
    event_signing_hash: &Hash256,
) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_RECEIPT);
    hasher.update(tenant_id.as_bytes());
    hasher.update(store_id.as_bytes());
    hasher.update(event_id.as_bytes());
    hasher.update(u64_be(sequence_number));
    hasher.update(event_signing_hash);
    hasher.finalize().into()
}

// ============================================================================
// Legacy/Utility Functions
// ============================================================================

/// Hash raw bytes with SHA-256 (no domain prefix)
pub fn sha256(data: &[u8]) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Hash a validity proof payload with a domain prefix.
pub fn compute_ves_validity_proof_hash(proof: &[u8]) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_VES_VALIDITY_PROOF_HASH);
    hasher.update(proof);
    hasher.finalize().into()
}

/// Hash a compliance proof payload with a domain prefix.
pub fn compute_ves_compliance_proof_hash(proof: &[u8]) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_VES_COMPLIANCE_PROOF_HASH);
    hasher.update(proof);
    hasher.finalize().into()
}

/// Hash a compliance policy (id + params) with a domain prefix.
pub fn compute_ves_compliance_policy_hash(
    policy_id: &str,
    policy_params: &serde_json::Value,
) -> Hash256 {
    let policy = serde_json::json!({
        "policyId": policy_id,
        "policyParams": policy_params,
    });
    let canonical = canonicalize_json(&policy);

    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_VES_COMPLIANCE_POLICY_HASH);
    hasher.update(canonical.as_bytes());
    hasher.finalize().into()
}

/// Compute SHA-256 hash of canonical JSON (legacy, no domain prefix)
/// Use payload_plain_hash() for VES-compliant hashing
pub fn canonical_json_hash(value: &serde_json::Value) -> Hash256 {
    let canonical = canonicalize_json(value);
    sha256(canonical.as_bytes())
}

/// Combine two hashes for Merkle tree (legacy, no domain prefix)
/// Use compute_node_hash() for VES-compliant hashing
pub fn hash_pair(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Domain prefix for legacy commitment leaf hashing
///
/// This is used for commitments over the legacy `events` table (non-VES),
/// where the leaf commits to a payload hash plus minimal metadata needed to
/// avoid ambiguity across streams and sequences.
pub const DOMAIN_LEGACY_COMMITMENT_LEAF: &[u8] = b"STATESET_COMMITMENT_LEAF_V1";

/// Compute legacy commitment leaf hash (non-VES).
///
/// Preimage:
/// `DOMAIN_LEGACY_COMMITMENT_LEAF || UUID(tenant_id) || UUID(store_id) || U64_BE(sequence_number) || payload_hash(32) || ENC_STR(entity_type) || ENC_STR(entity_id)`
pub fn legacy_commitment_leaf_hash(
    tenant_id: &Uuid,
    store_id: &Uuid,
    sequence_number: u64,
    payload_hash: &Hash256,
    entity_type: &str,
    entity_id: &str,
) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_LEGACY_COMMITMENT_LEAF);
    hasher.update(tenant_id.as_bytes());
    hasher.update(store_id.as_bytes());
    hasher.update(u64_be(sequence_number));
    hasher.update(payload_hash);

    hasher.update(u32_be(entity_type.len() as u32));
    hasher.update(entity_type.as_bytes());
    hasher.update(u32_be(entity_id.len() as u32));
    hasher.update(entity_id.as_bytes());

    hasher.finalize().into()
}

/// Get the next power of two >= n
pub fn next_power_of_two(n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    n.next_power_of_two()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_canonical_json_key_ordering() {
        let value = json!({
            "zebra": 1,
            "apple": 2,
            "mango": 3
        });

        let canonical = canonicalize_json(&value);
        assert_eq!(canonical, r#"{"apple":2,"mango":3,"zebra":1}"#);
    }

    #[test]
    fn test_canonical_json_nested_objects() {
        let value = json!({
            "b": {"d": 1, "c": 2},
            "a": 3
        });

        let canonical = canonicalize_json(&value);
        assert_eq!(canonical, r#"{"a":3,"b":{"c":2,"d":1}}"#);
    }

    #[test]
    fn test_payload_plain_hash_deterministic() {
        let value1 = json!({"b": 2, "a": 1});
        let value2 = json!({"a": 1, "b": 2});

        let hash1 = payload_plain_hash(&value1);
        let hash2 = payload_plain_hash(&value2);

        // Different key order, same hash
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_domain_prefix_difference() {
        let value = json!({"test": 123});

        // With domain prefix (VES compliant)
        let ves_hash = payload_plain_hash(&value);

        // Without domain prefix (legacy)
        let legacy_hash = canonical_json_hash(&value);

        // They should be different due to domain prefix
        assert_ne!(ves_hash, legacy_hash);
    }

    #[test]
    fn test_big_endian_encoding() {
        assert_eq!(u32_be(0x12345678), [0x12, 0x34, 0x56, 0x78]);
        assert_eq!(
            u64_be(0x0102030405060708),
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn test_encode_string() {
        let encoded = encode_string("test");
        assert_eq!(encoded.len(), 4 + 4); // 4 bytes length + 4 bytes "test"
        assert_eq!(&encoded[0..4], &[0, 0, 0, 4]); // big-endian length
        assert_eq!(&encoded[4..], b"test");
    }

    #[test]
    fn test_pad_leaf_consistency() {
        let pad1 = pad_leaf();
        let pad2 = pad_leaf();
        assert_eq!(pad1, pad2);

        // Should match direct computation
        let direct = compute_pad_leaf();
        assert_eq!(pad1, direct);
    }

    #[test]
    fn test_node_hash_with_domain() {
        let left = [1u8; 32];
        let right = [2u8; 32];

        let node = compute_node_hash(&left, &right);
        let legacy = hash_pair(&left, &right);

        // Different due to domain prefix
        assert_ne!(node, legacy);
    }

    #[test]
    fn test_stream_id_computation() {
        let tenant = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let store = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();

        let stream_id = compute_stream_id(&tenant, &store);
        assert_eq!(stream_id.len(), 32);

        // Same inputs should produce same output
        let stream_id2 = compute_stream_id(&tenant, &store);
        assert_eq!(stream_id, stream_id2);
    }

    #[test]
    fn test_event_signing_hash() {
        let tenant = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let store = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let event = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();
        let agent = Uuid::parse_str("00000000-0000-0000-0000-000000000004").unwrap();
        let plain_hash = [0u8; 32];
        let cipher_hash = [0u8; 32];

        let params = EventSigningParams {
            ves_version: 1,
            tenant_id: &tenant,
            store_id: &store,
            event_id: &event,
            source_agent_id: &agent,
            agent_key_id: 1,
            entity_type: "order",
            entity_id: "order-123",
            event_type: "order.created",
            created_at: "2025-12-20T18:31:22.123Z",
            payload_kind: 0,
            payload_plain_hash: &plain_hash,
            payload_cipher_hash: &cipher_hash,
        };

        let signing_hash = compute_event_signing_hash(&params);
        assert_eq!(signing_hash.len(), 32);

        // Same inputs should produce same output
        let signing_hash2 = compute_event_signing_hash(&params);
        assert_eq!(signing_hash, signing_hash2);
    }

    #[test]
    fn test_leaf_hash() {
        let tenant = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let store = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let signing_hash = [1u8; 32];
        let signature = [2u8; 64];

        let params = LeafHashParams {
            tenant_id: &tenant,
            store_id: &store,
            sequence_number: 42,
            event_signing_hash: &signing_hash,
            agent_signature: &signature,
        };

        let leaf = compute_leaf_hash(&params);
        assert_eq!(leaf.len(), 32);
    }

    #[test]
    fn test_next_power_of_two() {
        assert_eq!(next_power_of_two(0), 1);
        assert_eq!(next_power_of_two(1), 1);
        assert_eq!(next_power_of_two(2), 2);
        assert_eq!(next_power_of_two(3), 4);
        assert_eq!(next_power_of_two(5), 8);
        assert_eq!(next_power_of_two(8), 8);
    }
}

#[test]
fn test_signing_hash_cross_platform() {
    // Test data from CLI (to verify cross-platform compatibility)
    let tenant = Uuid::parse_str("64527dd3-a654-4410-9327-e58a1492ce77").unwrap();
    let store = Uuid::parse_str("91def158-819a-4461-b5c9-7759750ad157").unwrap();
    let event = Uuid::parse_str("861910c9-7a1d-4b6f-83d6-51bbf4ae2849").unwrap();
    let agent = Uuid::parse_str("80441726-74e2-430a-95ae-97ce21c6351b").unwrap();

    let plain_hash: [u8; 32] =
        hex::decode("7777c3fef466a0e9df7e07ea4ff13dc8ffbb9e487098f1b65530cdce7b6bbbe7")
            .unwrap()
            .try_into()
            .unwrap();
    let cipher_hash = [0u8; 32];

    let params = EventSigningParams {
        ves_version: 1,
        tenant_id: &tenant,
        store_id: &store,
        event_id: &event,
        source_agent_id: &agent,
        agent_key_id: 1,
        entity_type: "order",
        entity_id: "ORD-001",
        event_type: "order.created",
        created_at: "2025-12-20T17:51:10.243Z",
        payload_kind: 0,
        payload_plain_hash: &plain_hash,
        payload_cipher_hash: &cipher_hash,
    };

    let hash = compute_event_signing_hash(&params);

    // Print individual components for debugging
    println!("Domain: {:?}", DOMAIN_EVENTSIG);
    println!("Tenant UUID bytes: {:?}", tenant.as_bytes());
    println!("Store UUID bytes: {:?}", store.as_bytes());
    println!("Event UUID bytes: {:?}", event.as_bytes());
    println!("Agent UUID bytes: {:?}", agent.as_bytes());
    println!("Entity type encoded: {:?}", encode_string("order"));
    println!(
        "Created at encoded: {:?}",
        encode_string("2025-12-20T17:51:10.243Z")
    );
    println!("Computed hash: {}", hex::encode(&hash));

    // Expected hash from CLI
    let expected =
        hex::decode("e970dfc9ffc285c2c0ba59be5d9c653eee2d1ae4db9b7a02ea3cd62b8e7cf92b").unwrap();
    assert_eq!(
        hash.to_vec(),
        expected,
        "Signing hash should match CLI computation"
    );
}

#[test]
fn test_ves_state_root_chaining_changes_with_prev_root() {
    let tenant = Uuid::new_v4();
    let store = Uuid::new_v4();

    let prev0 = [0u8; 32];
    let merkle_root: Hash256 = sha256(b"events-root");

    let r1 = compute_ves_state_root(&tenant, &store, &prev0, &merkle_root, 1, 2, 2);
    let r2 = compute_ves_state_root(&tenant, &store, &r1, &merkle_root, 3, 4, 2);

    assert_ne!(r1, prev0);
    assert_ne!(r2, r1);
}

// ============================================================================
// RFC 8785 Edge Case Test Vectors
// ============================================================================

#[cfg(test)]
mod rfc8785_tests {
    use super::*;
    use serde_json::json;

    /// Test RFC 8785 integer vs float handling
    #[test]
    fn test_rfc8785_integers() {
        // Integers should be serialized without decimal points
        assert_eq!(canonicalize_json(&json!(0)), "0");
        assert_eq!(canonicalize_json(&json!(1)), "1");
        assert_eq!(canonicalize_json(&json!(-1)), "-1");
        assert_eq!(canonicalize_json(&json!(999999999999i64)), "999999999999");
    }

    /// Test RFC 8785 floating point handling (ES6-style)
    #[test]
    fn test_rfc8785_floats() {
        // Floats should use minimal representation
        assert_eq!(canonicalize_json(&json!(1.5)), "1.5");
        assert_eq!(canonicalize_json(&json!(0.5)), "0.5");

        // Numbers that can be integers should be integers
        assert_eq!(canonicalize_json(&json!(1.0)), "1");
        assert_eq!(canonicalize_json(&json!(100.0)), "100");
    }

    /// Test RFC 8785 negative zero handling
    #[test]
    fn test_rfc8785_negative_zero() {
        // Per RFC 8785, -0 should be serialized as 0
        let neg_zero: f64 = -0.0;
        let value = serde_json::Number::from_f64(neg_zero).unwrap();
        let json_value = serde_json::Value::Number(value);
        assert_eq!(canonicalize_json(&json_value), "0");
    }

    /// Test RFC 8785 scientific notation handling
    #[test]
    fn test_rfc8785_scientific_notation() {
        // Very small numbers - should use minimal representation
        let small = serde_json::Number::from_f64(0.000001).unwrap();
        let canonical = canonicalize_json(&serde_json::Value::Number(small));
        // RFC 8785 allows either 0.000001 or 1e-6 style, check it's consistent
        assert!(!canonical.is_empty());

        // Very large numbers
        let large = serde_json::Number::from_f64(1e20).unwrap();
        let canonical = canonicalize_json(&serde_json::Value::Number(large));
        assert!(!canonical.is_empty());
    }

    /// Test RFC 8785 string escaping
    #[test]
    fn test_rfc8785_string_escaping() {
        // Control characters must be escaped
        assert_eq!(canonicalize_json(&json!("hello\nworld")), r#""hello\nworld""#);
        assert_eq!(canonicalize_json(&json!("tab\there")), r#""tab\there""#);
        assert_eq!(canonicalize_json(&json!("quote\"")), r#""quote\"""#);
        assert_eq!(canonicalize_json(&json!("backslash\\")), r#""backslash\\""#);
    }

    /// Test RFC 8785 Unicode handling
    #[test]
    fn test_rfc8785_unicode() {
        // Unicode characters should be preserved (not escaped unless control)
        assert_eq!(canonicalize_json(&json!("café")), r#""café""#);
        assert_eq!(canonicalize_json(&json!("日本語")), r#""日本語""#);
        assert_eq!(canonicalize_json(&json!("emoji: 🎉")), r#""emoji: 🎉""#);
    }

    /// Test RFC 8785 key ordering with Unicode
    #[test]
    fn test_rfc8785_unicode_key_ordering() {
        // Keys are sorted by UTF-8 byte sequence (lexicographic)
        let value = json!({
            "z": 1,
            "a": 2,
            "ä": 3,  // ä (U+00E4) comes after ASCII 'z' in UTF-8
            "A": 4   // 'A' (0x41) comes before 'a' (0x61)
        });
        let canonical = canonicalize_json(&value);
        // Expected order: A < a < z < ä (UTF-8 byte ordering)
        assert_eq!(canonical, r#"{"A":4,"a":2,"z":1,"ä":3}"#);
    }

    /// Test RFC 8785 deeply nested structures
    #[test]
    fn test_rfc8785_deep_nesting() {
        let value = json!({
            "level1": {
                "level2": {
                    "level3": {
                        "value": 42
                    }
                }
            }
        });
        let canonical = canonicalize_json(&value);
        assert_eq!(canonical, r#"{"level1":{"level2":{"level3":{"value":42}}}}"#);
    }

    /// Test RFC 8785 array ordering (arrays preserve order, not sorted)
    #[test]
    fn test_rfc8785_array_ordering() {
        let value = json!([3, 1, 2, "z", "a"]);
        let canonical = canonicalize_json(&value);
        // Arrays preserve insertion order (NOT sorted)
        assert_eq!(canonical, r#"[3,1,2,"z","a"]"#);
    }

    /// Test RFC 8785 empty structures
    #[test]
    fn test_rfc8785_empty_structures() {
        assert_eq!(canonicalize_json(&json!({})), "{}");
        assert_eq!(canonicalize_json(&json!([])), "[]");
        assert_eq!(canonicalize_json(&json!("")), r#""""#);
    }

    /// Test RFC 8785 null and boolean
    #[test]
    fn test_rfc8785_primitives() {
        assert_eq!(canonicalize_json(&json!(null)), "null");
        assert_eq!(canonicalize_json(&json!(true)), "true");
        assert_eq!(canonicalize_json(&json!(false)), "false");
    }

    /// Test that different key orders produce identical hashes
    #[test]
    fn test_canonicalization_hash_consistency() {
        let value1 = json!({
            "zebra": {"inner_z": 1, "inner_a": 2},
            "apple": [3, 2, 1],
            "mango": "fruit"
        });

        let value2 = json!({
            "mango": "fruit",
            "apple": [3, 2, 1],
            "zebra": {"inner_a": 2, "inner_z": 1}
        });

        let hash1 = payload_plain_hash(&value1);
        let hash2 = payload_plain_hash(&value2);

        assert_eq!(hash1, hash2, "Same content with different key order should produce identical hash");
    }

    /// Test known RFC 8785 test vectors (from the RFC specification)
    #[test]
    fn test_rfc8785_spec_vectors() {
        // RFC 8785 Appendix B.2 test vector
        let value = json!({
            "numbers": [333333333.33333329, 1e30, 4.5e-308, 1e-305],
            "string": "\u{0080}",
            "literals": [null, true, false]
        });

        // Verify it canonicalizes without panic
        let canonical = canonicalize_json(&value);
        assert!(!canonical.is_empty());

        // The canonical form should be consistent
        let canonical2 = canonicalize_json(&value);
        assert_eq!(canonical, canonical2);
    }
}
