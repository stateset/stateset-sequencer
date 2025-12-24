# ADR-002: Domain-Separated Hashing

## Status

Accepted

## Context

The VES protocol requires cryptographic hashing for multiple purposes:
- Payload content hashing
- Event signing preimage construction
- Merkle tree leaf and node computation
- State root derivation
- Receipt generation

Without careful design, hash outputs from different contexts could collide, leading to potential security vulnerabilities (e.g., cross-protocol attacks, confusion attacks).

### Security Concern

Consider two hash computations:
```
H1 = SHA256("order-123" || signature)  // Event signing
H2 = SHA256("order-123" || signature)  // Merkle leaf
```

If the same data is hashed for different purposes, an attacker might be able to use a hash from one context in another.

## Decision

Implement **domain separation** by prepending a unique domain prefix to all hash computations.

### Domain Prefixes (VES v1.0)

```rust
// Payload hashing
DOMAIN_PAYLOAD_PLAIN = b"VES_PAYLOAD_PLAIN_V1"
DOMAIN_PAYLOAD_AAD   = b"VES_PAYLOAD_AAD_V1"
DOMAIN_PAYLOAD_CIPHER = b"VES_PAYLOAD_CIPHER_V1"

// Event signing
DOMAIN_EVENTSIG = b"VES_EVENTSIG_V1"

// Merkle tree
DOMAIN_LEAF     = b"VES_LEAF_V1"
DOMAIN_PAD_LEAF = b"VES_PAD_LEAF_V1"
DOMAIN_NODE     = b"VES_NODE_V1"

// State management
DOMAIN_STREAM     = b"VES_STREAM_V1"
DOMAIN_STATE_ROOT = b"VES_STATE_ROOT_V1"
DOMAIN_RECEIPT    = b"VES_RECEIPT_V1"
```

### Hash Construction

```rust
// Event signing hash
eventsig_preimage = DOMAIN_EVENTSIG || ves_version || tenant_id || ...
event_signing_hash = SHA256(eventsig_preimage)

// Merkle leaf hash
leaf_preimage = DOMAIN_LEAF || tenant_id || store_id || sequence || ...
leaf_hash = SHA256(leaf_preimage)
```

## Consequences

### Positive

- **Collision resistance across contexts** - Hashes from different domains cannot match
- **Protocol versioning** - `_V1` suffix allows future protocol upgrades
- **Clear semantics** - Each hash computation is self-documenting
- **Cross-implementation compatibility** - Explicit prefixes ensure consistent hashing

### Negative

- Slightly larger preimages (20-30 bytes overhead)
- Must maintain prefix registry to avoid duplicates
- Breaking change if prefixes need modification

### Implementation Notes

1. Prefixes are ASCII bytes, not hex-encoded
2. Prefixes include version suffix for future compatibility
3. All implementations (Rust, TypeScript, etc.) must use identical prefixes
4. Test vectors should verify cross-platform consistency

## References

- [IETF Domain Separation](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/)
- [NIST SP 800-185 - Derived Functions](https://csrc.nist.gov/publications/detail/sp/800-185/final)
- [VES v1.0 Specification - Section 3](../VES_SPEC.md)
