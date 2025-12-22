//! Cryptographic utilities for StateSet Sequencer
//!
//! Provides:
//! - Canonical JSON hashing (deterministic, cross-language compatible)
//! - Payload encryption (AES-GCM + HPKE for VES-ENC-1)
//! - Merkle tree operations with VES v1.0 domain separation
//! - Agent signing (Ed25519) per VES v1.0 Section 8

mod encrypt;
mod hash;
mod signing;

pub use encrypt::*;
pub use hash::*;
pub use signing::*;
