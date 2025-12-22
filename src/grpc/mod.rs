//! gRPC service implementations for StateSet Sequencer
//!
//! Implements the Sequencer gRPC service with Push, Pull, GetHead, and GetInclusionProof.

mod service;

pub use service::*;
