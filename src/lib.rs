//! StateSet Sequencer Library
//!
//! Verifiable Event Sync (VES) service for deterministic event ordering,
//! state projection, and cryptographic commitments.
//!
//! ## Modules
//!
//! - [`domain`] - Core domain types (events, entities, commitments)
//! - [`infra`] - Infrastructure implementations (PostgreSQL, SQLite)
//! - [`auth`] - Authentication (API keys, JWT)
//! - [`crypto`] - Cryptographic utilities (hashing, encryption)
//! - [`projection`] - Event projection and conflict handling
//! - [`metrics`] - Observability and metrics
//! - [`telemetry`] - Distributed tracing and OpenTelemetry integration
//! - [`api`] - REST API routes
//! - [`grpc`] - gRPC service implementations
//! - [`proto`] - Protocol buffer definitions

pub mod anchor;
pub mod api;
pub mod auth;
pub mod crypto;
pub mod domain;
pub mod grpc;
pub mod infra;
pub mod metrics;
pub mod migrations;
pub mod projection;
pub mod proto;
pub mod server;
pub mod telemetry;

// Re-export commonly used types
pub use domain::{
    AgentId, BatchCommitment, EntityType, EventBatch, EventEnvelope, EventType, Hash256,
    IngestReceipt, MerkleProof, ProjectionResult, SequencedEvent, StoreId, SyncState, TenantId,
};

pub use infra::{
    CommitmentEngine, EventStore, IngestService, Projector, Result, Sequencer, SequencerError,
};
