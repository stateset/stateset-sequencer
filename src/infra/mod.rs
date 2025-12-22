//! Infrastructure layer for StateSet Sequencer
//!
//! Contains trait definitions and implementations for:
//! - Event storage (PostgreSQL, SQLite)
//! - Sequencer (canonical ordering)
//! - Projector (state projection)
//! - Commitment engine (Merkle roots)

mod commitment;
mod error;
mod payload_encryption;
pub mod postgres;
pub mod sqlite;
mod traits;
mod ves_commitment;
mod ves_compliance;
mod ves_validity;

pub use commitment::PgCommitmentEngine;
pub use error::*;
pub use payload_encryption::{PayloadEncryption, PayloadEncryptionMode};
pub use postgres::{PgAgentKeyRegistry, PgEventStore, PgSequencer, VesSequencer};
pub use sqlite::SqliteOutbox;
pub use traits::*;
pub use ves_commitment::PgVesCommitmentEngine;
pub use ves_compliance::{PgVesComplianceProofStore, VesComplianceEventInputs};
pub use ves_validity::PgVesValidityProofStore;
