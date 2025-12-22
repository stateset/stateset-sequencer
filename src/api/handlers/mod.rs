//! REST API handlers organized by domain.

pub mod agent_keys;
pub mod anchoring;
pub mod commitments;
pub mod events;
pub mod ingest;
pub mod proofs;
pub mod ves;

pub use agent_keys::*;
pub use anchoring::*;
pub use commitments::*;
pub use events::*;
pub use ingest::*;
pub use proofs::*;
