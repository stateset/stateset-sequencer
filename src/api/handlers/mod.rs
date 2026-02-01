//! REST API handlers organized by domain.

pub mod agent_keys;
pub mod agents;
pub mod anchoring;
pub mod commitments;
pub mod events;
pub mod health;
pub mod ingest;
pub mod proofs;
pub mod schemas;
pub mod ves;
pub mod x402;

pub use agent_keys::*;
pub use agents::*;
pub use anchoring::*;
pub use commitments::*;
pub use events::*;
pub use health::*;
pub use ingest::*;
pub use proofs::*;
pub use schemas::*;
pub use x402::x402_router;
