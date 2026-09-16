//! gRPC Sequencer v2 service implementation
//!
//! Implements the VES v1.0 Protocol with bidirectional streaming support.
//!
//! Split by service boundary:
//! - [`sequencer`] — event push/pull/stream/sync (`SequencerServiceV2`)
//! - [`keys`] — agent key lifecycle (`KeyManagementServiceV2`)
//! - [`convert`] — stateless proto/domain conversions shared by both.

mod convert;
mod keys;
mod sequencer;

pub use keys::KeyManagementServiceV2;
pub use sequencer::SequencerServiceV2;

/// Maximum events allowed in a single gRPC push request.
pub(crate) const MAX_GRPC_BATCH_SIZE: usize = 1000;
/// Maximum entity history events returned per request.
pub(crate) const MAX_ENTITY_HISTORY: usize = crate::domain::MAX_ENTITY_HISTORY_PAGE as usize;

pub(crate) use super::{grpc_internal_error, grpc_sequencer_error};
