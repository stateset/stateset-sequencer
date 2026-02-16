//! gRPC service implementations for StateSet Sequencer
//!
//! Implements the Sequencer gRPC service with Push, Pull, GetHead, and GetInclusionProof.
use crate::infra::SequencerError;

mod interceptor;
mod service;
mod service_v2;

pub use interceptor::{AuthContextExt, GrpcAuthInterceptor};
pub use service::*;
pub use service_v2::{KeyManagementServiceV2, SequencerServiceV2};

/// Log the real error and return a generic `Status::internal` to the client.
pub(crate) fn grpc_internal_error(e: impl std::fmt::Display) -> tonic::Status {
    tracing::error!("gRPC internal error: {e}");
    tonic::Status::internal("internal error")
}

/// Map known sequencer invariants to explicit gRPC status codes.
pub(crate) fn grpc_sequencer_error(e: SequencerError) -> tonic::Status {
    match e {
        SequencerError::InvariantViolation { invariant, message }
            if invariant == "sequence_range" =>
        {
            tracing::warn!("gRPC sequence-range invariant violation: {message}");
            tonic::Status::out_of_range(message)
        }
        _ => grpc_internal_error(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grpc_sequence_range_invariant_is_out_of_range() {
        let status = grpc_sequencer_error(SequencerError::InvariantViolation {
            invariant: "sequence_range".to_string(),
            message: "gap detected".to_string(),
        });

        assert_eq!(status.code(), tonic::Code::OutOfRange);
        assert_eq!(status.message(), "gap detected");
    }

    #[test]
    fn test_grpc_other_sequencer_error_is_internal() {
        let status = grpc_sequencer_error(SequencerError::InvariantViolation {
            invariant: "other".to_string(),
            message: "bad state".to_string(),
        });

        assert_eq!(status.code(), tonic::Code::Internal);
        assert_eq!(status.message(), "internal error");
    }
}
