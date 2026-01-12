//! Protocol buffer definitions for StateSet Sequencer gRPC API

#![allow(clippy::all)]
#![allow(unused_imports)]

// Include the generated protobuf code - v1 (legacy)
include!("stateset.sequencer.v1.rs");

/// VES v1.0 Protocol - v2 API with bidirectional streaming
pub mod v2 {
    include!("stateset.sequencer.v2.rs");
}
