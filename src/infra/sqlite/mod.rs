//! SQLite implementations for local agent operations
//!
//! Provides the outbox pattern for CLI agents to capture events locally
//! before syncing to the remote sequencer.

mod outbox;

pub use outbox::*;
