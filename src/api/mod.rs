//! API layer for StateSet Sequencer.
//!
//! This module provides REST endpoints for event sync operations,
//! organized by domain for maintainability.

pub mod auth_helpers;
pub mod error;
pub mod handlers;
pub mod types;
pub mod utils;

pub use error::{ApiError, ErrorCode, ErrorDetails};

use axum::routing::{get, post};
use axum::Router;

use crate::server::AppState;

/// Build the `/api` router with all v1 endpoints.
pub fn router() -> Router<AppState> {
    Router::new()
        // Legacy event ingestion
        .route("/v1/events/ingest", post(handlers::ingest_events))
        // VES v1.0 endpoint with signature verification
        .route("/v1/ves/events/ingest", post(handlers::ingest_ves_events))
        // VES commitments + proofs
        .route(
            "/v1/ves/commitments",
            get(handlers::ves::list_ves_commitments),
        )
        .route(
            "/v1/ves/commitments",
            post(handlers::ves::create_ves_commitment),
        )
        .route(
            "/v1/ves/commitments/anchor",
            post(handlers::ves::commit_and_anchor_ves_commitment),
        )
        .route(
            "/v1/ves/commitments/:batch_id",
            get(handlers::ves::get_ves_commitment),
        )
        // VES validity proofs (externally generated)
        .route(
            "/v1/ves/validity/:batch_id/inputs",
            get(handlers::ves::get_ves_validity_public_inputs),
        )
        .route(
            "/v1/ves/validity/:batch_id/proofs",
            get(handlers::ves::list_ves_validity_proofs),
        )
        .route(
            "/v1/ves/validity/:batch_id/proofs",
            post(handlers::ves::submit_ves_validity_proof),
        )
        .route(
            "/v1/ves/validity/proofs/:proof_id",
            get(handlers::ves::get_ves_validity_proof),
        )
        .route(
            "/v1/ves/validity/proofs/:proof_id/verify",
            get(handlers::ves::verify_ves_validity_proof),
        )
        // VES compliance proofs (per-event, encrypted payloads)
        .route(
            "/v1/ves/compliance/:event_id/inputs",
            post(handlers::ves::get_ves_compliance_public_inputs),
        )
        .route(
            "/v1/ves/compliance/:event_id/proofs",
            get(handlers::ves::list_ves_compliance_proofs),
        )
        .route(
            "/v1/ves/compliance/:event_id/proofs",
            post(handlers::ves::submit_ves_compliance_proof),
        )
        .route(
            "/v1/ves/compliance/proofs/:proof_id",
            get(handlers::ves::get_ves_compliance_proof),
        )
        .route(
            "/v1/ves/compliance/proofs/:proof_id/verify",
            get(handlers::ves::verify_ves_compliance_proof),
        )
        .route(
            "/v1/ves/proofs/:sequence_number",
            get(handlers::ves::get_ves_inclusion_proof),
        )
        .route(
            "/v1/ves/proofs/verify",
            post(handlers::ves::verify_ves_proof),
        )
        // VES anchoring
        .route(
            "/v1/ves/anchor",
            post(handlers::ves::anchor_ves_commitment),
        )
        .route(
            "/v1/ves/anchor/:batch_id/verify",
            get(handlers::ves::verify_ves_anchor_onchain),
        )
        // Events
        .route("/v1/events", get(handlers::list_events))
        .route("/v1/head", get(handlers::get_head))
        // Legacy commitments
        .route("/v1/commitments", get(handlers::list_commitments))
        .route("/v1/commitments", post(handlers::create_commitment))
        .route("/v1/commitments/:batch_id", get(handlers::get_commitment))
        // Legacy proofs
        .route(
            "/v1/proofs/:sequence_number",
            get(handlers::get_inclusion_proof),
        )
        .route("/v1/proofs/verify", post(handlers::verify_proof))
        // Entity history
        .route(
            "/v1/entities/:entity_type/:entity_id",
            get(handlers::get_entity_history),
        )
        // Anchor endpoints
        .route("/v1/anchor/status", get(handlers::get_anchor_status))
        .route("/v1/anchor", post(handlers::anchor_commitment))
        .route(
            "/v1/anchor/:batch_id/verify",
            get(handlers::verify_anchor_onchain),
        )
        // Agent key management
        .route("/v1/agents/keys", post(handlers::register_agent_key))
        // Schema registry
        .route("/v1/schemas", get(handlers::list_schemas))
        .route("/v1/schemas", post(handlers::register_schema))
        .route("/v1/schemas/validate", post(handlers::validate_payload))
        .route("/v1/schemas/:schema_id", get(handlers::get_schema))
        .route(
            "/v1/schemas/:schema_id/status",
            axum::routing::put(handlers::update_schema_status),
        )
        .route(
            "/v1/schemas/:schema_id",
            axum::routing::delete(handlers::delete_schema),
        )
        .route(
            "/v1/schemas/event-type/:event_type",
            get(handlers::get_schemas_by_event_type),
        )
        .route(
            "/v1/schemas/event-type/:event_type/latest",
            get(handlers::get_latest_schema),
        )
}

/// Minimal root-level compatibility router for Set Chain's separate anchor service.
///
/// The `set/anchor` service expects these routes without the `/api` prefix.
pub fn anchor_compat_router() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/commitments/pending",
            get(handlers::ves::list_pending_ves_commitments),
        )
        .route(
            "/v1/commitments/:batch_id/anchored",
            post(handlers::ves::notify_ves_commitment_anchored),
        )
}
