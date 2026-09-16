//! Tonic gRPC serving for the StateSet Sequencer.
//!
//! Builds the v1 sequencer, v2 sequencer, and v2 key-management services
//! behind the shared auth interceptor and drives them with graceful shutdown.
//! [`super::run`] owns the listen address and the shutdown coordinator; this
//! module only assembles and serves the Tonic router so startup semantics stay
//! identical to the previous inline bootstrap.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tonic::transport::Server as TonicServer;
use tracing::info;

use crate::auth::AuthMiddlewareState;
use crate::grpc::{
    GrpcAuthInterceptor, KeyManagementServiceV2, SequencerService, SequencerServiceV2,
};
use crate::infra::{ShutdownCoordinator, ShutdownSignal};
use crate::proto::sequencer_server::SequencerServer as SequencerServerV1;
use crate::proto::v2::key_management_server::KeyManagementServer;
use crate::proto::v2::sequencer_server::SequencerServer as SequencerServerV2;

use super::config::DEFAULT_REQUEST_TIMEOUT_SECS;
use super::state::AppState;

/// Build the Tonic router for the v1/v2 sequencer and key-management APIs.
///
/// All three services share the HTTP auth stack (authenticator, auth mode,
/// and rate limiters) through one interceptor, and every RPC is bounded by
/// `GRPC_REQUEST_TIMEOUT_SECS` (default 30s).
pub(crate) fn build_grpc_router(
    state: &AppState,
    auth_state: &AuthMiddlewareState,
) -> tonic::transport::server::Router {
    // Create gRPC services
    let sequencer_v1_service = SequencerService::new(
        state.sequencer.clone(),
        state.event_store.clone(),
        state.commitment_reader.clone(),
        state.commitment_engine.clone(),
        state.cache_manager.clone(),
    );
    let sequencer_v2_service = SequencerServiceV2::new(
        state.ves_sequencer.clone(),
        state.ves_commitment_engine.clone(),
        state.ves_sequencer_reader.clone(),
        state.ves_commitment_reader.clone(),
        state.cache_manager.clone(),
    );
    let key_management_service = KeyManagementServiceV2::new(state.agent_key_registry.clone());

    // Create auth interceptor for gRPC (with shared rate limiter)
    let grpc_auth_interceptor = GrpcAuthInterceptor::new(
        auth_state.authenticator.clone(),
        auth_state.require_auth,
        auth_state.rate_limiter.clone(),
        auth_state.credential_rate_limiter.clone(),
    );

    let grpc_timeout = Duration::from_secs(
        std::env::var("GRPC_REQUEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_REQUEST_TIMEOUT_SECS),
    );
    TonicServer::builder()
        .timeout(grpc_timeout)
        .add_service(SequencerServerV1::with_interceptor(
            sequencer_v1_service,
            grpc_auth_interceptor.clone(),
        ))
        .add_service(SequencerServerV2::with_interceptor(
            sequencer_v2_service,
            grpc_auth_interceptor.clone(),
        ))
        .add_service(KeyManagementServer::with_interceptor(
            key_management_service,
            grpc_auth_interceptor,
        ))
}

/// Spawn the gRPC server task on `grpc_addr`; the task resolves once the
/// shutdown coordinator fires and Tonic drains.
pub(crate) fn spawn_grpc_server(
    state: &AppState,
    auth_state: &AuthMiddlewareState,
    grpc_addr: SocketAddr,
    shutdown_coordinator: &Arc<ShutdownCoordinator>,
) -> tokio::task::JoinHandle<()> {
    let router = build_grpc_router(state, auth_state);
    info!("Starting gRPC server on {}", grpc_addr);
    let grpc_shutdown: ShutdownSignal = shutdown_coordinator.signal();
    tokio::spawn(async move {
        if let Err(e) = router
            .serve_with_shutdown(grpc_addr, grpc_shutdown.wait())
            .await
        {
            tracing::error!("gRPC server error: {}", e);
        }
        info!("gRPC server shut down gracefully");
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::state::{test_app_state, test_auth_state};

    /// The extracted Tonic wiring must assemble all three services behind the
    /// shared auth interceptor without a live database or socket.
    #[tokio::test]
    async fn grpc_router_builds_all_services() {
        let state = test_app_state();
        let auth_state = test_auth_state();
        let _router = build_grpc_router(&state, &auth_state);
    }
}
