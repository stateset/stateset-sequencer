//! Leader election for singleton background workers (distributed / HA mode).
//!
//! When several sequencer nodes share one PostgreSQL database, the *write path*
//! is already safe to run on every node: per-`(tenant_id, store_id)` sequencing
//! serializes on a `FOR UPDATE` counter row regardless of which node performs
//! it (see `postgres::ves_sequencer`), so HTTP/gRPC ingest scales horizontally
//! with no coordination. What must **not** run on every node are the singleton
//! background workers — anchoring Merkle roots to L2 and x402 batch sequencing —
//! because duplicate runs waste gas and race with each other.
//!
//! This module elects one database lock holder for a given singleton worker using a
//! PostgreSQL **session-level advisory lock** (`pg_try_advisory_lock`). The lock
//! is held for the life of one dedicated connection and is released
//! automatically by PostgreSQL when that connection drops — including when the
//! leader node crashes — which gives failover for free: a standby acquires the
//! lock on its next retry. Single-node deployments are unaffected: the lone node
//! wins the lock immediately and behaves exactly as before.
//!
//! A database lease is not destination-enforced fencing: a partitioned worker
//! may continue external I/O until loss is detected. External writes still need
//! durable idempotency or fencing at their destination.
//!
//! Verification note: the advisory-lock acquisition and failover semantics
//! require a live PostgreSQL and are exercised by the `tests/` integration suite
//! (gated on `DATABASE_URL`); the non-DB control flow is unit-tested below.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use sqlx::postgres::PgPool;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::infra::{ShutdownCoordinator, ShutdownSignal};

/// Tuning for the election loop.
#[derive(Debug, Clone)]
pub struct ElectionConfig {
    /// How long a follower waits before re-attempting to become leader. This
    /// bounds failover latency after the current leader dies.
    pub retry_interval: Duration,
    /// How often the leader pings its lease connection to detect loss.
    pub health_interval: Duration,
}

impl Default for ElectionConfig {
    fn default() -> Self {
        Self {
            retry_interval: Duration::from_secs(10),
            health_interval: Duration::from_secs(5),
        }
    }
}

/// Stable advisory-lock keys for each singleton worker. Arbitrary but fixed and
/// unique within this application's advisory-lock namespace (no other code path
/// uses advisory locks, so collisions are impossible).
pub mod lock_keys {
    /// Leader lock for the x402 batch-sequencing worker.
    pub const X402_BATCH_WORKER: i64 = 0x5354_5341_5f78_3432;
    /// Leader lock for the L2 anchor worker.
    pub const ANCHOR_WORKER: i64 = 0x5354_5341_5f61_6e63;
    /// Leader lock for the autonomous x402 on-chain settlement worker.
    pub const SETTLEMENT_WORKER: i64 = 0x5354_5341_5f73_7431;
    /// Leader lock for the production state projection worker.
    pub const PROJECTION_WORKER: i64 = 0x5354_5341_5f70_726a;
    /// Leader lock for in-process STARK proof generation.
    pub const PROOF_WORKER: i64 = 0x5354_5341_5f70_7266;
}

/// Run `spawn_worker` while holding a PostgreSQL advisory lock on `lock_key`.
/// This is not a fencing guarantee for external side effects.
///
/// Returns immediately with a `JoinHandle` for the supervising task. The worker
/// is spawned only once this node holds leadership; followers idle and retry so
/// they can take over when the leader exits. While leader:
/// - a coordinated shutdown stops the worker, releases the lock, and returns;
/// - the worker exiting on its own (panic / early return) triggers a coordinated
///   shutdown (fail-fast — same policy as `supervise_worker`);
/// - losing the lease connection triggers a coordinated shutdown so the process
///   restarts and re-contends rather than silently running without the singleton.
pub fn spawn_elected_worker<Spawn, Stop, StopFut>(
    name: &'static str,
    lock_key: i64,
    pool: PgPool,
    config: ElectionConfig,
    shutdown: ShutdownSignal,
    coordinator: Arc<ShutdownCoordinator>,
    spawn_worker: Spawn,
) -> JoinHandle<()>
where
    Spawn: Fn() -> (JoinHandle<()>, Stop) + Send + 'static,
    Stop: FnOnce() -> StopFut + Send,
    StopFut: Future<Output = ()> + Send,
{
    tokio::spawn(async move {
        while !shutdown.is_shutdown() {
            // A dedicated connection holds the advisory lock for as long as we
            // remain leader; dropping it (or losing the node) releases the lock.
            let mut lease = match election_operation(
                &shutdown,
                config.health_interval,
                pool.acquire(),
            )
            .await
            {
                None => return,
                Some(Ok(Ok(conn))) => conn,
                Some(result) => {
                    warn!(worker = name, error = ?result, "could not acquire lease connection; retrying");
                    if sleep_or_shutdown(config.retry_interval, &shutdown).await {
                        return;
                    }
                    continue;
                }
            };

            // Even a failed/cancelled acquisition can have taken the lock on
            // the server before the response was lost. Never recycle this
            // session into the pool with unknown advisory-lock ownership.
            lease.close_on_drop();
            let acquired = election_operation(
                &shutdown,
                config.health_interval,
                sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_lock($1)")
                    .bind(lock_key)
                    .fetch_one(&mut *lease),
            )
            .await;
            let acquired = match acquired {
                None => return,
                Some(Ok(Ok(acquired))) => acquired,
                Some(result) => {
                    warn!(worker = name, error = ?result, "advisory lock probe failed or timed out; treating as follower");
                    false
                }
            };

            if !acquired {
                // Another node leads. Release this connection and retry later so
                // we can take over if the leader dies.
                drop(lease);
                if sleep_or_shutdown(config.retry_interval, &shutdown).await {
                    return;
                }
                continue;
            }

            info!(
                worker = name,
                "acquired leadership; starting singleton worker"
            );
            let (mut task, stop) = spawn_worker();
            // Dropping a JoinHandle detaches its task. Ensure cancellation or
            // panic of this supervisor cannot leave a worker running unowned.
            let _worker_guard = AbortWorkerOnDrop(task.abort_handle());
            let mut stop = Some(stop);
            let mut health = tokio::time::interval(config.health_interval);

            loop {
                tokio::select! {
                    _ = shutdown.wait() => {
                        info!(worker = name, "shutdown: stopping worker and releasing leadership");
                        if let Some(stop) = stop.take() {
                            stop_worker(&mut task, stop).await;
                        }
                        // close_on_drop releases the session lock without
                        // waiting on an unresponsive database connection.
                        return;
                    }
                    join_result = &mut task => {
                        match join_result {
                            Ok(()) => error!(worker = name, "worker exited unexpectedly while leader; triggering coordinated shutdown"),
                            Err(e) if e.is_panic() => error!(worker = name, error = ?e, "worker panicked while leader; triggering coordinated shutdown"),
                            Err(e) => error!(worker = name, error = ?e, "worker task failed to join; triggering coordinated shutdown"),
                        }
                        coordinator.shutdown().await;
                        return;
                    }
                    _ = health.tick() => {
                        // The advisory lock lives on this connection; if the ping
                        // fails the lock is (or is about to be) gone, so step down
                        // hard rather than run a second leader's worker.
                        let probe = election_operation(
                            &shutdown, config.health_interval,
                            sqlx::query("SELECT 1").execute(&mut *lease),
                        ).await;
                        if probe.is_none() {
                            if let Some(stop) = stop.take() {
                                stop_worker(&mut task, stop).await;
                            }
                            return;
                        }
                        if !matches!(probe, Some(Ok(Ok(_)))) {
                            error!(worker = name, "lost or timed out lease connection; triggering coordinated shutdown");
                            coordinator.shutdown().await;
                            if let Some(stop) = stop.take() {
                                stop_worker(&mut task, stop).await;
                            }
                            return;
                        }
                    }
                }
            }
        }
    })
}

struct AbortWorkerOnDrop(tokio::task::AbortHandle);

impl Drop for AbortWorkerOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Shutdown wins even if an operation is ready at the same time. Dropping a
/// cancelled database query is safe here because its lease is close-on-drop.
async fn election_operation<F: Future>(
    shutdown: &ShutdownSignal,
    deadline: Duration,
    operation: F,
) -> Option<Result<F::Output, tokio::time::error::Elapsed>> {
    tokio::select! {
        biased;
        _ = shutdown.wait() => None,
        result = tokio::time::timeout(deadline, operation) => Some(result),
    }
}

/// Give cooperative workers a bounded drain period, then cancel the task.
async fn stop_worker<Stop, StopFut>(task: &mut JoinHandle<()>, stop: Stop)
where
    Stop: FnOnce() -> StopFut,
    StopFut: Future<Output = ()>,
{
    let drained = tokio::time::timeout(Duration::from_secs(5), async {
        stop().await;
        let _ = (&mut *task).await;
    })
    .await;
    if drained.is_err() {
        task.abort();
    }
}

/// Sleep for `dur`, returning `true` if a shutdown arrived first (caller stops).
async fn sleep_or_shutdown(dur: Duration, shutdown: &ShutdownSignal) -> bool {
    tokio::select! {
        _ = shutdown.wait() => true,
        _ = tokio::time::sleep(dur) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn election_operation_stops_during_shutdown() {
        let coordinator = Arc::new(ShutdownCoordinator::new());
        let signal = coordinator.signal();
        let operation = tokio::spawn(async move {
            election_operation(
                &signal,
                Duration::from_secs(3600),
                std::future::pending::<()>(),
            )
            .await
        });
        coordinator.shutdown().await;
        assert!(tokio::time::timeout(Duration::from_secs(1), operation)
            .await
            .unwrap()
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn election_operation_times_out_and_prioritizes_shutdown() {
        let coordinator = ShutdownCoordinator::new();
        let signal = coordinator.signal();
        assert!(election_operation(
            &signal,
            Duration::from_millis(10),
            std::future::pending::<()>()
        )
        .await
        .unwrap()
        .is_err());
        coordinator.shutdown().await;
        assert!(
            election_operation(&signal, Duration::from_secs(1), std::future::ready(()))
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn dropping_supervisor_guard_cancels_worker() {
        let worker = tokio::spawn(std::future::pending::<()>());
        let guard = AbortWorkerOnDrop(worker.abort_handle());
        drop(guard);
        let error = tokio::time::timeout(Duration::from_secs(1), worker)
            .await
            .unwrap()
            .unwrap_err();
        assert!(error.is_cancelled());
    }

    #[tokio::test]
    async fn unresponsive_stop_callback_is_bounded_and_worker_aborted() {
        let mut task = tokio::spawn(std::future::pending::<()>());
        tokio::time::timeout(
            Duration::from_secs(7),
            stop_worker(&mut task, || async {
                std::future::pending::<()>().await;
            }),
        )
        .await
        .expect("stop callback must not block shutdown forever");
        assert!(task.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn cooperative_worker_is_drained() {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let mut task = tokio::spawn(async move {
            let _ = rx.await;
        });
        stop_worker(&mut task, || async {
            let _ = tx.send(());
        })
        .await;
        assert!(task.is_finished());
    }

    #[test]
    fn election_config_defaults_are_sane() {
        let cfg = ElectionConfig::default();
        assert!(cfg.retry_interval >= Duration::from_secs(1));
        assert!(cfg.health_interval >= Duration::from_secs(1));
        // Health checks must be at least as frequent as failover retries so the
        // leader notices lease loss before a follower could take over.
        assert!(cfg.health_interval <= cfg.retry_interval);
    }

    #[test]
    fn lock_keys_are_distinct() {
        let keys = [
            lock_keys::X402_BATCH_WORKER,
            lock_keys::ANCHOR_WORKER,
            lock_keys::SETTLEMENT_WORKER,
            lock_keys::PROJECTION_WORKER,
            lock_keys::PROOF_WORKER,
        ];
        for (i, a) in keys.iter().enumerate() {
            for b in &keys[i + 1..] {
                assert_ne!(a, b, "advisory-lock keys must be unique");
            }
        }
    }

    #[tokio::test]
    async fn sleep_or_shutdown_returns_true_when_already_shutting_down() {
        let coordinator = ShutdownCoordinator::new();
        let signal = coordinator.signal();
        coordinator.shutdown().await;
        // Long sleep, but shutdown is already triggered, so it must return
        // immediately with `true`.
        assert!(sleep_or_shutdown(Duration::from_secs(3600), &signal).await);
    }

    #[tokio::test]
    async fn sleep_or_shutdown_returns_false_on_timeout() {
        let coordinator = ShutdownCoordinator::new();
        let signal = coordinator.signal();
        assert!(!sleep_or_shutdown(Duration::from_millis(10), &signal).await);
    }
}
