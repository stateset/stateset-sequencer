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
//! This module elects exactly one node to run a given singleton worker using a
//! PostgreSQL **session-level advisory lock** (`pg_try_advisory_lock`). The lock
//! is held for the life of one dedicated connection and is released
//! automatically by PostgreSQL when that connection drops — including when the
//! leader node crashes — which gives failover for free: a standby acquires the
//! lock on its next retry. Single-node deployments are unaffected: the lone node
//! wins the lock immediately and behaves exactly as before.
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
}

/// Run `spawn_worker` on exactly one node at a time, elected via a PostgreSQL
/// advisory lock on `lock_key`.
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
            let mut lease = match pool.acquire().await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!(worker = name, error = %e, "could not acquire lease connection; retrying");
                    if sleep_or_shutdown(config.retry_interval, &shutdown).await {
                        return;
                    }
                    continue;
                }
            };

            let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
                .bind(lock_key)
                .fetch_one(&mut *lease)
                .await
                .unwrap_or_else(|e| {
                    warn!(worker = name, error = %e, "advisory lock probe failed; treating as follower");
                    false
                });

            if !acquired {
                // Another node leads. Release this connection and retry later so
                // we can take over if the leader dies.
                drop(lease);
                if sleep_or_shutdown(config.retry_interval, &shutdown).await {
                    return;
                }
                continue;
            }

            info!(worker = name, "acquired leadership; starting singleton worker");
            let (mut task, stop) = spawn_worker();
            let mut stop = Some(stop);
            let mut health = tokio::time::interval(config.health_interval);

            loop {
                tokio::select! {
                    _ = shutdown.wait() => {
                        info!(worker = name, "shutdown: stopping worker and releasing leadership");
                        if let Some(stop) = stop.take() {
                            stop().await;
                        }
                        let _ = task.await;
                        let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
                            .bind(lock_key)
                            .execute(&mut *lease)
                            .await;
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
                        if let Err(e) = sqlx::query("SELECT 1").execute(&mut *lease).await {
                            error!(worker = name, error = %e, "lost lease connection while leader; triggering coordinated shutdown");
                            if let Some(stop) = stop.take() {
                                stop().await;
                            }
                            let _ = task.await;
                            coordinator.shutdown().await;
                            return;
                        }
                    }
                }
            }
        }
    })
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
        assert_ne!(lock_keys::X402_BATCH_WORKER, lock_keys::ANCHOR_WORKER);
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
