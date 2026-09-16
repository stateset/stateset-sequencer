//! Background worker supervision.
//!
//! Singleton workers (batching, projection, anchoring, settlement) must never
//! silently stop: an unexpected exit escalates to a coordinated shutdown so a
//! process supervisor restarts the sequencer instead of running degraded.

use std::sync::Arc;

use tracing::error;

use crate::infra::{ShutdownCoordinator, ShutdownSignal};

/// Supervise a critical background worker for the lifetime of the process.
///
/// On a coordinated shutdown signal, runs `send_stop` (which tells the worker to
/// stop) and then drains the task. If the worker instead exits on its own
/// *before* shutdown — a panic or an early return — a critical background loop
/// (x402 batching, anchoring) has silently stopped; we log loudly and trigger a
/// coordinated shutdown so a process supervisor restarts the sequencer rather
/// than letting it run degraded.
///
/// This consolidates what were two near-identical `select!` supervision blocks
/// (one per worker) into a single audited code path.
pub(crate) fn supervise_worker<F, Fut>(
    name: &'static str,
    mut task: tokio::task::JoinHandle<()>,
    shutdown_signal: ShutdownSignal,
    coordinator: Arc<ShutdownCoordinator>,
    send_stop: F,
) where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        tokio::select! {
            _ = shutdown_signal.wait() => {
                // Normal shutdown path: ask the worker to stop, then drain it.
                send_stop().await;
                let _ = task.await;
            }
            join_result = &mut task => {
                match join_result {
                    Ok(()) => error!(
                        worker = name,
                        "worker exited unexpectedly before shutdown; triggering coordinated shutdown"
                    ),
                    Err(e) if e.is_panic() => error!(
                        worker = name, error = ?e,
                        "worker panicked; triggering coordinated shutdown"
                    ),
                    Err(e) => error!(
                        worker = name, error = ?e,
                        "worker task failed to join; triggering coordinated shutdown"
                    ),
                }
                coordinator.shutdown().await;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A worker that exits before shutdown must escalate to a coordinated
    /// shutdown so the process restarts instead of running degraded.
    #[tokio::test]
    async fn supervised_worker_exit_triggers_coordinated_shutdown() {
        let coordinator = Arc::new(ShutdownCoordinator::new());
        let task = tokio::spawn(async {});
        supervise_worker(
            "test_worker",
            task,
            coordinator.signal(),
            coordinator.clone(),
            || async {},
        );

        tokio::time::timeout(Duration::from_secs(5), async {
            while !coordinator.is_shutdown() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("coordinator should shut down after early worker exit");
    }
}
