//! Graceful shutdown handling
//!
//! Provides graceful shutdown support for the sequencer:
//! - Signal handling (SIGTERM, SIGINT)
//! - In-flight request draining
//! - Background task cleanup
//! - Resource cleanup

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::sync::{broadcast, watch, Notify};
use tracing::{info, warn};

/// Shutdown signal that can be cloned and shared
#[derive(Clone)]
pub struct ShutdownSignal {
    /// Whether shutdown has been initiated
    shutdown: Arc<AtomicBool>,
    /// Notification for shutdown
    notify: Arc<Notify>,
    /// Watch channel for shutdown state
    watch_rx: watch::Receiver<bool>,
}

impl ShutdownSignal {
    /// Check if shutdown has been initiated
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Wait for shutdown signal
    pub async fn wait(&self) {
        if self.is_shutdown() {
            return;
        }
        self.notify.notified().await;
    }

    /// Get a future that completes when shutdown is signaled
    pub async fn recv(&mut self) {
        let _ = self.watch_rx.changed().await;
    }
}

/// Tracks in-flight requests for graceful draining
#[derive(Default)]
pub struct RequestTracker {
    /// Number of active requests
    active: AtomicU64,
    /// Total requests handled
    total: AtomicU64,
}

impl RequestTracker {
    /// Create a new request tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a new request starting
    pub fn request_start(&self) -> RequestGuard<'_> {
        self.active.fetch_add(1, Ordering::SeqCst);
        self.total.fetch_add(1, Ordering::SeqCst);
        RequestGuard { tracker: self }
    }

    /// Get the number of active requests
    pub fn active_count(&self) -> u64 {
        self.active.load(Ordering::SeqCst)
    }

    /// Get the total number of requests
    pub fn total_count(&self) -> u64 {
        self.total.load(Ordering::SeqCst)
    }

    /// Wait for all requests to complete
    pub async fn wait_for_drain(&self, timeout: Duration) -> bool {
        let start = std::time::Instant::now();

        while self.active_count() > 0 {
            if start.elapsed() > timeout {
                warn!(
                    active = self.active_count(),
                    "Timeout waiting for requests to drain"
                );
                return false;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        info!("All requests drained successfully");
        true
    }
}

/// Guard that decrements active request count when dropped
pub struct RequestGuard<'a> {
    tracker: &'a RequestTracker,
}

impl<'a> Drop for RequestGuard<'a> {
    fn drop(&mut self) {
        self.tracker.active.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Shutdown coordinator that manages graceful shutdown
pub struct ShutdownCoordinator {
    /// Whether shutdown has been initiated
    shutdown: Arc<AtomicBool>,
    /// Notification for shutdown
    notify: Arc<Notify>,
    /// Watch channel sender
    watch_tx: watch::Sender<bool>,
    /// Broadcast channel for shutdown
    broadcast_tx: broadcast::Sender<()>,
    /// Request tracker
    request_tracker: Arc<RequestTracker>,
    /// Shutdown hooks
    hooks: tokio::sync::Mutex<Vec<Box<dyn FnOnce() + Send + 'static>>>,
}

impl ShutdownCoordinator {
    /// Create a new shutdown coordinator
    pub fn new() -> Self {
        let (watch_tx, _) = watch::channel(false);
        let (broadcast_tx, _) = broadcast::channel(16);

        Self {
            shutdown: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
            watch_tx,
            broadcast_tx,
            request_tracker: Arc::new(RequestTracker::new()),
            hooks: tokio::sync::Mutex::new(Vec::new()),
        }
    }

    /// Get a shutdown signal that can be cloned
    pub fn signal(&self) -> ShutdownSignal {
        ShutdownSignal {
            shutdown: self.shutdown.clone(),
            notify: self.notify.clone(),
            watch_rx: self.watch_tx.subscribe(),
        }
    }

    /// Get the request tracker
    pub fn request_tracker(&self) -> Arc<RequestTracker> {
        self.request_tracker.clone()
    }

    /// Subscribe to shutdown broadcast
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.broadcast_tx.subscribe()
    }

    /// Register a shutdown hook
    pub async fn register_hook<F>(&self, hook: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let mut hooks = self.hooks.lock().await;
        hooks.push(Box::new(hook));
    }

    /// Initiate shutdown
    pub async fn shutdown(&self) {
        if self.shutdown.swap(true, Ordering::SeqCst) {
            // Already shutting down
            return;
        }

        info!("Initiating graceful shutdown...");

        // Notify all waiters
        self.notify.notify_waiters();
        let _ = self.watch_tx.send(true);
        let _ = self.broadcast_tx.send(());

        // Run shutdown hooks
        let mut hooks = self.hooks.lock().await;
        for hook in hooks.drain(..) {
            hook();
        }
    }

    /// Perform graceful shutdown with timeout
    pub async fn graceful_shutdown(&self, drain_timeout: Duration) {
        self.shutdown().await;

        info!(
            active = self.request_tracker.active_count(),
            "Waiting for in-flight requests to complete..."
        );

        self.request_tracker.wait_for_drain(drain_timeout).await;

        info!("Graceful shutdown complete");
    }

    /// Check if shutdown has been initiated
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }
}

impl Default for ShutdownCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

/// Install signal handlers and return a future that completes on shutdown signal
pub async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C, initiating shutdown...");
        }
        _ = terminate => {
            info!("Received SIGTERM, initiating shutdown...");
        }
    }
}

/// Create a shutdown-aware task that stops when shutdown is signaled
pub fn spawn_until_shutdown<F>(
    signal: ShutdownSignal,
    task: F,
) -> tokio::task::JoinHandle<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        tokio::select! {
            _ = signal.wait() => {
                info!("Task stopped due to shutdown signal");
            }
            _ = task => {
                // Task completed normally
            }
        }
    })
}

// ============================================================================
// Shutdown-Aware Server
// ============================================================================

/// Configuration for graceful shutdown
#[derive(Debug, Clone)]
pub struct GracefulShutdownConfig {
    /// Timeout for draining in-flight requests
    pub drain_timeout: Duration,
    /// Delay before starting shutdown (for load balancer health checks)
    pub shutdown_delay: Duration,
}

impl Default for GracefulShutdownConfig {
    fn default() -> Self {
        Self {
            drain_timeout: Duration::from_secs(30),
            shutdown_delay: Duration::from_secs(5),
        }
    }
}

/// Serve with graceful shutdown support
pub async fn serve_with_shutdown<F, S>(
    listener: tokio::net::TcpListener,
    app: axum::Router<S>,
    coordinator: Arc<ShutdownCoordinator>,
    config: GracefulShutdownConfig,
) -> Result<(), std::io::Error>
where
    S: Clone + Send + Sync + 'static,
    axum::Router<S>: Into<axum::Router>,
{
    let router: axum::Router = app.into();

    let signal = coordinator.signal();

    info!("Starting server with graceful shutdown support");

    // Serve until shutdown signal
    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            signal.wait().await;

            info!(
                "Shutdown signal received, waiting {:?} before stopping...",
                config.shutdown_delay
            );

            // Delay to allow load balancer to stop sending requests
            tokio::time::sleep(config.shutdown_delay).await;
        })
        .await?;

    // Wait for requests to drain
    coordinator.graceful_shutdown(config.drain_timeout).await;

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_shutdown_signal() {
        let coordinator = ShutdownCoordinator::new();
        let signal = coordinator.signal();

        assert!(!signal.is_shutdown());

        coordinator.shutdown().await;

        assert!(signal.is_shutdown());
    }

    #[tokio::test]
    async fn test_request_tracker() {
        let tracker = RequestTracker::new();

        assert_eq!(tracker.active_count(), 0);
        assert_eq!(tracker.total_count(), 0);

        {
            let _guard1 = tracker.request_start();
            let _guard2 = tracker.request_start();

            assert_eq!(tracker.active_count(), 2);
            assert_eq!(tracker.total_count(), 2);
        }

        // Guards dropped
        assert_eq!(tracker.active_count(), 0);
        assert_eq!(tracker.total_count(), 2);
    }

    #[tokio::test]
    async fn test_request_drain() {
        let tracker = Arc::new(RequestTracker::new());
        let tracker2 = tracker.clone();

        // Start some requests
        let guards: Vec<_> = (0..3).map(|_| tracker.request_start()).collect();

        // Spawn drain task
        let drain_task = tokio::spawn(async move {
            tracker2.wait_for_drain(Duration::from_secs(5)).await
        });

        // Let drain run for a bit
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Complete requests
        drop(guards);

        // Drain should complete
        let drained = drain_task.await.unwrap();
        assert!(drained);
    }

    #[tokio::test]
    async fn test_shutdown_hook() {
        use std::sync::atomic::AtomicBool;

        let coordinator = ShutdownCoordinator::new();
        let hook_called = Arc::new(AtomicBool::new(false));
        let hook_called2 = hook_called.clone();

        coordinator
            .register_hook(move || {
                hook_called2.store(true, Ordering::SeqCst);
            })
            .await;

        assert!(!hook_called.load(Ordering::SeqCst));

        coordinator.shutdown().await;

        assert!(hook_called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_broadcast_subscription() {
        let coordinator = ShutdownCoordinator::new();
        let mut rx = coordinator.subscribe();

        let recv_task = tokio::spawn(async move { rx.recv().await });

        // Small delay to ensure receiver is ready
        tokio::time::sleep(Duration::from_millis(10)).await;

        coordinator.shutdown().await;

        let result = recv_task.await.unwrap();
        assert!(result.is_ok());
    }
}
