//! Integration tests for the leader-election mechanism (advisory locks).
//!
//! Ignored by default; run with `DATABASE_URL` set (locally or in CI). These
//! verify the three properties the singleton-worker election relies on:
//!   1. mutual exclusion — only one holder of a given key at a time,
//!   2. explicit release — `pg_advisory_unlock` frees it for the next contender,
//!   3. crash failover — closing the holder's *connection* auto-releases the
//!      lock, so a standby can take over without any explicit handoff.

use sqlx::postgres::PgPoolOptions;
use sqlx::{Connection, PgConnection};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use uuid::Uuid;

use stateset_sequencer::infra::{spawn_elected_worker, ElectionConfig, ShutdownCoordinator};

async fn connect() -> Option<PgConnection> {
    let url = std::env::var("DATABASE_URL").ok()?;
    PgConnection::connect(&url).await.ok()
}

/// A per-run key so parallel test runs (and the real worker keys) never collide.
fn unique_key() -> i64 {
    Uuid::new_v4().as_u128() as i64
}

async fn try_lock(conn: &mut PgConnection, key: i64) -> bool {
    sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_lock($1)")
        .bind(key)
        .fetch_one(conn)
        .await
        .expect("pg_try_advisory_lock should execute")
}

async fn unlock(conn: &mut PgConnection, key: i64) -> bool {
    sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1)")
        .bind(key)
        .fetch_one(conn)
        .await
        .expect("pg_advisory_unlock should execute")
}

#[tokio::test]
#[ignore]
async fn advisory_lock_is_mutually_exclusive_and_releasable() {
    let (Some(mut leader), Some(mut follower)) = (connect().await, connect().await) else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };
    let key = unique_key();

    // Leader wins.
    assert!(try_lock(&mut leader, key).await, "first contender must acquire");
    // Follower is excluded while the leader holds it.
    assert!(
        !try_lock(&mut follower, key).await,
        "second contender must be excluded while held"
    );

    // Leader releases; follower can now take over.
    assert!(unlock(&mut leader, key).await, "holder should release its lock");
    assert!(
        try_lock(&mut follower, key).await,
        "follower must acquire after explicit release"
    );

    let _ = unlock(&mut follower, key).await;
}

#[tokio::test]
#[ignore]
async fn advisory_lock_auto_releases_when_holder_connection_drops() {
    let key = unique_key();

    // Leader acquires on its own connection, then "crashes" (connection closed).
    {
        let Some(mut leader) = connect().await else {
            eprintln!("DATABASE_URL not set; skipping");
            return;
        };
        assert!(try_lock(&mut leader, key).await, "leader must acquire");
        leader.close().await.expect("close leader connection");
    }

    // A standby must be able to take over without any explicit unlock — this is
    // the failover guarantee. Allow a brief window for the backend session to be
    // reaped after close.
    let Some(mut standby) = connect().await else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };
    let mut acquired = false;
    for _ in 0..50 {
        if try_lock(&mut standby, key).await {
            acquired = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        acquired,
        "standby must acquire after the holder's connection dropped (auto-release)"
    );

    let _ = unlock(&mut standby, key).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn spawn_elected_worker_runs_on_exactly_one_node() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL not set; skipping");
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&url)
        .await
        .expect("connect pool");

    let key = unique_key();
    let cfg = ElectionConfig {
        retry_interval: Duration::from_millis(150),
        health_interval: Duration::from_millis(150),
    };

    // Counts how many "nodes" are concurrently running the singleton worker.
    let active = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));

    // Simulate three contending nodes sharing the same advisory-lock key.
    let coordinators: Vec<_> = (0..3).map(|_| Arc::new(ShutdownCoordinator::new())).collect();
    let mut handles = Vec::new();
    for coordinator in &coordinators {
        let active = active.clone();
        let max_seen = max_seen.clone();
        let handle = spawn_elected_worker(
            "test_worker",
            key,
            pool.clone(),
            cfg.clone(),
            coordinator.signal(),
            coordinator.clone(),
            move || {
                // Called only when this node is the elected leader.
                let n = active.fetch_add(1, Ordering::SeqCst) + 1;
                max_seen.fetch_max(n, Ordering::SeqCst);
                let stop_notify = Arc::new(Notify::new());
                let task_notify = stop_notify.clone();
                let active_on_stop = active.clone();
                let task = tokio::spawn(async move {
                    task_notify.notified().await;
                    active_on_stop.fetch_sub(1, Ordering::SeqCst);
                });
                (task, move || async move {
                    stop_notify.notify_one();
                })
            },
        );
        handles.push(handle);
    }

    // Give the cluster time to elect a leader and settle.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        active.load(Ordering::SeqCst),
        1,
        "exactly one node must run the singleton worker"
    );
    assert_eq!(
        max_seen.load(Ordering::SeqCst),
        1,
        "the worker must never have run on two nodes at once"
    );

    // Shut all nodes down and ensure the supervising tasks exit cleanly.
    for coordinator in &coordinators {
        coordinator.shutdown().await;
    }
    for handle in handles {
        let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
    }
    assert_eq!(
        active.load(Ordering::SeqCst),
        0,
        "the worker must stop on shutdown"
    );
}
