//! Synthetic BIGINT-boundary checks for VES batch admission. The directly
//! seeded counters are deliberately not full event histories; these tests
//! isolate capacity handling, not the gap-free ledger invariant.
mod common;

use std::sync::Arc;

use serde_json::json;
use stateset_sequencer::{
    auth::{AgentKeyEntry, AgentKeyLookup, AgentKeyRegistry},
    crypto::AgentSigningKey,
    domain::{AgentId, AgentKeyId, EntityType, EventType, StoreId, TenantId, VesEventEnvelope},
    infra::{PgAgentKeyRegistry, VesRejectionReason, VesSequencer},
};
use uuid::Uuid;

fn event(
    tenant: TenantId,
    store: StoreId,
    agent: AgentId,
    key: &AgentSigningKey,
    command: Uuid,
    base_version: u64,
    marker: &str,
) -> VesEventEnvelope {
    let mut event = VesEventEnvelope::new_plaintext(
        tenant,
        store,
        agent,
        AgentKeyId::default(),
        EntityType::order(),
        "capacity-order",
        EventType::new("order.updated"),
        json!({"marker": marker}),
        key,
    )
    .with_command_id(command)
    .with_base_version(base_version);
    event.sign_execution_controls(key);
    event
}

#[tokio::test]
#[ignore]
async fn version_rejections_do_not_consume_sequence_capacity() {
    let pool = common::connect_test_db(5)
        .await
        .expect("test database is required");
    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();
    let tenant = TenantId::new();
    let store = StoreId::new();
    let agent = AgentId::new();
    let key = AgentSigningKey::generate();
    let registry = Arc::new(PgAgentKeyRegistry::new(pool.clone()));
    registry
        .register_key(
            &AgentKeyLookup::new(&tenant, &agent, AgentKeyId::default()),
            AgentKeyEntry::new(key.public_key_bytes()),
        )
        .await
        .unwrap();
    let ves = VesSequencer::new(pool.clone(), registry).with_required_execution_binding(true);

    sqlx::query(
        "INSERT INTO ves_sequence_counters (tenant_id, store_id, current_sequence) VALUES ($1, $2, $3)",
    )
    .bind(tenant.0)
    .bind(store.0)
    .bind(i64::MAX - 1)
    .execute(&pool)
    .await
    .unwrap();

    let stale_command = Uuid::new_v4();
    let accepted_command = Uuid::new_v4();
    let stale = event(tenant, store, agent, &key, stale_command, 1, "stale");
    let fitting = event(tenant, store, agent, &key, accepted_command, 0, "fits");
    let result = ves
        .ingest(vec![stale.clone(), fitting.clone()])
        .await
        .unwrap();
    assert_eq!(result.events_accepted, 1);
    assert_eq!(result.assigned_sequence_start, Some(i64::MAX as u64));
    assert_eq!(result.assigned_sequence_end, Some(i64::MAX as u64));
    assert_eq!(result.head_sequence, i64::MAX as u64);
    assert_eq!(result.receipts.len(), 1);
    assert_eq!(result.receipts[0].event_id, fitting.event_id);
    assert_eq!(result.events_rejected.len(), 1);
    assert_eq!(result.events_rejected[0].event_id, stale.event_id);
    assert!(matches!(
        result.events_rejected[0].reason,
        VesRejectionReason::VersionConflict {
            expected: 1,
            actual: 0
        }
    ));
    assert_eq!(ves.head(&tenant, &store).await.unwrap(), i64::MAX as u64);

    let rows: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT event_id, sequence_number FROM ves_events WHERE tenant_id=$1 AND store_id=$2",
    )
    .bind(tenant.0)
    .bind(store.0)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rows, vec![(fitting.event_id, i64::MAX)]);
    let commands: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT command_id FROM ves_command_dedupe WHERE tenant_id=$1 AND store_id=$2",
    )
    .bind(tenant.0)
    .bind(store.0)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(commands, vec![(accepted_command,)]);

    // A later valid event cannot exceed BIGINT. The failed transaction must
    // roll back its provisional command reservation.
    let overflow = event(tenant, store, agent, &key, stale_command, 1, "overflow");
    assert!(ves.ingest(vec![overflow]).await.is_err());
    let command_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM ves_command_dedupe WHERE tenant_id=$1 AND store_id=$2",
    )
    .bind(tenant.0)
    .bind(store.0)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(command_count, 1);
    assert_eq!(ves.head(&tenant, &store).await.unwrap(), i64::MAX as u64);

    // If two members both pass their version checks but only one slot
    // remains, the second capacity error aborts the whole SQL transaction.
    let rollback_store = StoreId::new();
    sqlx::query(
        "INSERT INTO ves_sequence_counters (tenant_id, store_id, current_sequence) VALUES ($1, $2, $3)",
    )
    .bind(tenant.0)
    .bind(rollback_store.0)
    .bind(i64::MAX - 1)
    .execute(&pool)
    .await
    .unwrap();
    let first = event(
        tenant,
        rollback_store,
        agent,
        &key,
        Uuid::new_v4(),
        0,
        "first",
    );
    let second = event(
        tenant,
        rollback_store,
        agent,
        &key,
        Uuid::new_v4(),
        1,
        "second",
    );
    let first_id = first.event_id;
    let second_id = second.event_id;
    assert!(ves.ingest(vec![first, second]).await.is_err());
    assert_eq!(
        ves.head(&tenant, &rollback_store).await.unwrap(),
        (i64::MAX - 1) as u64
    );
    for table in ["ves_events", "ves_command_dedupe", "entity_versions"] {
        let sql = format!("SELECT count(*) FROM {table} WHERE tenant_id=$1 AND store_id=$2");
        let count: i64 = sqlx::query_scalar(&sql)
            .bind(tenant.0)
            .bind(rollback_store.0)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0, "{table} must roll back");
    }
    let receipt_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM ves_sequencer_receipts WHERE event_id IN ($1, $2)",
    )
    .bind(first_id)
    .bind(second_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(receipt_count, 0, "receipt rows must roll back");
}

#[tokio::test]
#[ignore]
async fn full_counter_allows_version_rejection_without_an_allocation() {
    let pool = common::connect_test_db(5)
        .await
        .expect("test database is required");
    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();
    let tenant = TenantId::new();
    let store = StoreId::new();
    let agent = AgentId::new();
    let key = AgentSigningKey::generate();
    let registry = Arc::new(PgAgentKeyRegistry::new(pool.clone()));
    registry
        .register_key(
            &AgentKeyLookup::new(&tenant, &agent, AgentKeyId::default()),
            AgentKeyEntry::new(key.public_key_bytes()),
        )
        .await
        .unwrap();
    let ves = VesSequencer::new(pool.clone(), registry).with_required_execution_binding(true);
    sqlx::query(
        "INSERT INTO ves_sequence_counters (tenant_id, store_id, current_sequence) VALUES ($1, $2, $3)",
    )
    .bind(tenant.0)
    .bind(store.0)
    .bind(i64::MAX)
    .execute(&pool)
    .await
    .unwrap();

    let stale = event(tenant, store, agent, &key, Uuid::new_v4(), 1, "stale");
    let result = ves.ingest(vec![stale]).await.unwrap();
    assert_eq!(result.events_accepted, 0);
    assert_eq!(result.head_sequence, i64::MAX as u64);
    assert!(matches!(
        result.events_rejected[0].reason,
        VesRejectionReason::VersionConflict {
            expected: 1,
            actual: 0
        }
    ));
    let reservation_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM ves_command_dedupe WHERE tenant_id=$1 AND store_id=$2",
    )
    .bind(tenant.0)
    .bind(store.0)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(reservation_count, 0);
}
