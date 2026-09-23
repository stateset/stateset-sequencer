//! Upgrade a populated v13 database and compare durable VES identifiers and hashes.
mod common;

use std::{borrow::Cow, path::Path};

use sqlx::{migrate::Migrator, postgres::PgPoolOptions};
use stateset_sequencer::infra::PgDeadLetterQueue;
use uuid::Uuid;

#[tokio::test]
#[ignore]
async fn upgrading_v13_preserves_ves_event_receipt_and_commitment_bytes() {
    let admin = common::connect_test_db(2)
        .await
        .expect("test database is required");
    // Historical migrations inspect information_schema without constraining
    // table_schema. A dedicated database avoids matches from concurrent tests.
    let database = format!("migration_verify_{}", Uuid::new_v4().simple());
    sqlx::raw_sql(&format!("CREATE DATABASE {database}"))
        .execute(&admin)
        .await
        .unwrap();
    let options = (*admin.connect_options()).clone().database(&database);
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options)
        .await
        .unwrap();

    let migration_path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations/postgres"));
    let mut old = Migrator::new(migration_path).await.unwrap();
    old.migrations = Cow::Owned(
        old.migrations
            .iter()
            .filter(|migration| migration.version <= 13)
            .cloned()
            .collect(),
    );
    old.run(&pool).await.unwrap();

    let tenant = Uuid::new_v4();
    let store = Uuid::new_v4();
    let agent = Uuid::new_v4();
    let event = Uuid::new_v4();
    let batch = Uuid::new_v4();
    let hash = vec![7u8; 32];
    let signature = vec![9u8; 64];
    sqlx::query(
        "INSERT INTO ves_events (event_id, tenant_id, store_id, source_agent_id, agent_key_id, \
         entity_type, entity_id, event_type, created_at, created_at_str, payload, \
         payload_plain_hash, payload_cipher_hash, event_signing_hash, agent_signature, sequence_number) \
         VALUES ($1,$2,$3,$4,1,'order','migration-order','order.created',NOW(), \
         '2025-01-01T00:00:00Z','{}'::jsonb,$5,$5,$5,$6,1)",
    )
    .bind(event).bind(tenant).bind(store).bind(agent).bind(&hash).bind(&signature)
    .execute(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO ves_sequencer_receipts (event_id, sequencer_id, sequence_number, receipt_hash) \
         VALUES ($1,$2,1,$3)",
    )
    .bind(event).bind(Uuid::new_v4()).bind(&hash).execute(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO ves_commitments (batch_id, tenant_id, store_id, tree_depth, leaf_count, \
         padded_leaf_count, merkle_root, prev_state_root, new_state_root, sequence_start, sequence_end) \
         VALUES ($1,$2,$3,1,1,1,$4,$4,$4,1,1)",
    )
    .bind(batch).bind(tenant).bind(store).bind(&hash).execute(&pool).await.unwrap();

    let before_event: (Uuid, i64, Vec<u8>) = sqlx::query_as(
        "SELECT event_id, sequence_number, event_signing_hash FROM ves_events WHERE event_id=$1",
    )
    .bind(event)
    .fetch_one(&pool)
    .await
    .unwrap();
    let before_receipt: (Uuid, i64, Vec<u8>) = sqlx::query_as(
        "SELECT event_id, sequence_number, receipt_hash FROM ves_sequencer_receipts WHERE event_id=$1",
    ).bind(event).fetch_one(&pool).await.unwrap();
    let before_roots: (Vec<u8>, Vec<u8>, Vec<u8>, i64, i64) = sqlx::query_as(
        "SELECT merkle_root, prev_state_root, new_state_root, sequence_start, sequence_end \
         FROM ves_commitments WHERE batch_id=$1",
    )
    .bind(batch)
    .fetch_one(&pool)
    .await
    .unwrap();

    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();
    let dead_letter_table_exists: bool =
        sqlx::query_scalar("SELECT to_regclass('dead_letter_events') IS NOT NULL")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        dead_letter_table_exists,
        "the current migration list must include the DLQ table"
    );
    let after_event: (Uuid, i64, Vec<u8>) = sqlx::query_as(
        "SELECT event_id, sequence_number, event_signing_hash FROM ves_events WHERE event_id=$1",
    )
    .bind(event)
    .fetch_one(&pool)
    .await
    .unwrap();
    let after_receipt: (Uuid, i64, Vec<u8>) = sqlx::query_as(
        "SELECT event_id, sequence_number, receipt_hash FROM ves_sequencer_receipts WHERE event_id=$1",
    ).bind(event).fetch_one(&pool).await.unwrap();
    let after_roots: (Vec<u8>, Vec<u8>, Vec<u8>, i64, i64) = sqlx::query_as(
        "SELECT merkle_root, prev_state_root, new_state_root, sequence_start, sequence_end \
         FROM ves_commitments WHERE batch_id=$1",
    )
    .bind(batch)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(after_event, before_event);
    assert_eq!(after_receipt, before_receipt);
    assert_eq!(after_roots, before_roots);

    let audit_before: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log")
        .fetch_one(&pool)
        .await
        .unwrap();
    let mut rolled_back = pool.begin().await.unwrap();
    sqlx::query("INSERT INTO agent_event_policies (tenant_id, agent_id) VALUES ($1, $2)")
        .bind(tenant)
        .bind(agent)
        .execute(&mut *rolled_back)
        .await
        .unwrap();
    rolled_back.rollback().await.unwrap();
    let audit_after_rollback: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(audit_after_rollback, audit_before);
    sqlx::query("INSERT INTO agent_event_policies (tenant_id, agent_id) VALUES ($1, $2)")
        .bind(tenant)
        .bind(agent)
        .execute(&pool)
        .await
        .unwrap();
    let audit_after_commit: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(audit_after_commit, audit_before + 1);
    let rotation_policy_id = Uuid::new_v4();
    let mut rolled_back_rotation = pool.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO key_rotation_policies (id, tenant_id, key_type) VALUES ($1, $2, 'signing')",
    )
    .bind(rotation_policy_id)
    .bind(tenant)
    .execute(&mut *rolled_back_rotation)
    .await
    .unwrap();
    rolled_back_rotation.rollback().await.unwrap();
    let count_after_rotation_rollback: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count_after_rotation_rollback, audit_after_commit);
    sqlx::query(
        "INSERT INTO key_rotation_policies (id, tenant_id, key_type) VALUES ($1, $2, 'signing')",
    )
    .bind(rotation_policy_id)
    .bind(tenant)
    .execute(&pool)
    .await
    .unwrap();
    let rotation_audit: (String, Option<Uuid>, Option<String>) = sqlx::query_as(
        "SELECT action, tenant_id, resource_id FROM audit_log WHERE resource_type = 'key_rotation_policies' ORDER BY chain_seq DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        rotation_audit,
        (
            "key_rotation_policies_insert".to_string(),
            Some(tenant),
            Some(rotation_policy_id.to_string())
        )
    );
    let scheduled_rotation_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO scheduled_key_rotations \
         (id, tenant_id, agent_id, key_type, current_key_id, scheduled_at, reason) \
         VALUES ($1, $2, $3, 'signing', 1, NOW(), 'manual')",
    )
    .bind(scheduled_rotation_id)
    .bind(tenant)
    .bind(agent)
    .execute(&pool)
    .await
    .unwrap();
    let schedule_audit: (String, Option<Uuid>, Option<String>) = sqlx::query_as(
        "SELECT action, tenant_id, resource_id FROM audit_log WHERE resource_type = 'scheduled_key_rotations' ORDER BY chain_seq DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        schedule_audit,
        (
            "scheduled_key_rotations_insert".to_string(),
            Some(tenant),
            Some(scheduled_rotation_id.to_string())
        )
    );
    let audit_valid: bool = sqlx::query_scalar("SELECT sequencer_verify_audit_chain()")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(audit_valid);

    sqlx::query(
        "INSERT INTO ves_compliance_proofs (proof_id, event_id, tenant_id, store_id, \
         proof_type, proof_version, policy_id, policy_hash, proof, proof_hash) \
         VALUES ($1,$2,$3,$4,'stark-compliance',2,'test-policy',$5,$6,$7)",
    )
    .bind(Uuid::new_v4())
    .bind(event)
    .bind(tenant)
    .bind(store)
    .bind(&hash)
    .bind(vec![1u8; 16])
    .bind(&hash)
    .execute(&pool)
    .await
    .unwrap();
    let job_status: String = sqlx::query_scalar(
        "SELECT status FROM ves_proof_jobs WHERE event_id = $1 AND policy_hash = $2",
    )
    .bind(event)
    .bind(&hash)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(job_status, "proved");

    let dead_letter_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO dead_letter_events (id, event_id, tenant_id, store_id, event_type, \
         reason, error_message, payload) VALUES ($1,$2,$3,$4,'order.created', \
         'handler_error','retry me','{}'::jsonb)",
    )
    .bind(dead_letter_id)
    .bind(Uuid::new_v4())
    .bind(tenant)
    .bind(store)
    .execute(&pool)
    .await
    .unwrap();
    let queue = PgDeadLetterQueue::new(pool.clone());
    let first = queue.mark_retrying(dead_letter_id).await.unwrap().unwrap();
    assert!(!queue
        .mark_resolved(dead_letter_id, Uuid::new_v4())
        .await
        .unwrap());
    assert!(queue
        .mark_retry_failed(dead_letter_id, first, "first failure")
        .await
        .unwrap());
    sqlx::query(
        "UPDATE dead_letter_events SET next_retry_at = NOW() - INTERVAL '1 second' WHERE id = $1",
    )
    .bind(dead_letter_id)
    .execute(&pool)
    .await
    .unwrap();
    let second = queue.mark_retrying(dead_letter_id).await.unwrap().unwrap();
    assert_ne!(first, second);
    assert!(!queue.mark_resolved(dead_letter_id, first).await.unwrap());
    assert!(queue.mark_resolved(dead_letter_id, second).await.unwrap());
    assert!(!queue.mark_resolved(dead_letter_id, second).await.unwrap());

    pool.close().await;
    sqlx::raw_sql(&format!("DROP DATABASE {database} WITH (FORCE)"))
        .execute(&admin)
        .await
        .unwrap();
}
