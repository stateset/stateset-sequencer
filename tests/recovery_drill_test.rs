//! Two-process fixture for scripts/run_recovery_drill.sh. Never runs implicitly.
use std::{fs::OpenOptions, io::Write, sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};
use stateset_sequencer::{
    auth::{AgentKeyEntry, AgentKeyLookup, AgentKeyRegistry},
    crypto::{AgentSigningKey, AgentVerifyingKey},
    domain::{AgentId, AgentKeyId, EntityType, EventType, StoreId, TenantId, VesEventEnvelope},
    infra::{
        EventStore, PayloadEncryption, PgAgentKeyRegistry, PgEventStore, PgVesCommitmentEngine,
        ProjectionWorkerConfig, ProjectionWorkerMessage, VesSequencer,
    },
    projection::ProjectionRunnerConfig,
};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
struct Receipt {
    event_id: Uuid,
    sequence: u64,
    hash: String,
    signature: String,
}

#[derive(Serialize, Deserialize)]
struct Fixture {
    events: Vec<VesEventEnvelope>,
    stored_events: Vec<VesEventEnvelope>,
    receipts: Vec<Receipt>,
    receipt_public_key: [u8; 32],
    commitment_id: Uuid,
    merkle_root: [u8; 32],
    projection_documents: Vec<(String, serde_json::Value, i64)>,
}

async fn projection_snapshot(
    pool: &sqlx::PgPool,
    tenant: TenantId,
    store: StoreId,
    expected: i64,
) -> Vec<(String, serde_json::Value, i64)> {
    let checkpoint: i64 = sqlx::query_scalar("SELECT last_projected_sequence FROM ves_projection_checkpoints WHERE tenant_id=$1 AND store_id=$2")
        .bind(tenant.0).bind(store.0).fetch_one(pool).await.unwrap();
    assert_eq!(checkpoint, expected);
    let documents: Vec<(String, serde_json::Value, i64)> = sqlx::query_as("SELECT entity_id, document, version FROM ves_projection_documents WHERE tenant_id=$1 AND store_id=$2 AND entity_type='order' ORDER BY entity_id")
        .bind(tenant.0).bind(store.0).fetch_all(pool).await.unwrap();
    let versions: Vec<(String, i64)> = sqlx::query_as("SELECT entity_id, version FROM ves_projection_entity_versions WHERE tenant_id=$1 AND store_id=$2 AND entity_type='order' ORDER BY entity_id")
        .bind(tenant.0).bind(store.0).fetch_all(pool).await.unwrap();
    assert_eq!(documents.len(), expected as usize);
    assert_eq!(versions.len(), documents.len());
    let mut expected_ids: Vec<_> = (0..expected)
        .map(|index| format!("recovery-{index}"))
        .collect();
    expected_ids.sort();
    assert_eq!(
        documents
            .iter()
            .map(|row| row.0.clone())
            .collect::<Vec<_>>(),
        expected_ids
    );
    for ((id, document, version), (version_id, stored_version)) in documents.iter().zip(versions) {
        assert_eq!(id, &version_id);
        assert_eq!(*version, 1);
        assert_eq!(stored_version, 1);
        assert_eq!(document["order_id"], *id);
        assert_eq!(document["customer_id"], "recovery-customer");
        assert_eq!(document["currency"], "CAD");
    }
    documents
}

async fn project_to(
    pool: &sqlx::PgPool,
    sequencer: Arc<VesSequencer<PgAgentKeyRegistry>>,
    tenant: TenantId,
    store: StoreId,
    expected: i64,
) {
    let event_store: Arc<dyn EventStore> = Arc::new(PgEventStore::new(
        pool.clone(),
        Arc::new(PayloadEncryption::disabled()),
    ));
    let config = ProjectionWorkerConfig {
        max_concurrent_streams: 2,
        discovery_interval: Duration::from_millis(10),
        discovery_page_size: 100,
        runner: ProjectionRunnerConfig {
            batch_size: 16,
            checkpoint_interval: 1,
            poll_interval_ms: 10,
            ..Default::default()
        },
    };
    let (task, control) = stateset_sequencer::infra::spawn_projection_worker(
        config,
        pool.clone(),
        event_store,
        Some(sequencer),
    );
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let checkpoint: Option<i64> = sqlx::query_scalar("SELECT last_projected_sequence FROM ves_projection_checkpoints WHERE tenant_id=$1 AND store_id=$2")
                .bind(tenant.0).bind(store.0).fetch_optional(pool).await.unwrap();
            if checkpoint == Some(expected) { break; }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Allow a restarted, already caught-up worker to discover the stream.
        tokio::time::sleep(Duration::from_millis(100)).await;
    }).await;
    control
        .send(ProjectionWorkerMessage::Shutdown)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    result.expect("projection catch-up deadline");
}

#[tokio::test]
#[ignore]
async fn recovery_fixture() {
    let Ok(phase) = std::env::var("SEQUENCER_RECOVERY_PHASE") else {
        eprintln!("Run this fixture through scripts/run_recovery_drill.sh");
        return;
    };
    assert!(matches!(phase.as_str(), "seed" | "verify" | "resume"));
    let path = std::env::var("SEQUENCER_RECOVERY_FIXTURE").expect("fixture path");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&std::env::var("DATABASE_URL").expect("database URL"))
        .await
        .unwrap();
    for setting in ["fsync", "full_page_writes", "synchronous_commit"] {
        let value: String = sqlx::query_scalar("SELECT current_setting($1)")
            .bind(setting)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(value, "on", "durability setting {setting} must be on");
    }
    let registry = Arc::new(PgAgentKeyRegistry::new(pool.clone()));
    let engine = PgVesCommitmentEngine::new(pool.clone());
    if phase == "seed" {
        stateset_sequencer::migrations::run_postgres(&pool)
            .await
            .unwrap();
        let tenant = TenantId::new();
        let store = StoreId::new();
        let agent = AgentId::new();
        let key = AgentSigningKey::generate();
        registry
            .register_key(
                &AgentKeyLookup::new(&tenant, &agent, AgentKeyId::default()),
                AgentKeyEntry::new(key.public_key_bytes()),
            )
            .await
            .unwrap();
        let receipt_key = AgentSigningKey::generate();
        let receipt_public_key = receipt_key.public_key_bytes();
        let sequencer = Arc::new(
            VesSequencer::new(pool.clone(), registry)
                .with_required_execution_binding(true)
                .with_signing_key(receipt_key),
        );
        let events: Vec<_> = (0..128)
            .map(|index| {
                let mut event = VesEventEnvelope::new_plaintext(
                    tenant,
                    store,
                    agent,
                    AgentKeyId::default(),
                    EntityType::order(),
                    format!("recovery-{index}"),
                    EventType::new("order.created"),
                    serde_json::json!({"customer_id":"recovery-customer", "total_amount": index, "currency":"CAD", "line_items":[]}),
                    &key,
                )
                .with_command_id(Uuid::new_v4())
                .with_base_version(0);
                event.sign_execution_controls(&key);
                event
            })
            .collect();
        let mut accepted = sequencer.ingest(events[..64].to_vec()).await.unwrap();
        assert!(accepted.events_rejected.is_empty());
        assert_eq!(accepted.events_accepted, 64);
        project_to(&pool, sequencer.clone(), tenant, store, 64).await;
        let projection_documents = projection_snapshot(&pool, tenant, store, 64).await;
        let tail = sequencer.ingest(events[64..].to_vec()).await.unwrap();
        assert!(tail.events_rejected.is_empty());
        assert_eq!(tail.events_accepted, 64);
        accepted.receipts.extend(tail.receipts);
        let receipts: Vec<_> = accepted
            .receipts
            .iter()
            .map(|receipt| Receipt {
                event_id: receipt.event_id,
                sequence: receipt.sequence_number,
                hash: hex::encode(receipt.receipt_hash),
                signature: hex::encode(receipt.sequencer_signature.expect("signed receipt")),
            })
            .collect();
        let commitment = engine
            .create_and_store_commitment(&tenant, &store, (1, events.len() as u64))
            .await
            .unwrap();
        let mut stored_events = Vec::new();
        for event in &events {
            let stored = sequencer.read_by_id(event.event_id).await.unwrap().unwrap();
            assert_eq!(
                stored.envelope.compute_signing_hash(),
                event.compute_signing_hash()
            );
            stored_events.push(stored.envelope);
        }
        let fixture = Fixture {
            events,
            stored_events,
            receipts,
            receipt_public_key,
            commitment_id: commitment.batch_id,
            merkle_root: commitment.merkle_root,
            projection_documents,
        };
        // Persist the external acknowledgement oracle before the orchestrator
        // crashes PostgreSQL. Never overwrite an existing oracle.
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        output
            .write_all(&serde_json::to_vec_pretty(&fixture).unwrap())
            .unwrap();
        output.sync_all().unwrap();
    } else {
        let fixture: Fixture = serde_json::from_reader(std::fs::File::open(path).unwrap()).unwrap();
        assert_eq!(fixture.events.len(), 128);
        assert_eq!(fixture.stored_events.len(), fixture.events.len());
        assert_eq!(fixture.receipts.len(), fixture.events.len());
        let first = &fixture.events[0];
        let agent_key = registry
            .get_key(&AgentKeyLookup::new(
                &first.tenant_id,
                &first.source_agent_id,
                first.agent_key_id,
            ))
            .await
            .expect("agent key survives recovery");
        let agent_verifying = AgentVerifyingKey::from_bytes(&agent_key.public_key).unwrap();
        let sequencer = Arc::new(
            VesSequencer::new(pool.clone(), registry).with_required_execution_binding(true),
        );
        assert_eq!(
            projection_snapshot(&pool, first.tenant_id, first.store_id, 64).await,
            fixture.projection_documents
        );
        assert_eq!(
            sequencer
                .head(&first.tenant_id, &first.store_id)
                .await
                .unwrap(),
            128
        );
        for (event, expected_stored) in fixture.events.iter().zip(&fixture.stored_events) {
            let stored = sequencer
                .read_by_id(event.event_id)
                .await
                .unwrap()
                .expect("acknowledged event survives");
            assert_eq!(
                serde_json::to_value(&stored.envelope).unwrap(),
                serde_json::to_value(expected_stored).unwrap()
            );
            assert_eq!(
                stored.envelope.compute_signing_hash(),
                event.compute_signing_hash()
            );
            stored.envelope.verify_signature(&agent_verifying).unwrap();
        }
        let replay = sequencer.ingest(fixture.events.clone()).await.unwrap();
        assert!(replay.events_rejected.is_empty());
        assert_eq!(replay.receipts.len(), fixture.receipts.len());
        let verifying = AgentVerifyingKey::from_bytes(&fixture.receipt_public_key).unwrap();
        for (actual, expected) in replay.receipts.iter().zip(&fixture.receipts) {
            assert_eq!(actual.event_id, expected.event_id);
            assert_eq!(actual.sequence_number, expected.sequence);
            assert_eq!(hex::encode(actual.receipt_hash), expected.hash);
            let signature = actual
                .sequencer_signature
                .expect("stored receipt signature");
            assert_eq!(hex::encode(signature), expected.signature);
            verifying.verify(&actual.receipt_hash, &signature).unwrap();
        }
        assert_eq!(
            sequencer
                .head(&first.tenant_id, &first.store_id)
                .await
                .unwrap(),
            128,
            "replay must not advance head"
        );
        let commitment = engine
            .get_commitment(fixture.commitment_id)
            .await
            .unwrap()
            .expect("commitment survives");
        assert_eq!(commitment.merkle_root, fixture.merkle_root);
        let leaves = engine
            .leaf_hashes_for_range(&first.tenant_id, &first.store_id, 1, 128)
            .await
            .unwrap();
        assert_eq!(leaves.len(), 128);
        for (index, leaf) in leaves.iter().enumerate() {
            let proof = engine.prove_inclusion(index, &leaves).unwrap();
            assert!(engine.verify_inclusion(*leaf, &proof, fixture.merkle_root));
        }
        if phase == "resume" {
            project_to(
                &pool,
                sequencer.clone(),
                first.tenant_id,
                first.store_id,
                128,
            )
            .await;
            let caught_up = projection_snapshot(&pool, first.tenant_id, first.store_id, 128).await;
            project_to(&pool, sequencer, first.tenant_id, first.store_id, 128).await;
            assert_eq!(
                projection_snapshot(&pool, first.tenant_id, first.store_id, 128).await,
                caught_up
            );
            println!("PROJECTION_RECOVERY_VERIFIED: checkpoint 64 -> 128; documents and versions stable after worker restart");
        }
    }
    pool.close().await;
}
