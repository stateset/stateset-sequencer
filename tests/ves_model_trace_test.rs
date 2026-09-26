//! A concrete PostgreSQL trace against the state rules in VesReplay.tla and
//! SequencerIngest.tla. The oracle below owns no SQL and does not call the
//! implementation's replay, command, or version helpers.
mod common;

use std::{collections::HashMap, sync::Arc};

use serde_json::json;
use stateset_sequencer::{
    auth::{AgentKeyEntry, AgentKeyLookup, AgentKeyRegistry},
    crypto::AgentSigningKey,
    domain::{AgentId, AgentKeyId, EntityType, EventType, StoreId, TenantId, VesEventEnvelope},
    infra::{PgAgentKeyRegistry, VesRejectionReason, VesSequencer},
};
use uuid::Uuid;

#[derive(Clone)]
struct Input {
    stream: usize,
    // An abstract identity for the complete signed body, including optional
    // controls. A changed scheme is a different body even with the same ID.
    body: &'static str,
    event: VesEventEnvelope,
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Accepted(u64),
    Replayed(u64),
    DuplicateEvent,
    DuplicateCommand,
    VersionConflict { expected: u64, actual: u64 },
}

struct Saved {
    stream: usize,
    body: &'static str,
    command: Uuid,
    sequence: u64,
}

struct TraceFixture {
    tenant: TenantId,
    stores: [StoreId; 2],
    agent: AgentId,
    key: AgentSigningKey,
}

#[derive(Default)]
struct Model {
    head: [u64; 2],
    version: [u64; 2],
    rows: [Vec<Uuid>; 2],
    saved: HashMap<Uuid, Saved>,
    commands: HashMap<(usize, Uuid), Uuid>,
}

impl Model {
    fn apply(&mut self, input: &Input) -> Outcome {
        let id = input.event.event_id;
        let command = input.event.command_id.expect("trace command");
        let base = input.event.base_version.expect("trace base version");
        if let Some(saved) = self.saved.get(&id) {
            return if saved.stream == input.stream
                && saved.body == input.body
                && saved.command == command
            {
                Outcome::Replayed(saved.sequence)
            } else {
                Outcome::DuplicateEvent
            };
        }
        if self.commands.contains_key(&(input.stream, command)) {
            return Outcome::DuplicateCommand;
        }
        let actual = self.version[input.stream];
        if base != actual {
            return Outcome::VersionConflict {
                expected: base,
                actual,
            };
        }
        self.head[input.stream] += 1;
        self.version[input.stream] += 1;
        let sequence = self.head[input.stream];
        self.rows[input.stream].push(id);
        self.commands.insert((input.stream, command), id);
        self.saved.insert(
            id,
            Saved {
                stream: input.stream,
                body: input.body,
                command,
                sequence,
            },
        );
        Outcome::Accepted(sequence)
    }
}

fn make_input(
    fixture: &TraceFixture,
    stream: usize,
    body: &'static str,
    command: Uuid,
    base: u64,
) -> Input {
    let mut event = VesEventEnvelope::new_plaintext(
        fixture.tenant,
        fixture.stores[stream],
        fixture.agent,
        AgentKeyId::default(),
        EntityType::order(),
        "trace-order",
        EventType::new("order.updated"),
        json!({"step": body}),
        &fixture.key,
    )
    .with_command_id(command)
    .with_base_version(base);
    event.sign_execution_controls(&fixture.key);
    Input {
        stream,
        body,
        event,
    }
}

#[tokio::test]
#[ignore]
async fn postgres_ves_ingest_refines_sequential_replay_trace() {
    let pool = common::connect_test_db(5)
        .await
        .expect("test database is required");
    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();
    let tenant = TenantId::new();
    let stores = [StoreId::new(), StoreId::new()];
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
    let fixture = TraceFixture {
        tenant,
        stores,
        agent,
        key,
    };
    let [c1, c2, c3, c4] = [
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    ];
    let new = |stream, body, command, base| make_input(&fixture, stream, body, command, base);
    let first = new(0, "first", c1, 0);
    let mut changed = first.clone();
    changed.body = "changed-scheme";
    changed.event.agent_signature_scheme = Some(2);
    let second_stream = new(1, "second-stream", c1, 0);
    let mut cross_stream_collision = first.clone();
    cross_stream_collision.stream = 1;
    cross_stream_collision.event.store_id = stores[1];

    let trace = [
        vec![first.clone()],
        vec![first.clone()],
        vec![changed],
        vec![new(0, "reused-command", c1, 1)],
        vec![new(0, "stale-version", c2, 0)],
        vec![new(0, "recovered-command", c2, 1)],
        vec![new(0, "batch-first", c3, 2), new(0, "batch-stale", c4, 2)],
        vec![new(0, "batch-retry", c4, 3)],
        vec![second_stream.clone()],
        vec![cross_stream_collision],
        vec![second_stream],
    ];
    assert_trace(&pool, &ves, &fixture, trace, "fixed").await;
}

async fn assert_trace(
    pool: &sqlx::PgPool,
    ves: &VesSequencer<PgAgentKeyRegistry>,
    fixture: &TraceFixture,
    trace: impl IntoIterator<Item = Vec<Input>>,
    label: &str,
) {
    let mut model = Model::default();
    let mut receipt_hashes = HashMap::new();
    for (step_index, inputs) in trace.into_iter().enumerate() {
        let step = format!("{label}/{step_index}");
        let stream = inputs[0].stream;
        let expected: Vec<_> = inputs.iter().map(|input| model.apply(input)).collect();
        let result = ves
            .ingest(inputs.iter().map(|input| input.event.clone()).collect())
            .await
            .unwrap();
        let accepted: Vec<_> = expected
            .iter()
            .filter_map(|outcome| match outcome {
                Outcome::Accepted(sequence) => Some(*sequence),
                _ => None,
            })
            .collect();
        assert_eq!(
            result.events_accepted as usize,
            accepted.len(),
            "step {step}"
        );
        assert_eq!(
            result.assigned_sequence_start,
            accepted.first().copied(),
            "step {step}"
        );
        assert_eq!(
            result.assigned_sequence_end,
            accepted.last().copied(),
            "step {step}"
        );
        assert_eq!(result.head_sequence, model.head[stream], "step {step}");
        for (input, outcome) in inputs.iter().zip(&expected) {
            match outcome {
                Outcome::Accepted(sequence) | Outcome::Replayed(sequence) => {
                    let receipt = result
                        .receipts
                        .iter()
                        .find(|r| r.event_id == input.event.event_id)
                        .expect("accepted or replayed event needs a receipt");
                    assert_eq!(receipt.sequence_number, *sequence, "step {step}");
                    if let Some(previous) =
                        receipt_hashes.insert(receipt.event_id, receipt.receipt_hash)
                    {
                        assert_eq!(
                            previous, receipt.receipt_hash,
                            "step {step}: replay changed receipt"
                        );
                    }
                }
                rejection => {
                    assert!(!result
                        .receipts
                        .iter()
                        .any(|r| r.event_id == input.event.event_id));
                    let actual = &result
                        .events_rejected
                        .iter()
                        .find(|r| r.event_id == input.event.event_id)
                        .expect("rejected event needs a reason")
                        .reason;
                    let matches = match (rejection, actual) {
                        (Outcome::DuplicateEvent, VesRejectionReason::DuplicateEventId)
                        | (Outcome::DuplicateCommand, VesRejectionReason::DuplicateCommandId) => {
                            true
                        }
                        (
                            Outcome::VersionConflict { expected, actual },
                            VesRejectionReason::VersionConflict {
                                expected: got_expected,
                                actual: got_actual,
                            },
                        ) => expected == got_expected && actual == got_actual,
                        _ => false,
                    };
                    assert!(
                        matches,
                        "step {step}: expected {rejection:?}, got {actual:?}"
                    );
                }
            }
        }
        assert_eq!(
            result.receipts.len() + result.events_rejected.len(),
            inputs.len(),
            "step {step}"
        );

        for (index, store) in fixture.stores.iter().enumerate() {
            assert_eq!(
                ves.head(&fixture.tenant, store).await.unwrap(),
                model.head[index],
                "step {step}"
            );
            let rows: Vec<(Uuid, i64)> = sqlx::query_as(
                "SELECT event_id, sequence_number FROM ves_events WHERE tenant_id=$1 AND store_id=$2 ORDER BY sequence_number"
            ).bind(fixture.tenant.0).bind(store.0).fetch_all(pool).await.unwrap();
            assert_eq!(rows.len(), model.rows[index].len(), "step {step}");
            for (position, (event_id, sequence)) in rows.iter().enumerate() {
                assert_eq!(
                    (*event_id, *sequence),
                    (model.rows[index][position], position as i64 + 1),
                    "step {step}"
                );
            }
            let version: Option<i64> = sqlx::query_scalar(
                "SELECT version FROM entity_versions WHERE tenant_id=$1 AND store_id=$2 AND entity_type='order' AND entity_id='trace-order'"
            ).bind(fixture.tenant.0).bind(store.0).fetch_optional(pool).await.unwrap();
            assert_eq!(
                version.unwrap_or(0),
                model.version[index] as i64,
                "step {step}"
            );
            let commands: Vec<(Uuid,)> = sqlx::query_as(
                "SELECT command_id FROM ves_command_dedupe WHERE tenant_id=$1 AND store_id=$2",
            )
            .bind(fixture.tenant.0)
            .bind(store.0)
            .fetch_all(pool)
            .await
            .unwrap();
            let expected_commands: std::collections::HashSet<_> = model
                .commands
                .keys()
                .filter_map(|(stream, command)| (*stream == index).then_some(*command))
                .collect();
            let actual_commands: std::collections::HashSet<_> =
                commands.into_iter().map(|(command,)| command).collect();
            assert_eq!(
                actual_commands, expected_commands,
                "step {step}: command reservations"
            );
            let receipts: Vec<(Uuid, i64)> = sqlx::query_as(
                "SELECT r.event_id, r.sequence_number FROM ves_sequencer_receipts r JOIN ves_events e USING (event_id) WHERE e.tenant_id=$1 AND e.store_id=$2 ORDER BY r.sequence_number"
            ).bind(fixture.tenant.0).bind(store.0).fetch_all(pool).await.unwrap();
            assert_eq!(receipts, rows, "step {step}: persisted receipts");
        }
    }
}

/// Exhaust every three-call word over a small replay/version/stream alphabet.
/// Each word uses a fresh tenant, so its initial database state matches the
/// model's empty state. This broadens the fixed trace without random seeds or
/// relying on a duplicate copy of the SQL implementation as the oracle.
#[tokio::test]
#[ignore]
async fn postgres_ves_ingest_refines_generated_sequential_traces() {
    let pool = common::connect_test_db(5)
        .await
        .expect("test database is required");
    stateset_sequencer::migrations::run_postgres(&pool)
        .await
        .unwrap();
    let registry = Arc::new(PgAgentKeyRegistry::new(pool.clone()));
    let ves =
        VesSequencer::new(pool.clone(), registry.clone()).with_required_execution_binding(true);

    for case in 0..125 {
        let fixture = TraceFixture {
            tenant: TenantId::new(),
            stores: [StoreId::new(), StoreId::new()],
            agent: AgentId::new(),
            key: AgentSigningKey::generate(),
        };
        registry
            .register_key(
                &AgentKeyLookup::new(&fixture.tenant, &fixture.agent, AgentKeyId::default()),
                AgentKeyEntry::new(fixture.key.public_key_bytes()),
            )
            .await
            .unwrap();
        let [c0, c1, c2] = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
        let alphabet = [
            make_input(&fixture, 0, "first-at-zero", c0, 0),
            make_input(&fixture, 0, "next-at-one", c1, 1),
            make_input(&fixture, 0, "reused-command", c0, 1),
            make_input(&fixture, 1, "other-stream", c0, 0),
            make_input(&fixture, 0, "competing-at-zero", c2, 0),
        ];
        let trace = [
            vec![alphabet[case / 25].clone()],
            vec![alphabet[(case / 5) % 5].clone()],
            vec![alphabet[case % 5].clone()],
        ];
        assert_trace(&pool, &ves, &fixture, trace, &format!("generated-{case}")).await;
    }
}
