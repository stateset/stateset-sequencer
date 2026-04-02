//! Performance benchmarks for StateSet Sequencer.
//!
//! Run with: cargo bench

#![allow(clippy::clone_on_copy)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use serde_json::json;
use stateset_sequencer::crypto::{
    compute_event_signing_hash, compute_leaf_hash, compute_node_hash, pad_leaf, EventSigningParams,
    LeafHashParams,
};
use stateset_sequencer::domain::{
    AgentId, EntityType, EventBatch, EventEnvelope, EventType, Hash256, StoreId, TenantId,
};
use uuid::Uuid;

/// Create a batch of test events
fn create_event_batch(count: usize) -> EventBatch {
    let tenant_id = TenantId::new();
    let store_id = StoreId::new();
    let agent_id = AgentId::new();

    let events: Vec<EventEnvelope> = (0..count)
        .map(|i| {
            EventEnvelope::new(
                tenant_id.clone(),
                store_id.clone(),
                EntityType::order(),
                format!("order-{}", i),
                EventType::new("order.created"),
                json!({
                    "customer_id": format!("cust-{}", i),
                    "total": i as f64 * 10.0,
                    "items": [
                        {"sku": "SKU-001", "quantity": 1, "price": 9.99},
                        {"sku": "SKU-002", "quantity": 2, "price": 19.99}
                    ]
                }),
                agent_id.clone(),
            )
        })
        .collect();

    EventBatch::new(agent_id, events)
}

/// Benchmark event envelope creation
fn bench_event_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_creation");

    for count in [1, 10, 100, 1000].iter() {
        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(
            BenchmarkId::new("create_batch", count),
            count,
            |b, &count| {
                b.iter(|| {
                    black_box(create_event_batch(count));
                });
            },
        );
    }

    group.finish();
}

/// Benchmark payload hash computation
fn bench_payload_hash(c: &mut Criterion) {
    let payload = json!({
        "customer_id": "cust-123",
        "total": 99.99,
        "items": [
            {"sku": "SKU-001", "quantity": 1, "price": 9.99},
            {"sku": "SKU-002", "quantity": 2, "price": 19.99},
            {"sku": "SKU-003", "quantity": 3, "price": 29.99}
        ],
        "shipping_address": {
            "street": "123 Main St",
            "city": "Anytown",
            "state": "CA",
            "zip": "12345"
        }
    });

    c.bench_function("payload_hash", |b| {
        b.iter(|| {
            black_box(EventEnvelope::compute_payload_hash(&payload));
        });
    });
}

/// Benchmark event signing bytes generation
fn bench_signing_bytes(c: &mut Criterion) {
    let envelope = EventEnvelope::new(
        TenantId::new(),
        StoreId::new(),
        EntityType::order(),
        "order-123",
        EventType::new("order.created"),
        json!({"customer_id": "cust-456"}),
        AgentId::new(),
    );

    c.bench_function("signing_bytes", |b| {
        b.iter(|| {
            black_box(envelope.signing_bytes());
        });
    });
}

/// Benchmark payload hash verification
fn bench_payload_verification(c: &mut Criterion) {
    let envelope = EventEnvelope::new(
        TenantId::new(),
        StoreId::new(),
        EntityType::order(),
        "order-123",
        EventType::new("order.created"),
        json!({"customer_id": "cust-456", "items": [{"sku": "SKU-001", "qty": 5}]}),
        AgentId::new(),
    );

    c.bench_function("payload_hash_verify", |b| {
        b.iter(|| {
            black_box(envelope.verify_payload_hash());
        });
    });
}

/// Benchmark VES event signing hash computation
fn bench_event_signing_hash(c: &mut Criterion) {
    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();
    let event_id = Uuid::new_v4();
    let agent_id = Uuid::new_v4();
    let payload_hash = [0xabu8; 32];
    let cipher_hash = [0u8; 32];

    c.bench_function("event_signing_hash", |b| {
        b.iter(|| {
            let params = EventSigningParams {
                ves_version: 1,
                tenant_id: &tenant_id,
                store_id: &store_id,
                event_id: &event_id,
                source_agent_id: &agent_id,
                agent_key_id: 1,
                entity_type: "order",
                entity_id: "order-12345",
                event_type: "order.created",
                created_at: "2025-01-01T00:00:00Z",
                payload_kind: 0,
                payload_plain_hash: &payload_hash,
                payload_cipher_hash: &cipher_hash,
            };
            black_box(compute_event_signing_hash(&params));
        });
    });
}

/// Benchmark Merkle leaf hash computation
fn bench_leaf_hash(c: &mut Criterion) {
    let tenant_id = Uuid::new_v4();
    let store_id = Uuid::new_v4();
    let signing_hash = [0xabu8; 32];
    let signature = [0xcdu8; 64];

    c.bench_function("leaf_hash", |b| {
        b.iter(|| {
            let params = LeafHashParams {
                tenant_id: &tenant_id,
                store_id: &store_id,
                sequence_number: 42,
                event_signing_hash: &signing_hash,
                agent_signature: &signature,
            };
            black_box(compute_leaf_hash(&params));
        });
    });
}

/// Benchmark Merkle node hash computation
fn bench_node_hash(c: &mut Criterion) {
    let left: Hash256 = [0xaau8; 32];
    let right: Hash256 = [0xbbu8; 32];

    c.bench_function("node_hash", |b| {
        b.iter(|| {
            black_box(compute_node_hash(&left, &right));
        });
    });
}

/// Build a complete Merkle tree from leaf hashes (mirrors ves_commitment build_levels)
fn build_merkle_tree(leaves: &[Hash256]) -> Hash256 {
    if leaves.is_empty() {
        return [0u8; 32];
    }

    // Pad to power of 2
    let padded_len = leaves.len().next_power_of_two();
    let mut current = Vec::with_capacity(padded_len);
    current.extend_from_slice(leaves);
    current.resize(padded_len, pad_leaf());

    // Build levels until root
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len() / 2);
        for pair in current.chunks_exact(2) {
            next.push(compute_node_hash(&pair[0], &pair[1]));
        }
        current = next;
    }

    current[0]
}

/// Benchmark Merkle tree construction at various sizes
fn bench_merkle_tree(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_tree");

    for count in [10, 100, 1000, 4096].iter() {
        // Generate random leaf hashes
        let leaves: Vec<Hash256> = (0..*count)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = (i & 0xff) as u8;
                h[1] = ((i >> 8) & 0xff) as u8;
                // Quick deterministic "hash" for benchmark input
                stateset_sequencer::crypto::sha256(&h)
            })
            .collect();

        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(
            BenchmarkId::new("build_tree", count),
            &leaves,
            |b, leaves| {
                b.iter(|| {
                    black_box(build_merkle_tree(leaves));
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_event_creation,
    bench_payload_hash,
    bench_signing_bytes,
    bench_payload_verification,
    bench_event_signing_hash,
    bench_leaf_hash,
    bench_node_hash,
    bench_merkle_tree,
);
criterion_main!(benches);
