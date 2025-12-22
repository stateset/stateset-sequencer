//! Performance benchmarks for StateSet Sequencer.
//!
//! Run with: cargo bench

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use serde_json::json;
use stateset_sequencer::domain::{AgentId, EntityType, EventBatch, EventEnvelope, EventType, StoreId, TenantId};

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
        group.bench_with_input(BenchmarkId::new("create_batch", count), count, |b, &count| {
            b.iter(|| {
                black_box(create_event_batch(count));
            });
        });
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

criterion_group!(
    benches,
    bench_event_creation,
    bench_payload_hash,
    bench_signing_bytes,
    bench_payload_verification
);
criterion_main!(benches);
