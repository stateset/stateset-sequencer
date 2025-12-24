# ADR-003: Trait-Based Service Abstraction

## Status

Accepted

## Context

The sequencer needs to support:
1. Multiple storage backends (PostgreSQL for production, SQLite for local agents)
2. Unit testing with mock implementations
3. Future extensibility (e.g., different commitment engines)
4. Clear separation between domain logic and infrastructure

### Requirements

- Services should be testable in isolation
- Implementations should be swappable at runtime
- Domain types should not depend on infrastructure details
- Async operations throughout (Tokio runtime)

## Decision

Use **Rust traits with `async_trait`** to define service interfaces.

### Core Traits

```rust
// src/infra/traits.rs

#[async_trait]
pub trait Sequencer: Send + Sync {
    async fn assign_sequence(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
        count: u32,
    ) -> Result<u64>;

    async fn head(
        &self,
        tenant_id: &TenantId,
        store_id: &StoreId,
    ) -> Result<u64>;
}

#[async_trait]
pub trait EventStore: Send + Sync {
    async fn store(&self, events: Vec<SequencedEvent>) -> Result<()>;
    async fn get(&self, event_id: Uuid) -> Result<Option<SequencedEvent>>;
    async fn list(&self, tenant_id: &TenantId, store_id: &StoreId, range: Range<u64>) -> Result<Vec<SequencedEvent>>;
}

#[async_trait]
pub trait CommitmentEngine: Send + Sync {
    fn compute_events_root(&self, leaves: &[Hash256]) -> Hash256;
    async fn create_commitment(&self, tenant_id: &TenantId, store_id: &StoreId, range: (u64, u64)) -> Result<BatchCommitment>;
    fn prove_inclusion(&self, leaf_index: usize, leaves: &[Hash256]) -> MerkleProof;
}
```

### Implementation Pattern

```rust
// Production implementation
pub struct PgSequencer {
    pool: PgPool,
}

#[async_trait]
impl Sequencer for PgSequencer {
    async fn assign_sequence(...) -> Result<u64> {
        // PostgreSQL implementation with FOR UPDATE
    }
}

// Mock for testing
#[cfg(test)]
mockall::mock! {
    pub Sequencer {}

    #[async_trait]
    impl Sequencer for Sequencer {
        async fn assign_sequence(...) -> Result<u64>;
        async fn head(...) -> Result<u64>;
    }
}
```

### Dependency Injection

Services are injected via `AppState`:

```rust
pub struct AppState {
    pub sequencer: Arc<dyn Sequencer>,
    pub event_store: Arc<dyn EventStore>,
    pub commitment_engine: Arc<dyn CommitmentEngine>,
}
```

## Consequences

### Positive

- **Testability** - Mock implementations for unit tests
- **Flexibility** - Swap implementations without changing consumers
- **Clear contracts** - Traits document expected behavior
- **Compile-time checking** - Rust ensures implementations match traits

### Negative

- Dynamic dispatch overhead (minimal with `Arc<dyn Trait>`)
- `async_trait` macro adds some complexity
- Must maintain trait + implementation in sync

### Trade-offs

We chose dynamic dispatch (`Arc<dyn Trait>`) over generics because:
1. Simpler `AppState` type (no generic parameters)
2. Easier to construct at runtime based on configuration
3. Performance overhead is negligible for our use case

## References

- [Rust Async Trait](https://docs.rs/async-trait/latest/async_trait/)
- [Mockall Documentation](https://docs.rs/mockall/latest/mockall/)
- [Dependency Injection in Rust](https://willcrichton.net/notes/rust-dependency-injection/)
