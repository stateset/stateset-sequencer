# ADR-001: Use PostgreSQL for Event Ordering

## Status

Accepted

## Context

The StateSet Sequencer requires deterministic, gap-free event ordering across multiple concurrent writers. We needed to choose a storage backend that could provide:

1. **Linearizable ordering** - Events must be assigned sequence numbers in a total order
2. **Gap-free sequences** - No missing sequence numbers allowed
3. **Durability** - Events must not be lost after acknowledgment
4. **Concurrent access** - Multiple agents can write simultaneously
5. **ACID transactions** - For atomic batch operations

### Options Considered

1. **PostgreSQL with `SELECT FOR UPDATE`**
   - Pros: Mature, ACID compliant, row-level locking, excellent tooling
   - Cons: Not designed for high-throughput append-only workloads

2. **Apache Kafka**
   - Pros: High throughput, built-in partitioning, replay capability
   - Cons: Eventual consistency, partition ordering only, complex setup

3. **Redis Streams**
   - Pros: Very fast, simple API, built-in ID generation
   - Cons: Persistence concerns, memory constraints, less mature

4. **Custom append-only log**
   - Pros: Full control, optimized for our use case
   - Cons: Significant engineering effort, maintenance burden

## Decision

We chose **PostgreSQL with `SELECT FOR UPDATE`** for sequence assignment.

### Implementation

```sql
-- Sequence counter per tenant/store stream
SELECT current_sequence FROM sequence_counters
WHERE tenant_id = $1 AND store_id = $2
FOR UPDATE;

-- Atomically increment and assign
UPDATE sequence_counters
SET current_sequence = current_sequence + $batch_size
WHERE tenant_id = $1 AND store_id = $2
RETURNING current_sequence;
```

This provides:
- **Serializable ordering** via row-level exclusive locks
- **Gap-free sequences** as assignment and storage are atomic
- **Per-stream independence** - different tenant/store pairs don't contend
- **Familiar operations** - standard SQL, easy debugging

## Consequences

### Positive

- Proven technology with excellent documentation
- Easy to backup, restore, and replicate
- Strong consistency guarantees
- Rich query capabilities for event history
- Excellent monitoring and profiling tools

### Negative

- Throughput limited by lock contention on hot streams
- Not optimized for append-only workloads
- Connection pool management required
- May need read replicas for high query loads

### Mitigations

- Use batch event insertion to reduce lock acquisitions
- Implement caching for commitment and proof queries
- Consider partitioning for very high-volume tenants
- Monitor lock wait times and optimize queries

## References

- [PostgreSQL Row-Level Locking](https://www.postgresql.org/docs/current/explicit-locking.html)
- [VES v1.0 Specification - Ordering Requirements](../VES_SPEC.md)
