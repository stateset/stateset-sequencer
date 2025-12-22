-- StateSet Sequencer: Production PostgreSQL Schema
-- Version: 0.3.0
-- Purpose: Server-side event store, projections, and commitments
--
-- Key characteristics:
-- - Sequencer owns ordering (sequence_number assigned server-side)
-- - No merkle_proofs table (proofs generated on demand)
-- - Append-only event log (immutable)
-- - Tenant/store isolation

-- ============================================================================
-- EVENT STORAGE (Append-Only)
-- ============================================================================

-- Main event storage table
-- Events are encrypted at rest, with only hashes available for verification
CREATE TABLE IF NOT EXISTS events (
    -- Globally unique event identifier (idempotency key)
    event_id UUID PRIMARY KEY,

    -- Optional idempotency key for "intent" (e.g. CLI command)
    command_id UUID,

    -- Canonical sequence number (assigned by sequencer, monotonic per tenant/store)
    sequence_number BIGINT NOT NULL,

    -- Tenant/store isolation
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,

    -- Entity classification
    entity_type VARCHAR(64) NOT NULL,
    entity_id VARCHAR(256) NOT NULL,
    event_type VARCHAR(64) NOT NULL,

    -- Encrypted payload (AES-256-GCM, per-tenant keys)
    payload_encrypted BYTEA NOT NULL,

    -- SHA-256 hash of canonical JSON payload (for Merkle leaves / ZK inputs)
    payload_hash BYTEA NOT NULL,

    -- Optimistic concurrency control (entity version at authoring time)
    base_version BIGINT,

    -- Source agent identifier
    source_agent UUID NOT NULL,

    -- Optional signature over envelope fields (Phase 1+)
    signature BYTEA,

    -- Client-side timestamp (metadata only; NOT used for ordering)
    created_at TIMESTAMPTZ NOT NULL,

    -- Server-side timestamp when sequence was assigned
    sequenced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Ensure sequence numbers are unique within tenant/store
    CONSTRAINT uq_events_sequence UNIQUE (tenant_id, store_id, sequence_number)
);

-- Primary query path: events by tenant/store/sequence
CREATE INDEX IF NOT EXISTS idx_events_tenant_store_seq
    ON events (tenant_id, store_id, sequence_number);

-- Entity event history
CREATE INDEX IF NOT EXISTS idx_events_entity
    ON events (tenant_id, store_id, entity_type, entity_id, sequence_number);

-- Command deduplication
CREATE INDEX IF NOT EXISTS idx_events_command
    ON events (command_id) WHERE command_id IS NOT NULL;

-- Event type filtering
CREATE INDEX IF NOT EXISTS idx_events_type
    ON events (tenant_id, store_id, event_type, sequence_number);


-- ============================================================================
-- PROJECTION STATE
-- ============================================================================

-- Projection checkpoint per tenant/store
-- Tracks how far the projector has processed
CREATE TABLE IF NOT EXISTS projection_checkpoints (
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,

    -- Last sequence number successfully projected
    last_projected_sequence BIGINT NOT NULL DEFAULT 0,

    -- Timestamp of last projection
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (tenant_id, store_id)
);


-- Entity versions for optimistic concurrency at apply-time
-- Updated by the projector when events are applied
CREATE TABLE IF NOT EXISTS entity_versions (
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,
    entity_type VARCHAR(64) NOT NULL,
    entity_id VARCHAR(256) NOT NULL,

    -- Current version (incremented on each successful projection)
    version BIGINT NOT NULL DEFAULT 0,

    -- Last update timestamp
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (tenant_id, store_id, entity_type, entity_id)
);

-- Quick version lookups
CREATE INDEX IF NOT EXISTS idx_entity_versions_lookup
    ON entity_versions (tenant_id, store_id, entity_type, entity_id);


-- ============================================================================
-- BATCH COMMITMENTS
-- ============================================================================

-- Batch commitments (roots only, no per-event proofs)
-- Proofs are generated on-demand from event hashes
CREATE TABLE IF NOT EXISTS commitments (
    -- Unique batch identifier
    batch_id UUID PRIMARY KEY,

    -- Tenant/store this batch belongs to
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,

    -- State root before applying this batch
    prev_state_root BYTEA NOT NULL,

    -- State root after applying this batch
    new_state_root BYTEA NOT NULL,

    -- Merkle root of events in this batch
    events_root BYTEA NOT NULL,

    -- Sequence range (inclusive)
    sequence_start BIGINT NOT NULL,
    sequence_end BIGINT NOT NULL,

    -- Number of events in this batch
    event_count INT NOT NULL,

    -- When this commitment was created
    committed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- On-chain transaction hash (Phase 1+)
    chain_tx_hash BYTEA,

    -- Constraint: sequence range must be valid
    CONSTRAINT chk_sequence_range CHECK (sequence_end >= sequence_start)
);

-- Find commitments by tenant/store and sequence range
CREATE INDEX IF NOT EXISTS idx_commitments_tenant_store_range
    ON commitments (tenant_id, store_id, sequence_start, sequence_end);

-- Find commitments by chain status
CREATE INDEX IF NOT EXISTS idx_commitments_anchored
    ON commitments (chain_tx_hash) WHERE chain_tx_hash IS NOT NULL;


-- ============================================================================
-- SYNC STATE (Agent Tracking)
-- ============================================================================

-- Track sync state per agent
CREATE TABLE IF NOT EXISTS agent_sync_state (
    -- Agent identifier
    agent_id UUID PRIMARY KEY,

    -- Tenant/store this agent operates on
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,

    -- Last sequence number pushed by this agent
    last_pushed_sequence BIGINT NOT NULL DEFAULT 0,

    -- Last sequence number pulled by this agent
    last_pulled_sequence BIGINT NOT NULL DEFAULT 0,

    -- Last sync timestamp
    last_sync_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Agent metadata (optional)
    metadata JSONB
);

-- Find agents by tenant/store
CREATE INDEX IF NOT EXISTS idx_agent_sync_tenant
    ON agent_sync_state (tenant_id, store_id);


-- ============================================================================
-- SEQUENCE COUNTERS
-- ============================================================================

-- Sequence counters per tenant/store
-- Used by sequencer to assign monotonic sequence numbers
CREATE TABLE IF NOT EXISTS sequence_counters (
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,

    -- Current head sequence (next event gets current_sequence + 1)
    current_sequence BIGINT NOT NULL DEFAULT 0,

    -- Last update timestamp
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (tenant_id, store_id)
);


-- ============================================================================
-- REJECTED EVENTS LOG
-- ============================================================================

-- Log of events that failed projection (for audit/debugging)
-- These correspond to system events emitted (event.rejected, operation.failed)
CREATE TABLE IF NOT EXISTS rejected_events_log (
    id BIGSERIAL PRIMARY KEY,

    -- Original event info
    event_id UUID NOT NULL,
    sequence_number BIGINT NOT NULL,
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,

    -- Entity info
    entity_type VARCHAR(64) NOT NULL,
    entity_id VARCHAR(256) NOT NULL,

    -- Rejection reason
    reason VARCHAR(64) NOT NULL,
    message TEXT,

    -- Version conflict details (if applicable)
    expected_version BIGINT,
    actual_version BIGINT,

    -- Rejection timestamp
    rejected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Reference to rejection event in main log
    rejection_event_id UUID
);

-- Find rejections by entity
CREATE INDEX IF NOT EXISTS idx_rejected_events_entity
    ON rejected_events_log (tenant_id, store_id, entity_type, entity_id);

-- Find rejections by time
CREATE INDEX IF NOT EXISTS idx_rejected_events_time
    ON rejected_events_log (tenant_id, store_id, rejected_at);


-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

-- Function to get next sequence number atomically
CREATE OR REPLACE FUNCTION get_next_sequence(
    p_tenant_id UUID,
    p_store_id UUID
) RETURNS BIGINT AS $$
DECLARE
    v_sequence BIGINT;
BEGIN
    INSERT INTO sequence_counters (tenant_id, store_id, current_sequence, updated_at)
    VALUES (p_tenant_id, p_store_id, 1, NOW())
    ON CONFLICT (tenant_id, store_id)
    DO UPDATE SET
        current_sequence = sequence_counters.current_sequence + 1,
        updated_at = NOW()
    RETURNING current_sequence INTO v_sequence;

    RETURN v_sequence;
END;
$$ LANGUAGE plpgsql;


-- Function to get current head sequence
CREATE OR REPLACE FUNCTION get_head_sequence(
    p_tenant_id UUID,
    p_store_id UUID
) RETURNS BIGINT AS $$
DECLARE
    v_sequence BIGINT;
BEGIN
    SELECT current_sequence INTO v_sequence
    FROM sequence_counters
    WHERE tenant_id = p_tenant_id AND store_id = p_store_id;

    RETURN COALESCE(v_sequence, 0);
END;
$$ LANGUAGE plpgsql;


-- Function to update entity version atomically
CREATE OR REPLACE FUNCTION update_entity_version(
    p_tenant_id UUID,
    p_store_id UUID,
    p_entity_type VARCHAR(64),
    p_entity_id VARCHAR(256),
    p_expected_version BIGINT
) RETURNS BIGINT AS $$
DECLARE
    v_current_version BIGINT;
    v_new_version BIGINT;
BEGIN
    -- Get current version with lock
    SELECT version INTO v_current_version
    FROM entity_versions
    WHERE tenant_id = p_tenant_id
      AND store_id = p_store_id
      AND entity_type = p_entity_type
      AND entity_id = p_entity_id
    FOR UPDATE;

    -- Check expected version (if provided and entity exists)
    IF v_current_version IS NOT NULL AND p_expected_version IS NOT NULL THEN
        IF v_current_version != p_expected_version THEN
            -- Return negative to indicate conflict
            RETURN -v_current_version;
        END IF;
    END IF;

    -- Upsert new version
    v_new_version := COALESCE(v_current_version, 0) + 1;

    INSERT INTO entity_versions (tenant_id, store_id, entity_type, entity_id, version, updated_at)
    VALUES (p_tenant_id, p_store_id, p_entity_type, p_entity_id, v_new_version, NOW())
    ON CONFLICT (tenant_id, store_id, entity_type, entity_id)
    DO UPDATE SET
        version = v_new_version,
        updated_at = NOW();

    RETURN v_new_version;
END;
$$ LANGUAGE plpgsql;
