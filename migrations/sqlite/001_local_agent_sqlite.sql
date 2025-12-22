-- StateSet Sequencer: Local Agent SQLite Schema
-- Version: 0.1.0
-- Purpose: Outbox pattern for CLI agents and local sync state tracking
--
-- This schema is used by embedded StateSet engines (CLI agents, local services)
-- to capture events locally before pushing to the remote sequencer.

-- Local outbox for pending events
-- Events are appended here during local mutations, then pushed to sequencer
CREATE TABLE IF NOT EXISTS outbox (
    -- Auto-incrementing local ID (for ordering within local session)
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Globally unique event identifier (idempotency at event level)
    event_id TEXT UNIQUE NOT NULL,

    -- Optional idempotency key for "intent" (e.g. CLI command)
    -- Multiple events from one command share the same command_id
    command_id TEXT,

    -- Tenant/store isolation
    tenant_id TEXT NOT NULL,
    store_id TEXT NOT NULL,

    -- Entity classification
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    event_type TEXT NOT NULL,

    -- Serialized JSON payload (cleartext locally, encrypted at remote)
    payload TEXT NOT NULL,

    -- SHA-256 hash of canonical JSON payload
    payload_hash TEXT NOT NULL,

    -- Optimistic concurrency control (entity version at authoring time)
    base_version INTEGER,

    -- Client-side timestamp (metadata only; NOT used for ordering)
    created_at TEXT NOT NULL DEFAULT (datetime('now')),

    -- Source agent identifier
    source_agent TEXT NOT NULL,

    -- Optional signature over envelope fields (Phase 1+)
    signature BLOB,

    -- Sync state: when this event was pushed to remote
    pushed_at TEXT,

    -- Sync state: when remote acknowledged this event
    acked_at TEXT,

    -- Assigned sequence number from remote (populated after ack)
    remote_sequence INTEGER,

    -- Validate payload is valid JSON
    CHECK(json_valid(payload))
);

-- Index for finding unpushed events
CREATE INDEX IF NOT EXISTS idx_outbox_unpushed
    ON outbox (pushed_at) WHERE pushed_at IS NULL;

-- Index for finding unacked events
CREATE INDEX IF NOT EXISTS idx_outbox_unacked
    ON outbox (acked_at) WHERE acked_at IS NULL AND pushed_at IS NOT NULL;

-- Index for entity event history
CREATE INDEX IF NOT EXISTS idx_outbox_entity
    ON outbox (tenant_id, store_id, entity_type, entity_id, created_at);

-- Index for command deduplication
CREATE INDEX IF NOT EXISTS idx_outbox_command
    ON outbox (command_id) WHERE command_id IS NOT NULL;


-- Local sync state tracking
-- Stores key-value pairs for sync position and agent configuration
CREATE TABLE IF NOT EXISTS sync_state (
    -- Key name (e.g., 'last_pushed_sequence', 'agent_id')
    key TEXT PRIMARY KEY,

    -- Value (JSON or string)
    value TEXT NOT NULL,

    -- Last update timestamp
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Expected keys in sync_state:
-- 'agent_id'              - This agent's unique identifier (UUID)
-- 'tenant_id'             - Tenant this agent belongs to (UUID)
-- 'store_id'              - Store this agent operates on (UUID)
-- 'last_pushed_sequence'  - Last sequence number pushed to remote
-- 'last_pulled_sequence'  - Last sequence number pulled from remote
-- 'head_sequence'         - Known head from last pull
-- 'last_sync_at'          - Timestamp of last successful sync


-- Local entity version cache (for optimistic concurrency)
-- Updated when events are applied locally or pulled from remote
CREATE TABLE IF NOT EXISTS entity_versions (
    -- Composite key
    tenant_id TEXT NOT NULL,
    store_id TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,

    -- Current version (incremented on each mutation)
    version INTEGER NOT NULL DEFAULT 0,

    -- Last update timestamp
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),

    PRIMARY KEY (tenant_id, store_id, entity_type, entity_id)
);

-- Index for quick lookups
CREATE INDEX IF NOT EXISTS idx_entity_versions_lookup
    ON entity_versions (tenant_id, store_id, entity_type, entity_id);


-- Pulled events cache (events received from remote)
-- Used for local replay and rebase operations
CREATE TABLE IF NOT EXISTS pulled_events (
    -- Remote sequence number (canonical ordering)
    sequence_number INTEGER PRIMARY KEY,

    -- Event identifier
    event_id TEXT UNIQUE NOT NULL,

    -- Command identifier
    command_id TEXT,

    -- Tenant/store
    tenant_id TEXT NOT NULL,
    store_id TEXT NOT NULL,

    -- Entity info
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    event_type TEXT NOT NULL,

    -- Payload
    payload TEXT NOT NULL,
    payload_hash TEXT NOT NULL,

    -- Version info
    base_version INTEGER,

    -- Timestamps
    created_at TEXT NOT NULL,
    sequenced_at TEXT NOT NULL,
    pulled_at TEXT NOT NULL DEFAULT (datetime('now')),

    -- Source agent
    source_agent TEXT NOT NULL,

    CHECK(json_valid(payload))
);

-- Index for entity history
CREATE INDEX IF NOT EXISTS idx_pulled_events_entity
    ON pulled_events (tenant_id, store_id, entity_type, entity_id, sequence_number);


-- Initialize default sync state
INSERT OR IGNORE INTO sync_state (key, value, updated_at) VALUES
    ('last_pushed_sequence', '0', datetime('now')),
    ('last_pulled_sequence', '0', datetime('now')),
    ('head_sequence', '0', datetime('now'));
