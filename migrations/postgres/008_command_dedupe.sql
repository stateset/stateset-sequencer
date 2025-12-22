-- StateSet Sequencer: Command deduplication tables
-- Version: 0.5.0
-- Purpose: Atomic command_id idempotency across concurrent ingests.

-- Legacy events command dedupe
CREATE TABLE IF NOT EXISTS event_command_dedupe (
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,
    command_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, store_id, command_id)
);

-- Backfill existing command_ids from events
INSERT INTO event_command_dedupe (tenant_id, store_id, command_id)
SELECT tenant_id, store_id, command_id
FROM events
WHERE command_id IS NOT NULL
ON CONFLICT DO NOTHING;

-- VES events command dedupe
CREATE TABLE IF NOT EXISTS ves_command_dedupe (
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,
    command_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, store_id, command_id)
);

-- Backfill existing command_ids from VES events
INSERT INTO ves_command_dedupe (tenant_id, store_id, command_id)
SELECT tenant_id, store_id, command_id
FROM ves_events
WHERE command_id IS NOT NULL
ON CONFLICT DO NOTHING;
