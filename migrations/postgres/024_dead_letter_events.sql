-- Projection failures must remain durable across worker restarts. Earlier
-- deployments created this table only through the optional queue initializer;
-- a fresh migrated database must contain it before any worker starts.
CREATE TABLE IF NOT EXISTS dead_letter_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,
    event_type TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    error_message TEXT NOT NULL,
    retry_count INT NOT NULL DEFAULT 0,
    max_retries INT NOT NULL DEFAULT 10,
    last_retry_at TIMESTAMPTZ,
    next_retry_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    payload JSONB NOT NULL,
    metadata JSONB,
    CONSTRAINT uq_dead_letter_event_id UNIQUE (event_id)
);

CREATE INDEX IF NOT EXISTS idx_dead_letter_tenant_store
    ON dead_letter_events (tenant_id, store_id);
CREATE INDEX IF NOT EXISTS idx_dead_letter_reason
    ON dead_letter_events (reason);
CREATE INDEX IF NOT EXISTS idx_dead_letter_created_at
    ON dead_letter_events (created_at);
CREATE INDEX IF NOT EXISTS idx_dead_letter_next_retry
    ON dead_letter_events (status, next_retry_at)
    WHERE status = 'pending';
