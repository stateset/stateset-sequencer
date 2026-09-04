-- Durable acknowledgement cursors for reconnectable agent subscriptions.

CREATE TABLE IF NOT EXISTS ves_agent_cursors (
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    acknowledged_sequence BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, store_id, agent_id),
    CONSTRAINT chk_ves_agent_cursor_nonnegative CHECK (acknowledged_sequence >= 0)
);

CREATE INDEX IF NOT EXISTS idx_ves_agent_cursors_agent
    ON ves_agent_cursors (agent_id, updated_at DESC);

COMMENT ON TABLE ves_agent_cursors IS
    'Monotonic durable VES acknowledgement cursor per tenant, store, and agent';
