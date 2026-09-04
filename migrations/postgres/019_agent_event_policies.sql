-- Server-enforced capabilities for autonomous agents.

CREATE TABLE IF NOT EXISTS agent_event_policies (
    tenant_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    allowed_event_types TEXT[] NOT NULL DEFAULT '{}',
    allowed_entity_types TEXT[] NOT NULL DEFAULT '{}',
    require_base_version BOOLEAN NOT NULL DEFAULT TRUE,
    max_payload_bytes INTEGER,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, agent_id),
    CONSTRAINT chk_agent_policy_event_count
        CHECK (cardinality(allowed_event_types) <= 128),
    CONSTRAINT chk_agent_policy_entity_count
        CHECK (cardinality(allowed_entity_types) <= 128),
    CONSTRAINT chk_agent_policy_payload_size
        CHECK (max_payload_bytes IS NULL OR max_payload_bytes > 0)
);

CREATE INDEX IF NOT EXISTS idx_agent_event_policies_enabled
    ON agent_event_policies (tenant_id, agent_id)
    WHERE enabled = TRUE;

COMMENT ON TABLE agent_event_policies IS
    'Server-enforced event and entity capabilities for autonomous agents';
