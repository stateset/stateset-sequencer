-- Migration: 009_api_keys.sql
-- Description: API key storage for persistent authentication
-- Supports the PgApiKeyStore implementation

-- ============================================================================
-- API Keys Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS api_keys (
    -- SHA-256 hash of the API key (never store plaintext)
    key_hash TEXT PRIMARY KEY,

    -- Tenant this key belongs to
    tenant_id UUID NOT NULL,

    -- Stores this key can access (empty array = all stores)
    store_ids UUID[] NOT NULL DEFAULT '{}',

    -- Permissions
    can_read BOOLEAN NOT NULL DEFAULT TRUE,
    can_write BOOLEAN NOT NULL DEFAULT FALSE,
    can_admin BOOLEAN NOT NULL DEFAULT FALSE,

    -- Optional agent association
    agent_id UUID,

    -- Key status
    active BOOLEAN NOT NULL DEFAULT TRUE,

    -- Rate limit (requests per minute, NULL = use default)
    rate_limit INTEGER,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT chk_rate_limit_positive CHECK (rate_limit IS NULL OR rate_limit > 0)
);

-- Index for tenant lookups (list keys for tenant)
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant
    ON api_keys (tenant_id, updated_at DESC);

-- Index for active key checks
CREATE INDEX IF NOT EXISTS idx_api_keys_active
    ON api_keys (active) WHERE active = TRUE;

-- Index for agent-specific keys
CREATE INDEX IF NOT EXISTS idx_api_keys_agent
    ON api_keys (agent_id) WHERE agent_id IS NOT NULL;

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON TABLE api_keys IS 'Persistent API key storage with SHA-256 hashed keys';
COMMENT ON COLUMN api_keys.key_hash IS 'SHA-256 hash of the plaintext API key';
COMMENT ON COLUMN api_keys.store_ids IS 'Array of store UUIDs this key can access; empty = all stores';
COMMENT ON COLUMN api_keys.rate_limit IS 'Per-key rate limit in requests/minute; NULL uses system default';
