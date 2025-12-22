-- Migration: 006_key_rotation_policies.sql
-- Description: Add key rotation policies and tracking tables
-- VES v1.0 Key Lifecycle Management

-- ============================================================================
-- Key Rotation Policies
-- ============================================================================

-- Policies for automatic key rotation per tenant/agent
CREATE TABLE IF NOT EXISTS key_rotation_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    agent_id UUID,  -- NULL = tenant-wide default policy
    key_type VARCHAR(20) NOT NULL CHECK (key_type IN ('signing', 'encryption')),

    -- Time-based rotation
    max_age_hours INTEGER CHECK (max_age_hours IS NULL OR max_age_hours > 0),

    -- Usage-based rotation
    max_usage_count BIGINT CHECK (max_usage_count IS NULL OR max_usage_count > 0),

    -- Warning settings
    warning_threshold_hours INTEGER DEFAULT 24 CHECK (warning_threshold_hours >= 0),

    -- Grace period for old keys after rotation
    grace_period_hours INTEGER DEFAULT 72 CHECK (grace_period_hours >= 0),

    -- Enforcement
    enforce_expiry BOOLEAN DEFAULT true,
    auto_rotate BOOLEAN DEFAULT false,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Unique policy per tenant/agent/key_type
    CONSTRAINT uq_rotation_policy UNIQUE (tenant_id, agent_id, key_type)
);

-- Index for policy lookups
CREATE INDEX idx_rotation_policies_tenant ON key_rotation_policies(tenant_id);
CREATE INDEX idx_rotation_policies_agent ON key_rotation_policies(tenant_id, agent_id) WHERE agent_id IS NOT NULL;

-- ============================================================================
-- Key Usage Tracking
-- ============================================================================

-- Track usage for usage-based rotation policies
CREATE TABLE IF NOT EXISTS key_usage_counters (
    tenant_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    key_id INTEGER NOT NULL,
    key_type VARCHAR(20) NOT NULL CHECK (key_type IN ('signing', 'encryption')),

    -- Usage statistics
    usage_count BIGINT NOT NULL DEFAULT 0,
    last_used_at TIMESTAMPTZ,

    -- First use tracking
    first_used_at TIMESTAMPTZ,

    PRIMARY KEY (tenant_id, agent_id, key_id, key_type)
);

-- Index for efficient lookups
CREATE INDEX idx_key_usage_agent ON key_usage_counters(tenant_id, agent_id);

-- ============================================================================
-- Scheduled Key Rotations
-- ============================================================================

-- Track scheduled and completed key rotations
CREATE TABLE IF NOT EXISTS scheduled_key_rotations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    key_type VARCHAR(20) NOT NULL CHECK (key_type IN ('signing', 'encryption')),

    -- Current key being rotated
    current_key_id INTEGER NOT NULL,

    -- Schedule
    scheduled_at TIMESTAMPTZ NOT NULL,

    -- Reason for rotation
    reason VARCHAR(50) NOT NULL CHECK (reason IN (
        'age_limit',      -- Key exceeded max age
        'usage_limit',    -- Key exceeded max usage
        'manual',         -- Manual rotation request
        'expiry',         -- Key approaching expiry
        'compromise',     -- Key may be compromised
        'policy_change'   -- Policy requirements changed
    )),

    -- Status tracking
    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN (
        'pending',
        'in_progress',
        'completed',
        'failed',
        'cancelled'
    )),

    -- Result tracking
    completed_at TIMESTAMPTZ,
    new_key_id INTEGER,
    error_message TEXT,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT chk_completed_has_new_key CHECK (
        status != 'completed' OR new_key_id IS NOT NULL
    ),
    CONSTRAINT chk_failed_has_error CHECK (
        status != 'failed' OR error_message IS NOT NULL
    )
);

-- Index for pending rotations
CREATE INDEX idx_scheduled_rotations_pending
    ON scheduled_key_rotations(scheduled_at)
    WHERE status = 'pending';

-- Index for agent lookups
CREATE INDEX idx_scheduled_rotations_agent
    ON scheduled_key_rotations(tenant_id, agent_id);

-- ============================================================================
-- Extend agent_signing_keys with expiry fields
-- ============================================================================

-- Add expiry and grace period columns if not exist
DO $$
BEGIN
    -- Add expires_at column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'agent_signing_keys' AND column_name = 'expires_at'
    ) THEN
        ALTER TABLE agent_signing_keys ADD COLUMN expires_at TIMESTAMPTZ;
    END IF;

    -- Add grace_until column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'agent_signing_keys' AND column_name = 'grace_until'
    ) THEN
        ALTER TABLE agent_signing_keys ADD COLUMN grace_until TIMESTAMPTZ;
    END IF;

    -- Add rotation_reason column
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'agent_signing_keys' AND column_name = 'rotation_reason'
    ) THEN
        ALTER TABLE agent_signing_keys ADD COLUMN rotation_reason VARCHAR(50);
    END IF;
END $$;

-- Constraint: grace_until must be after expires_at
ALTER TABLE agent_signing_keys
    DROP CONSTRAINT IF EXISTS chk_grace_after_expiry;
ALTER TABLE agent_signing_keys
    ADD CONSTRAINT chk_grace_after_expiry
    CHECK (grace_until IS NULL OR expires_at IS NULL OR grace_until >= expires_at);

-- Index for expiring keys
CREATE INDEX IF NOT EXISTS idx_agent_keys_expiring
    ON agent_signing_keys(expires_at)
    WHERE expires_at IS NOT NULL AND status = 'active';

-- ============================================================================
-- Key Rotation Audit Log
-- ============================================================================

CREATE TABLE IF NOT EXISTS key_rotation_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    key_type VARCHAR(20) NOT NULL,

    -- Action details
    action VARCHAR(50) NOT NULL CHECK (action IN (
        'key_generated',
        'key_registered',
        'key_rotated',
        'key_revoked',
        'key_expired',
        'grace_period_started',
        'grace_period_ended',
        'policy_updated'
    )),

    -- Key IDs involved
    old_key_id INTEGER,
    new_key_id INTEGER,

    -- Actor information
    actor_type VARCHAR(20) NOT NULL CHECK (actor_type IN (
        'system',      -- Automatic rotation
        'agent',       -- Agent-initiated
        'admin',       -- Admin-initiated
        'api'          -- API-initiated
    )),
    actor_id UUID,  -- Agent ID or admin ID

    -- Additional context
    metadata JSONB,

    -- Timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for audit queries
CREATE INDEX idx_key_rotation_audit_tenant ON key_rotation_audit_log(tenant_id, created_at DESC);
CREATE INDEX idx_key_rotation_audit_agent ON key_rotation_audit_log(tenant_id, agent_id, created_at DESC);

-- ============================================================================
-- Helper Functions
-- ============================================================================

-- Function to check if a key is within grace period
CREATE OR REPLACE FUNCTION is_key_in_grace_period(
    p_expires_at TIMESTAMPTZ,
    p_grace_until TIMESTAMPTZ,
    p_check_time TIMESTAMPTZ DEFAULT NOW()
) RETURNS BOOLEAN AS $$
BEGIN
    IF p_expires_at IS NULL OR p_grace_until IS NULL THEN
        RETURN FALSE;
    END IF;

    RETURN p_check_time >= p_expires_at AND p_check_time < p_grace_until;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function to get effective key status considering grace period
CREATE OR REPLACE FUNCTION get_key_effective_status(
    p_status VARCHAR,
    p_expires_at TIMESTAMPTZ,
    p_grace_until TIMESTAMPTZ,
    p_revoked_at TIMESTAMPTZ,
    p_check_time TIMESTAMPTZ DEFAULT NOW()
) RETURNS VARCHAR AS $$
BEGIN
    -- Explicitly revoked
    IF p_revoked_at IS NOT NULL THEN
        RETURN 'revoked';
    END IF;

    -- Check expiry
    IF p_expires_at IS NOT NULL THEN
        IF p_check_time >= p_expires_at THEN
            -- Past expiry - check grace period
            IF p_grace_until IS NOT NULL AND p_check_time < p_grace_until THEN
                RETURN 'grace_period';
            END IF;
            RETURN 'expired';
        END IF;
    END IF;

    -- Return stored status
    RETURN COALESCE(p_status, 'active');
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function to increment usage counter
CREATE OR REPLACE FUNCTION increment_key_usage(
    p_tenant_id UUID,
    p_agent_id UUID,
    p_key_id INTEGER,
    p_key_type VARCHAR
) RETURNS BIGINT AS $$
DECLARE
    v_count BIGINT;
BEGIN
    INSERT INTO key_usage_counters (tenant_id, agent_id, key_id, key_type, usage_count, last_used_at, first_used_at)
    VALUES (p_tenant_id, p_agent_id, p_key_id, p_key_type, 1, NOW(), NOW())
    ON CONFLICT (tenant_id, agent_id, key_id, key_type)
    DO UPDATE SET
        usage_count = key_usage_counters.usage_count + 1,
        last_used_at = NOW()
    RETURNING usage_count INTO v_count;

    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON TABLE key_rotation_policies IS 'Defines automatic key rotation policies per tenant/agent';
COMMENT ON TABLE key_usage_counters IS 'Tracks key usage for usage-based rotation policies';
COMMENT ON TABLE scheduled_key_rotations IS 'Tracks scheduled and completed key rotations';
COMMENT ON TABLE key_rotation_audit_log IS 'Audit trail for all key lifecycle events';

COMMENT ON FUNCTION is_key_in_grace_period IS 'Check if a key is currently in its grace period after expiry';
COMMENT ON FUNCTION get_key_effective_status IS 'Get the effective status of a key considering expiry and grace period';
COMMENT ON FUNCTION increment_key_usage IS 'Atomically increment the usage counter for a key';
