-- Migration: 007_encryption_groups.sql
-- Description: Add encryption key groups for multi-agent payload encryption
-- VES v1.0 Group Key Management

-- ============================================================================
-- Encryption Key Groups
-- ============================================================================

-- Groups of agents that can decrypt shared encrypted payloads
CREATE TABLE IF NOT EXISTS encryption_key_groups (
    group_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Group settings
    is_active BOOLEAN DEFAULT true,

    -- Creator tracking
    created_by UUID NOT NULL,  -- Agent ID who created the group

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Unique name within tenant
    CONSTRAINT uq_group_name_tenant UNIQUE (tenant_id, name)
);

-- Index for tenant lookups
CREATE INDEX idx_groups_tenant ON encryption_key_groups(tenant_id);
CREATE INDEX idx_groups_active ON encryption_key_groups(tenant_id, is_active) WHERE is_active = true;

-- ============================================================================
-- Group Membership
-- ============================================================================

-- Tracks which agents are members of which groups
CREATE TABLE IF NOT EXISTS encryption_key_group_members (
    group_id UUID NOT NULL REFERENCES encryption_key_groups(group_id) ON DELETE CASCADE,
    agent_id UUID NOT NULL,

    -- Member role
    role VARCHAR(20) NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member')),

    -- Encryption key ID for this member (used for wrapped DEK)
    encryption_key_id INTEGER NOT NULL,

    -- Who added this member
    added_by UUID NOT NULL,

    -- Timestamps
    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (group_id, agent_id)
);

-- Index for finding groups by agent
CREATE INDEX idx_group_members_agent ON encryption_key_group_members(agent_id);

-- ============================================================================
-- Agent Encryption Keys (X25519 public keys for group resolution)
-- ============================================================================

-- Stores X25519 public keys for agents (used for group encryption)
CREATE TABLE IF NOT EXISTS agent_encryption_keys (
    tenant_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    key_id INTEGER NOT NULL,

    -- X25519 public key (32 bytes)
    public_key BYTEA NOT NULL CHECK (length(public_key) = 32),

    -- Key status
    status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired')),

    -- Validity window
    valid_from TIMESTAMPTZ DEFAULT NOW(),
    valid_to TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,

    -- Metadata
    metadata TEXT,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (tenant_id, agent_id, key_id),

    -- Constraints
    CONSTRAINT chk_enc_key_revoked_consistent CHECK (
        (revoked_at IS NULL AND status != 'revoked') OR
        (revoked_at IS NOT NULL AND status = 'revoked')
    ),
    CONSTRAINT chk_enc_key_validity_window CHECK (
        valid_to IS NULL OR valid_from IS NULL OR valid_to > valid_from
    )
);

-- Index for active keys
CREATE INDEX idx_agent_enc_keys_active
    ON agent_encryption_keys(tenant_id, agent_id, status)
    WHERE status = 'active';

-- ============================================================================
-- Group Encryption Audit Log
-- ============================================================================

-- Tracks group key operations for compliance
CREATE TABLE IF NOT EXISTS group_key_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL,

    -- Action performed
    action VARCHAR(50) NOT NULL CHECK (action IN (
        'group_created',
        'group_deleted',
        'group_updated',
        'member_added',
        'member_removed',
        'member_role_changed',
        'member_key_refreshed',
        'encrypted_to_group'
    )),

    -- Actor
    actor_agent_id UUID NOT NULL,

    -- Target (for member actions)
    target_agent_id UUID,

    -- Event reference (for encrypted_to_group)
    event_id UUID,

    -- Additional context
    metadata JSONB,

    -- Timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for audit queries
CREATE INDEX idx_group_audit_group ON group_key_audit_log(group_id, created_at DESC);
CREATE INDEX idx_group_audit_actor ON group_key_audit_log(actor_agent_id, created_at DESC);

-- ============================================================================
-- Views for Group Management
-- ============================================================================

-- View: Groups with member count
CREATE OR REPLACE VIEW v_encryption_groups AS
SELECT
    g.group_id,
    g.tenant_id,
    g.name,
    g.description,
    g.is_active,
    g.created_by,
    g.created_at,
    g.updated_at,
    COUNT(m.agent_id) AS member_count,
    COUNT(m.agent_id) FILTER (WHERE m.role = 'admin') AS admin_count
FROM encryption_key_groups g
LEFT JOIN encryption_key_group_members m ON g.group_id = m.group_id
GROUP BY g.group_id;

-- View: Agent group memberships
CREATE OR REPLACE VIEW v_agent_group_memberships AS
SELECT
    m.agent_id,
    g.tenant_id,
    g.group_id,
    g.name AS group_name,
    m.role,
    m.added_at,
    m.added_by
FROM encryption_key_group_members m
JOIN encryption_key_groups g ON m.group_id = g.group_id
WHERE g.is_active = true;

-- ============================================================================
-- Helper Functions
-- ============================================================================

-- Function to get all recipient keys for a group
CREATE OR REPLACE FUNCTION get_group_recipient_keys(p_group_id UUID)
RETURNS TABLE (
    agent_id UUID,
    key_id INTEGER,
    public_key BYTEA
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        m.agent_id,
        m.encryption_key_id,
        k.public_key
    FROM encryption_key_group_members m
    JOIN encryption_key_groups g ON m.group_id = g.group_id
    JOIN agent_encryption_keys k ON (
        k.agent_id = m.agent_id AND
        k.key_id = m.encryption_key_id AND
        k.tenant_id = g.tenant_id
    )
    WHERE m.group_id = p_group_id
      AND g.is_active = true
      AND k.status = 'active';
END;
$$ LANGUAGE plpgsql STABLE;

-- Function to check if an agent can decrypt from a group
CREATE OR REPLACE FUNCTION can_agent_decrypt_from_group(
    p_group_id UUID,
    p_agent_id UUID
) RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM encryption_key_group_members m
        JOIN encryption_key_groups g ON m.group_id = g.group_id
        WHERE m.group_id = p_group_id
          AND m.agent_id = p_agent_id
          AND g.is_active = true
    );
END;
$$ LANGUAGE plpgsql STABLE;

-- Function to add member to group with audit logging
CREATE OR REPLACE FUNCTION add_group_member(
    p_group_id UUID,
    p_agent_id UUID,
    p_encryption_key_id INTEGER,
    p_added_by UUID,
    p_role VARCHAR DEFAULT 'member'
) RETURNS VOID AS $$
BEGIN
    -- Insert member
    INSERT INTO encryption_key_group_members (
        group_id, agent_id, encryption_key_id, added_by, role
    ) VALUES (
        p_group_id, p_agent_id, p_encryption_key_id, p_added_by, p_role
    );

    -- Update group timestamp
    UPDATE encryption_key_groups
    SET updated_at = NOW()
    WHERE group_id = p_group_id;

    -- Audit log
    INSERT INTO group_key_audit_log (
        group_id, action, actor_agent_id, target_agent_id, metadata
    ) VALUES (
        p_group_id, 'member_added', p_added_by, p_agent_id,
        jsonb_build_object('role', p_role, 'encryption_key_id', p_encryption_key_id)
    );
END;
$$ LANGUAGE plpgsql;

-- Function to remove member from group with audit logging
CREATE OR REPLACE FUNCTION remove_group_member(
    p_group_id UUID,
    p_agent_id UUID,
    p_removed_by UUID
) RETURNS VOID AS $$
DECLARE
    v_old_role VARCHAR;
BEGIN
    -- Get old role for audit
    SELECT role INTO v_old_role
    FROM encryption_key_group_members
    WHERE group_id = p_group_id AND agent_id = p_agent_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Agent is not a member of this group';
    END IF;

    -- Remove member
    DELETE FROM encryption_key_group_members
    WHERE group_id = p_group_id AND agent_id = p_agent_id;

    -- Update group timestamp
    UPDATE encryption_key_groups
    SET updated_at = NOW()
    WHERE group_id = p_group_id;

    -- Audit log
    INSERT INTO group_key_audit_log (
        group_id, action, actor_agent_id, target_agent_id, metadata
    ) VALUES (
        p_group_id, 'member_removed', p_removed_by, p_agent_id,
        jsonb_build_object('previous_role', v_old_role)
    );
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON TABLE encryption_key_groups IS 'Groups of agents that can decrypt shared encrypted payloads';
COMMENT ON TABLE encryption_key_group_members IS 'Membership records for encryption groups';
COMMENT ON TABLE agent_encryption_keys IS 'X25519 public keys for agents, used for group encryption';
COMMENT ON TABLE group_key_audit_log IS 'Audit trail for group key operations';

COMMENT ON FUNCTION get_group_recipient_keys IS 'Get all active recipient keys for a group';
COMMENT ON FUNCTION can_agent_decrypt_from_group IS 'Check if an agent is a member of a group';
COMMENT ON FUNCTION add_group_member IS 'Add a member to a group with audit logging';
COMMENT ON FUNCTION remove_group_member IS 'Remove a member from a group with audit logging';
