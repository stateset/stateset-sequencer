-- StateSet Sequencer: VES v1.0 Schema Extensions
-- Version: 1.0.0
-- Purpose: Agent key management and VES-compliant event storage
--
-- Key characteristics:
-- - Agent key registry with key rotation support
-- - VES v1.0 compliant event envelopes
-- - Encrypted payload storage with AAD binding
-- - Full signature and hash validation support

-- ============================================================================
-- AGENT SIGNING KEYS
-- ============================================================================

-- Agent Ed25519 public key registry
-- Supports key rotation, validity windows, and revocation
CREATE TABLE IF NOT EXISTS agent_signing_keys (
    -- Key identity (composite key)
    tenant_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    key_id INTEGER NOT NULL,

    -- Ed25519 public key (32 bytes)
    public_key BYTEA NOT NULL CHECK (length(public_key) = 32),

    -- Key lifecycle status
    status VARCHAR(16) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired')),

    -- Validity window (optional)
    valid_from TIMESTAMPTZ,
    valid_to TIMESTAMPTZ,

    -- Revocation timestamp (set when status becomes 'revoked')
    revoked_at TIMESTAMPTZ,

    -- Optional metadata (e.g., device info, purpose)
    metadata TEXT,

    -- Audit timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (tenant_id, agent_id, key_id),

    -- Ensure revoked_at is only set for revoked keys
    CONSTRAINT chk_revoked_consistent CHECK (
        (status = 'revoked' AND revoked_at IS NOT NULL) OR
        (status != 'revoked' AND revoked_at IS NULL)
    ),

    -- Ensure validity window is consistent
    CONSTRAINT chk_validity_window CHECK (
        valid_from IS NULL OR valid_to IS NULL OR valid_from <= valid_to
    )
);

-- Index for tenant/agent key lookups
CREATE INDEX IF NOT EXISTS idx_agent_keys_tenant_agent
    ON agent_signing_keys (tenant_id, agent_id);

-- Index for finding active keys
CREATE INDEX IF NOT EXISTS idx_agent_keys_active
    ON agent_signing_keys (tenant_id, agent_id, status)
    WHERE status = 'active';


-- ============================================================================
-- VES v1.0 EVENT STORAGE
-- ============================================================================

-- VES v1.0 compliant event envelopes
-- Supports both plaintext and encrypted payloads per VES-ENC-1
CREATE TABLE IF NOT EXISTS ves_events (
    -- Globally unique event identifier (idempotency key)
    event_id UUID PRIMARY KEY,

    -- Optional command idempotency key
    command_id UUID,

    -- VES protocol version (currently 1)
    ves_version INTEGER NOT NULL DEFAULT 1 CHECK (ves_version >= 1),

    -- Tenant/store isolation
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,

    -- Source agent and key used to sign
    source_agent_id UUID NOT NULL,
    agent_key_id INTEGER NOT NULL,

    -- Entity classification
    entity_type VARCHAR(64) NOT NULL,
    entity_id VARCHAR(256) NOT NULL,
    event_type VARCHAR(64) NOT NULL,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL,
    -- Raw, signed created_at string (RFC 3339) to preserve exact signature preimage
    created_at_str TEXT NOT NULL,
    sequenced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Payload (VES v1.0 Section 5)
    -- payload_kind: 0 = plaintext, 1 = encrypted
    payload_kind INTEGER NOT NULL DEFAULT 0 CHECK (payload_kind IN (0, 1)),

    -- Plaintext payload (when payload_kind = 0)
    payload JSONB,

    -- Encrypted payload structure (when payload_kind = 1)
    -- Follows VES-ENC-1 spec
    payload_encrypted JSONB,

    -- VES v1.0 hashes (32 bytes each)
    payload_plain_hash BYTEA NOT NULL CHECK (length(payload_plain_hash) = 32),
    payload_cipher_hash BYTEA NOT NULL CHECK (length(payload_cipher_hash) = 32),
    -- Event signing hash (32 bytes), used for Merkle leaves and receipts
    event_signing_hash BYTEA NOT NULL CHECK (length(event_signing_hash) = 32),

    -- Agent Ed25519 signature (64 bytes)
    agent_signature BYTEA NOT NULL CHECK (length(agent_signature) = 64),

    -- Sequence number (assigned by sequencer, monotonic per tenant/store)
    sequence_number BIGINT NOT NULL,

    -- Optimistic concurrency control
    base_version BIGINT,

    -- Ensure payload matches payload_kind
    CONSTRAINT chk_payload_kind_plaintext CHECK (
        payload_kind != 0 OR (payload IS NOT NULL AND payload_encrypted IS NULL)
    ),
    CONSTRAINT chk_payload_kind_encrypted CHECK (
        payload_kind != 1 OR (payload IS NULL AND payload_encrypted IS NOT NULL)
    ),

    -- Unique sequence per stream
    CONSTRAINT uq_ves_events_sequence UNIQUE (tenant_id, store_id, sequence_number)
);

-- Upgrade path: ensure required columns exist when upgrading from older schemas.
ALTER TABLE ves_events ADD COLUMN IF NOT EXISTS created_at_str TEXT;
ALTER TABLE ves_events ADD COLUMN IF NOT EXISTS event_signing_hash BYTEA;

-- Primary query path: events by tenant/store/sequence
CREATE INDEX IF NOT EXISTS idx_ves_events_tenant_store_seq
    ON ves_events (tenant_id, store_id, sequence_number);

-- Entity event history
CREATE INDEX IF NOT EXISTS idx_ves_events_entity
    ON ves_events (tenant_id, store_id, entity_type, entity_id, sequence_number);

-- Command deduplication
CREATE INDEX IF NOT EXISTS idx_ves_events_command
    ON ves_events (command_id) WHERE command_id IS NOT NULL;

-- Agent event lookups
CREATE INDEX IF NOT EXISTS idx_ves_events_agent
    ON ves_events (tenant_id, source_agent_id, sequenced_at);


-- ============================================================================
-- VES SEQUENCER RECEIPTS
-- ============================================================================

-- Sequencer receipts per VES v1.0 Section 8.4
CREATE TABLE IF NOT EXISTS ves_sequencer_receipts (
    -- Event being receipted (one receipt per event)
    event_id UUID PRIMARY KEY REFERENCES ves_events(event_id),

    -- Sequencer identity
    sequencer_id UUID NOT NULL,

    -- Assigned sequence
    sequence_number BIGINT NOT NULL,

    -- Receipt timestamp
    sequenced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Receipt hash per VES v1.0 Section 8.4
    -- SHA256(b"VES_RECEIPT_V1" || tenant_id || store_id || event_id || seq_be64 || event_signing_hash)
    receipt_hash BYTEA NOT NULL CHECK (length(receipt_hash) = 32),

    -- Sequencer signature over receipt_hash (optional, for trusted sequencers)
    sequencer_signature BYTEA CHECK (sequencer_signature IS NULL OR length(sequencer_signature) = 64)
);

-- Find receipts by event
CREATE INDEX IF NOT EXISTS idx_ves_receipts_event
    ON ves_sequencer_receipts (event_id);

-- Find receipts by sequencer
CREATE INDEX IF NOT EXISTS idx_ves_receipts_sequencer
    ON ves_sequencer_receipts (sequencer_id, sequenced_at);


-- ============================================================================
-- VES BATCH COMMITMENTS
-- ============================================================================

-- VES v1.0 compliant Merkle commitments
CREATE TABLE IF NOT EXISTS ves_commitments (
    -- Unique batch identifier
    batch_id UUID PRIMARY KEY,

    -- Tenant/store this batch belongs to
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,

    -- VES version for this commitment
    ves_version INTEGER NOT NULL DEFAULT 1,

    -- Merkle tree parameters
    tree_depth INTEGER NOT NULL,
    leaf_count INTEGER NOT NULL,
    padded_leaf_count INTEGER NOT NULL,

    -- Merkle root (VES v1.0 Section 11)
    merkle_root BYTEA NOT NULL CHECK (length(merkle_root) = 32),

    -- State progression
    prev_state_root BYTEA NOT NULL CHECK (length(prev_state_root) = 32),
    new_state_root BYTEA NOT NULL CHECK (length(new_state_root) = 32),

    -- Sequence range (inclusive)
    sequence_start BIGINT NOT NULL,
    sequence_end BIGINT NOT NULL,

    -- When this commitment was created
    committed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- On-chain anchoring (optional)
    chain_id INTEGER,
    chain_tx_hash BYTEA,
    chain_block_number BIGINT,
    anchored_at TIMESTAMPTZ,

    CONSTRAINT chk_sequence_range CHECK (sequence_end >= sequence_start),
    CONSTRAINT chk_leaf_count CHECK (leaf_count = sequence_end - sequence_start + 1)
);

-- Find commitments by tenant/store and sequence
CREATE INDEX IF NOT EXISTS idx_ves_commitments_sequence
    ON ves_commitments (tenant_id, store_id, sequence_start, sequence_end);

-- Find unanchored commitments
CREATE INDEX IF NOT EXISTS idx_ves_commitments_pending
    ON ves_commitments (tenant_id, store_id)
    WHERE chain_tx_hash IS NULL;


-- ============================================================================
-- VES REJECTION LOG
-- ============================================================================

-- Events rejected during VES validation
CREATE TABLE IF NOT EXISTS ves_rejections (
    id BIGSERIAL PRIMARY KEY,

    -- Event being rejected
    event_id UUID NOT NULL,

    -- Tenant/store context
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,

    -- Rejection details
    reason VARCHAR(64) NOT NULL,
    message TEXT,

    -- Rejection timestamp
    rejected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Find rejections by tenant/store
CREATE INDEX IF NOT EXISTS idx_ves_rejections_tenant
    ON ves_rejections (tenant_id, store_id, rejected_at);


-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

-- Function to check if an agent key is valid at a given time
CREATE OR REPLACE FUNCTION is_agent_key_valid(
    p_tenant_id UUID,
    p_agent_id UUID,
    p_key_id INTEGER,
    p_at TIMESTAMPTZ DEFAULT NOW()
) RETURNS BOOLEAN AS $$
DECLARE
    v_status VARCHAR(16);
    v_valid_from TIMESTAMPTZ;
    v_valid_to TIMESTAMPTZ;
BEGIN
    SELECT status, valid_from, valid_to
    INTO v_status, v_valid_from, v_valid_to
    FROM agent_signing_keys
    WHERE tenant_id = p_tenant_id
      AND agent_id = p_agent_id
      AND key_id = p_key_id;

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    -- Check status
    IF v_status != 'active' THEN
        RETURN FALSE;
    END IF;

    -- Check validity window
    IF v_valid_from IS NOT NULL AND p_at < v_valid_from THEN
        RETURN FALSE;
    END IF;

    IF v_valid_to IS NOT NULL AND p_at > v_valid_to THEN
        RETURN FALSE;
    END IF;

    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;


-- Function to get next key_id for an agent
CREATE OR REPLACE FUNCTION get_next_agent_key_id(
    p_tenant_id UUID,
    p_agent_id UUID
) RETURNS INTEGER AS $$
DECLARE
    v_max_key_id INTEGER;
BEGIN
    SELECT COALESCE(MAX(key_id), 0) INTO v_max_key_id
    FROM agent_signing_keys
    WHERE tenant_id = p_tenant_id AND agent_id = p_agent_id;

    RETURN v_max_key_id + 1;
END;
$$ LANGUAGE plpgsql;
