-- x402 Payment Protocol Tables
-- Supports agent-to-agent payment intents with batching for L2 settlement

-- x402 payment intents - individual payment authorizations from agents
CREATE TABLE IF NOT EXISTS x402_payment_intents (
    intent_id UUID PRIMARY KEY,
    x402_version INTEGER NOT NULL DEFAULT 1,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',

    -- Multi-tenancy
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,
    source_agent_id UUID NOT NULL,
    agent_key_id INTEGER NOT NULL,

    -- Payment parameters (signed by payer)
    payer_address VARCHAR(66) NOT NULL,
    payee_address VARCHAR(66) NOT NULL,
    amount BIGINT NOT NULL,
    asset VARCHAR(20) NOT NULL DEFAULT 'usdc',
    network VARCHAR(30) NOT NULL DEFAULT 'set_chain',
    chain_id BIGINT NOT NULL,
    token_address VARCHAR(66),

    -- Validity & replay protection
    created_at_unix BIGINT NOT NULL,
    valid_until BIGINT NOT NULL,
    nonce BIGINT NOT NULL,
    idempotency_key VARCHAR(255),

    -- Resource context
    resource_uri TEXT,
    description TEXT,
    order_id UUID,
    merchant_id VARCHAR(255),

    -- Cryptographic fields
    signing_hash BYTEA NOT NULL,
    payer_signature BYTEA NOT NULL,
    payer_public_key BYTEA,

    -- Sequencer-assigned fields
    sequence_number BIGINT,
    sequenced_at TIMESTAMPTZ,

    -- Batch assignment
    batch_id UUID,

    -- Settlement fields
    tx_hash VARCHAR(66),
    block_number BIGINT,
    settled_at TIMESTAMPTZ,

    -- Metadata
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT chk_x402_amount_positive CHECK (amount > 0),
    CONSTRAINT chk_x402_valid_until_future CHECK (valid_until >= created_at_unix),
    CONSTRAINT chk_x402_status CHECK (status IN ('pending', 'sequenced', 'batched', 'settled', 'expired', 'failed'))
);

-- Indexes for payment intents
CREATE INDEX IF NOT EXISTS idx_x402_intents_tenant_store
    ON x402_payment_intents (tenant_id, store_id);
CREATE INDEX IF NOT EXISTS idx_x402_intents_status
    ON x402_payment_intents (status);
CREATE INDEX IF NOT EXISTS idx_x402_intents_payer
    ON x402_payment_intents (payer_address);
CREATE INDEX IF NOT EXISTS idx_x402_intents_payee
    ON x402_payment_intents (payee_address);
CREATE INDEX IF NOT EXISTS idx_x402_intents_batch
    ON x402_payment_intents (batch_id) WHERE batch_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_x402_intents_sequence
    ON x402_payment_intents (tenant_id, store_id, sequence_number) WHERE sequence_number IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_x402_intents_idempotency
    ON x402_payment_intents (tenant_id, store_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_x402_intents_pending
    ON x402_payment_intents (tenant_id, store_id, network, status, created_at)
    WHERE status = 'sequenced';

-- x402 payment batches - aggregated batches for L2 settlement
CREATE TABLE IF NOT EXISTS x402_payment_batches (
    batch_id UUID PRIMARY KEY,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',

    -- Multi-tenancy
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,

    -- Batch parameters
    network VARCHAR(30) NOT NULL,
    payment_count INTEGER NOT NULL DEFAULT 0,
    total_amounts JSONB NOT NULL DEFAULT '[]',

    -- Merkle tree fields
    merkle_root BYTEA,
    prev_state_root BYTEA,
    new_state_root BYTEA,

    -- Sequence range
    sequence_start BIGINT NOT NULL DEFAULT 0,
    sequence_end BIGINT NOT NULL DEFAULT 0,

    -- Settlement fields
    tx_hash VARCHAR(66),
    block_number BIGINT,
    gas_used BIGINT,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    committed_at TIMESTAMPTZ,
    submitted_at TIMESTAMPTZ,
    settled_at TIMESTAMPTZ,

    -- Constraints
    CONSTRAINT chk_x402_batch_status CHECK (status IN ('pending', 'committed', 'submitted', 'settled', 'failed'))
);

-- Indexes for batches
CREATE INDEX IF NOT EXISTS idx_x402_batches_tenant_store
    ON x402_payment_batches (tenant_id, store_id);
CREATE INDEX IF NOT EXISTS idx_x402_batches_status
    ON x402_payment_batches (status);
CREATE INDEX IF NOT EXISTS idx_x402_batches_network
    ON x402_payment_batches (network, status);

-- x402 sequence counters - atomic sequence assignment per tenant/store
CREATE TABLE IF NOT EXISTS x402_sequence_counters (
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,
    current_sequence BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, store_id)
);

-- x402 nonce tracking - prevent replay attacks per payer
CREATE TABLE IF NOT EXISTS x402_nonce_tracking (
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,
    payer_address VARCHAR(66) NOT NULL,
    nonce BIGINT NOT NULL,
    intent_id UUID NOT NULL REFERENCES x402_payment_intents(intent_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, store_id, payer_address, nonce)
);

-- Backfill head sequence from existing x402 intents (if any)
INSERT INTO x402_sequence_counters (tenant_id, store_id, current_sequence, updated_at)
SELECT tenant_id, store_id, COALESCE(MAX(sequence_number), 0), NOW()
FROM x402_payment_intents
WHERE sequence_number IS NOT NULL
GROUP BY tenant_id, store_id
ON CONFLICT (tenant_id, store_id) DO UPDATE
SET current_sequence = GREATEST(x402_sequence_counters.current_sequence, EXCLUDED.current_sequence),
    updated_at = EXCLUDED.updated_at;
