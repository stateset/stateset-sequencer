-- Production projection runtime state.
--
-- `entity_versions` is part of sequencing/OCC and must not also be used as a
-- projector cursor. Keeping projection versions separate prevents a replay or
-- rebuild from changing write-path concurrency state.

CREATE TABLE IF NOT EXISTS projection_entity_versions (
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,
    entity_type VARCHAR(256) NOT NULL,
    entity_id VARCHAR(1024) NOT NULL,
    version BIGINT NOT NULL CHECK (version >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, store_id, entity_type, entity_id)
);

-- A deliberately generic JSONB read model keeps the projection engine useful
-- to consumers without coupling this service to an application's query schema.
-- Applications can index selected JSON paths or stream these rows downstream.
CREATE TABLE IF NOT EXISTS projection_documents (
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,
    entity_type VARCHAR(256) NOT NULL,
    entity_id VARCHAR(1024) NOT NULL,
    document JSONB NOT NULL,
    version BIGINT NOT NULL CHECK (version >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, store_id, entity_type, entity_id)
);

CREATE INDEX IF NOT EXISTS idx_projection_documents_updated
    ON projection_documents (tenant_id, store_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_projection_documents_document
    ON projection_documents USING GIN (document);

-- Durable state for the optional in-process compliance prover. This prevents a
-- malformed or non-compliant event from becoming a permanent hot-loop.
CREATE TABLE IF NOT EXISTS ves_proof_jobs (
    event_id UUID NOT NULL,
    policy_hash BYTEA NOT NULL CHECK (octet_length(policy_hash) = 32),
    status VARCHAR(32) NOT NULL CHECK (
        status IN ('retryable', 'proved', 'not_compliant', 'skipped', 'failed')
    ),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error TEXT,
    next_attempt_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (event_id, policy_hash)
);

CREATE INDEX IF NOT EXISTS idx_ves_proof_jobs_retry
    ON ves_proof_jobs (next_attempt_at)
    WHERE status = 'retryable';
