-- Source-isolated durable read models for the VES ledger. VES and legacy
-- sequence numbers are independent, so sharing checkpoints or versions would
-- allow one ledger to skip events from the other.

CREATE TABLE IF NOT EXISTS ves_projection_checkpoints (
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,
    last_projected_sequence BIGINT NOT NULL DEFAULT 0 CHECK (last_projected_sequence >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, store_id)
);

CREATE TABLE IF NOT EXISTS ves_projection_entity_versions (
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,
    entity_type VARCHAR(256) NOT NULL,
    entity_id VARCHAR(1024) NOT NULL,
    version BIGINT NOT NULL CHECK (version >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, store_id, entity_type, entity_id)
);

CREATE TABLE IF NOT EXISTS ves_projection_documents (
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,
    entity_type VARCHAR(256) NOT NULL,
    entity_id VARCHAR(1024) NOT NULL,
    document JSONB NOT NULL,
    version BIGINT NOT NULL CHECK (version >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, store_id, entity_type, entity_id)
);

CREATE INDEX IF NOT EXISTS idx_ves_projection_documents_updated
    ON ves_projection_documents (tenant_id, store_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_ves_projection_documents_document
    ON ves_projection_documents USING GIN (document);
