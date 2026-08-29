-- Migration: 018_event_schemas.sql
-- Purpose: bring the schema registry's `event_schemas` table under migration
-- control.
--
-- This table was previously created at boot by PgSchemaStore::initialize()
-- issuing runtime DDL. That left the registry outside migration version
-- control, required the application role to hold DDL grants in production,
-- and raced between replicas starting concurrently. It also meant a freshly
-- migrated database had no `event_schemas`, so the cross-tenant isolation
-- tests for the registry could not run.
--
-- IF NOT EXISTS keeps this a no-op on deployments where the old runtime DDL
-- already created the table.

CREATE TABLE IF NOT EXISTS event_schemas (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    event_type VARCHAR(255) NOT NULL,
    version INTEGER NOT NULL,
    schema_json JSONB NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'active',
    compatibility VARCHAR(16) NOT NULL DEFAULT 'backward',
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by VARCHAR(255),
    UNIQUE (tenant_id, event_type, version)
);

CREATE INDEX IF NOT EXISTS idx_event_schemas_tenant_type
    ON event_schemas (tenant_id, event_type);

CREATE INDEX IF NOT EXISTS idx_event_schemas_status
    ON event_schemas (tenant_id, event_type, status);

CREATE INDEX IF NOT EXISTS idx_event_schemas_version
    ON event_schemas (tenant_id, event_type, version DESC);

COMMENT ON TABLE event_schemas IS 'Registered per-tenant JSON Schemas for event payload validation';
