-- StateSet Sequencer: VES validity proofs registry
-- Version: 0.5.0
-- Purpose: Store externally-generated validity proofs for VES commitments.

CREATE TABLE IF NOT EXISTS ves_validity_proofs (
    proof_id UUID PRIMARY KEY,
    batch_id UUID NOT NULL REFERENCES ves_commitments(batch_id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,
    proof_type VARCHAR(32) NOT NULL,
    proof_version INTEGER NOT NULL DEFAULT 1 CHECK (proof_version >= 1),
    proof BYTEA NOT NULL,
    proof_hash BYTEA NOT NULL CHECK (length(proof_hash) = 32),
    public_inputs JSONB,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_ves_validity_proofs_batch_type_version
    ON ves_validity_proofs (batch_id, proof_type, proof_version);

CREATE INDEX IF NOT EXISTS idx_ves_validity_proofs_stream_submitted
    ON ves_validity_proofs (tenant_id, store_id, submitted_at);

CREATE INDEX IF NOT EXISTS idx_ves_validity_proofs_batch
    ON ves_validity_proofs (batch_id);

-- Defense-in-depth: ensure tenant/store matches the referenced commitment.
CREATE OR REPLACE FUNCTION enforce_ves_validity_proof_stream_match() RETURNS TRIGGER AS $fn$
DECLARE
    c_tenant UUID;
    c_store UUID;
BEGIN
    SELECT tenant_id, store_id INTO c_tenant, c_store
    FROM ves_commitments
    WHERE batch_id = NEW.batch_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown batch_id %', NEW.batch_id;
    END IF;

    IF NEW.tenant_id != c_tenant OR NEW.store_id != c_store THEN
        RAISE EXCEPTION 'tenant/store mismatch for batch_id %', NEW.batch_id;
    END IF;

    RETURN NEW;
END;
$fn$ LANGUAGE plpgsql;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'tg_ves_validity_proofs_stream_match'
    ) THEN
        CREATE TRIGGER tg_ves_validity_proofs_stream_match
        BEFORE INSERT OR UPDATE ON ves_validity_proofs
        FOR EACH ROW EXECUTE FUNCTION enforce_ves_validity_proof_stream_match();
    END IF;
END $$;

