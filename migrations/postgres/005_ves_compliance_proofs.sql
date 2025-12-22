-- StateSet Sequencer: VES compliance proofs registry
-- Purpose: Store externally-generated compliance proofs for encrypted VES events.

CREATE TABLE IF NOT EXISTS ves_compliance_proofs (
    proof_id UUID PRIMARY KEY,
    event_id UUID NOT NULL REFERENCES ves_events(event_id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,
    proof_type VARCHAR(32) NOT NULL,
    proof_version INTEGER NOT NULL DEFAULT 1 CHECK (proof_version >= 1),
    policy_id VARCHAR(64) NOT NULL,
    policy_params JSONB NOT NULL DEFAULT '{}'::jsonb,
    policy_hash BYTEA NOT NULL CHECK (length(policy_hash) = 32),
    proof BYTEA NOT NULL,
    proof_hash BYTEA NOT NULL CHECK (length(proof_hash) = 32),
    public_inputs JSONB,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_ves_compliance_proofs_event_policy_proof
    ON ves_compliance_proofs (event_id, proof_type, proof_version, policy_hash);

CREATE INDEX IF NOT EXISTS idx_ves_compliance_proofs_stream_submitted
    ON ves_compliance_proofs (tenant_id, store_id, submitted_at);

CREATE INDEX IF NOT EXISTS idx_ves_compliance_proofs_event
    ON ves_compliance_proofs (event_id);

-- Defense-in-depth: ensure tenant/store matches the referenced VES event.
CREATE OR REPLACE FUNCTION enforce_ves_compliance_proof_stream_match() RETURNS TRIGGER AS $fn$
DECLARE
    e_tenant UUID;
    e_store UUID;
BEGIN
    SELECT tenant_id, store_id INTO e_tenant, e_store
    FROM ves_events
    WHERE event_id = NEW.event_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown event_id %', NEW.event_id;
    END IF;

    IF NEW.tenant_id != e_tenant OR NEW.store_id != e_store THEN
        RAISE EXCEPTION 'tenant/store mismatch for event_id %', NEW.event_id;
    END IF;

    RETURN NEW;
END;
$fn$ LANGUAGE plpgsql;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'tg_ves_compliance_proofs_stream_match'
    ) THEN
        CREATE TRIGGER tg_ves_compliance_proofs_stream_match
        BEFORE INSERT OR UPDATE ON ves_compliance_proofs
        FOR EACH ROW EXECUTE FUNCTION enforce_ves_compliance_proof_stream_match();
    END IF;
END $$;

