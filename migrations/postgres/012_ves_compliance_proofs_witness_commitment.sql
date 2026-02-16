-- StateSet Sequencer: VES compliance proofs witness commitment
-- Purpose: Store the STARK witness commitment (Rescue hash output) alongside the proof.

ALTER TABLE ves_compliance_proofs
    ADD COLUMN IF NOT EXISTS witness_commitment BYTEA
        CHECK (witness_commitment IS NULL OR length(witness_commitment) = 32);

