-- StateSet Sequencer: Constraints and indexes
-- Version: 0.4.0
-- Purpose: Harden invariants and concurrency safety

-- Ensure one commitment start per stream (defense-in-depth against concurrent creation).
CREATE UNIQUE INDEX IF NOT EXISTS ux_commitments_stream_start
    ON commitments (tenant_id, store_id, sequence_start);

CREATE UNIQUE INDEX IF NOT EXISTS ux_ves_commitments_stream_start
    ON ves_commitments (tenant_id, store_id, sequence_start);

-- Ensure chain tx hashes (when present) are 32 bytes.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_commitments_chain_tx_hash_len'
    ) THEN
        ALTER TABLE commitments
            ADD CONSTRAINT chk_commitments_chain_tx_hash_len
            CHECK (chain_tx_hash IS NULL OR length(chain_tx_hash) = 32);
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_ves_commitments_chain_tx_hash_len'
    ) THEN
        ALTER TABLE ves_commitments
            ADD CONSTRAINT chk_ves_commitments_chain_tx_hash_len
            CHECK (chain_tx_hash IS NULL OR length(chain_tx_hash) = 32);
    END IF;
END $$;

