-- VES-specific sequence counters to avoid interleaving with legacy streams.

CREATE TABLE IF NOT EXISTS ves_sequence_counters (
    tenant_id UUID NOT NULL,
    store_id UUID NOT NULL,
    current_sequence BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, store_id)
);

-- Backfill head sequence from existing VES events.
INSERT INTO ves_sequence_counters (tenant_id, store_id, current_sequence, updated_at)
SELECT tenant_id, store_id, MAX(sequence_number), NOW()
FROM ves_events
GROUP BY tenant_id, store_id
ON CONFLICT (tenant_id, store_id) DO UPDATE
SET current_sequence = GREATEST(ves_sequence_counters.current_sequence, EXCLUDED.current_sequence),
    updated_at = EXCLUDED.updated_at;
