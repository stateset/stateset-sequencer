-- Shared fixed-window admission budgets. Store hashes, never credentials.
CREATE TABLE sequencer_rate_limit_budgets (
    key_hash TEXT PRIMARY KEY CHECK (length(key_hash) = 64),
    used BIGINT NOT NULL CHECK (used >= 0),
    expires_at TIMESTAMPTZ NOT NULL,
    window_seconds BIGINT NOT NULL CHECK (window_seconds > 0)
);
CREATE INDEX sequencer_rate_limit_expiry ON sequencer_rate_limit_budgets (expires_at);

CREATE FUNCTION sequencer_take_rate_limit(
    p_key TEXT, p_limit BIGINT, p_window BIGINT, p_capacity BIGINT
) RETURNS BOOLEAN LANGUAGE plpgsql AS $$
DECLARE
    budget sequencer_rate_limit_budgets%ROWTYPE;
    current_time_at_lock TIMESTAMPTZ;
BEGIN
    IF length(p_key) <> 64 OR p_limit < 1 OR p_window < 1 OR p_capacity < 1 THEN
        RAISE EXCEPTION 'invalid rate limit configuration';
    END IF;
    LOOP
        SELECT * INTO budget FROM sequencer_rate_limit_budgets
            WHERE key_hash = p_key FOR UPDATE;
        IF FOUND THEN
            -- Evaluate database time after waiting for the row, not at transaction start.
            current_time_at_lock := clock_timestamp();
            IF budget.expires_at <= current_time_at_lock THEN
                UPDATE sequencer_rate_limit_budgets SET used = 1,
                    expires_at = current_time_at_lock + p_window * INTERVAL '1 second',
                    window_seconds = p_window WHERE key_hash = p_key;
                RETURN TRUE;
            END IF;
            IF budget.window_seconds <> p_window THEN
                RAISE EXCEPTION 'inconsistent rate limit window across replicas';
            END IF;
            IF budget.used >= p_limit THEN RETURN FALSE; END IF;
            UPDATE sequencer_rate_limit_budgets SET used = used + 1 WHERE key_hash = p_key;
            RETURN TRUE;
        END IF;

        -- Serialize only new-key admission so concurrent identities cannot exceed
        -- the storage cap. Existing budgets only contend on their own row.
        PERFORM pg_advisory_xact_lock(6004514665705169236);
        IF EXISTS (SELECT 1 FROM sequencer_rate_limit_budgets WHERE key_hash = p_key) THEN
            CONTINUE;
        END IF;
        IF (SELECT count(*) FROM sequencer_rate_limit_budgets) >= p_capacity THEN
            DELETE FROM sequencer_rate_limit_budgets WHERE expires_at <= clock_timestamp();
            IF (SELECT count(*) FROM sequencer_rate_limit_budgets) >= p_capacity THEN
                RETURN FALSE;
            END IF;
        END IF;
        INSERT INTO sequencer_rate_limit_budgets VALUES (
            p_key, 0, clock_timestamp() + p_window * INTERVAL '1 second', p_window
        );
    END LOOP;
END;
$$;
