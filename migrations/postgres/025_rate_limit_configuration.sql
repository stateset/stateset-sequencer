-- Persist the configured limit with each live window. Different replicas must
-- not silently admit against different limits for the same identity.
ALTER TABLE sequencer_rate_limit_budgets
    ADD COLUMN limit_count BIGINT CHECK (limit_count > 0);

CREATE OR REPLACE FUNCTION sequencer_take_rate_limit(
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
            current_time_at_lock := clock_timestamp();
            IF budget.expires_at <= current_time_at_lock THEN
                UPDATE sequencer_rate_limit_budgets SET used = 1,
                    expires_at = current_time_at_lock + p_window * INTERVAL '1 second',
                    window_seconds = p_window, limit_count = p_limit
                    WHERE key_hash = p_key;
                RETURN TRUE;
            END IF;
            IF budget.window_seconds <> p_window THEN
                RAISE EXCEPTION 'inconsistent rate limit window across replicas';
            END IF;
            -- Existing rows from migration 023 learn the configured limit at
            -- first access, while the row lock prevents a concurrent mismatch.
            IF budget.limit_count IS NULL THEN
                UPDATE sequencer_rate_limit_budgets SET limit_count = p_limit
                    WHERE key_hash = p_key;
            ELSIF budget.limit_count <> p_limit THEN
                RAISE EXCEPTION 'inconsistent rate limit count across replicas';
            END IF;
            IF budget.used >= p_limit THEN RETURN FALSE; END IF;
            UPDATE sequencer_rate_limit_budgets SET used = used + 1 WHERE key_hash = p_key;
            RETURN TRUE;
        END IF;

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
        INSERT INTO sequencer_rate_limit_budgets
            (key_hash, used, expires_at, window_seconds, limit_count)
        VALUES (p_key, 0, clock_timestamp() + p_window * INTERVAL '1 second',
                p_window, p_limit);
    END LOOP;
END;
$$;
