ALTER TABLE dead_letter_events ADD COLUMN claim_token UUID;
CREATE INDEX dead_letter_retry_lease ON dead_letter_events (last_retry_at)
    WHERE status = 'retrying';
