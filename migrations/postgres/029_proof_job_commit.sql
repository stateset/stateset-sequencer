-- A generated proof and its terminal worker outcome must appear atomically.
CREATE FUNCTION sequencer_mark_proof_job_proved() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.proof_type = 'stark-compliance' THEN
        INSERT INTO ves_proof_jobs
            (event_id, policy_hash, status, attempts, updated_at)
        VALUES (NEW.event_id, NEW.policy_hash, 'proved', 1, NOW())
        ON CONFLICT (event_id, policy_hash) DO UPDATE SET
            status = 'proved', last_error = NULL,
            next_attempt_at = NULL, updated_at = NOW();
    END IF;
    RETURN NEW;
END;
$$;

INSERT INTO ves_proof_jobs (event_id, policy_hash, status, attempts, updated_at)
SELECT DISTINCT event_id, policy_hash, 'proved', 1, NOW()
FROM ves_compliance_proofs WHERE proof_type = 'stark-compliance'
ON CONFLICT (event_id, policy_hash) DO UPDATE SET
    status = 'proved', last_error = NULL,
    next_attempt_at = NULL, updated_at = NOW();

CREATE TRIGGER proof_job_commit
    AFTER INSERT ON ves_compliance_proofs
    FOR EACH ROW EXECUTE FUNCTION sequencer_mark_proof_job_proved();
