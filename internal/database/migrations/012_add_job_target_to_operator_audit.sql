ALTER TABLE stackpilot.operator_audit_events
    ADD COLUMN target_job_id uuid NULL REFERENCES stackpilot.jobs(id) ON DELETE SET NULL;

ALTER TABLE stackpilot.operator_audit_events
    ADD CONSTRAINT operator_audit_events_target_mutual_exclusion
    CHECK (target_operator_id IS NULL OR target_job_id IS NULL);
---- create above / drop below ----
ALTER TABLE stackpilot.operator_audit_events
    DROP CONSTRAINT IF EXISTS operator_audit_events_target_mutual_exclusion;

ALTER TABLE stackpilot.operator_audit_events
    DROP COLUMN IF EXISTS target_job_id;
