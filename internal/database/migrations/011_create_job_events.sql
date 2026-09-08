CREATE TABLE stackpilot.job_events (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    job_id uuid NOT NULL REFERENCES stackpilot.jobs(id) ON DELETE CASCADE,
    event_type text NOT NULL,
    attempt integer NOT NULL,
    actor_type text NOT NULL,
    actor_identifier text NOT NULL,
    failure_code text NULL,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT job_events_event_type_check CHECK (event_type IN ('job.created', 'job.dispatched', 'job.requeued', 'job.started', 'job.succeeded', 'job.failed', 'job.unknown')),
    CONSTRAINT job_events_actor_type_check CHECK (actor_type IN ('operator', 'agent', 'controller')),
    CONSTRAINT job_events_attempt_range CHECK (attempt >= 0 AND attempt <= 5),
    CONSTRAINT job_events_failure_code_check CHECK (failure_code IS NULL OR failure_code IN ('executor_error', 'dispatch_exhausted', 'execution_timeout')),
    CONSTRAINT job_events_actor_identifier_length CHECK (char_length(actor_identifier) >= 1 AND char_length(actor_identifier) <= 64),
    CONSTRAINT job_events_actor_identifier_shape CHECK (
        (actor_type = 'controller' AND actor_identifier = 'controller') OR
        (actor_type = 'operator' AND char_length(actor_identifier) >= 3 AND char_length(actor_identifier) <= 64 AND actor_identifier ~ '^[a-z0-9][a-z0-9._-]{2,63}$') OR
        (actor_type = 'agent' AND actor_identifier ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    )
);

CREATE INDEX job_events_job_id_occurred_at_idx ON stackpilot.job_events (job_id, occurred_at ASC, id ASC);
---- create above / drop below ----
DROP TABLE stackpilot.job_events;
