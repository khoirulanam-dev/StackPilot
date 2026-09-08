CREATE TABLE stackpilot.jobs (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    agent_id uuid NOT NULL REFERENCES stackpilot.agents(id) ON DELETE RESTRICT,
    created_by_operator_id uuid NOT NULL REFERENCES stackpilot.operators(id) ON DELETE RESTRICT,
    created_by_username text NOT NULL,
    idempotency_key_hash bytea NOT NULL,
    action_type text NOT NULL,
    state text NOT NULL,
    attempt integer NOT NULL DEFAULT 0,
    failure_code text NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    dispatched_at timestamptz NULL,
    dispatch_expires_at timestamptz NULL,
    started_at timestamptz NULL,
    execution_deadline_at timestamptz NULL,
    finished_at timestamptz NULL,
    CONSTRAINT jobs_created_by_username_length CHECK (char_length(created_by_username) >= 3 AND char_length(created_by_username) <= 64),
    CONSTRAINT jobs_created_by_username_format CHECK (created_by_username ~ '^[a-z0-9][a-z0-9._-]{2,63}$'),
    CONSTRAINT jobs_idempotency_key_hash_length CHECK (octet_length(idempotency_key_hash) = 32),
    CONSTRAINT jobs_action_type_check CHECK (action_type IN ('agent.ping')),
    CONSTRAINT jobs_state_check CHECK (state IN ('queued', 'dispatched', 'running', 'succeeded', 'failed', 'unknown')),
    CONSTRAINT jobs_attempt_range CHECK (attempt >= 0 AND attempt <= 5),
    CONSTRAINT jobs_failure_code_check CHECK (failure_code IS NULL OR failure_code IN ('executor_error', 'dispatch_exhausted', 'execution_timeout')),
    CONSTRAINT jobs_state_failure_code_consistency CHECK (
        (state IN ('queued', 'dispatched', 'running') AND failure_code IS NULL) OR
        (state = 'succeeded' AND failure_code IS NULL) OR
        (state = 'failed' AND failure_code IN ('executor_error', 'dispatch_exhausted')) OR
        (state = 'unknown' AND failure_code = 'execution_timeout')
    ),
    CONSTRAINT jobs_finished_at_consistency CHECK (
        (state IN ('queued', 'dispatched', 'running') AND finished_at IS NULL) OR
        (state IN ('succeeded', 'failed', 'unknown') AND finished_at IS NOT NULL)
    )
);

CREATE INDEX jobs_claim_idx ON stackpilot.jobs (agent_id, state, created_at, id);
CREATE INDEX jobs_listing_idx ON stackpilot.jobs (created_at DESC, id DESC);
CREATE INDEX jobs_creator_idx ON stackpilot.jobs (created_by_operator_id);
CREATE UNIQUE INDEX jobs_idempotency_idx ON stackpilot.jobs (created_by_operator_id, idempotency_key_hash);
CREATE UNIQUE INDEX jobs_agent_inflight_idx ON stackpilot.jobs (agent_id) WHERE state IN ('dispatched', 'running');
CREATE INDEX jobs_expired_dispatched_idx ON stackpilot.jobs (dispatch_expires_at) WHERE state = 'dispatched';
CREATE INDEX jobs_expired_running_idx ON stackpilot.jobs (execution_deadline_at) WHERE state = 'running';
---- create above / drop below ----
DROP TABLE stackpilot.jobs;
