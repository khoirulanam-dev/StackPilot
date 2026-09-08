CREATE TABLE stackpilot.operator_audit_events (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    actor_operator_id uuid NULL REFERENCES stackpilot.operators(id) ON DELETE SET NULL,
    actor_username text NOT NULL,
    action text NOT NULL,
    target_operator_id uuid NULL REFERENCES stackpilot.operators(id) ON DELETE SET NULL,
    target_username text NULL,
    outcome text NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT operator_audit_events_actor_username_length CHECK (char_length(actor_username) >= 1 AND char_length(actor_username) <= 64),
    CONSTRAINT operator_audit_events_action_length CHECK (char_length(action) >= 1 AND char_length(action) <= 64),
    CONSTRAINT operator_audit_events_action_format CHECK (action ~ '^[a-z0-9._-]+$'),
    CONSTRAINT operator_audit_events_target_username_length CHECK (target_username IS NULL OR (char_length(target_username) >= 1 AND char_length(target_username) <= 64)),
    CONSTRAINT operator_audit_events_outcome_check CHECK (outcome IN ('success', 'failure', 'denied'))
);

CREATE INDEX operator_audit_events_occurred_at_idx ON stackpilot.operator_audit_events(occurred_at DESC, id DESC);
CREATE INDEX operator_audit_events_actor_operator_id_idx ON stackpilot.operator_audit_events(actor_operator_id);
---- create above / drop below ----
DROP TABLE stackpilot.operator_audit_events;
