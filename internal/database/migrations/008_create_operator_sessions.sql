CREATE TABLE stackpilot.operator_sessions (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    operator_id uuid NOT NULL REFERENCES stackpilot.operators(id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    CONSTRAINT operator_sessions_token_hash_length CHECK (octet_length(token_hash) = 32),
    CONSTRAINT operator_sessions_expires_at_check CHECK (expires_at > created_at)
);

CREATE INDEX operator_sessions_operator_id_idx ON stackpilot.operator_sessions(operator_id);
CREATE INDEX operator_sessions_expires_at_idx ON stackpilot.operator_sessions(expires_at);
---- create above / drop below ----
DROP TABLE stackpilot.operator_sessions;
