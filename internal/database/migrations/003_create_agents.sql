CREATE TABLE stackpilot.agents (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    public_key bytea NOT NULL UNIQUE,
    enrollment_token_id uuid NOT NULL UNIQUE REFERENCES stackpilot.enrollment_tokens(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agents_public_key_length CHECK (octet_length(public_key) = 32)
);
---- create above / drop below ----
DROP TABLE stackpilot.agents;
