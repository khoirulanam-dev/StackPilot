CREATE TABLE stackpilot.enrollment_tokens (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    token_hash bytea NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz NULL,
    CONSTRAINT enrollment_tokens_token_hash_length CHECK (octet_length(token_hash) = 32)
);
---- create above / drop below ----
DROP TABLE stackpilot.enrollment_tokens;
