CREATE TABLE stackpilot.operators (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    username text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    role text NOT NULL,
    disabled_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT operators_username_length CHECK (char_length(username) >= 3 AND char_length(username) <= 64),
    CONSTRAINT operators_username_format CHECK (username ~ '^[a-z0-9][a-z0-9._-]{2,63}$'),
    CONSTRAINT operators_password_hash_length CHECK (char_length(password_hash) >= 50 AND char_length(password_hash) <= 256),
    CONSTRAINT operators_role_check CHECK (role IN ('viewer', 'operator', 'admin'))
);
---- create above / drop below ----
DROP TABLE stackpilot.operators;
