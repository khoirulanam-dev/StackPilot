ALTER TABLE stackpilot.agents
    ADD COLUMN last_seen_at timestamptz NULL,
    ADD COLUMN protocol_version integer NULL,
    ADD CONSTRAINT agents_protocol_version_check CHECK (protocol_version IS NULL OR protocol_version > 0);
---- create above / drop below ----
ALTER TABLE stackpilot.agents
    DROP CONSTRAINT agents_protocol_version_check,
    DROP COLUMN protocol_version,
    DROP COLUMN last_seen_at;
