package database

import (
	"strings"
	"testing"
)

func TestEmbeddedMigrations(t *testing.T) {
	migrations, err := getEmbeddedMigrations()
	if err != nil {
		t.Fatalf("getEmbeddedMigrations() failed: %v", err)
	}

	if len(migrations) != 12 {
		t.Fatalf("expected exactly 12 migrations, got %d", len(migrations))
	}

	// Verify exact migration order
	expected001 := "001_create_stackpilot_schema.sql"
	expected002 := "002_create_enrollment_tokens.sql"
	expected003 := "003_create_agents.sql"
	expected004 := "004_add_agent_presence.sql"
	expected005 := "005_create_agent_inventory.sql"
	expected006 := "006_create_agent_telemetry.sql"
	expected007 := "007_create_operators.sql"
	expected008 := "008_create_operator_sessions.sql"
	expected009 := "009_create_operator_audit_events.sql"
	expected010 := "010_create_jobs.sql"
	expected011 := "011_create_job_events.sql"
	expected012 := "012_add_job_target_to_operator_audit.sql"

	if migrations[0] != expected001 {
		t.Errorf("expected first migration %q, got %q", expected001, migrations[0])
	}
	if migrations[1] != expected002 {
		t.Errorf("expected second migration %q, got %q", expected002, migrations[1])
	}
	if migrations[2] != expected003 {
		t.Errorf("expected third migration %q, got %q", expected003, migrations[2])
	}
	if migrations[3] != expected004 {
		t.Errorf("expected fourth migration %q, got %q", expected004, migrations[3])
	}
	if migrations[4] != expected005 {
		t.Errorf("expected fifth migration %q, got %q", expected005, migrations[4])
	}
	if migrations[5] != expected006 {
		t.Errorf("expected sixth migration %q, got %q", expected006, migrations[5])
	}
	if migrations[6] != expected007 {
		t.Errorf("expected seventh migration %q, got %q", expected007, migrations[6])
	}
	if migrations[7] != expected008 {
		t.Errorf("expected eighth migration %q, got %q", expected008, migrations[7])
	}
	if migrations[8] != expected009 {
		t.Errorf("expected ninth migration %q, got %q", expected009, migrations[8])
	}
	if migrations[9] != expected010 {
		t.Errorf("expected tenth migration %q, got %q", expected010, migrations[9])
	}
	if migrations[10] != expected011 {
		t.Errorf("expected eleventh migration %q, got %q", expected011, migrations[10])
	}
	if migrations[11] != expected012 {
		t.Errorf("expected twelfth migration %q, got %q", expected012, migrations[11])
	}

	// Verify migration 001 contents
	content001, err := migrationsFS.ReadFile("migrations/" + expected001)
	if err != nil {
		t.Fatalf("failed to read %s: %v", expected001, err)
	}
	sql001 := string(content001)
	if !strings.Contains(sql001, "CREATE SCHEMA stackpilot;") {
		t.Errorf("migration 001 missing CREATE SCHEMA stackpilot: %s", sql001)
	}
	if !strings.Contains(sql001, "DROP SCHEMA stackpilot;") {
		t.Errorf("migration 001 missing DROP SCHEMA stackpilot: %s", sql001)
	}
	normalized001 := strings.ToLower(sql001)
	if strings.Contains(normalized001, "cascade") {
		t.Errorf("migration 001 must not use CASCADE: %s", sql001)
	}

	// Verify migration 002 contents
	content002, err := migrationsFS.ReadFile("migrations/" + expected002)
	if err != nil {
		t.Fatalf("failed to read %s: %v", expected002, err)
	}
	sql002 := string(content002)

	requiredClauses002 := []string{
		"CREATE TABLE stackpilot.enrollment_tokens",
		"token_hash bytea NOT NULL UNIQUE",
		"octet_length(token_hash) = 32",
		"expires_at timestamptz NOT NULL",
		"consumed_at timestamptz NULL",
		"uuidv7()",
		"---- create above / drop below ----",
		"DROP TABLE stackpilot.enrollment_tokens;",
	}
	for _, clause := range requiredClauses002 {
		if !strings.Contains(sql002, clause) {
			t.Errorf("migration 002 missing required clause %q", clause)
		}
	}

	normalized002 := strings.ToLower(sql002)
	prohibitedKeywords002 := []string{
		"cascade",
		"plaintext",
		"secret",
		"token text",
		"token varchar",
	}
	for _, keyword := range prohibitedKeywords002 {
		if strings.Contains(normalized002, keyword) {
			t.Errorf("migration 002 contains prohibited term %q", keyword)
		}
	}

	// Verify migration 003 contents
	content003, err := migrationsFS.ReadFile("migrations/" + expected003)
	if err != nil {
		t.Fatalf("failed to read %s: %v", expected003, err)
	}
	sql003 := string(content003)

	requiredClauses003 := []string{
		"CREATE TABLE stackpilot.agents",
		"public_key bytea NOT NULL UNIQUE",
		"octet_length(public_key) = 32",
		"enrollment_token_id uuid NOT NULL UNIQUE",
		"REFERENCES stackpilot.enrollment_tokens(id)",
		"created_at timestamptz",
		"uuidv7()",
		"---- create above / drop below ----",
		"DROP TABLE stackpilot.agents;",
	}
	for _, clause := range requiredClauses003 {
		if !strings.Contains(sql003, clause) {
			t.Errorf("migration 003 missing required clause %q", clause)
		}
	}

	normalized003 := strings.ToLower(sql003)
	prohibitedKeywords003 := []string{
		"cascade",
		"private_key",
		"secret",
		"password",
		"hostname",
		"heartbeat",
		"metadata",
	}
	for _, keyword := range prohibitedKeywords003 {
		if strings.Contains(normalized003, keyword) {
			t.Errorf("migration 003 contains prohibited term %q", keyword)
		}
	}

	// Verify migration 004 contents
	content004, err := migrationsFS.ReadFile("migrations/" + expected004)
	if err != nil {
		t.Fatalf("failed to read %s: %v", expected004, err)
	}
	sql004 := string(content004)

	requiredClauses004 := []string{
		"ALTER TABLE stackpilot.agents",
		"last_seen_at timestamptz NULL",
		"protocol_version integer NULL",
		"agents_protocol_version_check CHECK (protocol_version IS NULL OR protocol_version > 0)",
		"---- create above / drop below ----",
		"DROP CONSTRAINT agents_protocol_version_check",
		"DROP COLUMN protocol_version",
		"DROP COLUMN last_seen_at",
	}
	for _, clause := range requiredClauses004 {
		if !strings.Contains(sql004, clause) {
			t.Errorf("migration 004 missing required clause %q", clause)
		}
	}

	normalized004 := strings.ToLower(sql004)
	prohibitedKeywords004 := []string{
		"cascade",
		"online",
		"offline",
		"status",
		"hostname",
		"metrics",
	}
	for _, keyword := range prohibitedKeywords004 {
		if strings.Contains(normalized004, keyword) {
			t.Errorf("migration 004 contains prohibited term %q", keyword)
		}
	}

	// Verify migration 005 contents
	content005, err := migrationsFS.ReadFile("migrations/" + expected005)
	if err != nil {
		t.Fatalf("failed to read %s: %v", expected005, err)
	}
	sql005 := string(content005)

	requiredClauses005 := []string{
		"CREATE TABLE stackpilot.agent_inventory",
		"agent_id uuid PRIMARY KEY REFERENCES stackpilot.agents(id) ON DELETE CASCADE",
		"hostname text NOT NULL",
		"os_id text NOT NULL",
		"os_name text NOT NULL",
		"os_version text NOT NULL",
		"kernel_release text NOT NULL",
		"architecture text NOT NULL",
		"cpu_logical_cores integer NOT NULL",
		"memory_total_bytes bigint NOT NULL",
		"reported_at timestamptz NOT NULL DEFAULT now()",
		"CONSTRAINT agent_inventory_hostname_check",
		"CONSTRAINT agent_inventory_os_id_check",
		"CONSTRAINT agent_inventory_os_name_check",
		"CONSTRAINT agent_inventory_os_version_check",
		"CONSTRAINT agent_inventory_kernel_release_check",
		"CONSTRAINT agent_inventory_architecture_check",
		"CONSTRAINT agent_inventory_cpu_logical_cores_check",
		"CONSTRAINT agent_inventory_memory_total_bytes_check",
		"---- create above / drop below ----",
		"DROP TABLE stackpilot.agent_inventory;",
	}
	for _, clause := range requiredClauses005 {
		if !strings.Contains(sql005, clause) {
			t.Errorf("migration 005 missing required clause %q", clause)
		}
	}

	normalized005 := strings.ToLower(sql005)
	prohibitedKeywords005 := []string{
		"jsonb",
		"raw_payload",
		"ip_addresses",
		"mac_addresses",
		"collected_at",
		"updated_at",
		"metrics",
	}
	for _, keyword := range prohibitedKeywords005 {
		if strings.Contains(normalized005, keyword) {
			t.Errorf("migration 005 contains prohibited term %q", keyword)
		}
	}

	// Verify migration 006 contents
	content006, err := migrationsFS.ReadFile("migrations/" + expected006)
	if err != nil {
		t.Fatalf("failed to read %s: %v", expected006, err)
	}
	sql006 := string(content006)

	requiredClauses006 := []string{
		"CREATE TABLE stackpilot.agent_telemetry",
		"agent_id uuid PRIMARY KEY REFERENCES stackpilot.agents(id) ON DELETE CASCADE",
		"cpu_usage_basis_points integer NOT NULL",
		"memory_total_bytes bigint NOT NULL",
		"memory_used_bytes bigint NOT NULL",
		"memory_available_bytes bigint NOT NULL",
		"load_1m_milli bigint NOT NULL",
		"load_5m_milli bigint NOT NULL",
		"load_15m_milli bigint NOT NULL",
		"root_filesystem_total_bytes bigint NOT NULL",
		"root_filesystem_used_bytes bigint NOT NULL",
		"root_filesystem_available_bytes bigint NOT NULL",
		"network_receive_bytes_total bigint NOT NULL",
		"network_transmit_bytes_total bigint NOT NULL",
		"uptime_seconds bigint NOT NULL",
		"sample_window_ms bigint NOT NULL",
		"reported_at timestamptz NOT NULL DEFAULT now()",
		"CONSTRAINT agent_telemetry_cpu_usage_basis_points_check",
		"CONSTRAINT agent_telemetry_memory_total_bytes_check",
		"CONSTRAINT agent_telemetry_memory_available_bytes_check",
		"CONSTRAINT agent_telemetry_memory_used_bytes_check",
		"CONSTRAINT agent_telemetry_load_1m_milli_check",
		"CONSTRAINT agent_telemetry_load_5m_milli_check",
		"CONSTRAINT agent_telemetry_load_15m_milli_check",
		"CONSTRAINT agent_telemetry_root_filesystem_total_bytes_check",
		"CONSTRAINT agent_telemetry_root_filesystem_used_bytes_check",
		"CONSTRAINT agent_telemetry_root_filesystem_available_bytes_check",
		"CONSTRAINT agent_telemetry_network_receive_bytes_total_check",
		"CONSTRAINT agent_telemetry_network_transmit_bytes_total_check",
		"CONSTRAINT agent_telemetry_uptime_seconds_check",
		"CONSTRAINT agent_telemetry_sample_window_ms_check",
		"---- create above / drop below ----",
		"DROP TABLE stackpilot.agent_telemetry;",
	}
	for _, clause := range requiredClauses006 {
		if !strings.Contains(sql006, clause) {
			t.Errorf("migration 006 missing required clause %q", clause)
		}
	}

	normalized006 := strings.ToLower(sql006)
	prohibitedKeywords006 := []string{
		"jsonb",
		"raw_payload",
		"history",
		"timescale",
		"prometheus",
		"collected_at",
		"client_timestamp",
	}
	for _, keyword := range prohibitedKeywords006 {
		if strings.Contains(normalized006, keyword) {
			t.Errorf("migration 006 contains prohibited term %q", keyword)
		}
	}

	parts006 := strings.Split(sql006, "---- create above / drop below ----")
	if len(parts006) == 2 && strings.Contains(strings.ToLower(parts006[1]), "cascade") {
		t.Errorf("migration 006 drop statement must not use CASCADE: %s", parts006[1])
	}

	// Verify migration 007 contents
	content007, err := migrationsFS.ReadFile("migrations/" + expected007)
	if err != nil {
		t.Fatalf("failed to read %s: %v", expected007, err)
	}
	sql007 := string(content007)
	requiredClauses007 := []string{
		"CREATE TABLE stackpilot.operators",
		"id uuid PRIMARY KEY DEFAULT uuidv7()",
		"username text NOT NULL UNIQUE",
		"password_hash text NOT NULL",
		"role text NOT NULL",
		"disabled_at timestamptz NULL",
		"created_at timestamptz NOT NULL DEFAULT now()",
		"updated_at timestamptz NOT NULL DEFAULT now()",
		"CONSTRAINT operators_username_length CHECK (char_length(username) >= 3 AND char_length(username) <= 64)",
		"CONSTRAINT operators_username_format CHECK (username ~ '^[a-z0-9][a-z0-9._-]{2,63}$')",
		"CONSTRAINT operators_password_hash_length CHECK (char_length(password_hash) >= 50 AND char_length(password_hash) <= 256)",
		"CONSTRAINT operators_role_check CHECK (role IN ('viewer', 'operator', 'admin'))",
		"---- create above / drop below ----",
		"DROP TABLE stackpilot.operators;",
	}
	for _, clause := range requiredClauses007 {
		if !strings.Contains(sql007, clause) {
			t.Errorf("migration 007 missing required clause %q", clause)
		}
	}
	parts007 := strings.Split(sql007, "---- create above / drop below ----")
	if len(parts007) == 2 && strings.Contains(strings.ToLower(parts007[1]), "cascade") {
		t.Errorf("migration 007 drop statement must not use CASCADE: %s", parts007[1])
	}
	if strings.Contains(strings.ToLower(sql007), "citext") {
		t.Errorf("migration 007 must not use CITEXT: %s", sql007)
	}

	// Verify migration 008 contents
	content008, err := migrationsFS.ReadFile("migrations/" + expected008)
	if err != nil {
		t.Fatalf("failed to read %s: %v", expected008, err)
	}
	sql008 := string(content008)
	requiredClauses008 := []string{
		"CREATE TABLE stackpilot.operator_sessions",
		"id uuid PRIMARY KEY DEFAULT uuidv7()",
		"operator_id uuid NOT NULL REFERENCES stackpilot.operators(id) ON DELETE CASCADE",
		"token_hash bytea NOT NULL UNIQUE",
		"created_at timestamptz NOT NULL DEFAULT now()",
		"expires_at timestamptz NOT NULL",
		"CONSTRAINT operator_sessions_token_hash_length CHECK (octet_length(token_hash) = 32)",
		"CONSTRAINT operator_sessions_expires_at_check CHECK (expires_at > created_at)",
		"CREATE INDEX operator_sessions_operator_id_idx ON stackpilot.operator_sessions(operator_id);",
		"CREATE INDEX operator_sessions_expires_at_idx ON stackpilot.operator_sessions(expires_at);",
		"---- create above / drop below ----",
		"DROP TABLE stackpilot.operator_sessions;",
	}
	for _, clause := range requiredClauses008 {
		if !strings.Contains(sql008, clause) {
			t.Errorf("migration 008 missing required clause %q", clause)
		}
	}
	parts008 := strings.Split(sql008, "---- create above / drop below ----")
	if len(parts008) == 2 && strings.Contains(strings.ToLower(parts008[1]), "cascade") {
		t.Errorf("migration 008 drop statement must not use CASCADE: %s", parts008[1])
	}

	// Verify migration 009 contents
	content009, err := migrationsFS.ReadFile("migrations/" + expected009)
	if err != nil {
		t.Fatalf("failed to read %s: %v", expected009, err)
	}
	sql009 := string(content009)
	requiredClauses009 := []string{
		"CREATE TABLE stackpilot.operator_audit_events",
		"id uuid PRIMARY KEY DEFAULT uuidv7()",
		"actor_operator_id uuid NULL REFERENCES stackpilot.operators(id) ON DELETE SET NULL",
		"actor_username text NOT NULL",
		"action text NOT NULL",
		"target_operator_id uuid NULL REFERENCES stackpilot.operators(id) ON DELETE SET NULL",
		"target_username text NULL",
		"outcome text NOT NULL",
		"occurred_at timestamptz NOT NULL DEFAULT now()",
		"CONSTRAINT operator_audit_events_actor_username_length CHECK (char_length(actor_username) >= 1 AND char_length(actor_username) <= 64)",
		"CONSTRAINT operator_audit_events_action_length CHECK (char_length(action) >= 1 AND char_length(action) <= 64)",
		"CONSTRAINT operator_audit_events_action_format CHECK (action ~ '^[a-z0-9._-]+$')",
		"CONSTRAINT operator_audit_events_target_username_length CHECK (target_username IS NULL OR (char_length(target_username) >= 1 AND char_length(target_username) <= 64))",
		"CONSTRAINT operator_audit_events_outcome_check CHECK (outcome IN ('success', 'failure', 'denied'))",
		"CREATE INDEX operator_audit_events_occurred_at_idx ON stackpilot.operator_audit_events(occurred_at DESC, id DESC);",
		"CREATE INDEX operator_audit_events_actor_operator_id_idx ON stackpilot.operator_audit_events(actor_operator_id);",
		"---- create above / drop below ----",
		"DROP TABLE stackpilot.operator_audit_events;",
	}
	for _, clause := range requiredClauses009 {
		if !strings.Contains(sql009, clause) {
			t.Errorf("migration 009 missing required clause %q", clause)
		}
	}
	parts009 := strings.Split(sql009, "---- create above / drop below ----")
	if len(parts009) == 2 && strings.Contains(strings.ToLower(parts009[1]), "cascade") {
		t.Errorf("migration 009 drop statement must not use CASCADE: %s", parts009[1])
	}
	normalized009 := strings.ToLower(sql009)
	if strings.Contains(normalized009, "json") {
		t.Errorf("migration 009 must not contain JSON/JSONB: %s", sql009)
	}

	// Verify migration 010 contents
	content010, err := migrationsFS.ReadFile("migrations/" + expected010)
	if err != nil {
		t.Fatalf("failed to read %s: %v", expected010, err)
	}
	sql010 := string(content010)
	requiredClauses010 := []string{
		"CREATE TABLE stackpilot.jobs",
		"id uuid PRIMARY KEY DEFAULT uuidv7()",
		"agent_id uuid NOT NULL REFERENCES stackpilot.agents(id) ON DELETE RESTRICT",
		"created_by_operator_id uuid NOT NULL REFERENCES stackpilot.operators(id) ON DELETE RESTRICT",
		"created_by_username text NOT NULL",
		"idempotency_key_hash bytea NOT NULL",
		"action_type text NOT NULL",
		"state text NOT NULL",
		"attempt integer NOT NULL DEFAULT 0",
		"failure_code text NULL",
		"created_at timestamptz NOT NULL DEFAULT now()",
		"updated_at timestamptz NOT NULL DEFAULT now()",
		"CONSTRAINT jobs_created_by_username_length",
		"CONSTRAINT jobs_created_by_username_format",
		"CONSTRAINT jobs_idempotency_key_hash_length",
		"CONSTRAINT jobs_action_type_check CHECK (action_type IN ('agent.ping'))",
		"CONSTRAINT jobs_state_check CHECK (state IN ('queued', 'dispatched', 'running', 'succeeded', 'failed', 'unknown'))",
		"CONSTRAINT jobs_attempt_range CHECK (attempt >= 0 AND attempt <= 5)",
		"CONSTRAINT jobs_failure_code_check",
		"CONSTRAINT jobs_state_failure_code_consistency",
		"CONSTRAINT jobs_finished_at_consistency",
		"CREATE INDEX jobs_claim_idx ON stackpilot.jobs (agent_id, state, created_at, id);",
		"CREATE INDEX jobs_listing_idx ON stackpilot.jobs (created_at DESC, id DESC);",
		"CREATE INDEX jobs_creator_idx ON stackpilot.jobs (created_by_operator_id);",
		"CREATE UNIQUE INDEX jobs_idempotency_idx ON stackpilot.jobs (created_by_operator_id, idempotency_key_hash);",
		"CREATE UNIQUE INDEX jobs_agent_inflight_idx ON stackpilot.jobs (agent_id) WHERE state IN ('dispatched', 'running');",
		"---- create above / drop below ----",
		"DROP TABLE stackpilot.jobs;",
	}
	for _, clause := range requiredClauses010 {
		if !strings.Contains(sql010, clause) {
			t.Errorf("migration 010 missing required clause %q", clause)
		}
	}
	parts010 := strings.Split(sql010, "---- create above / drop below ----")
	if len(parts010) == 2 && strings.Contains(strings.ToLower(parts010[1]), "cascade") {
		t.Errorf("migration 010 drop statement must not use CASCADE: %s", parts010[1])
	}
	normalized010 := strings.ToLower(sql010)
	if strings.Contains(normalized010, "json") {
		t.Errorf("migration 010 must not contain JSON/JSONB: %s", sql010)
	}

	// Verify migration 011 contents
	content011, err := migrationsFS.ReadFile("migrations/" + expected011)
	if err != nil {
		t.Fatalf("failed to read %s: %v", expected011, err)
	}
	sql011 := string(content011)
	requiredClauses011 := []string{
		"CREATE TABLE stackpilot.job_events",
		"id uuid PRIMARY KEY DEFAULT uuidv7()",
		"job_id uuid NOT NULL REFERENCES stackpilot.jobs(id) ON DELETE CASCADE",
		"event_type text NOT NULL",
		"attempt integer NOT NULL",
		"actor_type text NOT NULL",
		"actor_identifier text NOT NULL",
		"failure_code text NULL",
		"occurred_at timestamptz NOT NULL DEFAULT now()",
		"CONSTRAINT job_events_event_type_check",
		"CONSTRAINT job_events_actor_type_check",
		"CONSTRAINT job_events_attempt_range",
		"CONSTRAINT job_events_failure_code_check",
		"CONSTRAINT job_events_actor_identifier_length",
		"CONSTRAINT job_events_actor_identifier_shape",
		"CREATE INDEX job_events_job_id_occurred_at_idx ON stackpilot.job_events (job_id, occurred_at ASC, id ASC);",
		"---- create above / drop below ----",
		"DROP TABLE stackpilot.job_events;",
	}
	for _, clause := range requiredClauses011 {
		if !strings.Contains(sql011, clause) {
			t.Errorf("migration 011 missing required clause %q", clause)
		}
	}
	parts011 := strings.Split(sql011, "---- create above / drop below ----")
	if len(parts011) == 2 && strings.Contains(strings.ToLower(parts011[1]), "cascade") {
		t.Errorf("migration 011 drop statement must not use CASCADE: %s", parts011[1])
	}
	normalized011 := strings.ToLower(sql011)
	if strings.Contains(normalized011, "json") {
		t.Errorf("migration 011 must not contain JSON/JSONB: %s", sql011)
	}

	// Verify migration 012 contents
	content012, err := migrationsFS.ReadFile("migrations/" + expected012)
	if err != nil {
		t.Fatalf("failed to read %s: %v", expected012, err)
	}
	sql012 := string(content012)
	requiredClauses012 := []string{
		"ALTER TABLE stackpilot.operator_audit_events",
		"ADD COLUMN target_job_id uuid NULL REFERENCES stackpilot.jobs(id) ON DELETE SET NULL;",
		"ADD CONSTRAINT operator_audit_events_target_mutual_exclusion",
		"CHECK (target_operator_id IS NULL OR target_job_id IS NULL);",
		"---- create above / drop below ----",
		"DROP CONSTRAINT IF EXISTS operator_audit_events_target_mutual_exclusion;",
		"DROP COLUMN IF EXISTS target_job_id;",
	}
	for _, clause := range requiredClauses012 {
		if !strings.Contains(sql012, clause) {
			t.Errorf("migration 012 missing required clause %q", clause)
		}
	}
	parts012 := strings.Split(sql012, "---- create above / drop below ----")
	if len(parts012) == 2 && strings.Contains(strings.ToLower(parts012[1]), "cascade") {
		t.Errorf("migration 012 drop statement must not use CASCADE: %s", parts012[1])
	}
}

func TestProhibitedKeywordsGuard_Detection(t *testing.T) {
	prohibitedKeywords := []string{
		"cascade",
		"plaintext",
		"secret",
		"token text",
		"token varchar",
	}

	cases := []struct {
		input           string
		expectedBlocked bool
		keyword         string
	}{
		{"DROP SCHEMA stackpilot CASCADE;", true, "cascade"},
		{"DROP TABLE t cascade;", true, "cascade"},
		{"DROP TABLE t CasCade;", true, "cascade"},
		{"token PLAINTEXT not allowed", true, "plaintext"},
		{"top SECRET column", true, "secret"},
		{"column token TEXT not allowed", true, "token text"},
		{"column token VARCHAR(255)", true, "token varchar"},
		{"token_hash bytea NOT NULL UNIQUE", false, ""},
	}

	for _, tc := range cases {
		normalized := strings.ToLower(tc.input)
		var matched string
		for _, kw := range prohibitedKeywords {
			if strings.Contains(normalized, kw) {
				matched = kw
				break
			}
		}
		if tc.expectedBlocked && matched != tc.keyword {
			t.Errorf("input %q: expected match %q, got %q", tc.input, tc.keyword, matched)
		}
		if !tc.expectedBlocked && matched != "" {
			t.Errorf("input %q: expected no match, got %q", tc.input, matched)
		}
	}
}
