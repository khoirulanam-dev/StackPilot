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

	if len(migrations) != 4 {
		t.Fatalf("expected exactly 4 migrations, got %d", len(migrations))
	}

	// Verify exact migration order
	expected001 := "001_create_stackpilot_schema.sql"
	expected002 := "002_create_enrollment_tokens.sql"
	expected003 := "003_create_agents.sql"
	expected004 := "004_add_agent_presence.sql"

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
