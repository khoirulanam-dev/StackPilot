package database

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"stackpilot/internal/enrollment"
)

func TestPostgreSQLIntegration(t *testing.T) {
	testURL, ok := os.LookupEnv("STACKPILOT_TEST_DATABASE_URL")
	if !ok || testURL == "" {
		t.Skip("skipping integration test: STACKPILOT_TEST_DATABASE_URL not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Connect and 2. Ping successfully
	db, err := Open(ctx, testURL)
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(ctx); err != nil {
		t.Fatalf("database ping failed: %v", err)
	}

	// 3. Run migrations
	if err := db.Migrate(ctx, nil); err != nil {
		t.Fatalf("first migration failed: %v", err)
	}

	// 4. Verify schema 'stackpilot' exists
	var schemaExists bool
	err = db.pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM information_schema.schemata WHERE schema_name = 'stackpilot')").Scan(&schemaExists)
	if err != nil {
		t.Fatalf("failed to query schema existence: %v", err)
	}
	if !schemaExists {
		t.Fatal("expected schema 'stackpilot' to exist, but it was not found")
	}

	// 5. Verify migration version is 2 (migration 001 and 002 applied)
	var version int32
	err = db.pool.QueryRow(ctx, "SELECT version FROM public.stackpilot_schema_version").Scan(&version)
	if err != nil {
		t.Fatalf("failed to query schema version: %v", err)
	}
	if version != 2 {
		t.Fatalf("expected schema version 2, got %d", version)
	}

	// 6. Run migration again (verify idempotence)
	if err := db.Migrate(ctx, nil); err != nil {
		t.Fatalf("second migration run failed: %v", err)
	}

	// 7. Verify version remains 2
	err = db.pool.QueryRow(ctx, "SELECT version FROM public.stackpilot_schema_version").Scan(&version)
	if err != nil {
		t.Fatalf("failed to query schema version after second run: %v", err)
	}
	if version != 2 {
		t.Fatalf("expected schema version to remain 2, got %d", version)
	}

	// 8. Verify table columns in stackpilot.enrollment_tokens (plaintext storage verification)
	rows, err := db.pool.Query(ctx, `
		SELECT column_name
		FROM information_schema.columns
		WHERE table_schema = 'stackpilot' AND table_name = 'enrollment_tokens'
		ORDER BY ordinal_position
	`)
	if err != nil {
		t.Fatalf("failed to query columns of enrollment_tokens: %v", err)
	}
	defer rows.Close()

	var columns []string
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			t.Fatalf("failed to scan column name: %v", err)
		}
		columns = append(columns, col)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows iteration error: %v", err)
	}

	expectedColumns := map[string]bool{
		"id":          true,
		"token_hash":  true,
		"created_at":  true,
		"expires_at":  true,
		"consumed_at": true,
	}
	if len(columns) != len(expectedColumns) {
		t.Fatalf("expected %d columns, got %d: %v", len(expectedColumns), len(columns), columns)
	}
	for _, col := range columns {
		if !expectedColumns[col] {
			t.Errorf("unexpected column %q found in enrollment_tokens table", col)
		}
		if col == "token" || col == "plaintext" || col == "secret" {
			t.Errorf("prohibited plaintext secret column %q found in enrollment_tokens", col)
		}
	}

	// 9. Issue enrollment token using real creation workflow
	startTime := time.Now()
	plaintextToken, err := enrollment.IssueToken(ctx, db)
	if err != nil {
		t.Fatalf("IssueToken failed: %v", err)
	}
	if !strings.HasPrefix(plaintextToken, enrollment.TokenPrefix) {
		t.Fatal("issued token does not have expected prefix")
	}

	expectedHash := enrollment.HashToken(plaintextToken)

	// 10. Query the inserted token record by hash
	var (
		rowID      string
		storedHash []byte
		createdAt  time.Time
		expiresAt  time.Time
		consumedAt sql.NullTime
	)
	err = db.pool.QueryRow(ctx, `
		SELECT id::text, token_hash, created_at, expires_at, consumed_at
		FROM stackpilot.enrollment_tokens
		WHERE token_hash = $1
	`, expectedHash[:]).Scan(&rowID, &storedHash, &createdAt, &expiresAt, &consumedAt)
	if err != nil {
		t.Fatalf("failed to query inserted enrollment token by hash: %v", err)
	}

	// Verify stored token_hash is 32 bytes and equals SHA-256 of plaintext
	if len(storedHash) != 32 {
		t.Fatalf("expected stored token_hash length 32, got %d", len(storedHash))
	}
	if !bytes.Equal(storedHash, expectedHash[:]) {
		t.Fatal("stored token hash does not match SHA-256 of issued token")
	}

	// Verify consumed_at IS NULL
	if consumedAt.Valid {
		t.Errorf("expected consumed_at to be NULL, got %v", consumedAt.Time)
	}

	// Verify expires_at is approximately 15 minutes after created_at
	expectedExpiry := createdAt.Add(enrollment.TokenLifetime)
	expiryDiff := expiresAt.Sub(expectedExpiry)
	if expiryDiff < -5*time.Second || expiryDiff > 5*time.Second {
		t.Errorf("expires_at %v deviates significantly from expected %v (diff: %v)", expiresAt, expectedExpiry, expiryDiff)
	}

	// Verify created_at is reasonable
	if createdAt.Before(startTime.Add(-5*time.Second)) || createdAt.After(time.Now().Add(5*time.Second)) {
		t.Errorf("created_at %v out of reasonable range", createdAt)
	}

	// Verify row ID is UUID version 7
	// Canonical UUID format: 8-4-4-4-12 hex digits. The version digit is character 14 (0-indexed).
	// In UUIDv7, that character is '7'.
	if len(rowID) != 36 || rowID[14] != '7' {
		t.Errorf("expected row ID to be UUIDv7 (char 14 == '7'), got %q", rowID)
	}
}
