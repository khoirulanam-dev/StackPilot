package database

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
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

	// 5. Verify migration version is 4 (migrations 001, 002, 003, 004 applied)
	var version int32
	err = db.pool.QueryRow(ctx, "SELECT version FROM public.stackpilot_schema_version").Scan(&version)
	if err != nil {
		t.Fatalf("failed to query schema version: %v", err)
	}
	if version != 4 {
		t.Fatalf("expected schema version 4, got %d", version)
	}

	// 6. Run migration again (verify idempotence)
	if err := db.Migrate(ctx, nil); err != nil {
		t.Fatalf("second migration run failed: %v", err)
	}

	// 7. Verify version remains 4
	err = db.pool.QueryRow(ctx, "SELECT version FROM public.stackpilot_schema_version").Scan(&version)
	if err != nil {
		t.Fatalf("failed to query schema version after second run: %v", err)
	}
	if version != 4 {
		t.Fatalf("expected schema version to remain 4, got %d", version)
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

	var tokenColumns []string
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			t.Fatalf("failed to scan column name: %v", err)
		}
		tokenColumns = append(tokenColumns, col)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows iteration error: %v", err)
	}

	expectedTokenColumns := map[string]bool{
		"id":          true,
		"token_hash":  true,
		"created_at":  true,
		"expires_at":  true,
		"consumed_at": true,
	}
	if len(tokenColumns) != len(expectedTokenColumns) {
		t.Fatalf("expected %d columns, got %d: %v", len(expectedTokenColumns), len(tokenColumns), tokenColumns)
	}
	for _, col := range tokenColumns {
		if !expectedTokenColumns[col] {
			t.Errorf("unexpected column %q found in enrollment_tokens table", col)
		}
		if col == "token" || col == "plaintext" || col == "secret" {
			t.Errorf("prohibited plaintext secret column %q found in enrollment_tokens", col)
		}
	}

	// 9. Verify table columns in stackpilot.agents
	agentRows, err := db.pool.Query(ctx, `
		SELECT column_name
		FROM information_schema.columns
		WHERE table_schema = 'stackpilot' AND table_name = 'agents'
		ORDER BY ordinal_position
	`)
	if err != nil {
		t.Fatalf("failed to query columns of agents: %v", err)
	}
	defer agentRows.Close()

	var agentColumns []string
	for agentRows.Next() {
		var col string
		if err := agentRows.Scan(&col); err != nil {
			t.Fatalf("failed to scan column name: %v", err)
		}
		agentColumns = append(agentColumns, col)
	}
	if err := agentRows.Err(); err != nil {
		t.Fatalf("rows iteration error: %v", err)
	}

	expectedAgentColumns := map[string]bool{
		"id":                  true,
		"public_key":          true,
		"enrollment_token_id": true,
		"created_at":          true,
		"last_seen_at":        true,
		"protocol_version":    true,
	}
	if len(agentColumns) != len(expectedAgentColumns) {
		t.Fatalf("expected %d columns in agents, got %d: %v", len(expectedAgentColumns), len(agentColumns), agentColumns)
	}
	for _, col := range agentColumns {
		if !expectedAgentColumns[col] {
			t.Errorf("unexpected column %q found in agents table", col)
		}
		if col == "token" || col == "private_key" || col == "secret" || col == "password" {
			t.Errorf("prohibited column %q found in agents table", col)
		}
	}

	// 10. Issue enrollment token using real creation workflow
	startTime := time.Now()
	plaintextToken, err := enrollment.IssueToken(ctx, db)
	if err != nil {
		t.Fatalf("IssueToken failed: %v", err)
	}
	if !strings.HasPrefix(plaintextToken, enrollment.TokenPrefix) {
		t.Fatal("issued token does not have expected prefix")
	}

	tokenHash := enrollment.HashToken(plaintextToken)

	// Generate two Ed25519 keypairs
	pubKeyA, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key A: %v", err)
	}
	var keyA [32]byte
	copy(keyA[:], pubKeyA)

	pubKeyB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key B: %v", err)
	}
	var keyB [32]byte
	copy(keyB[:], pubKeyB)

	// 11. Test first enrollment (token + key A) -> success, created == true
	agentA, created, err := db.RegisterAgent(ctx, tokenHash, keyA)
	if err != nil {
		t.Fatalf("RegisterAgent with key A failed: %v", err)
	}
	if !created {
		t.Fatal("expected created == true for first registration")
	}
	if len(agentA.ID) != 36 || agentA.ID[14] != '7' {
		t.Errorf("expected Agent ID to be UUIDv7 (char 14 == '7'), got %q", agentA.ID)
	}
	if !bytes.Equal(agentA.PublicKey[:], keyA[:]) {
		t.Fatal("registered agent public key does not match key A")
	}

	// Verify token row now has consumed_at NOT NULL
	var (
		tokenRowID string
		consumedAt sql.NullTime
	)
	err = db.pool.QueryRow(ctx, "SELECT id::text, consumed_at FROM stackpilot.enrollment_tokens WHERE token_hash = $1", tokenHash[:]).Scan(&tokenRowID, &consumedAt)
	if err != nil {
		t.Fatalf("failed to query token row: %v", err)
	}
	if !consumedAt.Valid {
		t.Fatal("expected consumed_at to be NOT NULL after successful enrollment")
	}

	// Verify stackpilot.agents references the consumed token
	var storedTokenID string
	err = db.pool.QueryRow(ctx, "SELECT enrollment_token_id::text FROM stackpilot.agents WHERE id = $1::uuid", agentA.ID).Scan(&storedTokenID)
	if err != nil {
		t.Fatalf("failed to query agent enrollment_token_id: %v", err)
	}
	if storedTokenID != tokenRowID {
		t.Fatalf("expected agent enrollment_token_id %q, got %q", tokenRowID, storedTokenID)
	}

	// 12. Idempotent Retry: same token + same key A -> returns same Agent ID, created == false
	agentRetry, createdRetry, err := db.RegisterAgent(ctx, tokenHash, keyA)
	if err != nil {
		t.Fatalf("idempotent retry failed: %v", err)
	}
	if createdRetry {
		t.Fatal("expected created == false for idempotent retry")
	}
	if agentRetry.ID != agentA.ID {
		t.Fatalf("expected same agent ID %q on idempotent retry, got %q", agentA.ID, agentRetry.ID)
	}

	// Verify agent count for this token is still exactly 1
	var agentCount int
	err = db.pool.QueryRow(ctx, "SELECT count(*) FROM stackpilot.agents WHERE enrollment_token_id = $1::uuid", tokenRowID).Scan(&agentCount)
	if err != nil {
		t.Fatalf("failed to count agents: %v", err)
	}
	if agentCount != 1 {
		t.Fatalf("expected exactly 1 agent row, got %d", agentCount)
	}

	// 13. Idempotent Retry AFTER Expiration (Finding 9):
	// Set the consumed token's expires_at into the past
	_, err = db.pool.Exec(ctx, "UPDATE stackpilot.enrollment_tokens SET expires_at = now() - interval '1 hour' WHERE id = $1::uuid", tokenRowID)
	if err != nil {
		t.Fatalf("failed to expire consumed token: %v", err)
	}

	// Retrying with the same key A must still succeed and return the existing Agent
	agentRetryExpired, createdRetryExpired, err := db.RegisterAgent(ctx, tokenHash, keyA)
	if err != nil {
		t.Fatalf("idempotent retry after expiration failed: %v", err)
	}
	if createdRetryExpired {
		t.Fatal("expected created == false for idempotent retry after expiration")
	}
	if agentRetryExpired.ID != agentA.ID {
		t.Fatalf("expected same agent ID %q on idempotent retry after expiration, got %q", agentA.ID, agentRetryExpired.ID)
	}

	// Same consumed-and-now-expired token with DIFFERENT key B: MUST be rejected
	_, _, err = db.RegisterAgent(ctx, tokenHash, keyB)
	if err == nil {
		t.Fatal("expected enrollment rejection for consumed-and-expired token with different key, got nil")
	}
	if !errors.Is(err, enrollment.ErrEnrollmentRejected) {
		t.Fatalf("expected ErrEnrollmentRejected, got: %v", err)
	}

	// 14. Expired token rejection: unconsumed token with expires_at in the past
	expiredPlaintext, err := enrollment.IssueToken(ctx, db)
	if err != nil {
		t.Fatalf("failed to issue token for expired test: %v", err)
	}
	expiredHash := enrollment.HashToken(expiredPlaintext)

	_, err = db.pool.Exec(ctx, `
		UPDATE stackpilot.enrollment_tokens
		SET expires_at = now() - interval '30 minutes'
		WHERE token_hash = $1
	`, expiredHash[:])
	if err != nil {
		t.Fatalf("failed to update expired test token: %v", err)
	}

	_, _, err = db.RegisterAgent(ctx, expiredHash, keyB)
	if err == nil {
		t.Fatal("expected enrollment rejection for expired token, got nil")
	}
	if !errors.Is(err, enrollment.ErrEnrollmentRejected) {
		t.Fatalf("expected ErrEnrollmentRejected for expired token, got: %v", err)
	}

	// 15. Concurrency integration test: race two different public keys against the same valid token
	concPlaintext, err := enrollment.IssueToken(ctx, db)
	if err != nil {
		t.Fatalf("failed to issue token for concurrency test: %v", err)
	}
	concHash := enrollment.HashToken(concPlaintext)

	pubKeyC, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key C: %v", err)
	}
	var keyC [32]byte
	copy(keyC[:], pubKeyC)

	pubKeyD, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key D: %v", err)
	}
	var keyD [32]byte
	copy(keyD[:], pubKeyD)

	type concResult struct {
		record  *enrollment.AgentRecord
		created bool
		err     error
	}

	startBarrier := make(chan struct{})
	results := make(chan concResult, 2)

	for _, k := range [][32]byte{keyC, keyD} {
		pub := k
		go func() {
			<-startBarrier
			rec, created, regErr := db.RegisterAgent(ctx, concHash, pub)
			results <- concResult{record: rec, created: created, err: regErr}
		}()
	}

	// Release both goroutines simultaneously
	close(startBarrier)

	r1 := <-results
	r2 := <-results

	var (
		winsCount   int
		rejectCount int
	)
	for _, res := range []concResult{r1, r2} {
		if res.err == nil && res.created {
			winsCount++
		} else if errors.Is(res.err, enrollment.ErrEnrollmentRejected) {
			rejectCount++
		}
	}

	if winsCount != 1 || rejectCount != 1 {
		t.Fatalf("concurrency test failed: expected 1 winner and 1 rejection, got %d winners and %d rejections", winsCount, rejectCount)
	}

	// 16. M0.6: FindAgentByPublicKey
	// 16a. Lookup existing agentA
	foundAgent, err := db.FindAgentByPublicKey(ctx, keyA)
	if err != nil {
		t.Fatalf("failed to find agentA by public key: %v", err)
	}
	if foundAgent.ID != agentA.ID {
		t.Fatalf("expected agent ID %q, got %q", agentA.ID, foundAgent.ID)
	}
	if !bytes.Equal(foundAgent.PublicKey[:], keyA[:]) {
		t.Fatalf("expected public key to match keyA")
	}

	// 16b. Lookup unknown random public key -> ErrAgentNotFound
	pubKeyUnknown, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate unknown key: %v", err)
	}
	var keyUnknown [32]byte
	copy(keyUnknown[:], pubKeyUnknown)

	_, err = db.FindAgentByPublicKey(ctx, keyUnknown)
	if err == nil {
		t.Fatal("expected ErrAgentNotFound for unknown public key, got nil")
	}
	if !errors.Is(err, enrollment.ErrAgentNotFound) {
		t.Fatalf("expected ErrAgentNotFound, got: %v", err)
	}

	// 17. M0.7: Presence & Heartbeat Foundation
	// 17a. Create a fresh randomized Agent for heartbeat testing
	plaintextTokenH, err := enrollment.IssueToken(ctx, db)
	if err != nil {
		t.Fatalf("failed to issue enrollment token for agentH: %v", err)
	}
	hashH := enrollment.HashToken(plaintextTokenH)

	pubKeyH, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key for agentH: %v", err)
	}
	var keyH [32]byte
	copy(keyH[:], pubKeyH)

	agentH, createdH, err := db.RegisterAgent(ctx, hashH, keyH)
	if err != nil || !createdH {
		t.Fatalf("failed to register agentH: %v", err)
	}

	// Verify before heartbeat: last_seen_at IS NULL, protocol_version IS NULL
	foundBeforeH, err := db.FindAgentByPublicKey(ctx, keyH)
	if err != nil {
		t.Fatalf("failed to lookup agentH before heartbeat: %v", err)
	}
	if foundBeforeH.LastSeenAt != nil {
		t.Fatalf("expected last_seen_at to be nil before first heartbeat, got %v", foundBeforeH.LastSeenAt)
	}
	if foundBeforeH.ProtocolVersion != nil {
		t.Fatalf("expected protocol_version to be nil before first heartbeat, got %v", foundBeforeH.ProtocolVersion)
	}

	// Record first heartbeat with protocol_version 1
	recH1, err := db.RecordAgentHeartbeat(ctx, keyH, 1)
	if err != nil {
		t.Fatalf("RecordAgentHeartbeat failed on first heartbeat: %v", err)
	}
	if recH1.ID != agentH.ID {
		t.Fatalf("expected agent ID %q, got %q", agentH.ID, recH1.ID)
	}
	if recH1.LastSeenAt == nil {
		t.Fatal("expected last_seen_at to be non-nil after first heartbeat")
	}
	if recH1.ProtocolVersion == nil || *recH1.ProtocolVersion != 1 {
		t.Fatalf("expected protocol_version to be 1, got %v", recH1.ProtocolVersion)
	}

	firstSeenAt := *recH1.LastSeenAt

	// Record second heartbeat
	recH2, err := db.RecordAgentHeartbeat(ctx, keyH, 1)
	if err != nil {
		t.Fatalf("RecordAgentHeartbeat failed on second heartbeat: %v", err)
	}
	if recH2.LastSeenAt == nil {
		t.Fatal("expected last_seen_at to be non-nil after second heartbeat")
	}
	if recH2.LastSeenAt.Before(firstSeenAt) {
		t.Fatalf("expected second last_seen_at (%v) to be >= first (%v)", recH2.LastSeenAt, firstSeenAt)
	}

	// 17b. Unknown public key heartbeat returns safe ErrAgentNotFound
	pubKeyUnknownH, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}
	var keyUnknownH [32]byte
	copy(keyUnknownH[:], pubKeyUnknownH)

	_, err = db.RecordAgentHeartbeat(ctx, keyUnknownH, 1)
	if err == nil {
		t.Fatal("expected error for unknown public key heartbeat, got nil")
	}
	if !errors.Is(err, enrollment.ErrAgentNotFound) {
		t.Fatalf("expected ErrAgentNotFound for unknown public key heartbeat, got %v", err)
	}
	if strings.Contains(err.Error(), "pgx") || strings.Contains(err.Error(), "sql") {
		t.Fatalf("raw pgx/sql error leaked in error message: %v", err)
	}

	// Ensure database created_at is reasonable
	if startTime.After(time.Now().Add(5 * time.Second)) {
		t.Errorf("startTime out of reasonable range")
	}
}
