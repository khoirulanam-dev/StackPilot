package database

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"stackpilot/internal/enrollment"
	"stackpilot/internal/job"
	"stackpilot/internal/operator"
	"stackpilot/internal/protocol"

	"github.com/google/uuid"
)

func TestPostgreSQLIntegration(t *testing.T) {
	testURL, ok := os.LookupEnv("STACKPILOT_TEST_DATABASE_URL")
	if !ok || testURL == "" {
		t.Log("PostgreSQL integration SKIPPED")
		t.Skip("PostgreSQL integration SKIPPED: STACKPILOT_TEST_DATABASE_URL not set")
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

	// 5. Verify migration version is 12 (migrations 001-012 applied)
	var version int32
	err = db.pool.QueryRow(ctx, "SELECT version FROM public.stackpilot_schema_version").Scan(&version)
	if err != nil {
		t.Fatalf("failed to query schema version: %v", err)
	}
	if version != 12 {
		t.Fatalf("expected schema version 12, got %d", version)
	}

	// 6. Run db.Migrate() a second time (idempotency check)
	err = db.Migrate(ctx, nil)
	if err != nil {
		t.Fatalf("second db.Migrate() failed: %v", err)
	}

	// 7. Verify version remains 12
	err = db.pool.QueryRow(ctx, "SELECT version FROM public.stackpilot_schema_version").Scan(&version)
	if err != nil {
		t.Fatalf("failed to query schema version after second run: %v", err)
	}
	if version != 12 {
		t.Fatalf("expected schema version to remain 12, got %d", version)
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
	recH1, hasActive1, err := db.RecordAgentHeartbeat(ctx, keyH, 1)
	if err != nil {
		t.Fatalf("RecordAgentHeartbeat failed on first heartbeat: %v", err)
	}
	if hasActive1 {
		t.Fatal("expected hasActiveJobs to be false for agent with no jobs")
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
	recH2, hasActive2, err := db.RecordAgentHeartbeat(ctx, keyH, 1)
	if err != nil {
		t.Fatalf("RecordAgentHeartbeat failed on second heartbeat: %v", err)
	}
	if hasActive2 {
		t.Fatal("expected hasActiveJobs to be false for agent with no jobs")
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

	_, _, err = db.RecordAgentHeartbeat(ctx, keyUnknownH, 1)
	if err == nil {
		t.Fatal("expected error for unknown public key heartbeat, got nil")
	}
	if !errors.Is(err, enrollment.ErrAgentNotFound) {
		t.Fatalf("expected ErrAgentNotFound for unknown public key heartbeat, got %v", err)
	}
	if strings.Contains(err.Error(), "pgx") || strings.Contains(err.Error(), "sql") {
		t.Fatalf("raw pgx/sql error leaked in error message: %v", err)
	}

	// Verify no inventory row exists for agent prior to first report
	var initialCount int
	err = db.pool.QueryRow(ctx, "SELECT count(*) FROM stackpilot.agent_inventory WHERE agent_id = $1::uuid", agentH.ID).Scan(&initialCount)
	if err != nil {
		t.Fatalf("failed to query initial agent_inventory count: %v", err)
	}
	if initialCount != 0 {
		t.Fatalf("expected 0 inventory rows before first submission, got %d", initialCount)
	}

	invReq1 := &protocol.InventoryRequest{
		ProtocolVersion:  1,
		Hostname:         "integration-node-01",
		OSID:             "debian",
		OSName:           "Debian GNU/Linux",
		OSVersion:        "12",
		KernelRelease:    "6.1.0-21-amd64",
		Architecture:     "amd64",
		CPULogicalCores:  4,
		MemoryTotalBytes: 8589934592,
	}

	err = db.RecordAgentInventory(ctx, keyH, invReq1)
	if err != nil {
		t.Fatalf("RecordAgentInventory failed on first insert: %v", err)
	}

	// Verify stored columns match the reported inventory payload
	var (
		scannedAgentID   string
		scannedHostname  string
		scannedOSID      string
		scannedOSName    string
		scannedOSVersion string
		scannedKernel    string
		scannedArch      string
		scannedCores     int
		scannedMem       int64
		firstReportedAt  time.Time
	)
	err = db.pool.QueryRow(ctx, `
		SELECT agent_id, hostname, os_id, os_name, os_version, kernel_release, architecture, cpu_logical_cores, memory_total_bytes, reported_at
		FROM stackpilot.agent_inventory
		WHERE agent_id = $1::uuid
	`, agentH.ID).Scan(
		&scannedAgentID,
		&scannedHostname,
		&scannedOSID,
		&scannedOSName,
		&scannedOSVersion,
		&scannedKernel,
		&scannedArch,
		&scannedCores,
		&scannedMem,
		&firstReportedAt,
	)
	if err != nil {
		t.Fatalf("failed to query agent_inventory: %v", err)
	}
	if scannedAgentID != agentH.ID {
		t.Fatalf("expected agent_id %q, got %q", agentH.ID, scannedAgentID)
	}
	if scannedHostname != invReq1.Hostname {
		t.Fatalf("expected hostname %q, got %q", invReq1.Hostname, scannedHostname)
	}
	if scannedOSID != invReq1.OSID {
		t.Fatalf("expected os_id %q, got %q", invReq1.OSID, scannedOSID)
	}
	if scannedOSName != invReq1.OSName {
		t.Fatalf("expected os_name %q, got %q", invReq1.OSName, scannedOSName)
	}
	if scannedOSVersion != invReq1.OSVersion {
		t.Fatalf("expected os_version %q, got %q", invReq1.OSVersion, scannedOSVersion)
	}
	if scannedKernel != invReq1.KernelRelease {
		t.Fatalf("expected kernel_release %q, got %q", invReq1.KernelRelease, scannedKernel)
	}
	if scannedArch != invReq1.Architecture {
		t.Fatalf("expected architecture %q, got %q", invReq1.Architecture, scannedArch)
	}
	if scannedCores != invReq1.CPULogicalCores {
		t.Fatalf("expected cpu_logical_cores %d, got %d", invReq1.CPULogicalCores, scannedCores)
	}
	if scannedMem != invReq1.MemoryTotalBytes {
		t.Fatalf("expected memory_total_bytes %d, got %d", invReq1.MemoryTotalBytes, scannedMem)
	}
	if firstReportedAt.IsZero() {
		t.Fatal("expected non-zero reported_at")
	}

	// Verify complete snapshot replacement: every mutable field is changed on second submission
	invReq2 := &protocol.InventoryRequest{
		ProtocolVersion:  1,
		Hostname:         "integration-node-02-upgraded",
		OSID:             "ubuntu",
		OSName:           "Ubuntu Linux",
		OSVersion:        "24.04",
		KernelRelease:    "6.8.0-40-generic",
		Architecture:     "arm64",
		CPULogicalCores:  16,
		MemoryTotalBytes: 34359738368,
	}
	err = db.RecordAgentInventory(ctx, keyH, invReq2)
	if err != nil {
		t.Fatalf("RecordAgentInventory failed on update: %v", err)
	}

	var (
		scannedAgentID2   string
		scannedHostname2  string
		scannedOSID2      string
		scannedOSName2    string
		scannedOSVersion2 string
		scannedKernel2    string
		scannedArch2      string
		scannedCores2     int
		scannedMem2       int64
		secondReportedAt  time.Time
	)
	err = db.pool.QueryRow(ctx, `
		SELECT agent_id, hostname, os_id, os_name, os_version, kernel_release, architecture, cpu_logical_cores, memory_total_bytes, reported_at
		FROM stackpilot.agent_inventory
		WHERE agent_id = $1::uuid
	`, agentH.ID).Scan(
		&scannedAgentID2,
		&scannedHostname2,
		&scannedOSID2,
		&scannedOSName2,
		&scannedOSVersion2,
		&scannedKernel2,
		&scannedArch2,
		&scannedCores2,
		&scannedMem2,
		&secondReportedAt,
	)
	if err != nil {
		t.Fatalf("failed to query updated agent_inventory: %v", err)
	}

	if scannedAgentID2 != agentH.ID {
		t.Fatalf("expected agent_id unchanged (%q), got %q", agentH.ID, scannedAgentID2)
	}
	if scannedHostname2 != invReq2.Hostname {
		t.Fatalf("expected hostname %q, got %q", invReq2.Hostname, scannedHostname2)
	}
	if scannedOSID2 != invReq2.OSID {
		t.Fatalf("expected os_id %q, got %q", invReq2.OSID, scannedOSID2)
	}
	if scannedOSName2 != invReq2.OSName {
		t.Fatalf("expected os_name %q, got %q", invReq2.OSName, scannedOSName2)
	}
	if scannedOSVersion2 != invReq2.OSVersion {
		t.Fatalf("expected os_version %q, got %q", invReq2.OSVersion, scannedOSVersion2)
	}
	if scannedKernel2 != invReq2.KernelRelease {
		t.Fatalf("expected kernel_release %q, got %q", invReq2.KernelRelease, scannedKernel2)
	}
	if scannedArch2 != invReq2.Architecture {
		t.Fatalf("expected architecture %q, got %q", invReq2.Architecture, scannedArch2)
	}
	if scannedCores2 != invReq2.CPULogicalCores {
		t.Fatalf("expected cpu_logical_cores %d, got %d", invReq2.CPULogicalCores, scannedCores2)
	}
	if scannedMem2 != invReq2.MemoryTotalBytes {
		t.Fatalf("expected memory_total_bytes %d, got %d", invReq2.MemoryTotalBytes, scannedMem2)
	}
	if secondReportedAt.Before(firstReportedAt) {
		t.Fatalf("expected second reported_at (%v) to be >= first (%v)", secondReportedAt, firstReportedAt)
	}

	// Table retains only current snapshot per agent (at most one row)
	var rowCount int
	err = db.pool.QueryRow(ctx, "SELECT count(*) FROM stackpilot.agent_inventory WHERE agent_id = $1::uuid", agentH.ID).Scan(&rowCount)
	if err != nil {
		t.Fatalf("failed to count agent_inventory rows: %v", err)
	}
	if rowCount != 1 {
		t.Fatalf("expected exactly 1 inventory snapshot row, got %d", rowCount)
	}

	// Reporting inventory for an unenrolled key must fail and leave table contents untouched
	var totalBeforeUnknown int
	err = db.pool.QueryRow(ctx, "SELECT count(*) FROM stackpilot.agent_inventory").Scan(&totalBeforeUnknown)
	if err != nil {
		t.Fatalf("failed to count total agent_inventory rows before unknown attempt: %v", err)
	}

	err = db.RecordAgentInventory(ctx, keyUnknownH, invReq1)
	if err == nil {
		t.Fatal("expected error for unknown public key inventory, got nil")
	}
	if !errors.Is(err, enrollment.ErrAgentNotFound) {
		t.Fatalf("expected ErrAgentNotFound for unknown public key inventory, got %v", err)
	}

	var totalAfterUnknown int
	err = db.pool.QueryRow(ctx, "SELECT count(*) FROM stackpilot.agent_inventory").Scan(&totalAfterUnknown)
	if err != nil {
		t.Fatalf("failed to count total agent_inventory rows after unknown attempt: %v", err)
	}
	if totalAfterUnknown != totalBeforeUnknown {
		t.Fatalf("expected total inventory row count to remain %d, got %d", totalBeforeUnknown, totalAfterUnknown)
	}

	var countAfterUnknown int
	err = db.pool.QueryRow(ctx, "SELECT count(*) FROM stackpilot.agent_inventory WHERE agent_id = $1::uuid", agentH.ID).Scan(&countAfterUnknown)
	if err != nil {
		t.Fatalf("failed to count agent_inventory rows after unknown attempt: %v", err)
	}
	if countAfterUnknown != 1 {
		t.Fatalf("expected agent inventory row count to remain 1 after unknown attempt, got %d", countAfterUnknown)
	}

	var initialTelemetryCount int
	err = db.pool.QueryRow(ctx, "SELECT count(*) FROM stackpilot.agent_telemetry WHERE agent_id = $1::uuid", agentH.ID).Scan(&initialTelemetryCount)
	if err != nil {
		t.Fatalf("failed to query initial agent_telemetry count: %v", err)
	}
	if initialTelemetryCount != 0 {
		t.Fatalf("expected 0 telemetry rows before first submission, got %d", initialTelemetryCount)
	}

	telemReq1 := &protocol.TelemetryRequest{
		ProtocolVersion:              1,
		CPUUsageBasisPoints:          2500,
		MemoryTotalBytes:             16777216000,
		MemoryUsedBytes:              8388608000,
		MemoryAvailableBytes:         8388608000,
		Load1mMilli:                  1250,
		Load5mMilli:                  950,
		Load15mMilli:                 600,
		RootFilesystemTotalBytes:     107374182400,
		RootFilesystemUsedBytes:      42949672960,
		RootFilesystemAvailableBytes: 64424509440,
		NetworkReceiveBytesTotal:     10485760,
		NetworkTransmitBytesTotal:    5242880,
		UptimeSeconds:                3600,
		SampleWindowMS:               30000,
	}

	err = db.RecordAgentTelemetry(ctx, keyH, telemReq1)
	if err != nil {
		t.Fatalf("RecordAgentTelemetry failed on first insert: %v", err)
	}

	var (
		scannedTelemAgentID  string
		scannedCPU           int
		scannedMemTotal      int64
		scannedMemUsed       int64
		scannedMemAvail      int64
		scannedLoad1         int64
		scannedLoad5         int64
		scannedLoad15        int64
		scannedFSTotal       int64
		scannedFSUsed        int64
		scannedFSAvail       int64
		scannedNetRX         int64
		scannedNetTX         int64
		scannedUptime        int64
		scannedWindow        int64
		firstTelemReportedAt time.Time
	)
	err = db.pool.QueryRow(ctx, `
		SELECT agent_id, cpu_usage_basis_points, memory_total_bytes, memory_used_bytes, memory_available_bytes,
		       load_1m_milli, load_5m_milli, load_15m_milli,
		       root_filesystem_total_bytes, root_filesystem_used_bytes, root_filesystem_available_bytes,
		       network_receive_bytes_total, network_transmit_bytes_total,
		       uptime_seconds, sample_window_ms, reported_at
		FROM stackpilot.agent_telemetry
		WHERE agent_id = $1::uuid
	`, agentH.ID).Scan(
		&scannedTelemAgentID,
		&scannedCPU,
		&scannedMemTotal,
		&scannedMemUsed,
		&scannedMemAvail,
		&scannedLoad1,
		&scannedLoad5,
		&scannedLoad15,
		&scannedFSTotal,
		&scannedFSUsed,
		&scannedFSAvail,
		&scannedNetRX,
		&scannedNetTX,
		&scannedUptime,
		&scannedWindow,
		&firstTelemReportedAt,
	)
	if err != nil {
		t.Fatalf("failed to query agent_telemetry: %v", err)
	}
	if scannedTelemAgentID != agentH.ID {
		t.Fatalf("expected agent_id %q, got %q", agentH.ID, scannedTelemAgentID)
	}
	if scannedCPU != telemReq1.CPUUsageBasisPoints {
		t.Fatalf("expected cpu %d, got %d", telemReq1.CPUUsageBasisPoints, scannedCPU)
	}
	if scannedMemTotal != telemReq1.MemoryTotalBytes {
		t.Fatalf("expected memory_total %d, got %d", telemReq1.MemoryTotalBytes, scannedMemTotal)
	}
	if scannedMemUsed != telemReq1.MemoryUsedBytes {
		t.Fatalf("expected memory_used %d, got %d", telemReq1.MemoryUsedBytes, scannedMemUsed)
	}
	if scannedMemAvail != telemReq1.MemoryAvailableBytes {
		t.Fatalf("expected memory_available %d, got %d", telemReq1.MemoryAvailableBytes, scannedMemAvail)
	}
	if scannedLoad1 != telemReq1.Load1mMilli {
		t.Fatalf("expected load1 %d, got %d", telemReq1.Load1mMilli, scannedLoad1)
	}
	if scannedLoad5 != telemReq1.Load5mMilli {
		t.Fatalf("expected load5 %d, got %d", telemReq1.Load5mMilli, scannedLoad5)
	}
	if scannedLoad15 != telemReq1.Load15mMilli {
		t.Fatalf("expected load15 %d, got %d", telemReq1.Load15mMilli, scannedLoad15)
	}
	if scannedFSTotal != telemReq1.RootFilesystemTotalBytes {
		t.Fatalf("expected fs_total %d, got %d", telemReq1.RootFilesystemTotalBytes, scannedFSTotal)
	}
	if scannedFSUsed != telemReq1.RootFilesystemUsedBytes {
		t.Fatalf("expected fs_used %d, got %d", telemReq1.RootFilesystemUsedBytes, scannedFSUsed)
	}
	if scannedFSAvail != telemReq1.RootFilesystemAvailableBytes {
		t.Fatalf("expected fs_available %d, got %d", telemReq1.RootFilesystemAvailableBytes, scannedFSAvail)
	}
	if scannedNetRX != telemReq1.NetworkReceiveBytesTotal {
		t.Fatalf("expected net_rx %d, got %d", telemReq1.NetworkReceiveBytesTotal, scannedNetRX)
	}
	if scannedNetTX != telemReq1.NetworkTransmitBytesTotal {
		t.Fatalf("expected net_tx %d, got %d", telemReq1.NetworkTransmitBytesTotal, scannedNetTX)
	}
	if scannedUptime != telemReq1.UptimeSeconds {
		t.Fatalf("expected uptime %d, got %d", telemReq1.UptimeSeconds, scannedUptime)
	}
	if scannedWindow != telemReq1.SampleWindowMS {
		t.Fatalf("expected sample_window_ms %d, got %d", telemReq1.SampleWindowMS, scannedWindow)
	}
	if firstTelemReportedAt.IsZero() {
		t.Fatal("expected non-zero reported_at")
	}

	telemReq2 := &protocol.TelemetryRequest{
		ProtocolVersion:              1,
		CPUUsageBasisPoints:          7850,
		MemoryTotalBytes:             33554432000,
		MemoryUsedBytes:              20971520000,
		MemoryAvailableBytes:         12582912000,
		Load1mMilli:                  4500,
		Load5mMilli:                  3200,
		Load15mMilli:                 1800,
		RootFilesystemTotalBytes:     214748364800,
		RootFilesystemUsedBytes:      107374182400,
		RootFilesystemAvailableBytes: 107374182400,
		NetworkReceiveBytesTotal:     52428800,
		NetworkTransmitBytesTotal:    26214400,
		UptimeSeconds:                7200,
		SampleWindowMS:               29500,
	}

	err = db.RecordAgentTelemetry(ctx, keyH, telemReq2)
	if err != nil {
		t.Fatalf("RecordAgentTelemetry failed on second update: %v", err)
	}

	var (
		scannedTelemAgentID2  string
		scannedCPU2           int
		scannedMemTotal2      int64
		scannedMemUsed2       int64
		scannedMemAvail2      int64
		scannedLoad1_2        int64
		scannedLoad5_2        int64
		scannedLoad15_2       int64
		scannedFSTotal2       int64
		scannedFSUsed2        int64
		scannedFSAvail2       int64
		scannedNetRX2         int64
		scannedNetTX2         int64
		scannedUptime2        int64
		scannedWindow2        int64
		secondTelemReportedAt time.Time
	)
	err = db.pool.QueryRow(ctx, `
		SELECT agent_id, cpu_usage_basis_points, memory_total_bytes, memory_used_bytes, memory_available_bytes,
		       load_1m_milli, load_5m_milli, load_15m_milli,
		       root_filesystem_total_bytes, root_filesystem_used_bytes, root_filesystem_available_bytes,
		       network_receive_bytes_total, network_transmit_bytes_total,
		       uptime_seconds, sample_window_ms, reported_at
		FROM stackpilot.agent_telemetry
		WHERE agent_id = $1::uuid
	`, agentH.ID).Scan(
		&scannedTelemAgentID2,
		&scannedCPU2,
		&scannedMemTotal2,
		&scannedMemUsed2,
		&scannedMemAvail2,
		&scannedLoad1_2,
		&scannedLoad5_2,
		&scannedLoad15_2,
		&scannedFSTotal2,
		&scannedFSUsed2,
		&scannedFSAvail2,
		&scannedNetRX2,
		&scannedNetTX2,
		&scannedUptime2,
		&scannedWindow2,
		&secondTelemReportedAt,
	)
	if err != nil {
		t.Fatalf("failed to query updated agent_telemetry: %v", err)
	}

	if scannedTelemAgentID2 != agentH.ID {
		t.Fatalf("expected agent_id unchanged (%q), got %q", agentH.ID, scannedTelemAgentID2)
	}
	if scannedCPU2 != telemReq2.CPUUsageBasisPoints {
		t.Fatalf("expected cpu %d, got %d", telemReq2.CPUUsageBasisPoints, scannedCPU2)
	}
	if scannedMemTotal2 != telemReq2.MemoryTotalBytes {
		t.Fatalf("expected memory_total %d, got %d", telemReq2.MemoryTotalBytes, scannedMemTotal2)
	}
	if scannedMemUsed2 != telemReq2.MemoryUsedBytes {
		t.Fatalf("expected memory_used %d, got %d", telemReq2.MemoryUsedBytes, scannedMemUsed2)
	}
	if scannedMemAvail2 != telemReq2.MemoryAvailableBytes {
		t.Fatalf("expected memory_available %d, got %d", telemReq2.MemoryAvailableBytes, scannedMemAvail2)
	}
	if scannedLoad1_2 != telemReq2.Load1mMilli {
		t.Fatalf("expected load1 %d, got %d", telemReq2.Load1mMilli, scannedLoad1_2)
	}
	if scannedLoad5_2 != telemReq2.Load5mMilli {
		t.Fatalf("expected load5 %d, got %d", telemReq2.Load5mMilli, scannedLoad5_2)
	}
	if scannedLoad15_2 != telemReq2.Load15mMilli {
		t.Fatalf("expected load15 %d, got %d", telemReq2.Load15mMilli, scannedLoad15_2)
	}
	if scannedFSTotal2 != telemReq2.RootFilesystemTotalBytes {
		t.Fatalf("expected fs_total %d, got %d", telemReq2.RootFilesystemTotalBytes, scannedFSTotal2)
	}
	if scannedFSUsed2 != telemReq2.RootFilesystemUsedBytes {
		t.Fatalf("expected fs_used %d, got %d", telemReq2.RootFilesystemUsedBytes, scannedFSUsed2)
	}
	if scannedFSAvail2 != telemReq2.RootFilesystemAvailableBytes {
		t.Fatalf("expected fs_available %d, got %d", telemReq2.RootFilesystemAvailableBytes, scannedFSAvail2)
	}
	if scannedNetRX2 != telemReq2.NetworkReceiveBytesTotal {
		t.Fatalf("expected net_rx %d, got %d", telemReq2.NetworkReceiveBytesTotal, scannedNetRX2)
	}
	if scannedNetTX2 != telemReq2.NetworkTransmitBytesTotal {
		t.Fatalf("expected net_tx %d, got %d", telemReq2.NetworkTransmitBytesTotal, scannedNetTX2)
	}
	if scannedUptime2 != telemReq2.UptimeSeconds {
		t.Fatalf("expected uptime %d, got %d", telemReq2.UptimeSeconds, scannedUptime2)
	}
	if scannedWindow2 != telemReq2.SampleWindowMS {
		t.Fatalf("expected sample_window_ms %d, got %d", telemReq2.SampleWindowMS, scannedWindow2)
	}
	if secondTelemReportedAt.Before(firstTelemReportedAt) {
		t.Fatalf("expected second reported_at (%v) to be >= first (%v)", secondTelemReportedAt, firstTelemReportedAt)
	}

	var telemRowCount int
	err = db.pool.QueryRow(ctx, "SELECT count(*) FROM stackpilot.agent_telemetry WHERE agent_id = $1::uuid", agentH.ID).Scan(&telemRowCount)
	if err != nil {
		t.Fatalf("failed to count agent_telemetry rows: %v", err)
	}
	if telemRowCount != 1 {
		t.Fatalf("expected exactly 1 telemetry snapshot row, got %d", telemRowCount)
	}

	var totalTelemBeforeUnknown int
	err = db.pool.QueryRow(ctx, "SELECT count(*) FROM stackpilot.agent_telemetry").Scan(&totalTelemBeforeUnknown)
	if err != nil {
		t.Fatalf("failed to count total agent_telemetry rows before unknown attempt: %v", err)
	}

	err = db.RecordAgentTelemetry(ctx, keyUnknownH, telemReq1)
	if err == nil {
		t.Fatal("expected error for unknown public key telemetry, got nil")
	}
	if !errors.Is(err, enrollment.ErrAgentNotFound) {
		t.Fatalf("expected ErrAgentNotFound for unknown public key telemetry, got %v", err)
	}

	var totalTelemAfterUnknown int
	err = db.pool.QueryRow(ctx, "SELECT count(*) FROM stackpilot.agent_telemetry").Scan(&totalTelemAfterUnknown)
	if err != nil {
		t.Fatalf("failed to count total agent_telemetry rows after unknown attempt: %v", err)
	}
	if totalTelemAfterUnknown != totalTelemBeforeUnknown {
		t.Fatalf("expected total telemetry row count to remain %d, got %d", totalTelemBeforeUnknown, totalTelemAfterUnknown)
	}

	// Ensure database created_at is reasonable
	if startTime.After(time.Now().Add(5 * time.Second)) {
		t.Errorf("startTime out of reasonable range")
	}

	adminUsername := fmt.Sprintf("admin-%d", time.Now().UnixNano())
	adminPW := "Correct-Horse-Battery-Staple-123!"
	adminHash, err := operator.HashPassword(adminPW)
	if err != nil {
		t.Fatalf("failed to hash admin password: %v", err)
	}

	adminOp, err := db.CreateOperator(ctx, adminUsername, adminHash, operator.RoleAdmin)
	if err != nil {
		t.Fatalf("failed to create admin operator: %v", err)
	}

	if adminOp.Username != adminUsername {
		t.Fatalf("expected canonical username %q, got %q", adminUsername, adminOp.Username)
	}
	if adminOp.Role != operator.RoleAdmin {
		t.Fatalf("expected role admin, got %q", adminOp.Role)
	}
	if !strings.HasPrefix(adminOp.PasswordHash, "$argon2id$v=19$m=32768,t=3,p=1$") {
		t.Fatalf("expected argon2id PHC hash, got %q", adminOp.PasswordHash)
	}
	if strings.Contains(adminOp.PasswordHash, adminPW) {
		t.Fatal("plaintext password leaked into password_hash")
	}

	_, err = db.CreateOperator(ctx, adminUsername, adminHash, operator.RoleAdmin)
	if err == nil {
		t.Fatal("expected duplicate username to fail, got nil")
	}
	if !errors.Is(err, operator.ErrUsernameConflict) {
		t.Fatalf("expected ErrUsernameConflict, got %v", err)
	}

	viewerUsername := fmt.Sprintf("viewer-%d", time.Now().UnixNano())
	viewerHash, err := operator.HashPassword("Another-Valid-Password-123!")
	if err != nil {
		t.Fatalf("failed to hash viewer password: %v", err)
	}
	viewerOp, err := db.CreateOperator(ctx, viewerUsername, viewerHash, operator.RoleViewer)
	if err != nil {
		t.Fatalf("failed to create viewer operator: %v", err)
	}

	opUsername := fmt.Sprintf("operator-%d", time.Now().UnixNano())
	opHash, err := operator.HashPassword("Another-Valid-Password-456!")
	if err != nil {
		t.Fatalf("failed to hash operator password: %v", err)
	}
	operatorOp, err := db.CreateOperator(ctx, opUsername, opHash, operator.RoleOperator)
	if err != nil {
		t.Fatalf("failed to create operator: %v", err)
	}

	fetchedAdmin, err := db.GetOperatorByUsername(ctx, adminUsername)
	if err != nil {
		t.Fatalf("GetOperatorByUsername failed: %v", err)
	}
	if fetchedAdmin.ID != adminOp.ID || fetchedAdmin.Role != operator.RoleAdmin {
		t.Fatalf("fetched admin operator mismatch: %+v", fetchedAdmin)
	}

	// Security invariant: Corrupt database role must fail closed and return safe error without exposing password hash.
	corruptUsername := fmt.Sprintf("corrupt-%d", time.Now().UnixNano())
	corruptHash, _ := operator.HashPassword("ValidPassword123!")
	corruptOp, err := db.CreateOperator(ctx, corruptUsername, corruptHash, operator.RoleOperator)
	if err != nil {
		t.Fatalf("failed to create operator for corrupt role test: %v", err)
	}
	_, err = db.pool.Exec(ctx, "ALTER TABLE stackpilot.operators DROP CONSTRAINT operators_role_check")
	if err == nil {
		_, _ = db.pool.Exec(ctx, "UPDATE stackpilot.operators SET role = 'corrupt' WHERE id = $1::uuid", corruptOp.ID)
		_, corruptErr := db.GetOperatorByUsername(ctx, corruptUsername)
		if corruptErr == nil || !strings.Contains(corruptErr.Error(), "corrupt operator role") {
			t.Fatalf("expected GetOperatorByUsername to fail with corrupt operator role, got %v", corruptErr)
		}
		_, _ = db.pool.Exec(ctx, "UPDATE stackpilot.operators SET role = 'operator' WHERE id = $1::uuid", corruptOp.ID)
		_, _ = db.pool.Exec(ctx, "ALTER TABLE stackpilot.operators ADD CONSTRAINT operators_role_check CHECK (role IN ('viewer', 'operator', 'admin'))")
	}

	sessTokens := make([]string, 10)
	for i := 0; i < 10; i++ {
		tok, err := operator.GenerateSessionToken()
		if err != nil {
			t.Fatalf("failed to generate session token: %v", err)
		}
		sessTokens[i] = tok
		tokHash := operator.HashSessionToken(tok)
		sess, err := db.CreateOperatorSession(ctx, adminOp.ID, tokHash)
		if err != nil {
			t.Fatalf("failed to create session %d: %v", i, err)
		}
		expectedExpiry := time.Now().Add(operator.SessionLifetime)
		diff := sess.ExpiresAt.Sub(expectedExpiry)
		if diff < -30*time.Second || diff > 30*time.Second {
			t.Fatalf("session expires_at %v deviates from expected DB now + SessionLifetime %v by %v", sess.ExpiresAt, expectedExpiry, diff)
		}
	}

	var activeCount int
	err = db.pool.QueryRow(ctx, "SELECT count(*) FROM stackpilot.operator_sessions WHERE operator_id = $1::uuid AND expires_at > now()", adminOp.ID).Scan(&activeCount)
	if err != nil {
		t.Fatalf("failed to count active sessions: %v", err)
	}
	if activeCount != operator.MaxActiveSessionsPerOperator {
		t.Fatalf("expected exactly %d active sessions, got %d", operator.MaxActiveSessionsPerOperator, activeCount)
	}

	for i := 0; i < 2; i++ {
		h := operator.HashSessionToken(sessTokens[i])
		p, err := db.FindOperatorSessionByTokenHash(ctx, h)
		if err == nil || p != nil {
			t.Fatalf("expected pruned session %d to be revoked, got principal %+v", i, p)
		}
	}

	newestHash := operator.HashSessionToken(sessTokens[9])
	principal, err := db.FindOperatorSessionByTokenHash(ctx, newestHash)
	if err != nil {
		t.Fatalf("failed to find active session by token hash: %v", err)
	}
	if principal.OperatorID != adminOp.ID || principal.Username != adminOp.Username || principal.Role != operator.RoleAdmin {
		t.Fatalf("unexpected principal: %+v", principal)
	}

	// Security invariant: Verify TOCTOU race prevention inside session transaction when operator is disabled.
	disabledUsername := fmt.Sprintf("disabled-%d", time.Now().UnixNano())
	disabledHash, _ := operator.HashPassword("ValidPassword123!")
	disabledOp, err := db.CreateOperator(ctx, disabledUsername, disabledHash, operator.RoleOperator)
	if err != nil {
		t.Fatalf("failed to create operator for TOCTOU test: %v", err)
	}
	if _, err := db.pool.Exec(ctx, "UPDATE stackpilot.operators SET disabled_at = now() WHERE id = $1::uuid", disabledOp.ID); err != nil {
		t.Fatalf("failed to disable operator: %v", err)
	}
	disTok, _ := operator.GenerateSessionToken()
	_, disErr := db.CreateOperatorSession(ctx, disabledOp.ID, operator.HashSessionToken(disTok))
	if !errors.Is(disErr, operator.ErrAuthenticationFailed) {
		t.Fatalf("expected ErrAuthenticationFailed for disabled operator in CreateOperatorSession, got: %v", disErr)
	}

	// Security invariant: RevokeOperatorSession must fail and omit audit if operatorID does not own session.
	err = db.RevokeOperatorSession(ctx, principal.SessionID, viewerOp.ID, viewerOp.Username)
	if !errors.Is(err, operator.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound when revoking session with wrong operator ID, got: %v", err)
	}

	err = db.RevokeOperatorSession(ctx, "018f0000-0000-7000-8000-000000000000", adminOp.ID, adminOp.Username)
	if !errors.Is(err, operator.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound for non-existent session ID, got: %v", err)
	}

	err = db.RevokeOperatorSession(ctx, principal.SessionID, adminOp.ID, adminOp.Username)
	if err != nil {
		t.Fatalf("failed to revoke session: %v", err)
	}

	pAfterLogout, err := db.FindOperatorSessionByTokenHash(ctx, newestHash)
	if err == nil || pAfterLogout != nil {
		t.Fatal("expected revoked session to fail authentication, got principal")
	}

	auditEvents, err := db.RecordAndListAuditEvents(ctx, adminOp.ID, adminOp.Username, 100)
	if err != nil {
		t.Fatalf("RecordAndListAuditEvents failed: %v", err)
	}
	if len(auditEvents) == 0 {
		t.Fatal("expected audit events, got 0")
	}

	actionCounts := make(map[operator.AuditAction]int)
	for _, ev := range auditEvents {
		actionCounts[ev.Action]++
		if ev.Outcome != operator.OutcomeSuccess {
			t.Errorf("expected outcome success, got %q", ev.Outcome)
		}
	}
	if actionCounts[operator.ActionOperatorCreated] < 4 {
		t.Errorf("expected at least 4 operator.created events, got %d", actionCounts[operator.ActionOperatorCreated])
	}
	if actionCounts[operator.ActionOperatorLogin] < 10 {
		t.Errorf("expected at least 10 operator.login events, got %d", actionCounts[operator.ActionOperatorLogin])
	}
	if actionCounts[operator.ActionOperatorLogout] < 1 {
		t.Errorf("expected at least 1 operator.logout event, got %d", actionCounts[operator.ActionOperatorLogout])
	}
	if actionCounts[operator.ActionOperatorAuditRead] < 1 {
		t.Errorf("expected at least 1 operator.audit.read event, got %d", actionCounts[operator.ActionOperatorAuditRead])
	}

	_ = operatorOp
}

func TestPostgreSQL_M011_JobLifecycle(t *testing.T) {
	testURL, ok := os.LookupEnv("STACKPILOT_TEST_DATABASE_URL")
	if !ok || testURL == "" {
		t.Log("PostgreSQL integration SKIPPED")
		t.Skip("PostgreSQL integration SKIPPED: STACKPILOT_TEST_DATABASE_URL not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	db, err := Open(ctx, testURL)
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(ctx); err != nil {
		t.Fatalf("database ping failed: %v", err)
	}

	if err := db.Migrate(ctx, nil); err != nil {
		t.Fatalf("db.Migrate failed: %v", err)
	}

	createTestOp := func(username string, role operator.Role) *operator.OperatorRecord {
		passHash, err := operator.HashPassword("validPassword123!")
		if err != nil {
			t.Fatalf("failed to hash password: %v", err)
		}
		op, err := db.CreateOperator(ctx, username, passHash, role)
		if err != nil {
			t.Fatalf("failed to create operator: %v", err)
		}
		return op
	}

	createTestAgent := func() *enrollment.AgentRecord {
		rawToken, err := enrollment.IssueToken(ctx, db)
		if err != nil {
			t.Fatalf("failed to issue token: %v", err)
		}
		tokenHash := enrollment.HashToken(rawToken)

		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}
		var pub32 [32]byte
		copy(pub32[:], pub)

		agentRec, _, err := db.RegisterAgent(ctx, tokenHash, pub32)
		if err != nil {
			t.Fatalf("failed to register agent: %v", err)
		}
		return agentRec
	}

	t.Run("schema_tables_columns_indexes_and_constraints", func(t *testing.T) {
		var version int32
		err := db.pool.QueryRow(ctx, "SELECT version FROM public.stackpilot_schema_version").Scan(&version)
		if err != nil {
			t.Fatalf("failed to query schema version: %v", err)
		}
		if version != 12 {
			t.Fatalf("expected schema version 12, got %d", version)
		}

		for _, tbl := range []string{"jobs", "job_events"} {
			var exists bool
			err := db.pool.QueryRow(ctx, `
				SELECT EXISTS(
					SELECT 1 FROM information_schema.tables
					WHERE table_schema = 'stackpilot' AND table_name = $1
				)
			`, tbl).Scan(&exists)
			if err != nil || !exists {
				t.Fatalf("expected table stackpilot.%s to exist (err=%v)", tbl, err)
			}
		}

		var auditColExists bool
		err = db.pool.QueryRow(ctx, `
			SELECT EXISTS(
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'stackpilot' AND table_name = 'operator_audit_events' AND column_name = 'target_job_id'
			)
		`).Scan(&auditColExists)
		if err != nil || !auditColExists {
			t.Fatalf("expected target_job_id column on stackpilot.operator_audit_events (err=%v)", err)
		}

		expectedIndexes := []string{
			"jobs_claim_idx",
			"jobs_listing_idx",
			"jobs_creator_idx",
			"jobs_idempotency_idx",
			"jobs_agent_inflight_idx",
			"jobs_expired_dispatched_idx",
			"jobs_expired_running_idx",
			"job_events_job_id_occurred_at_idx",
		}
		for _, idx := range expectedIndexes {
			var exists bool
			err := db.pool.QueryRow(ctx, `
				SELECT EXISTS(
					SELECT 1 FROM pg_indexes
					WHERE schemaname = 'stackpilot' AND indexname = $1
				)
			`, idx).Scan(&exists)
			if err != nil || !exists {
				t.Fatalf("expected index %s to exist (err=%v)", idx, err)
			}
		}

		expectedConstraints := []string{
			"jobs_action_type_check",
			"jobs_state_check",
			"jobs_attempt_range",
			"jobs_failure_code_check",
			"jobs_state_failure_code_consistency",
			"jobs_idempotency_key_hash_length",
			"job_events_actor_identifier_shape",
			"operator_audit_events_target_mutual_exclusion",
		}
		for _, con := range expectedConstraints {
			var exists bool
			err := db.pool.QueryRow(ctx, `
				SELECT EXISTS(
					SELECT 1 FROM pg_constraint
					WHERE conname = $1
				)
			`, con).Scan(&exists)
			if err != nil || !exists {
				t.Fatalf("expected constraint %s to exist (err=%v)", con, err)
			}
		}
	})

	t.Run("create_job_lifecycle_atomicity_and_replay", func(t *testing.T) {
		op := createTestOp(fmt.Sprintf("op-create-%s", uuid.New().String()[:8]), operator.RoleAdmin)
		ag := createTestAgent()

		opID, _ := uuid.Parse(op.ID)
		agID, _ := uuid.Parse(ag.ID)
		keyHash := [32]byte{0x01, 0x02, 0x03}

		created, isNew, err := db.CreateJob(ctx, opID, agID, job.ActionAgentPing, keyHash)
		if err != nil {
			t.Fatalf("CreateJob failed: %v", err)
		}
		if !isNew {
			t.Fatal("expected isNew=true on first creation")
		}
		if created.State != job.StateQueued {
			t.Fatalf("expected state queued, got %s", created.State)
		}

		events, err := db.ListJobEvents(ctx, created.ID, 10)
		if err != nil {
			t.Fatalf("ListJobEvents failed: %v", err)
		}
		if len(events) != 1 {
			t.Fatalf("expected exactly 1 job event, got %d", len(events))
		}
		if events[0].EventType != job.EventJobCreated {
			t.Fatalf("expected event type job.created, got %s", events[0].EventType)
		}

		var auditCount int
		err = db.pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM stackpilot.operator_audit_events
			WHERE action = 'job.created' AND target_job_id = $1
		`, created.ID).Scan(&auditCount)
		if err != nil {
			t.Fatalf("failed to query audit count: %v", err)
		}
		if auditCount != 1 {
			t.Fatalf("expected exactly 1 job.created audit event, got %d", auditCount)
		}

		replayed, replayIsNew, err := db.CreateJob(ctx, opID, agID, job.ActionAgentPing, keyHash)
		if err != nil {
			t.Fatalf("exact replay failed: %v", err)
		}
		if replayIsNew {
			t.Fatal("expected replayIsNew=false on idempotent replay")
		}
		if replayed.ID != created.ID {
			t.Fatalf("expected replayed job ID %s, got %s", created.ID, replayed.ID)
		}

		eventsAfter, _ := db.ListJobEvents(ctx, created.ID, 10)
		if len(eventsAfter) != 1 {
			t.Fatalf("expected still 1 event after replay, got %d", len(eventsAfter))
		}
		_ = db.pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM stackpilot.operator_audit_events
			WHERE action = 'job.created' AND target_job_id = $1
		`, created.ID).Scan(&auditCount)
		if auditCount != 1 {
			t.Fatalf("expected audit count to remain 1 after replay, got %d", auditCount)
		}

		_, _, err = db.CreateJob(ctx, opID, agID, "different.action", keyHash)
		if !errors.Is(err, job.ErrJobIdempotencyConflict) {
			t.Fatalf("expected ErrJobIdempotencyConflict, got %v", err)
		}

		_, _, err = db.CreateJob(ctx, opID, uuid.New(), job.ActionAgentPing, [32]byte{0x99})
		if !errors.Is(err, job.ErrAgentNotFound) {
			t.Fatalf("expected ErrAgentNotFound, got %v", err)
		}
	})

	t.Run("concurrent_exact_same_key_creation", func(t *testing.T) {
		op := createTestOp(fmt.Sprintf("op-conc-%s", uuid.New().String()[:8]), operator.RoleAdmin)
		ag := createTestAgent()

		opID, _ := uuid.Parse(op.ID)
		agID, _ := uuid.Parse(ag.ID)
		var keyHash [32]byte
		_, _ = rand.Read(keyHash[:])

		concurrency := 10
		type result struct {
			j     *job.Job
			isNew bool
			err   error
		}
		resChan := make(chan result, concurrency)

		for i := 0; i < concurrency; i++ {
			go func() {
				j, isNew, err := db.CreateJob(ctx, opID, agID, job.ActionAgentPing, keyHash)
				resChan <- result{j: j, isNew: isNew, err: err}
			}()
		}

		var firstID uuid.UUID
		firstCount := 0
		replayCount := 0
		for i := 0; i < concurrency; i++ {
			res := <-resChan
			if res.err != nil {
				t.Fatalf("concurrent create job returned error: %v", res.err)
			}
			if firstID == uuid.Nil {
				firstID = res.j.ID
			} else if res.j.ID != firstID {
				t.Fatalf("concurrent create returned different Job IDs: %s != %s", firstID, res.j.ID)
			}
			if res.isNew {
				firstCount++
			} else {
				replayCount++
			}
		}

		if firstCount != 1 {
			t.Fatalf("expected exactly 1 first creation with isNew=true, got %d", firstCount)
		}
		if replayCount != concurrency-1 {
			t.Fatalf("expected %d replays with isNew=false, got %d", concurrency-1, replayCount)
		}

		events, err := db.ListJobEvents(ctx, firstID, 10)
		if err != nil {
			t.Fatalf("failed to list events: %v", err)
		}
		if len(events) != 1 {
			t.Fatalf("expected exactly 1 job event, got %d", len(events))
		}

		var auditCount int
		err = db.pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM stackpilot.operator_audit_events
			WHERE action = 'job.created' AND target_job_id = $1
		`, firstID).Scan(&auditCount)
		if err != nil {
			t.Fatalf("failed to query audit count: %v", err)
		}
		if auditCount != 1 {
			t.Fatalf("expected exactly 1 audit event, got %d", auditCount)
		}
	})

	t.Run("concurrent_queue_cap_with_distinct_operators", func(t *testing.T) {
		ops := make([]*operator.OperatorRecord, 5)
		for i := 0; i < 5; i++ {
			ops[i] = createTestOp(fmt.Sprintf("op-cap-%d-%s", i, uuid.New().String()[:8]), operator.RoleAdmin)
		}
		ag := createTestAgent()
		agID, _ := uuid.Parse(ag.ID)
		primaryOpID, _ := uuid.Parse(ops[0].ID)

		var lastKeyHash [32]byte
		for i := 0; i < 63; i++ {
			var kh [32]byte
			_, _ = rand.Read(kh[:])
			created, isNew, err := db.CreateJob(ctx, primaryOpID, agID, job.ActionAgentPing, kh)
			if err != nil {
				t.Fatalf("failed to create job %d: %v", i, err)
			}
			if !isNew {
				t.Fatalf("expected isNew=true for job %d", i)
			}
			_ = created
			lastKeyHash = kh
		}

		concurrency := 5
		type capResult struct {
			isNew bool
			err   error
		}
		resChan := make(chan capResult, concurrency)
		for i := 0; i < concurrency; i++ {
			opID, _ := uuid.Parse(ops[i].ID)
			go func() {
				var kh [32]byte
				_, _ = rand.Read(kh[:])
				_, isNew, err := db.CreateJob(ctx, opID, agID, job.ActionAgentPing, kh)
				resChan <- capResult{isNew: isNew, err: err}
			}()
		}

		successes := 0
		fullErrors := 0
		for i := 0; i < concurrency; i++ {
			res := <-resChan
			if res.err == nil {
				if !res.isNew {
					t.Fatalf("expected successful creation at cap to have isNew=true")
				}
				successes++
			} else if errors.Is(res.err, job.ErrQueueFull) {
				fullErrors++
			} else {
				t.Fatalf("unexpected error during queue race: %v", res.err)
			}
		}

		if successes != 1 {
			t.Fatalf("expected exactly 1 success reaching cap 64, got %d", successes)
		}
		if fullErrors != concurrency-1 {
			t.Fatalf("expected %d ErrQueueFull, got %d", concurrency-1, fullErrors)
		}

		var count int
		err := db.pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM stackpilot.jobs
			WHERE agent_id = $1 AND state IN ('queued', 'dispatched', 'running')
		`, agID).Scan(&count)
		if err != nil {
			t.Fatalf("failed to query active count: %v", err)
		}
		if count != 64 {
			t.Fatalf("expected exactly 64 active jobs, got %d", count)
		}

		var overKh [32]byte
		_, _ = rand.Read(overKh[:])
		_, _, err = db.CreateJob(ctx, primaryOpID, agID, job.ActionAgentPing, overKh)
		if !errors.Is(err, job.ErrQueueFull) {
			t.Fatalf("expected ErrQueueFull at 64 jobs, got %v", err)
		}

		replayed, replayIsNew, err := db.CreateJob(ctx, primaryOpID, agID, job.ActionAgentPing, lastKeyHash)
		if err != nil {
			t.Fatalf("expected idempotent replay to succeed when queue full, got: %v", err)
		}
		if replayIsNew {
			t.Fatal("expected replayIsNew=false on idempotent replay at queue cap")
		}
		if replayed == nil {
			t.Fatal("expected non-nil job on idempotent replay")
		}
	})

	t.Run("claim_next_agent_job_fifo_and_inflight", func(t *testing.T) {
		op := createTestOp(fmt.Sprintf("op-claim-%s", uuid.New().String()[:8]), operator.RoleAdmin)
		ag1 := createTestAgent()
		ag2 := createTestAgent()

		opID, _ := uuid.Parse(op.ID)
		ag1ID, _ := uuid.Parse(ag1.ID)
		ag2ID, _ := uuid.Parse(ag2.ID)

		var kh1, kh2, khAg2 [32]byte
		_, _ = rand.Read(kh1[:])
		_, _ = rand.Read(kh2[:])
		_, _ = rand.Read(khAg2[:])

		j1, _, err := db.CreateJob(ctx, opID, ag1ID, job.ActionAgentPing, kh1)
		if err != nil {
			t.Fatalf("failed to create j1: %v", err)
		}

		_, err = db.pool.Exec(ctx, "UPDATE stackpilot.jobs SET created_at = clock_timestamp() - interval '10 seconds' WHERE id = $1", j1.ID)
		if err != nil {
			t.Fatalf("failed to set j1 created_at: %v", err)
		}

		j2, _, err := db.CreateJob(ctx, opID, ag1ID, job.ActionAgentPing, kh2)
		if err != nil {
			t.Fatalf("failed to create j2: %v", err)
		}

		jAg2, _, err := db.CreateJob(ctx, opID, ag2ID, job.ActionAgentPing, khAg2)
		if err != nil {
			t.Fatalf("failed to create jAg2: %v", err)
		}

		claimed1, err := db.ClaimNextAgentJob(ctx, ag1ID)
		if err != nil {
			t.Fatalf("ClaimNextAgentJob failed: %v", err)
		}
		if claimed1 == nil || claimed1.JobID != j1.ID.String() {
			t.Fatalf("expected oldest job %s, got %v", j1.ID, claimed1)
		}
		if claimed1.Attempt != 1 {
			t.Fatalf("expected attempt 1, got %d", claimed1.Attempt)
		}

		claimed2, err := db.ClaimNextAgentJob(ctx, ag1ID)
		if err != nil {
			t.Fatalf("ClaimNextAgentJob while in-flight failed: %v", err)
		}
		if claimed2 != nil {
			t.Fatalf("expected nil when in-flight job exists, got %v", claimed2)
		}

		claimedAg2, err := db.ClaimNextAgentJob(ctx, ag2ID)
		if err != nil {
			t.Fatalf("ag2 claim failed: %v", err)
		}
		if claimedAg2 == nil || claimedAg2.JobID != jAg2.ID.String() {
			t.Fatalf("expected ag2 job %s, got %v", jAg2.ID, claimedAg2)
		}

		_ = j2
	})

	t.Run("concurrent_different_agent_claims", func(t *testing.T) {
		op := createTestOp(fmt.Sprintf("op-diff-%s", uuid.New().String()[:8]), operator.RoleAdmin)
		agA := createTestAgent()
		agB := createTestAgent()

		opID, _ := uuid.Parse(op.ID)
		agAID, _ := uuid.Parse(agA.ID)
		agBID, _ := uuid.Parse(agB.ID)

		var khA, khB [32]byte
		_, _ = rand.Read(khA[:])
		_, _ = rand.Read(khB[:])

		jA, _, err := db.CreateJob(ctx, opID, agAID, job.ActionAgentPing, khA)
		if err != nil {
			t.Fatalf("failed to create job for Agent A: %v", err)
		}
		jB, _, err := db.CreateJob(ctx, opID, agBID, job.ActionAgentPing, khB)
		if err != nil {
			t.Fatalf("failed to create job for Agent B: %v", err)
		}

		startBarrier := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)

		var claimA, claimB *protocol.JobAssignment
		var errA, errB error

		go func() {
			defer wg.Done()
			<-startBarrier
			claimA, errA = db.ClaimNextAgentJob(ctx, agAID)
		}()

		go func() {
			defer wg.Done()
			<-startBarrier
			claimB, errB = db.ClaimNextAgentJob(ctx, agBID)
		}()

		close(startBarrier)
		wg.Wait()

		if errA != nil {
			t.Fatalf("Agent A claim failed: %v", errA)
		}
		if errB != nil {
			t.Fatalf("Agent B claim failed: %v", errB)
		}

		if claimA == nil || claimA.JobID != jA.ID.String() {
			t.Fatalf("expected Agent A to claim job %s, got %v", jA.ID, claimA)
		}
		if claimB == nil || claimB.JobID != jB.ID.String() {
			t.Fatalf("expected Agent B to claim job %s, got %v", jB.ID, claimB)
		}
	})

	t.Run("concurrent_same_agent_claims", func(t *testing.T) {
		op := createTestOp(fmt.Sprintf("op-conc-claim-%s", uuid.New().String()[:8]), operator.RoleAdmin)
		ag := createTestAgent()

		opID, _ := uuid.Parse(op.ID)
		agID, _ := uuid.Parse(ag.ID)

		for i := 0; i < 3; i++ {
			var kh [32]byte
			_, _ = rand.Read(kh[:])
			_, _, err := db.CreateJob(ctx, opID, agID, job.ActionAgentPing, kh)
			if err != nil {
				t.Fatalf("failed to create job: %v", err)
			}
		}

		concurrency := 5
		type claimRes struct {
			a   *protocol.JobAssignment
			err error
		}
		ch := make(chan claimRes, concurrency)
		for i := 0; i < concurrency; i++ {
			go func() {
				a, err := db.ClaimNextAgentJob(ctx, agID)
				ch <- claimRes{a: a, err: err}
			}()
		}

		claimedCount := 0
		nilCount := 0
		for i := 0; i < concurrency; i++ {
			res := <-ch
			if res.err != nil {
				t.Fatalf("concurrent claim produced error: %v", res.err)
			}
			if res.a != nil {
				claimedCount++
			} else {
				nilCount++
			}
		}

		if claimedCount != 1 {
			t.Fatalf("expected exactly 1 claim success, got %d", claimedCount)
		}
		if nilCount != concurrency-1 {
			t.Fatalf("expected %d nil claims, got %d", concurrency-1, nilCount)
		}
	})

	t.Run("start_agent_job_lifecycle_and_conflicts", func(t *testing.T) {
		op := createTestOp(fmt.Sprintf("op-start-%s", uuid.New().String()[:8]), operator.RoleAdmin)
		ag := createTestAgent()

		opID, _ := uuid.Parse(op.ID)
		agID, _ := uuid.Parse(ag.ID)
		var kh [32]byte
		_, _ = rand.Read(kh[:])

		j, _, err := db.CreateJob(ctx, opID, agID, job.ActionAgentPing, kh)
		if err != nil {
			t.Fatalf("failed to create job: %v", err)
		}

		claimed, err := db.ClaimNextAgentJob(ctx, agID)
		if err != nil || claimed == nil {
			t.Fatalf("failed to claim job: %v", err)
		}
		claimedJobID, _ := uuid.Parse(claimed.JobID)

		err = db.StartAgentJob(ctx, uuid.New(), claimedJobID, claimed.Attempt)
		if !errors.Is(err, job.ErrJobConflict) {
			t.Fatalf("expected ErrJobConflict for wrong agent, got %v", err)
		}

		err = db.StartAgentJob(ctx, agID, claimedJobID, claimed.Attempt+1)
		if !errors.Is(err, job.ErrJobConflict) {
			t.Fatalf("expected ErrJobConflict for wrong attempt, got %v", err)
		}

		concurrency := 5
		errChan := make(chan error, concurrency)
		for i := 0; i < concurrency; i++ {
			go func() {
				errChan <- db.StartAgentJob(ctx, agID, claimedJobID, claimed.Attempt)
			}()
		}

		startSuccess := 0
		startConflict := 0
		for i := 0; i < concurrency; i++ {
			err := <-errChan
			if err == nil {
				startSuccess++
			} else if errors.Is(err, job.ErrJobConflict) {
				startConflict++
			} else {
				t.Fatalf("unexpected start error: %v", err)
			}
		}

		if startSuccess != 1 {
			t.Fatalf("expected exactly 1 start success, got %d", startSuccess)
		}
		if startConflict != concurrency-1 {
			t.Fatalf("expected %d conflicts, got %d", concurrency-1, startConflict)
		}

		runningJob, err := db.GetJobByID(ctx, claimedJobID)
		if err != nil {
			t.Fatalf("GetJobByID failed: %v", err)
		}
		if runningJob.State != job.StateRunning {
			t.Fatalf("expected state running, got %s", runningJob.State)
		}
		if runningJob.ExecutionDeadlineAt == nil {
			t.Fatal("expected non-nil ExecutionDeadlineAt")
		}

		// Expired start test: dispatch lease expired before StartAgentJob
		// First complete runningJob to free in-flight slot
		_ = db.CompleteAgentJob(ctx, agID, claimedJobID, claimed.Attempt, "succeeded", "")

		var khExp [32]byte
		_, _ = rand.Read(khExp[:])
		jExp, _, err := db.CreateJob(ctx, opID, agID, job.ActionAgentPing, khExp)
		if err != nil {
			t.Fatalf("failed to create expired job: %v", err)
		}
		claimedExp, err := db.ClaimNextAgentJob(ctx, agID)
		if err != nil || claimedExp == nil {
			t.Fatalf("failed to claim jExp: %v", err)
		}
		expJobID, _ := uuid.Parse(claimedExp.JobID)

		_, err = db.pool.Exec(ctx, `
			UPDATE stackpilot.jobs
			SET dispatch_expires_at = clock_timestamp() - interval '1 second'
			WHERE id = $1
		`, expJobID)
		if err != nil {
			t.Fatalf("failed to expire dispatch lease: %v", err)
		}

		err = db.StartAgentJob(ctx, agID, expJobID, claimedExp.Attempt)
		if !errors.Is(err, job.ErrJobConflict) {
			t.Fatalf("expected ErrJobConflict on expired start, got %v", err)
		}

		reconciledExp, err := db.GetJobByID(ctx, expJobID)
		if err != nil {
			t.Fatalf("GetJobByID failed: %v", err)
		}
		if reconciledExp.State != job.StateQueued {
			t.Fatalf("expected state queued after expired start reconciliation, got %s", reconciledExp.State)
		}

		_ = j
		_ = jExp
	})

	t.Run("complete_agent_job_outcomes_and_replay", func(t *testing.T) {
		op := createTestOp(fmt.Sprintf("op-comp-%s", uuid.New().String()[:8]), operator.RoleAdmin)
		ag := createTestAgent()

		opID, _ := uuid.Parse(op.ID)
		agID, _ := uuid.Parse(ag.ID)

		var khSucc [32]byte
		_, _ = rand.Read(khSucc[:])
		jSuccess, _, _ := db.CreateJob(ctx, opID, agID, job.ActionAgentPing, khSucc)
		claimedSuccess, _ := db.ClaimNextAgentJob(ctx, agID)
		succJobID, _ := uuid.Parse(claimedSuccess.JobID)
		_ = db.StartAgentJob(ctx, agID, succJobID, claimedSuccess.Attempt)

		err := db.CompleteAgentJob(ctx, agID, succJobID, claimedSuccess.Attempt, "succeeded", "")
		if err != nil {
			t.Fatalf("CompleteAgentJob success failed: %v", err)
		}

		err = db.CompleteAgentJob(ctx, agID, succJobID, claimedSuccess.Attempt, "succeeded", "")
		if err != nil {
			t.Fatalf("CompleteAgentJob exact replay failed: %v", err)
		}

		err = db.CompleteAgentJob(ctx, agID, succJobID, claimedSuccess.Attempt, "failed", "executor_error")
		if !errors.Is(err, job.ErrJobConflict) {
			t.Fatalf("expected ErrJobConflict on conflicting replay, got %v", err)
		}

		var khFail [32]byte
		_, _ = rand.Read(khFail[:])
		jFail, _, _ := db.CreateJob(ctx, opID, agID, job.ActionAgentPing, khFail)
		claimedFail, _ := db.ClaimNextAgentJob(ctx, agID)
		failJobID, _ := uuid.Parse(claimedFail.JobID)
		_ = db.StartAgentJob(ctx, agID, failJobID, claimedFail.Attempt)

		err = db.CompleteAgentJob(ctx, agID, failJobID, claimedFail.Attempt, "failed", "executor_error")
		if err != nil {
			t.Fatalf("CompleteAgentJob failure failed: %v", err)
		}

		err = db.CompleteAgentJob(ctx, agID, failJobID, claimedFail.Attempt, "failed", "executor_error")
		if err != nil {
			t.Fatalf("CompleteAgentJob failure exact replay failed: %v", err)
		}

		if err := db.CompleteAgentJob(ctx, agID, failJobID, claimedFail.Attempt, "succeeded", "arbitrary"); !errors.Is(err, job.ErrJobConflict) {
			t.Fatalf("expected ErrJobConflict for succeeded with failure code, got %v", err)
		}
		if err := db.CompleteAgentJob(ctx, agID, failJobID, claimedFail.Attempt, "failed", "arbitrary"); !errors.Is(err, job.ErrJobConflict) {
			t.Fatalf("expected ErrJobConflict for failed with arbitrary failure code, got %v", err)
		}
		if err := db.CompleteAgentJob(ctx, agID, failJobID, claimedFail.Attempt, "invalid_outcome", ""); !errors.Is(err, job.ErrJobConflict) {
			t.Fatalf("expected ErrJobConflict for invalid outcome, got %v", err)
		}

		_ = jSuccess
		_ = jFail
	})

	t.Run("complete_agent_job_late_deadline_transition_unknown", func(t *testing.T) {
		op := createTestOp(fmt.Sprintf("op-late-%s", uuid.New().String()[:8]), operator.RoleAdmin)
		ag := createTestAgent()

		opID, _ := uuid.Parse(op.ID)
		agID, _ := uuid.Parse(ag.ID)

		var kh [32]byte
		_, _ = rand.Read(kh[:])
		jLate, _, err := db.CreateJob(ctx, opID, agID, job.ActionAgentPing, kh)
		if err != nil {
			t.Fatalf("failed to create job: %v", err)
		}
		claimed, err := db.ClaimNextAgentJob(ctx, agID)
		if err != nil || claimed == nil {
			t.Fatalf("failed to claim job: %v", err)
		}
		lateJobID, _ := uuid.Parse(claimed.JobID)
		if err := db.StartAgentJob(ctx, agID, lateJobID, claimed.Attempt); err != nil {
			t.Fatalf("failed to start job: %v", err)
		}

		_, err = db.pool.Exec(ctx, `
			UPDATE stackpilot.jobs
			SET execution_deadline_at = clock_timestamp() - interval '1 second'
			WHERE id = $1
		`, lateJobID)
		if err != nil {
			t.Fatalf("failed to expire deadline: %v", err)
		}

		err = db.CompleteAgentJob(ctx, agID, lateJobID, claimed.Attempt, "succeeded", "")
		if !errors.Is(err, job.ErrJobConflict) {
			t.Fatalf("expected ErrJobConflict on late completion, got %v", err)
		}

		reconciled, err := db.GetJobByID(ctx, lateJobID)
		if err != nil {
			t.Fatalf("GetJobByID failed: %v", err)
		}
		if reconciled.State != job.StateUnknown {
			t.Fatalf("expected state unknown for late completion, got %s", reconciled.State)
		}
		if reconciled.FailureCode == nil || *reconciled.FailureCode != "execution_timeout" {
			t.Fatalf("expected failure code execution_timeout, got %v", reconciled.FailureCode)
		}

		err = db.CompleteAgentJob(ctx, agID, lateJobID, claimed.Attempt, "succeeded", "")
		if !errors.Is(err, job.ErrJobConflict) {
			t.Fatalf("expected ErrJobConflict on second completion for unknown job, got %v", err)
		}

		_ = jLate
	})

	t.Run("complete_agent_job_running_null_deadline_fail_closed", func(t *testing.T) {
		op := createTestOp(fmt.Sprintf("op-null-dl-%s", uuid.New().String()[:8]), operator.RoleAdmin)
		ag := createTestAgent()

		opID, _ := uuid.Parse(op.ID)
		agID, _ := uuid.Parse(ag.ID)

		var kh [32]byte
		_, _ = rand.Read(kh[:])
		jNull, isNew, err := db.CreateJob(ctx, opID, agID, job.ActionAgentPing, kh)
		if err != nil || !isNew {
			t.Fatalf("CreateJob failed: %v", err)
		}
		claimed, err := db.ClaimNextAgentJob(ctx, agID)
		if err != nil || claimed == nil {
			t.Fatalf("ClaimNextAgentJob failed: %v", err)
		}
		nullJobID, _ := uuid.Parse(claimed.JobID)
		if err := db.StartAgentJob(ctx, agID, nullJobID, claimed.Attempt); err != nil {
			t.Fatalf("StartAgentJob failed: %v", err)
		}

		// Corrupt row by clearing execution_deadline_at while state is running
		_, err = db.pool.Exec(ctx, `
			UPDATE stackpilot.jobs
			SET execution_deadline_at = NULL
			WHERE id = $1
		`, nullJobID)
		if err != nil {
			t.Fatalf("failed to set execution_deadline_at to NULL: %v", err)
		}

		// CompleteAgentJob MUST return a safe backend corruption error, NOT ErrJobConflict
		err = db.CompleteAgentJob(ctx, agID, nullJobID, claimed.Attempt, "succeeded", "")
		if err == nil {
			t.Fatal("expected error on CompleteAgentJob with NULL execution_deadline_at, got nil")
		}
		if errors.Is(err, job.ErrJobConflict) {
			t.Fatalf("expected backend corruption error, not ErrJobConflict: %v", err)
		}

		// State must remain running, no transition accepted, and no new events written
		var st string
		var fc *string
		err = db.pool.QueryRow(ctx, "SELECT state, failure_code FROM stackpilot.jobs WHERE id = $1", nullJobID).Scan(&st, &fc)
		if err != nil {
			t.Fatalf("failed to query job state: %v", err)
		}
		if st != string(job.StateRunning) {
			t.Fatalf("expected state to remain running, got %s", st)
		}

		events, err := db.ListJobEvents(ctx, nullJobID, 10)
		if err != nil {
			t.Fatalf("failed to list job events: %v", err)
		}
		if len(events) != 3 {
			t.Fatalf("expected exactly 3 events (no terminal event written), got %d", len(events))
		}

		_ = jNull
	})

	t.Run("claim_next_agent_job_corrupt_attempt_fail_closed", func(t *testing.T) {
		op := createTestOp(fmt.Sprintf("op-corrupt-att-%s", uuid.New().String()[:8]), operator.RoleAdmin)
		ag := createTestAgent()

		opID, _ := uuid.Parse(op.ID)
		agID, _ := uuid.Parse(ag.ID)

		var kh [32]byte
		_, _ = rand.Read(kh[:])
		jCorrupt, isNew, err := db.CreateJob(ctx, opID, agID, job.ActionAgentPing, kh)
		if err != nil || !isNew {
			t.Fatalf("CreateJob failed: %v", err)
		}

		// Corrupt attempt count on queued row to MaxDispatchAttempts (5)
		_, err = db.pool.Exec(ctx, "UPDATE stackpilot.jobs SET attempt = 5 WHERE id = $1", jCorrupt.ID)
		if err != nil {
			t.Fatalf("failed to corrupt attempt: %v", err)
		}

		// ClaimNextAgentJob must reject corrupt attempt with internal error before writing attempt 6
		_, err = db.ClaimNextAgentJob(ctx, agID)
		if err == nil {
			t.Fatal("expected error on claiming job with attempt >= MaxDispatchAttempts, got nil")
		}

		_ = jCorrupt
	})

	t.Run("event_order_and_count_lifecycle", func(t *testing.T) {
		op := createTestOp(fmt.Sprintf("op-evt-%s", uuid.New().String()[:8]), operator.RoleAdmin)
		ag := createTestAgent()

		opID, _ := uuid.Parse(op.ID)
		agID, _ := uuid.Parse(ag.ID)

		var kh [32]byte
		_, _ = rand.Read(kh[:])

		j, isNew, err := db.CreateJob(ctx, opID, agID, job.ActionAgentPing, kh)
		if err != nil || !isNew {
			t.Fatalf("CreateJob failed: %v (isNew=%v)", err, isNew)
		}

		claimed, err := db.ClaimNextAgentJob(ctx, agID)
		if err != nil || claimed == nil {
			t.Fatalf("ClaimNextAgentJob failed: %v", err)
		}
		jobID, _ := uuid.Parse(claimed.JobID)

		if err := db.StartAgentJob(ctx, agID, jobID, claimed.Attempt); err != nil {
			t.Fatalf("StartAgentJob failed: %v", err)
		}

		if err := db.CompleteAgentJob(ctx, agID, jobID, claimed.Attempt, "succeeded", ""); err != nil {
			t.Fatalf("CompleteAgentJob failed: %v", err)
		}

		// Exact completion replay must NOT create another terminal event
		if err := db.CompleteAgentJob(ctx, agID, jobID, claimed.Attempt, "succeeded", ""); err != nil {
			t.Fatalf("CompleteAgentJob replay failed: %v", err)
		}

		events, err := db.ListJobEvents(ctx, jobID, 10)
		if err != nil {
			t.Fatalf("ListJobEvents failed: %v", err)
		}

		if len(events) != 4 {
			t.Fatalf("expected exactly 4 events for succeeded lifecycle, got %d", len(events))
		}

		expectedTypes := []string{
			job.EventJobCreated,
			job.EventJobDispatched,
			job.EventJobStarted,
			job.EventJobSucceeded,
		}
		for i, expected := range expectedTypes {
			if events[i].EventType != expected {
				t.Fatalf("event %d: expected %s, got %s", i, expected, events[i].EventType)
			}
			if i > 0 {
				if events[i].OccurredAt.Before(events[i-1].OccurredAt) {
					t.Fatalf("events not ordered by occurred_at ASC: index %d (%v) before %d (%v)",
						i, events[i].OccurredAt, i-1, events[i-1].OccurredAt)
				}
			}
		}

		_ = j
	})

	t.Run("expiry_attempts_1_through_5_separately", func(t *testing.T) {
		op := createTestOp(fmt.Sprintf("op-exp-seq-%s", uuid.New().String()[:8]), operator.RoleAdmin)
		ag := createTestAgent()

		opID, _ := uuid.Parse(op.ID)
		agID, _ := uuid.Parse(ag.ID)

		for att := 1; att <= 4; att++ {
			var kh [32]byte
			_, _ = rand.Read(kh[:])
			j, isNew, err := db.CreateJob(ctx, opID, agID, job.ActionAgentPing, kh)
			if err != nil || !isNew {
				t.Fatalf("attempt %d: CreateJob failed: %v", att, err)
			}

			claimed, err := db.ClaimNextAgentJob(ctx, agID)
			if err != nil || claimed == nil {
				t.Fatalf("attempt %d: ClaimNextAgentJob failed: %v", att, err)
			}
			jobID, _ := uuid.Parse(claimed.JobID)

			_, err = db.pool.Exec(ctx, `
				UPDATE stackpilot.jobs
				SET attempt = $2,
				    dispatch_expires_at = clock_timestamp() - interval '10 seconds'
				WHERE id = $1
			`, jobID, att)
			if err != nil {
				t.Fatalf("attempt %d: update failed: %v", att, err)
			}

			reconciled, err := db.GetJobByID(ctx, jobID)
			if err != nil {
				t.Fatalf("attempt %d: GetJobByID failed: %v", att, err)
			}
			if reconciled.State != job.StateQueued {
				t.Fatalf("attempt %d: expected state queued after expiry, got %s", att, reconciled.State)
			}

			_, _ = db.pool.Exec(ctx, "DELETE FROM stackpilot.jobs WHERE id = $1", jobID)
			_ = j
		}

		var kh5 [32]byte
		_, _ = rand.Read(kh5[:])
		j5, isNew, err := db.CreateJob(ctx, opID, agID, job.ActionAgentPing, kh5)
		if err != nil || !isNew {
			t.Fatalf("attempt 5: CreateJob failed: %v", err)
		}

		claimed5, err := db.ClaimNextAgentJob(ctx, agID)
		if err != nil || claimed5 == nil {
			t.Fatalf("attempt 5: ClaimNextAgentJob failed: %v", err)
		}
		jobID5, _ := uuid.Parse(claimed5.JobID)

		_, err = db.pool.Exec(ctx, `
			UPDATE stackpilot.jobs
			SET attempt = 5,
			    dispatch_expires_at = clock_timestamp() - interval '10 seconds'
			WHERE id = $1
		`, jobID5)
		if err != nil {
			t.Fatalf("attempt 5: update failed: %v", err)
		}

		reconciled5, err := db.GetJobByID(ctx, jobID5)
		if err != nil {
			t.Fatalf("attempt 5: GetJobByID failed: %v", err)
		}
		if reconciled5.State != job.StateFailed {
			t.Fatalf("attempt 5: expected state failed, got %s", reconciled5.State)
		}
		if reconciled5.FailureCode == nil || *reconciled5.FailureCode != "dispatch_exhausted" {
			t.Fatalf("attempt 5: expected failure code dispatch_exhausted, got %v", reconciled5.FailureCode)
		}

		_ = j5
	})

	t.Run("expiration_reconciliation_running_deadline", func(t *testing.T) {
		op := createTestOp(fmt.Sprintf("op-run-exp-%s", uuid.New().String()[:8]), operator.RoleAdmin)
		ag := createTestAgent()

		opID, _ := uuid.Parse(op.ID)
		agID, _ := uuid.Parse(ag.ID)

		var khUnk [32]byte
		_, _ = rand.Read(khUnk[:])
		jUnknown, isNew, err := db.CreateJob(ctx, opID, agID, job.ActionAgentPing, khUnk)
		if err != nil || !isNew {
			t.Fatalf("CreateJob failed: %v", err)
		}
		claimedUnk, err := db.ClaimNextAgentJob(ctx, agID)
		if err != nil || claimedUnk == nil {
			t.Fatalf("ClaimNextAgentJob failed: %v", err)
		}
		claimedUnkID, _ := uuid.Parse(claimedUnk.JobID)
		if err := db.StartAgentJob(ctx, agID, claimedUnkID, claimedUnk.Attempt); err != nil {
			t.Fatalf("StartAgentJob failed: %v", err)
		}

		_, err = db.pool.Exec(ctx, `
			UPDATE stackpilot.jobs
			SET execution_deadline_at = clock_timestamp() - interval '10 seconds'
			WHERE id = $1
		`, claimedUnkID)
		if err != nil {
			t.Fatalf("failed to set execution_deadline_at in past: %v", err)
		}

		reconciledUnk, err := db.GetJobByID(ctx, claimedUnkID)
		if err != nil {
			t.Fatalf("GetJobByID failed: %v", err)
		}
		if reconciledUnk.State != job.StateUnknown {
			t.Fatalf("expected state unknown, got %s", reconciledUnk.State)
		}
		if reconciledUnk.FailureCode == nil || *reconciledUnk.FailureCode != "execution_timeout" {
			t.Fatalf("expected failure code execution_timeout, got %v", reconciledUnk.FailureCode)
		}

		claimAfterUnk, err := db.ClaimNextAgentJob(ctx, agID)
		if err != nil {
			t.Fatalf("ClaimNextAgentJob failed: %v", err)
		}
		if claimAfterUnk != nil {
			t.Fatalf("expected nil claim after unknown job, got %v", claimAfterUnk)
		}

		_ = jUnknown
	})
}
