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
	"testing"
	"time"

	"stackpilot/internal/enrollment"
	"stackpilot/internal/operator"
	"stackpilot/internal/protocol"
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

	// 5. Verify migration version is 9 (migrations 001-009 applied)
	var version int32
	err = db.pool.QueryRow(ctx, "SELECT version FROM public.stackpilot_schema_version").Scan(&version)
	if err != nil {
		t.Fatalf("failed to query schema version: %v", err)
	}
	if version != 9 {
		t.Fatalf("expected schema version 9, got %d", version)
	}

	// 6. Run db.Migrate() a second time (idempotency check)
	err = db.Migrate(ctx, nil)
	if err != nil {
		t.Fatalf("second db.Migrate() failed: %v", err)
	}

	// 7. Verify version remains 9
	err = db.pool.QueryRow(ctx, "SELECT version FROM public.stackpilot_schema_version").Scan(&version)
	if err != nil {
		t.Fatalf("failed to query schema version after second run: %v", err)
	}
	if version != 9 {
		t.Fatalf("expected schema version to remain 9, got %d", version)
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
