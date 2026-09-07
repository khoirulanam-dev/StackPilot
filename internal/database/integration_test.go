package database

import (
	"context"
	"os"
	"testing"
	"time"
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

	// 5. Verify migration version is 1
	var version int32
	err = db.pool.QueryRow(ctx, "SELECT version FROM public.stackpilot_schema_version").Scan(&version)
	if err != nil {
		t.Fatalf("failed to query schema version: %v", err)
	}
	if version != 1 {
		t.Fatalf("expected schema version 1, got %d", version)
	}

	// 6. Run migration again (verify idempotence)
	if err := db.Migrate(ctx, nil); err != nil {
		t.Fatalf("second migration run failed: %v", err)
	}

	// 7. Verify version remains 1
	err = db.pool.QueryRow(ctx, "SELECT version FROM public.stackpilot_schema_version").Scan(&version)
	if err != nil {
		t.Fatalf("failed to query schema version after second run: %v", err)
	}
	if version != 1 {
		t.Fatalf("expected schema version to remain 1, got %d", version)
	}
}
