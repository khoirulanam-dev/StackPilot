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

	if len(migrations) != 1 {
		t.Fatalf("expected exactly 1 migration, got %d", len(migrations))
	}

	expectedName := "001_create_stackpilot_schema.sql"
	if migrations[0] != expectedName {
		t.Errorf("expected migration %q, got %q", expectedName, migrations[0])
	}

	content, err := migrationsFS.ReadFile("migrations/" + expectedName)
	if err != nil {
		t.Fatalf("failed to read embedded migration file: %v", err)
	}

	sqlStr := string(content)
	if !strings.Contains(sqlStr, "CREATE SCHEMA stackpilot;") {
		t.Errorf("migration missing CREATE SCHEMA stackpilot: %s", sqlStr)
	}

	if !strings.Contains(sqlStr, "---- create above / drop below ----") {
		t.Errorf("migration missing Tern separator: %s", sqlStr)
	}

	if !strings.Contains(sqlStr, "DROP SCHEMA stackpilot;") {
		t.Errorf("migration missing DROP SCHEMA stackpilot: %s", sqlStr)
	}

	if strings.Contains(sqlStr, "CASCADE") {
		t.Errorf("migration must not use CASCADE: %s", sqlStr)
	}
}
