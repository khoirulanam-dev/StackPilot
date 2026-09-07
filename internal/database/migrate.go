package database

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"time"

	"github.com/jackc/tern/v2/migrate"
)

const (
	versionTable            = "public.stackpilot_schema_version"
	defaultMigrationTimeout = 30 * time.Second
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// getEmbeddedMigrations returns the filenames of embedded migration SQL files.
func getEmbeddedMigrations() ([]string, error) {
	subFS, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("failed to open migrations directory: %w", err)
	}
	return migrate.FindMigrations(subFS)
}

// Migrate executes pending Tern migrations using embedded migration SQL.
func (db *DB) Migrate(ctx context.Context, logger *slog.Logger) error {
	if db.pool == nil {
		return fmt.Errorf("database pool is not initialized")
	}

	migrateCtx, cancel := context.WithTimeout(ctx, defaultMigrationTimeout)
	defer cancel()

	conn, err := db.pool.Acquire(migrateCtx)
	if err != nil {
		return fmt.Errorf("database migration failed: failed to acquire connection: %w", sanitizeError(err))
	}
	defer conn.Release()

	m, err := migrate.NewMigrator(migrateCtx, conn.Conn(), versionTable)
	if err != nil {
		return fmt.Errorf("database migration failed: failed to create migrator: %w", sanitizeError(err))
	}

	subFS, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("database migration failed: failed to access migrations directory: %w", err)
	}

	if err := m.LoadMigrations(subFS); err != nil {
		return fmt.Errorf("database migration failed: failed to load migrations: %w", err)
	}

	if logger != nil {
		m.OnStart = func(sequence int32, name, direction, sql string) {
			logger.Info("applying migration",
				"sequence", sequence,
				"name", name,
				"direction", direction,
			)
		}
	}

	if err := m.Migrate(migrateCtx); err != nil {
		return fmt.Errorf("database migration failed: %w", sanitizeError(err))
	}

	return nil
}
