package database

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"stackpilot/internal/enrollment"
)

const (
	defaultMaxConns       = 10
	defaultMinConns       = 0
	defaultConnectTimeout = 5 * time.Second
	applicationName       = "stackpilot-controller"
)

// DB encapsulates the PostgreSQL connection pool and lifecycle operations.
type DB struct {
	pool *pgxpool.Pool
}

// configurePool constructs and tunes a pgxpool.Config from a raw PostgreSQL database URL.
func configurePool(databaseURL string) (*pgxpool.Config, error) {
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database configuration")
	}

	poolConfig.MaxConns = defaultMaxConns
	poolConfig.MinConns = defaultMinConns
	if poolConfig.ConnConfig.RuntimeParams == nil {
		poolConfig.ConnConfig.RuntimeParams = make(map[string]string)
	}
	poolConfig.ConnConfig.RuntimeParams["application_name"] = applicationName
	poolConfig.ConnConfig.RequireAuth = "scram-sha-256"

	return poolConfig, nil
}

// Open creates the connection pool and performs an initial bounded ping check.
func Open(ctx context.Context, databaseURL string) (*DB, error) {
	poolConfig, err := configurePool(databaseURL)
	if err != nil {
		return nil, err
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database pool")
	}

	db := &DB{pool: pool}

	pingCtx, cancel := context.WithTimeout(ctx, defaultConnectTimeout)
	defer cancel()

	if err := db.Ping(pingCtx); err != nil {
		db.Close()
		return nil, fmt.Errorf("database ping failed: %w", sanitizeError(err))
	}

	return db, nil
}

// Ping checks database connectivity within the provided context.
func (db *DB) Ping(ctx context.Context) error {
	if db.pool == nil {
		return fmt.Errorf("database pool is not initialized")
	}
	return db.pool.Ping(ctx)
}

// Close closes all connections in the pool.
func (db *DB) Close() {
	if db.pool != nil {
		db.pool.Close()
	}
}

// CreateEnrollmentToken inserts a token hash and its expiration into stackpilot.enrollment_tokens.
func (db *DB) CreateEnrollmentToken(ctx context.Context, tokenHash [32]byte, expiresAt time.Time) (*enrollment.TokenRecord, error) {
	if db.pool == nil {
		return nil, fmt.Errorf("database pool is not initialized")
	}

	const query = `
		INSERT INTO stackpilot.enrollment_tokens (token_hash, expires_at)
		VALUES ($1, $2)
		RETURNING id::text, created_at, expires_at
	`

	record := &enrollment.TokenRecord{}
	err := db.pool.QueryRow(ctx, query, tokenHash[:], expiresAt).Scan(
		&record.ID,
		&record.CreatedAt,
		&record.ExpiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create enrollment token: %w", sanitizeError(err))
	}

	return record, nil
}

var (
	passwordPattern = regexp.MustCompile(`(?i)(password=)[^\s&,]+`)
	userinfoPattern = regexp.MustCompile(`(:)[^/@:]+(@)`)
)

// sanitizeError returns a safe error representation preventing credential leakage.
func sanitizeError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	msg = passwordPattern.ReplaceAllString(msg, "${1}[REDACTED]")
	msg = userinfoPattern.ReplaceAllString(msg, "${1}[REDACTED]${2}")
	return errors.New(msg)
}
