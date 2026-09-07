package database

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

// RegisterAgent atomically consumes an enrollment token and creates an Agent identity in a single transaction.
// It implements safe idempotent retry for the same token + same public key.
func (db *DB) RegisterAgent(ctx context.Context, tokenHash [32]byte, publicKey [32]byte) (*enrollment.AgentRecord, bool, error) {
	if db.pool == nil {
		return nil, false, fmt.Errorf("database pool is not initialized")
	}

	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("failed to begin transaction: %w", sanitizeError(err))
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	// 1. Query token row FOR UPDATE with database-side expiration check
	const queryToken = `
		SELECT id::text, (now() >= expires_at) AS is_expired, consumed_at
		FROM stackpilot.enrollment_tokens
		WHERE token_hash = $1
		FOR UPDATE
	`

	var (
		tokenID    string
		isExpired  bool
		consumedAt sql.NullTime
	)

	err = tx.QueryRow(ctx, queryToken, tokenHash[:]).Scan(&tokenID, &isExpired, &consumedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, enrollment.ErrEnrollmentRejected
		}
		return nil, false, fmt.Errorf("failed to query enrollment token: %w", sanitizeError(err))
	}

	// 2. If already consumed: verify idempotent retry for same public key (even if token has since expired)
	if consumedAt.Valid {
		const queryExistingAgent = `
			SELECT id::text, public_key, created_at
			FROM stackpilot.agents
			WHERE enrollment_token_id = $1::uuid
		`
		var (
			existingID        string
			existingPubKey    []byte
			existingCreatedAt time.Time
		)
		err = tx.QueryRow(ctx, queryExistingAgent, tokenID).Scan(&existingID, &existingPubKey, &existingCreatedAt)
		if err != nil {
			return nil, false, fmt.Errorf("failed to query existing agent: %w", sanitizeError(err))
		}

		if !bytes.Equal(existingPubKey, publicKey[:]) {
			// Consumed token with different public key: reject
			return nil, false, enrollment.ErrEnrollmentRejected
		}

		if err := tx.Commit(ctx); err != nil {
			return nil, false, fmt.Errorf("failed to commit transaction: %w", sanitizeError(err))
		}

		return &enrollment.AgentRecord{
			ID:        existingID,
			PublicKey: publicKey,
			CreatedAt: existingCreatedAt,
		}, false, nil
	}

	// 3. ONLY if token is still unconsumed: check expiration
	if isExpired {
		return nil, false, enrollment.ErrEnrollmentRejected
	}

	// 3. Not consumed: insert new agent record
	const insertAgent = `
		INSERT INTO stackpilot.agents (public_key, enrollment_token_id)
		VALUES ($1, $2::uuid)
		RETURNING id::text, created_at
	`
	var (
		agentID        string
		agentCreatedAt time.Time
	)
	err = tx.QueryRow(ctx, insertAgent, publicKey[:], tokenID).Scan(&agentID, &agentCreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			// Unique violation on public_key
			return nil, false, enrollment.ErrIdentityConflict
		}
		return nil, false, fmt.Errorf("failed to insert agent: %w", sanitizeError(err))
	}

	// 4. Mark token consumed
	const consumeToken = `
		UPDATE stackpilot.enrollment_tokens
		SET consumed_at = now()
		WHERE id = $1::uuid
	`
	tag, err := tx.Exec(ctx, consumeToken, tokenID)
	if err != nil {
		return nil, false, fmt.Errorf("failed to update enrollment token: %w", sanitizeError(err))
	}
	if tag.RowsAffected() != 1 {
		return nil, false, fmt.Errorf("unexpected rows affected marking token consumed: %d", tag.RowsAffected())
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, false, fmt.Errorf("failed to commit transaction: %w", sanitizeError(err))
	}

	return &enrollment.AgentRecord{
		ID:        agentID,
		PublicKey: publicKey,
		CreatedAt: agentCreatedAt,
	}, true, nil
}

// FindAgentByPublicKey queries stackpilot.agents for an Agent by 32-byte Ed25519 public key.
// It returns enrollment.ErrAgentNotFound if no agent with the given public key exists.
func (db *DB) FindAgentByPublicKey(ctx context.Context, publicKey [32]byte) (*enrollment.AgentRecord, error) {
	if db.pool == nil {
		return nil, fmt.Errorf("database pool is not initialized")
	}

	const query = `
		SELECT id::text, public_key, created_at
		FROM stackpilot.agents
		WHERE public_key = $1
	`

	var (
		id        string
		pubKey    []byte
		createdAt time.Time
	)

	err := db.pool.QueryRow(ctx, query, publicKey[:]).Scan(&id, &pubKey, &createdAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, enrollment.ErrAgentNotFound
		}
		return nil, fmt.Errorf("failed to query agent: %w", sanitizeError(err))
	}

	if len(pubKey) != 32 {
		return nil, fmt.Errorf("unexpected public key length in database: %d", len(pubKey))
	}

	var pub [32]byte
	copy(pub[:], pubKey)

	return &enrollment.AgentRecord{
		ID:        id,
		PublicKey: pub,
		CreatedAt: createdAt,
	}, nil
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
