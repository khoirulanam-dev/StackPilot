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
	"stackpilot/internal/operator"
	"stackpilot/internal/protocol"
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
		SELECT id::text, public_key, created_at, last_seen_at, protocol_version
		FROM stackpilot.agents
		WHERE public_key = $1
	`

	var (
		id              string
		pubKey          []byte
		createdAt       time.Time
		lastSeenAt      *time.Time
		protocolVersion *int
	)

	err := db.pool.QueryRow(ctx, query, publicKey[:]).Scan(&id, &pubKey, &createdAt, &lastSeenAt, &protocolVersion)
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
		ID:              id,
		PublicKey:       pub,
		CreatedAt:       createdAt,
		LastSeenAt:      lastSeenAt,
		ProtocolVersion: protocolVersion,
	}, nil
}

// RecordAgentHeartbeat updates the agent's presence timestamp to database now() and records protocol_version.
func (db *DB) RecordAgentHeartbeat(ctx context.Context, publicKey [32]byte, protocolVersion int) (*enrollment.AgentRecord, error) {
	if db.pool == nil {
		return nil, fmt.Errorf("database pool is not initialized")
	}

	const query = `
		UPDATE stackpilot.agents
		SET
			last_seen_at = now(),
			protocol_version = $2
		WHERE public_key = $1
		RETURNING id::text, created_at, last_seen_at, protocol_version
	`

	var (
		id                     string
		createdAt              time.Time
		lastSeenAt             *time.Time
		protocolVersionScanned *int
	)

	err := db.pool.QueryRow(ctx, query, publicKey[:], protocolVersion).Scan(&id, &createdAt, &lastSeenAt, &protocolVersionScanned)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, enrollment.ErrAgentNotFound
		}
		return nil, fmt.Errorf("failed to record agent heartbeat: %w", sanitizeError(err))
	}

	return &enrollment.AgentRecord{
		ID:              id,
		PublicKey:       publicKey,
		CreatedAt:       createdAt,
		LastSeenAt:      lastSeenAt,
		ProtocolVersion: protocolVersionScanned,
	}, nil
}

// RecordAgentInventory updates or inserts the agent's current host inventory snapshot in one database round trip.
func (db *DB) RecordAgentInventory(ctx context.Context, publicKey [32]byte, req *protocol.InventoryRequest) error {
	if db.pool == nil {
		return fmt.Errorf("database pool is not initialized")
	}
	if req == nil {
		return fmt.Errorf("inventory request is nil")
	}

	const query = `
		WITH target_agent AS (
			SELECT id
			FROM stackpilot.agents
			WHERE public_key = $1
		),
		upserted AS (
			INSERT INTO stackpilot.agent_inventory (
				agent_id,
				hostname,
				os_id,
				os_name,
				os_version,
				kernel_release,
				architecture,
				cpu_logical_cores,
				memory_total_bytes,
				reported_at
			)
			SELECT
				target_agent.id,
				$2, $3, $4, $5, $6, $7, $8, $9,
				now()
			FROM target_agent
			ON CONFLICT (agent_id)
			DO UPDATE SET
				hostname = EXCLUDED.hostname,
				os_id = EXCLUDED.os_id,
				os_name = EXCLUDED.os_name,
				os_version = EXCLUDED.os_version,
				kernel_release = EXCLUDED.kernel_release,
				architecture = EXCLUDED.architecture,
				cpu_logical_cores = EXCLUDED.cpu_logical_cores,
				memory_total_bytes = EXCLUDED.memory_total_bytes,
				reported_at = now()
			RETURNING agent_id
		)
		SELECT agent_id
		FROM upserted;
	`

	var agentID string
	err := db.pool.QueryRow(ctx, query,
		publicKey[:],
		req.Hostname,
		req.OSID,
		req.OSName,
		req.OSVersion,
		req.KernelRelease,
		req.Architecture,
		req.CPULogicalCores,
		req.MemoryTotalBytes,
	).Scan(&agentID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return enrollment.ErrAgentNotFound
		}
		return fmt.Errorf("failed to record agent inventory: %w", sanitizeError(err))
	}

	return nil
}

// RecordAgentTelemetry updates or inserts the current runtime telemetry snapshot for an Agent in one round-trip.
func (db *DB) RecordAgentTelemetry(ctx context.Context, publicKey [32]byte, req *protocol.TelemetryRequest) error {
	if db.pool == nil {
		return fmt.Errorf("database pool is not initialized")
	}
	if req == nil {
		return errors.New("telemetry request is nil")
	}

	const query = `
		WITH target_agent AS (
			SELECT id
			FROM stackpilot.agents
			WHERE public_key = $1
		),
		upserted AS (
			INSERT INTO stackpilot.agent_telemetry (
				agent_id,
				cpu_usage_basis_points,
				memory_total_bytes,
				memory_used_bytes,
				memory_available_bytes,
				load_1m_milli,
				load_5m_milli,
				load_15m_milli,
				root_filesystem_total_bytes,
				root_filesystem_used_bytes,
				root_filesystem_available_bytes,
				network_receive_bytes_total,
				network_transmit_bytes_total,
				uptime_seconds,
				sample_window_ms,
				reported_at
			)
			SELECT
				target_agent.id,
				$2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
				now()
			FROM target_agent
			ON CONFLICT (agent_id)
			DO UPDATE SET
				cpu_usage_basis_points = EXCLUDED.cpu_usage_basis_points,
				memory_total_bytes = EXCLUDED.memory_total_bytes,
				memory_used_bytes = EXCLUDED.memory_used_bytes,
				memory_available_bytes = EXCLUDED.memory_available_bytes,
				load_1m_milli = EXCLUDED.load_1m_milli,
				load_5m_milli = EXCLUDED.load_5m_milli,
				load_15m_milli = EXCLUDED.load_15m_milli,
				root_filesystem_total_bytes = EXCLUDED.root_filesystem_total_bytes,
				root_filesystem_used_bytes = EXCLUDED.root_filesystem_used_bytes,
				root_filesystem_available_bytes = EXCLUDED.root_filesystem_available_bytes,
				network_receive_bytes_total = EXCLUDED.network_receive_bytes_total,
				network_transmit_bytes_total = EXCLUDED.network_transmit_bytes_total,
				uptime_seconds = EXCLUDED.uptime_seconds,
				sample_window_ms = EXCLUDED.sample_window_ms,
				reported_at = now()
			RETURNING agent_id
		)
		SELECT agent_id
		FROM upserted;
	`

	var agentID string
	err := db.pool.QueryRow(ctx, query,
		publicKey[:],
		req.CPUUsageBasisPoints,
		req.MemoryTotalBytes,
		req.MemoryUsedBytes,
		req.MemoryAvailableBytes,
		req.Load1mMilli,
		req.Load5mMilli,
		req.Load15mMilli,
		req.RootFilesystemTotalBytes,
		req.RootFilesystemUsedBytes,
		req.RootFilesystemAvailableBytes,
		req.NetworkReceiveBytesTotal,
		req.NetworkTransmitBytesTotal,
		req.UptimeSeconds,
		req.SampleWindowMS,
	).Scan(&agentID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return enrollment.ErrAgentNotFound
		}
		return fmt.Errorf("failed to record agent telemetry: %w", sanitizeError(err))
	}

	return nil
}

// CreateOperator creates a new operator and records an audit event atomically.
func (db *DB) CreateOperator(ctx context.Context, username, passwordHash string, role operator.Role) (*operator.OperatorRecord, error) {
	if db.pool == nil {
		return nil, fmt.Errorf("database pool is not initialized")
	}

	username = operator.NormalizeUsername(username)
	if err := operator.ValidateUsername(username); err != nil {
		return nil, err
	}
	if !role.Valid() {
		return nil, fmt.Errorf("invalid operator role: %q", role)
	}

	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", sanitizeError(err))
	}
	defer tx.Rollback(ctx)

	const insertOpQuery = `
		INSERT INTO stackpilot.operators (username, password_hash, role)
		VALUES ($1, $2, $3)
		RETURNING id::text, username, password_hash, role, disabled_at, created_at, updated_at
	`

	var record operator.OperatorRecord
	var roleStr string
	err = tx.QueryRow(ctx, insertOpQuery, username, passwordHash, string(role)).Scan(
		&record.ID,
		&record.Username,
		&record.PasswordHash,
		&roleStr,
		&record.DisabledAt,
		&record.CreatedAt,
		&record.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, operator.ErrUsernameConflict
		}
		return nil, fmt.Errorf("failed to insert operator: %w", sanitizeError(err))
	}
	record.Role = operator.Role(roleStr)

	const insertAuditQuery = `
		INSERT INTO stackpilot.operator_audit_events (
			actor_operator_id, actor_username, action, target_operator_id, target_username, outcome
		) VALUES (
			NULL, 'system', $1, $2, $3, $4
		)
	`
	_, err = tx.Exec(ctx, insertAuditQuery,
		string(operator.ActionOperatorCreated),
		record.ID,
		record.Username,
		string(operator.OutcomeSuccess),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to record operator creation audit event: %w", sanitizeError(err))
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit operator creation: %w", sanitizeError(err))
	}

	return &record, nil
}

// GetOperatorByUsername retrieves an operator record by username for credential verification.
func (db *DB) GetOperatorByUsername(ctx context.Context, username string) (*operator.OperatorRecord, error) {
	if db.pool == nil {
		return nil, fmt.Errorf("database pool is not initialized")
	}

	username = operator.NormalizeUsername(username)
	const query = `
		SELECT id::text, username, password_hash, role, disabled_at, created_at, updated_at
		FROM stackpilot.operators
		WHERE username = $1
	`

	var record operator.OperatorRecord
	var roleStr string
	err := db.pool.QueryRow(ctx, query, username).Scan(
		&record.ID,
		&record.Username,
		&record.PasswordHash,
		&roleStr,
		&record.DisabledAt,
		&record.CreatedAt,
		&record.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, operator.ErrOperatorNotFound
		}
		return nil, fmt.Errorf("failed to query operator: %w", sanitizeError(err))
	}
	role, err := operator.ParseRole(roleStr)
	if err != nil {
		return nil, fmt.Errorf("corrupt operator role: %w", sanitizeError(err))
	}
	record.Role = role
	return &record, nil
}

// CreateOperatorSession serializes concurrent session creations, verifies enabled status, bounds active sessions,
// and records the login audit event atomically.
func (db *DB) CreateOperatorSession(ctx context.Context, operatorID string, tokenHash [32]byte) (*operator.SessionRecord, error) {
	if db.pool == nil {
		return nil, fmt.Errorf("database pool is not initialized")
	}

	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin session transaction: %w", sanitizeError(err))
	}
	defer tx.Rollback(ctx)

	// Lock operator row to eliminate TOCTOU race: verify account remains active and derive canonical username.
	var (
		lockedID          string
		canonicalUsername string
	)
	err = tx.QueryRow(ctx, `SELECT id::text, username FROM stackpilot.operators WHERE id = $1 AND disabled_at IS NULL FOR UPDATE`, operatorID).Scan(&lockedID, &canonicalUsername)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, operator.ErrAuthenticationFailed
		}
		return nil, fmt.Errorf("failed to lock operator record: %w", sanitizeError(err))
	}

	_, err = tx.Exec(ctx, `DELETE FROM stackpilot.operator_sessions WHERE operator_id = $1 AND expires_at <= now()`, operatorID)
	if err != nil {
		return nil, fmt.Errorf("failed to prune expired sessions: %w", sanitizeError(err))
	}

	retainCount := operator.MaxActiveSessionsPerOperator - 1
	const pruneExcessQuery = `
		DELETE FROM stackpilot.operator_sessions
		WHERE operator_id = $1
		  AND id NOT IN (
			SELECT id FROM stackpilot.operator_sessions
			WHERE operator_id = $1
			ORDER BY created_at DESC, id DESC
			LIMIT $2
		  )
	`
	if _, err = tx.Exec(ctx, pruneExcessQuery, operatorID, retainCount); err != nil {
		return nil, fmt.Errorf("failed to prune excess sessions: %w", sanitizeError(err))
	}

	lifetimeSeconds := int64(operator.SessionLifetime / time.Second)
	const insertSessionQuery = `
		INSERT INTO stackpilot.operator_sessions (operator_id, token_hash, expires_at)
		VALUES ($1, $2, now() + ($3 * interval '1 second'))
		RETURNING id::text, operator_id::text, created_at, expires_at
	`
	var sessionRec operator.SessionRecord
	err = tx.QueryRow(ctx, insertSessionQuery, operatorID, tokenHash[:], lifetimeSeconds).Scan(
		&sessionRec.ID,
		&sessionRec.OperatorID,
		&sessionRec.CreatedAt,
		&sessionRec.ExpiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to insert session: %w", sanitizeError(err))
	}

	const insertAuditQuery = `
		INSERT INTO stackpilot.operator_audit_events (
			actor_operator_id, actor_username, action, target_operator_id, target_username, outcome
		) VALUES (
			$1, $2, $3, $1, $2, $4
		)
	`
	_, err = tx.Exec(ctx, insertAuditQuery,
		operatorID,
		canonicalUsername,
		string(operator.ActionOperatorLogin),
		string(operator.OutcomeSuccess),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to record login audit event: %w", sanitizeError(err))
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit session transaction: %w", sanitizeError(err))
	}

	return &sessionRec, nil
}

// FindOperatorSessionByTokenHash queries the active session and joined operator identity in a single round-trip.
func (db *DB) FindOperatorSessionByTokenHash(ctx context.Context, tokenHash [32]byte) (*operator.Principal, error) {
	if db.pool == nil {
		return nil, fmt.Errorf("database pool is not initialized")
	}

	const query = `
		SELECT
			o.id::text,
			o.username,
			o.role,
			s.id::text,
			s.expires_at
		FROM stackpilot.operator_sessions s
		JOIN stackpilot.operators o ON s.operator_id = o.id
		WHERE s.token_hash = $1
		  AND s.expires_at > now()
		  AND o.disabled_at IS NULL
	`

	var (
		p       operator.Principal
		roleStr string
	)
	err := db.pool.QueryRow(ctx, query, tokenHash[:]).Scan(
		&p.OperatorID,
		&p.Username,
		&roleStr,
		&p.SessionID,
		&p.ExpiresAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, operator.ErrAuthenticationFailed
		}
		return nil, fmt.Errorf("failed to query session: %w", sanitizeError(err))
	}

	role, err := operator.ParseRole(roleStr)
	if err != nil {
		return nil, operator.ErrAuthenticationFailed
	}
	p.Role = role
	return &p, nil
}

// RevokeOperatorSession deletes the specified session scoped by both session ID and operator ID,
// and records the logout audit event atomically only if the session was found and deleted.
func (db *DB) RevokeOperatorSession(ctx context.Context, sessionID string, operatorID string, username string) error {
	if db.pool == nil {
		return fmt.Errorf("database pool is not initialized")
	}

	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin logout transaction: %w", sanitizeError(err))
	}
	defer tx.Rollback(ctx)

	var deletedID string
	err = tx.QueryRow(ctx, `
		DELETE FROM stackpilot.operator_sessions
		WHERE id = $1 AND operator_id = $2
		RETURNING id::text
	`, sessionID, operatorID).Scan(&deletedID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return operator.ErrSessionNotFound
		}
		return fmt.Errorf("failed to delete session: %w", sanitizeError(err))
	}

	const insertAuditQuery = `
		INSERT INTO stackpilot.operator_audit_events (
			actor_operator_id, actor_username, action, target_operator_id, target_username, outcome
		) VALUES (
			$1, $2, $3, NULL, NULL, $4
		)
	`
	_, err = tx.Exec(ctx, insertAuditQuery,
		operatorID,
		username,
		string(operator.ActionOperatorLogout),
		string(operator.OutcomeSuccess),
	)
	if err != nil {
		return fmt.Errorf("failed to record logout audit event: %w", sanitizeError(err))
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit logout transaction: %w", sanitizeError(err))
	}
	return nil
}

// RecordAndListAuditEvents records the operator.audit.read event before listing historical audit records.
func (db *DB) RecordAndListAuditEvents(ctx context.Context, actorOperatorID string, actorUsername string, limit int) ([]operator.AuditEventRecord, error) {
	if db.pool == nil {
		return nil, fmt.Errorf("database pool is not initialized")
	}
	if limit <= 0 || limit > 200 {
		return nil, fmt.Errorf("invalid audit limit: %d", limit)
	}

	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin audit read transaction: %w", sanitizeError(err))
	}
	defer tx.Rollback(ctx)

	const insertAuditQuery = `
		INSERT INTO stackpilot.operator_audit_events (
			actor_operator_id, actor_username, action, target_operator_id, target_username, outcome
		) VALUES (
			$1, $2, $3, NULL, NULL, $4
		)
	`
	_, err = tx.Exec(ctx, insertAuditQuery,
		actorOperatorID,
		actorUsername,
		string(operator.ActionOperatorAuditRead),
		string(operator.OutcomeSuccess),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to record audit read event: %w", sanitizeError(err))
	}

	const listAuditQuery = `
		SELECT
			id::text,
			occurred_at,
			actor_operator_id::text,
			actor_username,
			action,
			target_operator_id::text,
			target_username,
			outcome
		FROM stackpilot.operator_audit_events
		ORDER BY occurred_at DESC, id DESC
		LIMIT $1
	`
	rows, err := tx.Query(ctx, listAuditQuery, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit events: %w", sanitizeError(err))
	}
	defer rows.Close()

	var events []operator.AuditEventRecord
	for rows.Next() {
		var ev operator.AuditEventRecord
		var actStr, outStr string
		var actorID, targetID *string
		if err := rows.Scan(
			&ev.ID,
			&ev.OccurredAt,
			&actorID,
			&ev.ActorUsername,
			&actStr,
			&targetID,
			&ev.TargetUsername,
			&outStr,
		); err != nil {
			return nil, fmt.Errorf("failed to scan audit event: %w", sanitizeError(err))
		}
		ev.ActorOperatorID = actorID
		ev.TargetOperatorID = targetID
		ev.Action = operator.AuditAction(actStr)
		ev.Outcome = operator.AuditOutcome(outStr)
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating audit events: %w", sanitizeError(err))
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit audit read transaction: %w", sanitizeError(err))
	}

	if events == nil {
		events = []operator.AuditEventRecord{}
	}
	return events, nil
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
