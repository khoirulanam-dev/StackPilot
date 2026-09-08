package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"stackpilot/internal/job"
	"stackpilot/internal/operator"
	"stackpilot/internal/protocol"
)

// CreateJob creates a new job record for the specified target agent in a single transaction.
// It enforces creator permissions, idempotency scoping, agent existence, active queue limits,
// and atomically records the job, its creation event, and operator audit event.
// Returns the job record and isNew=false on exact idempotent replay.
func (db *DB) CreateJob(ctx context.Context, operatorID uuid.UUID, agentID uuid.UUID, action job.Action, idempotencyKeyHash [32]byte) (*job.Job, bool, error) {
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

	// Creator operator row lock serializes concurrent creation for this operator
	const queryOp = `
		SELECT username, role, disabled_at
		FROM stackpilot.operators
		WHERE id = $1
		FOR UPDATE
	`
	var (
		username   string
		roleStr    string
		disabledAt any
	)
	err = tx.QueryRow(ctx, queryOp, operatorID).Scan(&username, &roleStr, &disabledAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, job.ErrOperatorAuthRequired
		}
		return nil, false, fmt.Errorf("failed to query operator: %w", sanitizeError(err))
	}
	if disabledAt != nil {
		return nil, false, job.ErrOperatorAuthRequired
	}
	r, err := operator.ParseRole(roleStr)
	if err != nil {
		return nil, false, fmt.Errorf("corrupt operator role in database: %w", sanitizeError(err))
	}
	if !r.HasPermission(operator.PermissionOperationsExecute) {
		return nil, false, job.ErrPermissionDenied
	}

	const queryIdempotency = `
		SELECT id, agent_id, created_by_operator_id, created_by_username,
		       action_type, state, attempt, failure_code,
		       created_at, updated_at, dispatched_at, dispatch_expires_at,
		       started_at, execution_deadline_at, finished_at
		FROM stackpilot.jobs
		WHERE created_by_operator_id = $1 AND idempotency_key_hash = $2
		FOR UPDATE
	`
	var existing job.Job
	var stateStr, fcStr *string
	err = tx.QueryRow(ctx, queryIdempotency, operatorID, idempotencyKeyHash[:]).Scan(
		&existing.ID,
		&existing.AgentID,
		&existing.CreatedByOperatorID,
		&existing.CreatedByUsername,
		&existing.ActionType,
		&stateStr,
		&existing.Attempt,
		&fcStr,
		&existing.CreatedAt,
		&existing.UpdatedAt,
		&existing.DispatchedAt,
		&existing.DispatchExpiresAt,
		&existing.StartedAt,
		&existing.ExecutionDeadlineAt,
		&existing.FinishedAt,
	)
	if err == nil {
		existing.IdempotencyKeyHash = idempotencyKeyHash
		if stateStr != nil {
			existing.State = job.State(*stateStr)
		}
		existing.FailureCode = fcStr

		if err := validateJobRow(&existing); err != nil {
			return nil, false, fmt.Errorf("corrupt existing job in database: %w", err)
		}

		if existing.AgentID == agentID && existing.ActionType == string(action) {
			// Idempotent exact replay succeeds even if active queue is currently full
			if err := tx.Commit(ctx); err != nil {
				return nil, false, fmt.Errorf("failed to commit idempotent replay: %w", sanitizeError(err))
			}
			return &existing, false, nil
		}
		return nil, false, job.ErrJobIdempotencyConflict
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, fmt.Errorf("failed to check idempotency key: %w", sanitizeError(err))
	}

	// Target Agent row lock serializes queue-count check and insertion per agent
	const queryAgent = `
		SELECT id
		FROM stackpilot.agents
		WHERE id = $1
		FOR UPDATE
	`
	var lockedAgentID uuid.UUID
	err = tx.QueryRow(ctx, queryAgent, agentID).Scan(&lockedAgentID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, job.ErrAgentNotFound
		}
		return nil, false, fmt.Errorf("failed to lock agent row: %w", sanitizeError(err))
	}

	const queryActiveCount = `
		SELECT count(*)
		FROM stackpilot.jobs
		WHERE agent_id = $1 AND state IN ('queued', 'dispatched', 'running')
	`
	var activeCount int
	err = tx.QueryRow(ctx, queryActiveCount, agentID).Scan(&activeCount)
	if err != nil {
		return nil, false, fmt.Errorf("failed to count active jobs: %w", sanitizeError(err))
	}
	if activeCount >= job.MaxActiveJobsPerAgent {
		return nil, false, job.ErrQueueFull
	}

	const insertJob = `
		INSERT INTO stackpilot.jobs (
			agent_id,
			created_by_operator_id,
			created_by_username,
			idempotency_key_hash,
			action_type,
			state,
			attempt
		) VALUES (
			$1, $2, $3, $4, $5, 'queued', 0
		)
		RETURNING id, created_at, updated_at
	`
	var newJob job.Job
	newJob.AgentID = agentID
	newJob.CreatedByOperatorID = operatorID
	newJob.CreatedByUsername = username
	newJob.IdempotencyKeyHash = idempotencyKeyHash
	newJob.ActionType = string(action)
	newJob.State = job.StateQueued
	newJob.Attempt = 0

	err = tx.QueryRow(ctx, insertJob,
		agentID,
		operatorID,
		username,
		idempotencyKeyHash[:],
		action,
	).Scan(&newJob.ID, &newJob.CreatedAt, &newJob.UpdatedAt)
	if err != nil {
		return nil, false, fmt.Errorf("failed to insert job: %w", sanitizeError(err))
	}

	const insertEvent = `
		INSERT INTO stackpilot.job_events (
			job_id,
			event_type,
			attempt,
			actor_type,
			actor_identifier
		) VALUES (
			$1, $2, 0, 'operator', $3
		)
	`
	_, err = tx.Exec(ctx, insertEvent, newJob.ID, job.EventJobCreated, username)
	if err != nil {
		return nil, false, fmt.Errorf("failed to insert job created event: %w", sanitizeError(err))
	}

	const insertAudit = `
		INSERT INTO stackpilot.operator_audit_events (
			actor_operator_id,
			actor_username,
			action,
			target_job_id,
			outcome
		) VALUES (
			$1, $2, $3, $4, $5
		)
	`
	_, err = tx.Exec(ctx, insertAudit,
		operatorID,
		username,
		operator.ActionJobCreated,
		newJob.ID,
		operator.OutcomeSuccess,
	)
	if err != nil {
		return nil, false, fmt.Errorf("failed to insert operator audit event: %w", sanitizeError(err))
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, false, fmt.Errorf("failed to commit job creation: %w", sanitizeError(err))
	}

	return &newJob, true, nil
}

// reconcileExpiredJobsInTx reconciles expired dispatched and running jobs within an active transaction.
// When agentID is nil, total processed jobs across dispatched and running are strictly capped at limit (<= 100).
func reconcileExpiredJobsInTx(ctx context.Context, tx pgx.Tx, agentID *uuid.UUID, limit int) error {
	if limit <= 0 || limit > 100 {
		limit = 100
	}

	type expiredJob struct {
		id      uuid.UUID
		attempt int
	}

	// Expired dispatched jobs reconciliation using post-lock clock_timestamp()
	var queryDispatched string
	var args []any
	if agentID != nil {
		queryDispatched = `
			SELECT id, attempt
			FROM stackpilot.jobs
			WHERE agent_id = $1 AND state = 'dispatched' AND dispatch_expires_at <= clock_timestamp()
			FOR UPDATE
		`
		args = []any{*agentID}
	} else {
		queryDispatched = `
			SELECT id, attempt
			FROM stackpilot.jobs
			WHERE state = 'dispatched' AND dispatch_expires_at <= clock_timestamp()
			ORDER BY dispatch_expires_at ASC
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		`
		args = []any{limit}
	}

	rows, err := tx.Query(ctx, queryDispatched, args...)
	if err != nil {
		return fmt.Errorf("failed to query expired dispatched jobs: %w", sanitizeError(err))
	}
	var expiredDispatched []expiredJob
	for rows.Next() {
		var ej expiredJob
		if err := rows.Scan(&ej.id, &ej.attempt); err != nil {
			rows.Close()
			return fmt.Errorf("failed to scan expired dispatched job: %w", sanitizeError(err))
		}
		expiredDispatched = append(expiredDispatched, ej)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating expired dispatched jobs: %w", sanitizeError(err))
	}

	for _, ej := range expiredDispatched {
		if ej.attempt < job.MaxDispatchAttempts {
			const requeueSQL = `
				UPDATE stackpilot.jobs
				SET
					state = 'queued',
					dispatched_at = NULL,
					dispatch_expires_at = NULL,
					updated_at = clock_timestamp()
				WHERE id = $1
			`
			if _, err := tx.Exec(ctx, requeueSQL, ej.id); err != nil {
				return fmt.Errorf("failed to requeue job: %w", sanitizeError(err))
			}
			const eventSQL = `
				INSERT INTO stackpilot.job_events (
					job_id, event_type, attempt, actor_type, actor_identifier
				) VALUES (
					$1, $2, $3, 'controller', 'controller'
				)
			`
			if _, err := tx.Exec(ctx, eventSQL, ej.id, job.EventJobRequeued, ej.attempt); err != nil {
				return fmt.Errorf("failed to insert requeued event: %w", sanitizeError(err))
			}
		} else {
			const failSQL = `
				UPDATE stackpilot.jobs
				SET
					state = 'failed',
					failure_code = 'dispatch_exhausted',
					dispatch_expires_at = NULL,
					finished_at = clock_timestamp(),
					updated_at = clock_timestamp()
				WHERE id = $1
			`
			if _, err := tx.Exec(ctx, failSQL, ej.id); err != nil {
				return fmt.Errorf("failed to mark job dispatch_exhausted: %w", sanitizeError(err))
			}
			const eventSQL = `
				INSERT INTO stackpilot.job_events (
					job_id, event_type, attempt, actor_type, actor_identifier, failure_code
				) VALUES (
					$1, $2, $3, 'controller', 'controller', 'dispatch_exhausted'
				)
			`
			if _, err := tx.Exec(ctx, eventSQL, ej.id, job.EventJobFailed, ej.attempt); err != nil {
				return fmt.Errorf("failed to insert dispatch_exhausted event: %w", sanitizeError(err))
			}
		}
	}

	// Bounded reconciliation: ensure global reconciliation does not exceed limit total
	remainingLimit := limit - len(expiredDispatched)
	if remainingLimit <= 0 && agentID == nil {
		return nil
	}

	var queryRunning string
	if agentID != nil {
		queryRunning = `
			SELECT id, attempt
			FROM stackpilot.jobs
			WHERE agent_id = $1 AND state = 'running' AND execution_deadline_at <= clock_timestamp()
			FOR UPDATE
		`
		args = []any{*agentID}
	} else {
		queryRunning = `
			SELECT id, attempt
			FROM stackpilot.jobs
			WHERE state = 'running' AND execution_deadline_at <= clock_timestamp()
			ORDER BY execution_deadline_at ASC
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		`
		args = []any{remainingLimit}
	}

	rowsRun, err := tx.Query(ctx, queryRunning, args...)
	if err != nil {
		return fmt.Errorf("failed to query expired running jobs: %w", sanitizeError(err))
	}
	var expiredRunning []expiredJob
	for rowsRun.Next() {
		var ej expiredJob
		if err := rowsRun.Scan(&ej.id, &ej.attempt); err != nil {
			rowsRun.Close()
			return fmt.Errorf("failed to scan expired running job: %w", sanitizeError(err))
		}
		expiredRunning = append(expiredRunning, ej)
	}
	rowsRun.Close()
	if err := rowsRun.Err(); err != nil {
		return fmt.Errorf("error iterating expired running jobs: %w", sanitizeError(err))
	}

	for _, ej := range expiredRunning {
		const unknownSQL = `
			UPDATE stackpilot.jobs
			SET
				state = 'unknown',
				failure_code = 'execution_timeout',
				execution_deadline_at = NULL,
				finished_at = clock_timestamp(),
				updated_at = clock_timestamp()
			WHERE id = $1
		`
		if _, err := tx.Exec(ctx, unknownSQL, ej.id); err != nil {
			return fmt.Errorf("failed to mark running job unknown: %w", sanitizeError(err))
		}
		const eventSQL = `
			INSERT INTO stackpilot.job_events (
				job_id, event_type, attempt, actor_type, actor_identifier, failure_code
			) VALUES (
				$1, $2, $3, 'controller', 'controller', 'execution_timeout'
			)
		`
		if _, err := tx.Exec(ctx, eventSQL, ej.id, job.EventJobUnknown, ej.attempt); err != nil {
			return fmt.Errorf("failed to insert unknown event: %w", sanitizeError(err))
		}
	}

	return nil
}

// reconcileSingleJobInTx reconciles a specific job's expiration status within an active transaction.
func reconcileSingleJobInTx(ctx context.Context, tx pgx.Tx, jobID uuid.UUID) error {
	const querySingle = `
		SELECT state, attempt, dispatch_expires_at, execution_deadline_at
		FROM stackpilot.jobs
		WHERE id = $1
		FOR UPDATE
	`
	var (
		st           string
		att          int
		dispExpires  *time.Time
		execDeadline *time.Time
	)
	err := tx.QueryRow(ctx, querySingle, jobID).Scan(&st, &att, &dispExpires, &execDeadline)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return job.ErrJobNotFound
		}
		return fmt.Errorf("failed to query job for reconciliation: %w", sanitizeError(err))
	}

	var wallNow time.Time
	err = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&wallNow)
	if err != nil {
		return fmt.Errorf("failed to evaluate reconciliation clock: %w", sanitizeError(err))
	}

	dispExpired := dispExpires != nil && !wallNow.Before(*dispExpires)
	execExpired := execDeadline != nil && !wallNow.Before(*execDeadline)

	if st == string(job.StateDispatched) && dispExpired {
		if att < job.MaxDispatchAttempts {
			const requeueSQL = `
				UPDATE stackpilot.jobs
				SET state = 'queued', dispatched_at = NULL, dispatch_expires_at = NULL, updated_at = $2
				WHERE id = $1
			`
			if _, err := tx.Exec(ctx, requeueSQL, jobID, wallNow); err != nil {
				return fmt.Errorf("failed to requeue expired dispatched job: %w", sanitizeError(err))
			}
			const eventSQL = `
				INSERT INTO stackpilot.job_events (job_id, event_type, attempt, actor_type, actor_identifier)
				VALUES ($1, $2, $3, 'controller', 'controller')
			`
			if _, err := tx.Exec(ctx, eventSQL, jobID, job.EventJobRequeued, att); err != nil {
				return fmt.Errorf("failed to insert requeued event: %w", sanitizeError(err))
			}
		} else {
			const failSQL = `
				UPDATE stackpilot.jobs
				SET state = 'failed', failure_code = 'dispatch_exhausted', dispatch_expires_at = NULL, finished_at = $2, updated_at = $2
				WHERE id = $1
			`
			if _, err := tx.Exec(ctx, failSQL, jobID, wallNow); err != nil {
				return fmt.Errorf("failed to fail expired dispatched job: %w", sanitizeError(err))
			}
			const eventSQL = `
				INSERT INTO stackpilot.job_events (job_id, event_type, attempt, actor_type, actor_identifier, failure_code)
				VALUES ($1, $2, $3, 'controller', 'controller', 'dispatch_exhausted')
			`
			if _, err := tx.Exec(ctx, eventSQL, jobID, job.EventJobFailed, att); err != nil {
				return fmt.Errorf("failed to insert dispatch_exhausted event: %w", sanitizeError(err))
			}
		}
	} else if st == string(job.StateRunning) && execExpired {
		const unknownSQL = `
			UPDATE stackpilot.jobs
			SET state = 'unknown', failure_code = 'execution_timeout', execution_deadline_at = NULL, finished_at = $2, updated_at = $2
			WHERE id = $1
		`
		if _, err := tx.Exec(ctx, unknownSQL, jobID, wallNow); err != nil {
			return fmt.Errorf("failed to transition expired running job to unknown: %w", sanitizeError(err))
		}
		const eventSQL = `
			INSERT INTO stackpilot.job_events (job_id, event_type, attempt, actor_type, actor_identifier, failure_code)
			VALUES ($1, $2, $3, 'controller', 'controller', 'execution_timeout')
		`
		if _, err := tx.Exec(ctx, eventSQL, jobID, job.EventJobUnknown, att); err != nil {
			return fmt.Errorf("failed to insert unknown event: %w", sanitizeError(err))
		}
	}

	return nil
}

// GetJobByID retrieves a safe job entity by ID, opportunistically reconciling its state if expired.
func (db *DB) GetJobByID(ctx context.Context, jobID uuid.UUID) (*job.Job, error) {
	if db.pool == nil {
		return nil, fmt.Errorf("database pool is not initialized")
	}

	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin reconciliation transaction: %w", sanitizeError(err))
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	if err := reconcileSingleJobInTx(ctx, tx, jobID); err != nil {
		if errors.Is(err, job.ErrJobNotFound) {
			return nil, job.ErrJobNotFound
		}
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit job reconciliation: %w", sanitizeError(err))
	}

	const query = `
		SELECT id, agent_id, created_by_operator_id, created_by_username,
		       action_type, state, attempt, failure_code,
		       created_at, updated_at, dispatched_at, dispatch_expires_at,
		       started_at, execution_deadline_at, finished_at
		FROM stackpilot.jobs
		WHERE id = $1
	`
	var j job.Job
	var stateStr, fcStr *string
	err = db.pool.QueryRow(ctx, query, jobID).Scan(
		&j.ID,
		&j.AgentID,
		&j.CreatedByOperatorID,
		&j.CreatedByUsername,
		&j.ActionType,
		&stateStr,
		&j.Attempt,
		&fcStr,
		&j.CreatedAt,
		&j.UpdatedAt,
		&j.DispatchedAt,
		&j.DispatchExpiresAt,
		&j.StartedAt,
		&j.ExecutionDeadlineAt,
		&j.FinishedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, job.ErrJobNotFound
		}
		return nil, fmt.Errorf("failed to query job: %w", sanitizeError(err))
	}
	if stateStr != nil {
		j.State = job.State(*stateStr)
	}
	j.FailureCode = fcStr
	if err := validateJobRow(&j); err != nil {
		return nil, fmt.Errorf("corrupt job row in database: %w", err)
	}
	return &j, nil
}

// ListJobs returns a bounded list of jobs matching optional filter criteria, newest first.
func (db *DB) ListJobs(ctx context.Context, limit int, agentID *uuid.UUID, state *job.State) ([]job.Job, error) {
	if db.pool == nil {
		return nil, fmt.Errorf("database pool is not initialized")
	}
	if limit <= 0 || limit > 200 {
		limit = 100
	}

	// Reconcile expired jobs bounded to at most 100 total
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin list reconciliation transaction: %w", sanitizeError(err))
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	if err := reconcileExpiredJobsInTx(ctx, tx, agentID, 100); err != nil {
		return nil, fmt.Errorf("failed to reconcile expired jobs: %w", sanitizeError(err))
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit list reconciliation: %w", sanitizeError(err))
	}

	baseQuery := `
		SELECT id, agent_id, created_by_operator_id, created_by_username,
		       action_type, state, attempt, failure_code,
		       created_at, updated_at, dispatched_at, dispatch_expires_at,
		       started_at, execution_deadline_at, finished_at
		FROM stackpilot.jobs
	`
	var conditions []string
	var args []any
	argIdx := 1

	if agentID != nil {
		conditions = append(conditions, fmt.Sprintf("agent_id = $%d", argIdx))
		args = append(args, *agentID)
		argIdx++
	}
	if state != nil {
		conditions = append(conditions, fmt.Sprintf("state = $%d", argIdx))
		args = append(args, string(*state))
		argIdx++
	}

	if len(conditions) > 0 {
		baseQuery += " WHERE "
		for i, c := range conditions {
			if i > 0 {
				baseQuery += " AND "
			}
			baseQuery += c
		}
	}

	baseQuery += fmt.Sprintf(" ORDER BY created_at DESC, id DESC LIMIT $%d", argIdx)
	args = append(args, limit)

	rows, err := db.pool.Query(ctx, baseQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list jobs: %w", sanitizeError(err))
	}
	defer rows.Close()

	var jobs []job.Job
	for rows.Next() {
		var j job.Job
		var stateStr, fcStr *string
		if err := rows.Scan(
			&j.ID,
			&j.AgentID,
			&j.CreatedByOperatorID,
			&j.CreatedByUsername,
			&j.ActionType,
			&stateStr,
			&j.Attempt,
			&fcStr,
			&j.CreatedAt,
			&j.UpdatedAt,
			&j.DispatchedAt,
			&j.DispatchExpiresAt,
			&j.StartedAt,
			&j.ExecutionDeadlineAt,
			&j.FinishedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan job: %w", sanitizeError(err))
		}
		if stateStr != nil {
			j.State = job.State(*stateStr)
		}
		j.FailureCode = fcStr
		if err := validateJobRow(&j); err != nil {
			return nil, fmt.Errorf("corrupt job row in database: %w", err)
		}
		jobs = append(jobs, j)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating jobs: %w", sanitizeError(err))
	}
	if jobs == nil {
		jobs = []job.Job{}
	}
	return jobs, nil
}

// ListJobEvents retrieves append-only history events for a given job ordered chronologically.
func (db *DB) ListJobEvents(ctx context.Context, jobID uuid.UUID, limit int) ([]job.JobEvent, error) {
	if db.pool == nil {
		return nil, fmt.Errorf("database pool is not initialized")
	}
	if limit <= 0 || limit > 200 {
		limit = 100
	}

	const checkJob = `SELECT 1 FROM stackpilot.jobs WHERE id = $1`
	var exists int
	err := db.pool.QueryRow(ctx, checkJob, jobID).Scan(&exists)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, job.ErrJobNotFound
		}
		return nil, fmt.Errorf("failed to check job: %w", sanitizeError(err))
	}

	const query = `
		SELECT id, job_id, event_type, attempt, actor_type, actor_identifier, failure_code, occurred_at
		FROM stackpilot.job_events
		WHERE job_id = $1
		ORDER BY occurred_at ASC, id ASC
		LIMIT $2
	`
	rows, err := db.pool.Query(ctx, query, jobID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list job events: %w", sanitizeError(err))
	}
	defer rows.Close()

	var events []job.JobEvent
	for rows.Next() {
		var ev job.JobEvent
		if err := rows.Scan(
			&ev.ID,
			&ev.JobID,
			&ev.EventType,
			&ev.Attempt,
			&ev.ActorType,
			&ev.ActorIdentifier,
			&ev.FailureCode,
			&ev.OccurredAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan job event: %w", sanitizeError(err))
		}
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating job events: %w", sanitizeError(err))
	}
	if events == nil {
		events = []job.JobEvent{}
	}
	return events, nil
}

// ClaimNextAgentJob reconciles expired jobs for an agent, checks the one in-flight invariant,
// and claims the oldest queued job in FIFO order. Returns nil if no job is available.
func (db *DB) ClaimNextAgentJob(ctx context.Context, agentID uuid.UUID) (*protocol.JobAssignment, error) {
	if db.pool == nil {
		return nil, fmt.Errorf("database pool is not initialized")
	}

	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", sanitizeError(err))
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	// Target Agent row lock serializes claim operations per agent to guarantee strict FIFO dispatch ordering
	const lockAgent = `
		SELECT id
		FROM stackpilot.agents
		WHERE id = $1
		FOR UPDATE
	`
	var lockedAgentID uuid.UUID
	err = tx.QueryRow(ctx, lockAgent, agentID).Scan(&lockedAgentID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // Agent not found
		}
		return nil, fmt.Errorf("failed to lock agent row: %w", sanitizeError(err))
	}

	if err := reconcileExpiredJobsInTx(ctx, tx, &agentID, 64); err != nil {
		return nil, fmt.Errorf("failed to reconcile expired jobs for agent: %w", sanitizeError(err))
	}

	const queryInFlight = `
		SELECT 1
		FROM stackpilot.jobs
		WHERE agent_id = $1 AND state IN ('dispatched', 'running')
		LIMIT 1
	`
	var inFlightExists int
	err = tx.QueryRow(ctx, queryInFlight, agentID).Scan(&inFlightExists)
	if err == nil {
		// Agent already has an active in-flight job; cannot claim another
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("failed to commit claim check: %w", sanitizeError(err))
		}
		return nil, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("failed to check in-flight jobs: %w", sanitizeError(err))
	}

	const claimQuery = `
		SELECT id, attempt, action_type
		FROM stackpilot.jobs
		WHERE agent_id = $1 AND state = 'queued'
		ORDER BY created_at ASC, id ASC
		LIMIT 1
		FOR UPDATE
	`
	var (
		claimedID     uuid.UUID
		currAttempt   int
		actionTypeStr string
	)
	err = tx.QueryRow(ctx, claimQuery, agentID).Scan(&claimedID, &currAttempt, &actionTypeStr)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			if err := tx.Commit(ctx); err != nil {
				return nil, fmt.Errorf("failed to commit claim check: %w", sanitizeError(err))
			}
			return nil, nil // No queued jobs to claim
		}
		return nil, fmt.Errorf("failed to claim job: %w", sanitizeError(err))
	}

	if actionTypeStr != string(job.ActionAgentPing) {
		return nil, fmt.Errorf("corrupt action type in database: %q", actionTypeStr)
	}

	if currAttempt < 0 || currAttempt >= job.MaxDispatchAttempts {
		return nil, fmt.Errorf("corrupt queued job %s: attempt %d outside valid claim range [0, %d)", claimedID, currAttempt, job.MaxDispatchAttempts)
	}

	newAttempt := currAttempt + 1

	const updateDispatched = `
		WITH transition_clock AS (
			SELECT clock_timestamp() AS ts
		)
		UPDATE stackpilot.jobs
		SET
			state = 'dispatched',
			attempt = $2,
			dispatched_at = transition_clock.ts,
			dispatch_expires_at = transition_clock.ts + ($3 * interval '1 second'),
			updated_at = transition_clock.ts
		FROM transition_clock
		WHERE stackpilot.jobs.id = $1
	`
	_, err = tx.Exec(ctx, updateDispatched, claimedID, newAttempt, int(job.DispatchLease.Seconds()))
	if err != nil {
		return nil, fmt.Errorf("failed to update job to dispatched: %w", sanitizeError(err))
	}

	const insertDispatchedEvent = `
		INSERT INTO stackpilot.job_events (
			job_id,
			event_type,
			attempt,
			actor_type,
			actor_identifier
		) VALUES (
			$1, $2, $3, 'controller', 'controller'
		)
	`
	_, err = tx.Exec(ctx, insertDispatchedEvent, claimedID, job.EventJobDispatched, newAttempt)
	if err != nil {
		return nil, fmt.Errorf("failed to insert dispatched event: %w", sanitizeError(err))
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit job claim: %w", sanitizeError(err))
	}

	return &protocol.JobAssignment{
		JobID:   claimedID.String(),
		Attempt: newAttempt,
		Action:  actionTypeStr,
	}, nil
}

// StartAgentJob authorizes execution for an assigned job via a lock-then-clock transition (dispatched -> running).
// The row is locked FOR UPDATE first, then clock_timestamp() is acquired post-lock for accurate lease validation.
// It is intentionally non-idempotent: exactly one request may succeed; duplicates or expired leases return ErrJobConflict.
func (db *DB) StartAgentJob(ctx context.Context, agentID uuid.UUID, jobID uuid.UUID, attempt int) error {
	if db.pool == nil {
		return fmt.Errorf("database pool is not initialized")
	}

	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", sanitizeError(err))
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	const lockJob = `
		SELECT state, attempt, agent_id, dispatch_expires_at
		FROM stackpilot.jobs
		WHERE id = $1
		FOR UPDATE
	`
	var (
		currentState string
		currAttempt  int
		targetAgent  uuid.UUID
		dispExpires  *time.Time
	)
	err = tx.QueryRow(ctx, lockJob, jobID).Scan(&currentState, &currAttempt, &targetAgent, &dispExpires)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return job.ErrJobConflict
		}
		return fmt.Errorf("failed to lock job for start: %w", sanitizeError(err))
	}

	if currentState != string(job.StateDispatched) ||
		targetAgent != agentID ||
		currAttempt != attempt ||
		dispExpires == nil {
		return job.ErrJobConflict
	}

	const updateRunning = `
		WITH transition_clock AS (
			SELECT clock_timestamp() AS ts
		)
		UPDATE stackpilot.jobs
		SET
			state = 'running',
			started_at = transition_clock.ts,
			execution_deadline_at = transition_clock.ts + ($2 * interval '1 second'),
			dispatch_expires_at = NULL,
			updated_at = transition_clock.ts
		FROM transition_clock
		WHERE stackpilot.jobs.id = $1
		  AND stackpilot.jobs.agent_id = $3
		  AND stackpilot.jobs.state = 'dispatched'
		  AND stackpilot.jobs.attempt = $4
		  AND stackpilot.jobs.dispatch_expires_at > transition_clock.ts
		RETURNING transition_clock.ts
	`
	var transitionTS time.Time
	err = tx.QueryRow(ctx, updateRunning, jobID, int(job.ExecutionResultDeadline.Seconds()), agentID, attempt).Scan(&transitionTS)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return job.ErrJobConflict
		}
		return fmt.Errorf("failed to transition job to running: %w", sanitizeError(err))
	}

	const insertStartEvent = `
		INSERT INTO stackpilot.job_events (
			job_id,
			event_type,
			attempt,
			actor_type,
			actor_identifier
		) VALUES (
			$1, $2, $3, 'agent', $4
		)
	`
	_, err = tx.Exec(ctx, insertStartEvent, jobID, job.EventJobStarted, attempt, agentID.String())
	if err != nil {
		return fmt.Errorf("failed to insert job started event: %w", sanitizeError(err))
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit start transition: %w", sanitizeError(err))
	}

	return nil
}

// CompleteAgentJob reports the terminal outcome of a job.
// It supports idempotent replay for exact match of terminal state and failure code.
// Late completions (past deadline) force transition to unknown and return ErrJobConflict.
// Uses lock-then-clock pattern: row locked FOR UPDATE, then clock_timestamp() for accurate deadline evaluation.
func (db *DB) CompleteAgentJob(ctx context.Context, agentID uuid.UUID, jobID uuid.UUID, attempt int, outcome string, failureCode string) error {
	if db.pool == nil {
		return fmt.Errorf("database pool is not initialized")
	}

	// Domain validation: enforce outcome/failureCode consistency at the persistence boundary
	if outcome == "succeeded" && failureCode != "" {
		return job.ErrJobConflict
	}
	if outcome == "failed" && failureCode != "executor_error" {
		return job.ErrJobConflict
	}
	if outcome != "succeeded" && outcome != "failed" {
		return job.ErrJobConflict
	}

	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", sanitizeError(err))
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	// Lock row FOR UPDATE first without clock in target list
	const queryJob = `
		SELECT state, attempt, failure_code, execution_deadline_at, agent_id
		FROM stackpilot.jobs
		WHERE id = $1
		FOR UPDATE
	`
	var (
		currentState string
		currAttempt  int
		currFC       *string
		execDeadline *time.Time
		targetAgent  uuid.UUID
	)
	err = tx.QueryRow(ctx, queryJob, jobID).Scan(&currentState, &currAttempt, &currFC, &execDeadline, &targetAgent)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return job.ErrJobConflict
		}
		return fmt.Errorf("failed to query job for completion: %w", sanitizeError(err))
	}

	if targetAgent != agentID || currAttempt != attempt {
		return job.ErrJobConflict
	}

	if currentState == string(job.StateRunning) {
		// Enforce fail-closed: running job MUST have non-NULL execution_deadline_at
		if execDeadline == nil {
			return fmt.Errorf("corrupt running job %s: execution_deadline_at is NULL", jobID)
		}

		// Evaluate transition time post-lock in subsequent statement
		var wallNow time.Time
		err = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&wallNow)
		if err != nil {
			return fmt.Errorf("failed to evaluate completion clock: %w", sanitizeError(err))
		}

		isDeadlinePassed := !wallNow.Before(*execDeadline)

		if isDeadlinePassed {
			// Late completion: mark unknown using post-lock wallNow
			const updateUnknown = `
				UPDATE stackpilot.jobs
				SET
					state = 'unknown',
					failure_code = 'execution_timeout',
					execution_deadline_at = NULL,
					finished_at = $2,
					updated_at = $2
				WHERE id = $1
			`
			if _, err := tx.Exec(ctx, updateUnknown, jobID, wallNow); err != nil {
				return fmt.Errorf("failed to update late job to unknown: %w", sanitizeError(err))
			}
			const eventUnknown = `
				INSERT INTO stackpilot.job_events (
					job_id, event_type, attempt, actor_type, actor_identifier, failure_code
				) VALUES (
					$1, $2, $3, 'controller', 'controller', 'execution_timeout'
				)
			`
			if _, err := tx.Exec(ctx, eventUnknown, jobID, job.EventJobUnknown, attempt); err != nil {
				return fmt.Errorf("failed to insert unknown event: %w", sanitizeError(err))
			}
			if err := tx.Commit(ctx); err != nil {
				return fmt.Errorf("failed to commit unknown transition: %w", sanitizeError(err))
			}
			return job.ErrJobConflict
		}

		if outcome == "succeeded" {
			const updateSucceeded = `
				UPDATE stackpilot.jobs
				SET
					state = 'succeeded',
					failure_code = NULL,
					execution_deadline_at = NULL,
					finished_at = $2,
					updated_at = $2
				WHERE id = $1
			`
			if _, err := tx.Exec(ctx, updateSucceeded, jobID, wallNow); err != nil {
				return fmt.Errorf("failed to update job to succeeded: %w", sanitizeError(err))
			}
			const eventSucceeded = `
				INSERT INTO stackpilot.job_events (
					job_id, event_type, attempt, actor_type, actor_identifier
				) VALUES (
					$1, $2, $3, 'agent', $4
				)
			`
			if _, err := tx.Exec(ctx, eventSucceeded, jobID, job.EventJobSucceeded, attempt, agentID.String()); err != nil {
				return fmt.Errorf("failed to insert succeeded event: %w", sanitizeError(err))
			}
		} else {
			// outcome == "failed" (validated above)
			const updateFailed = `
				UPDATE stackpilot.jobs
				SET
					state = 'failed',
					failure_code = 'executor_error',
					execution_deadline_at = NULL,
					finished_at = $2,
					updated_at = $2
				WHERE id = $1
			`
			if _, err := tx.Exec(ctx, updateFailed, jobID, wallNow); err != nil {
				return fmt.Errorf("failed to update job to failed: %w", sanitizeError(err))
			}
			const eventFailed = `
				INSERT INTO stackpilot.job_events (
					job_id, event_type, attempt, actor_type, actor_identifier, failure_code
				) VALUES (
					$1, $2, $3, 'agent', $4, 'executor_error'
				)
			`
			if _, err := tx.Exec(ctx, eventFailed, jobID, job.EventJobFailed, attempt, agentID.String()); err != nil {
				return fmt.Errorf("failed to insert failed event: %w", sanitizeError(err))
			}
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("failed to commit completion: %w", sanitizeError(err))
		}
		return nil
	}

	// Idempotent replay: exact match of terminal state and failure code
	if currentState == outcome {
		fcMatch := false
		if outcome == "succeeded" && (currFC == nil || *currFC == "") && failureCode == "" {
			fcMatch = true
		} else if outcome == "failed" && currFC != nil && *currFC == "executor_error" && failureCode == "executor_error" {
			fcMatch = true
		}

		if fcMatch {
			if err := tx.Commit(ctx); err != nil {
				return fmt.Errorf("failed to commit idempotent replay: %w", sanitizeError(err))
			}
			return nil
		}
	}

	return job.ErrJobConflict
}

// validateJobRow enforces strict fail-closed validation of job row invariants.
// Rejects unknown states, unknown actions, negative/excessive attempts,
// and state/failure_code inconsistency.
func validateJobRow(j *job.Job) error {
	if !j.State.Valid() {
		return fmt.Errorf("corrupt job state: %q", j.State)
	}
	if j.ActionType != string(job.ActionAgentPing) {
		return fmt.Errorf("corrupt action type: %q", j.ActionType)
	}
	if j.Attempt < 0 || j.Attempt > job.MaxDispatchAttempts {
		return fmt.Errorf("corrupt attempt count: %d", j.Attempt)
	}
	var fc *job.FailureCode
	if j.FailureCode != nil {
		code := job.FailureCode(*j.FailureCode)
		fc = &code
	}
	if err := job.ValidateStateFailureCode(j.State, fc); err != nil {
		return fmt.Errorf("corrupt job failure code consistency: %w", err)
	}
	return nil
}
