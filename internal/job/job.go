package job

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	DispatchLease           = 30 * time.Second
	MaxDispatchAttempts     = 5
	ExecutionResultDeadline = 60 * time.Second
	MaxActiveJobsPerAgent   = 64
)

const (
	EventJobCreated    = "job.created"
	EventJobDispatched = "job.dispatched"
	EventJobRequeued   = "job.requeued"
	EventJobStarted    = "job.started"
	EventJobSucceeded  = "job.succeeded"
	EventJobFailed     = "job.failed"
	EventJobUnknown    = "job.unknown"
)

const (
	ActorTypeOperator   = "operator"
	ActorTypeAgent      = "agent"
	ActorTypeController = "controller"
)

// Job represents a persistent job entity.
type Job struct {
	ID                  uuid.UUID
	AgentID             uuid.UUID
	CreatedByOperatorID uuid.UUID
	CreatedByUsername   string
	IdempotencyKeyHash  [32]byte
	ActionType          string
	State               State
	Attempt             int
	FailureCode         *string
	CreatedAt           time.Time
	UpdatedAt           time.Time
	DispatchedAt        *time.Time
	DispatchExpiresAt   *time.Time
	StartedAt           *time.Time
	ExecutionDeadlineAt *time.Time
	FinishedAt          *time.Time
}

// JobEvent represents an immutable append-only event in a job's lifecycle.
type JobEvent struct {
	ID              uuid.UUID
	JobID           uuid.UUID
	EventType       string
	Attempt         int
	ActorType       string
	ActorIdentifier string
	FailureCode     *string
	OccurredAt      time.Time
}

var (
	ErrInvalidUUID            = errors.New("invalid canonical UUID")
	ErrJobNotFound            = errors.New("job not found")
	ErrJobConflict            = errors.New("job conflict")
	ErrJobIdempotencyConflict = errors.New("idempotency conflict")
	ErrQueueFull              = errors.New("queue full")
	ErrAgentNotFound          = errors.New("agent not found")
	ErrOperatorAuthRequired   = errors.New("operator authentication required")
	ErrPermissionDenied       = errors.New("permission denied")
)

// ValidateCanonicalUUID parses a string and ensures it strictly matches canonical lowercase UUID format.
func ValidateCanonicalUUID(s string) (uuid.UUID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: %v", ErrInvalidUUID, err)
	}
	if id.String() != s {
		return uuid.Nil, fmt.Errorf("%w: non-canonical UUID representation %q", ErrInvalidUUID, s)
	}
	return id, nil
}
