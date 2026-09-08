package operator

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

var (
	ErrUsernameConflict     = errors.New("username already exists")
	ErrOperatorNotFound     = errors.New("operator not found")
	ErrAuthenticationFailed = errors.New("invalid credentials")
	ErrSessionNotFound      = errors.New("session not found")
)

var canonicalUsernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)

// NormalizeUsername normalizes the username to lowercase ASCII.
func NormalizeUsername(u string) string {
	return strings.ToLower(u)
}

// ValidateUsername checks that a normalized username complies with canonical constraints.
func ValidateUsername(u string) error {
	if len(u) < 3 || len(u) > 64 {
		return errors.New("username must be between 3 and 64 characters")
	}
	if !canonicalUsernamePattern.MatchString(u) {
		return errors.New("username must begin with a-z or 0-9 and contain only lowercase letters, digits, '.', '_', or '-'")
	}
	return nil
}

// AuditAction represents typed audit action identifiers.
type AuditAction string

const (
	ActionOperatorCreated   AuditAction = "operator.created"
	ActionOperatorLogin     AuditAction = "operator.login"
	ActionOperatorLogout    AuditAction = "operator.logout"
	ActionOperatorAuditRead AuditAction = "operator.audit.read"
	ActionJobCreated        AuditAction = "job.created"
)

// AuditOutcome represents typed audit outcome states.
type AuditOutcome string

const (
	OutcomeSuccess AuditOutcome = "success"
	OutcomeFailure AuditOutcome = "failure"
	OutcomeDenied  AuditOutcome = "denied"
)

// OperatorRecord represents the internal database record for an operator.
type OperatorRecord struct {
	ID           string
	Username     string
	PasswordHash string
	Role         Role
	DisabledAt   *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// SafeOperator represents a redacted operator identity safe for external exposure.
type SafeOperator struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

// SessionRecord represents the internal database record for an active session.
type SessionRecord struct {
	ID         string
	OperatorID string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// AuditEventRecord represents an immutable audit log entry.
type AuditEventRecord struct {
	ID               string       `json:"id"`
	OccurredAt       time.Time    `json:"occurred_at"`
	ActorOperatorID  *string      `json:"actor_operator_id"`
	ActorUsername    string       `json:"actor_username"`
	Action           AuditAction  `json:"action"`
	TargetOperatorID *string      `json:"target_operator_id"`
	TargetUsername   *string      `json:"target_username"`
	TargetJobID      *string      `json:"target_job_id"`
	Outcome          AuditOutcome `json:"outcome"`
}
