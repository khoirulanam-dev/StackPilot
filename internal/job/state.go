package job

import (
	"errors"
	"fmt"
)

// State represents the lifecycle state of a job.
type State string

const (
	StateQueued     State = "queued"
	StateDispatched State = "dispatched"
	StateRunning    State = "running"
	StateSucceeded  State = "succeeded"
	StateFailed     State = "failed"
	StateUnknown    State = "unknown"
)

// IsTerminal reports whether the state is one of the final lifecycle states.
func (s State) IsTerminal() bool {
	return s == StateSucceeded || s == StateFailed || s == StateUnknown
}

// Valid checks if the state is one of the recognized job states.
func (s State) Valid() bool {
	switch s {
	case StateQueued, StateDispatched, StateRunning, StateSucceeded, StateFailed, StateUnknown:
		return true
	default:
		return false
	}
}

// FailureCode represents typed failure reasons.
type FailureCode string

const (
	FailureCodeExecutorError     FailureCode = "executor_error"
	FailureCodeDispatchExhausted FailureCode = "dispatch_exhausted"
	FailureCodeExecutionTimeout  FailureCode = "execution_timeout"
)

// Valid checks if the failure code is one of the recognized failure codes.
func (fc FailureCode) Valid() bool {
	switch fc {
	case FailureCodeExecutorError, FailureCodeDispatchExhausted, FailureCodeExecutionTimeout:
		return true
	default:
		return false
	}
}

var (
	ErrInvalidStateTransition = errors.New("invalid state transition")
	ErrInvalidFailureCode     = errors.New("invalid failure code")
)

// ValidateTransition enforces the exact state transitions allowed in M0.11 fail-closed.
// Allowed:
//
//	queued -> dispatched
//	dispatched -> running
//	dispatched -> queued (lease expired and attempt budget remains)
//	dispatched -> failed (lease expired at maximum attempts)
//	running -> succeeded
//	running -> failed
//	running -> unknown (execution result deadline expired)
func ValidateTransition(from, to State) error {
	switch from {
	case StateQueued:
		if to == StateDispatched {
			return nil
		}
	case StateDispatched:
		if to == StateRunning || to == StateQueued || to == StateFailed {
			return nil
		}
	case StateRunning:
		if to == StateSucceeded || to == StateFailed || to == StateUnknown {
			return nil
		}
	}
	return fmt.Errorf("%w: cannot transition from %q to %q", ErrInvalidStateTransition, from, to)
}

// ValidateStateFailureCode enforces state/failure_code consistency rules:
// - succeeded: failure_code must be empty
// - failed: failure_code must be executor_error or dispatch_exhausted
// - unknown: failure_code must be execution_timeout
// - queued, dispatched, running: failure_code must be empty
func ValidateStateFailureCode(state State, fc *FailureCode) error {
	switch state {
	case StateSucceeded, StateQueued, StateDispatched, StateRunning:
		if fc != nil && *fc != "" {
			return fmt.Errorf("%w: failure code must be empty for state %s", ErrInvalidFailureCode, state)
		}
		return nil
	case StateFailed:
		if fc == nil || (*fc != FailureCodeExecutorError && *fc != FailureCodeDispatchExhausted) {
			return fmt.Errorf("%w: failed state requires executor_error or dispatch_exhausted", ErrInvalidFailureCode)
		}
		return nil
	case StateUnknown:
		if fc == nil || *fc != FailureCodeExecutionTimeout {
			return fmt.Errorf("%w: unknown state requires execution_timeout", ErrInvalidFailureCode)
		}
		return nil
	default:
		return fmt.Errorf("unknown state: %s", state)
	}
}
