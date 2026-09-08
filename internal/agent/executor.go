package agent

import (
	"context"
	"errors"
	"fmt"

	"stackpilot/internal/job"
)

var (
	ErrUnknownAction = errors.New("unknown action")
)

// TypedExecutor defines the contract for executing typed actions on an Agent.
type TypedExecutor interface {
	Execute(ctx context.Context, action string) error
}

// defaultPingExecutor implements TypedExecutor strictly supporting agent.ping with zero OS side effects.
type defaultPingExecutor struct{}

// NewExecutor returns a default TypedExecutor supporting agent.ping.
func NewExecutor() TypedExecutor {
	return &defaultPingExecutor{}
}

// Execute validates and runs the requested typed action.
// In M0.11, only agent.ping is supported; it completes immediately with zero OS side effects.
func (e *defaultPingExecutor) Execute(ctx context.Context, action string) error {
	if job.Action(action) != job.ActionAgentPing {
		return fmt.Errorf("%w: %q", ErrUnknownAction, action)
	}
	return nil
}
