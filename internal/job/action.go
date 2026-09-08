package job

import "errors"

// Action represents a typed job action.
type Action string

const (
	ActionAgentPing Action = "agent.ping"
)

var ErrInvalidAction = errors.New("invalid action")

// ValidateAction checks if an action is valid in M0.11 fail-closed.
func ValidateAction(action Action) error {
	if action == ActionAgentPing {
		return nil
	}
	return ErrInvalidAction
}
