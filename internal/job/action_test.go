package job

import (
	"errors"
	"testing"
)

func TestAction_Validation(t *testing.T) {
	if err := ValidateAction(ActionAgentPing); err != nil {
		t.Fatalf("expected ActionAgentPing to be valid, got: %v", err)
	}

	unknownActions := []Action{
		"",
		"agent.pong",
		"execute",
		"shell",
		"agent.ping.v2",
		"agent.reboot",
	}

	for _, action := range unknownActions {
		err := ValidateAction(action)
		if err == nil {
			t.Errorf("expected action %q to be rejected, got nil", action)
		}
		if !errors.Is(err, ErrInvalidAction) {
			t.Errorf("expected ErrInvalidAction for %q, got: %v", action, err)
		}
	}
}
