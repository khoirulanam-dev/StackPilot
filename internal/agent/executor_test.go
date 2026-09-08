package agent

import (
	"context"
	"errors"
	"testing"

	"stackpilot/internal/job"
)

func TestExecutor_AgentPing(t *testing.T) {
	exec := NewExecutor()
	ctx := context.Background()

	// agent.ping must succeed immediately
	if err := exec.Execute(ctx, string(job.ActionAgentPing)); err != nil {
		t.Fatalf("expected agent.ping to succeed, got: %v", err)
	}

	// Any other action must fail closed
	disallowedActions := []string{
		"",
		"agent.pong",
		"execute",
		"shell",
		"reboot",
		"docker.run",
		"systemctl.restart",
	}

	for _, action := range disallowedActions {
		err := exec.Execute(ctx, action)
		if err == nil {
			t.Errorf("expected disallowed action %q to fail, got nil", action)
		}
		if !errors.Is(err, ErrUnknownAction) {
			t.Errorf("expected ErrUnknownAction for %q, got: %v", action, err)
		}
	}
}
