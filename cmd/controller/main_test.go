package main

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"stackpilot/internal/enrollment"
)

type mockTokenPersister struct {
	createFunc func(ctx context.Context, tokenHash [32]byte, expiresAt time.Time) (*enrollment.TokenRecord, error)
}

func (m *mockTokenPersister) CreateEnrollmentToken(ctx context.Context, tokenHash [32]byte, expiresAt time.Time) (*enrollment.TokenRecord, error) {
	if m.createFunc != nil {
		return m.createFunc(ctx, tokenHash, expiresAt)
	}
	return &enrollment.TokenRecord{
		ID:        "mock-uuid-v7",
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}, nil
}

func TestRunCommand_Dispatch(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	t.Run("unknown command returns error", func(t *testing.T) {
		err := run([]string{"unknown"}, stdout, stderr)
		if err == nil {
			t.Fatal("expected error for unknown command, got nil")
		}
		if !strings.Contains(err.Error(), "unknown command") {
			t.Errorf("expected error to mention 'unknown command', got %q", err.Error())
		}
	})

	t.Run("missing enrollment-token subcommand returns error", func(t *testing.T) {
		err := run([]string{"enrollment-token"}, stdout, stderr)
		if err == nil {
			t.Fatal("expected error for missing subcommand, got nil")
		}
		if !strings.Contains(err.Error(), "missing subcommand") {
			t.Errorf("expected error to mention 'missing subcommand', got %q", err.Error())
		}
	})

	t.Run("unknown enrollment-token subcommand returns error", func(t *testing.T) {
		err := run([]string{"enrollment-token", "list"}, stdout, stderr)
		if err == nil {
			t.Fatal("expected error for unknown subcommand, got nil")
		}
		if !strings.Contains(err.Error(), "unknown enrollment-token subcommand") {
			t.Errorf("expected error to mention 'unknown enrollment-token subcommand', got %q", err.Error())
		}
	})

	t.Run("no-command mode dispatches to server and checks configuration", func(t *testing.T) {
		// Empty environment should cause runServer to fail at LoadConfig without starting server
		t.Setenv("STACKPILOT_DATABASE_URL", "")
		err := run([]string{}, stdout, stderr)
		if err == nil {
			t.Fatal("expected runServer to fail on missing config, got nil")
		}
		if !strings.Contains(err.Error(), "STACKPILOT_DATABASE_URL") {
			t.Errorf("expected config validation error, got %q", err.Error())
		}
	})
}

func TestIssueAndPrintEnrollmentToken_Success(t *testing.T) {
	persister := &mockTokenPersister{}
	stdout := &bytes.Buffer{}

	err := issueAndPrintEnrollmentToken(context.Background(), persister, stdout)
	if err != nil {
		t.Fatalf("issueAndPrintEnrollmentToken failed: %v", err)
	}

	output := stdout.String()
	// 1. Must start with sp_enroll_
	if !strings.HasPrefix(output, enrollment.TokenPrefix) {
		t.Fatal("stdout does not begin with enrollment token prefix")
	}

	// 2. Must end with newline
	if !strings.HasSuffix(output, "\n") {
		t.Fatal("stdout does not end with newline")
	}

	// 3. Exactly one logical token line
	if strings.Count(output, "\n") != 1 {
		t.Fatal("stdout does not end with exactly one newline")
	}

	// 4. Token contains no multiple newlines, spaces, or labels
	token := strings.TrimSuffix(output, "\n")
	if strings.Contains(token, "\n") {
		t.Fatal("stdout contains multiple newlines")
	}
	if strings.Contains(token, " ") {
		t.Fatal("stdout contains extra characters or labels")
	}
}

func TestIssueAndPrintEnrollmentToken_PersistenceFailure(t *testing.T) {
	const syntheticSecret = "stackpilot-super-secret-enrollment-value"
	const mockErrorPrefix = "database connection terminated with secret"
	persister := &mockTokenPersister{
		createFunc: func(ctx context.Context, tokenHash [32]byte, expiresAt time.Time) (*enrollment.TokenRecord, error) {
			return nil, fmt.Errorf("%s %s", mockErrorPrefix, syntheticSecret)
		},
	}
	stdout := &bytes.Buffer{}

	err := issueAndPrintEnrollmentToken(context.Background(), persister, stdout)
	if err == nil {
		t.Fatal("expected error on persistence failure, got nil")
	}

	// 1. Plaintext token must not be written to stdout
	if stdout.Len() != 0 {
		t.Fatal("stdout was not empty on persistence failure")
	}

	// 2. Returned error does NOT contain synthetic secret
	if strings.Contains(err.Error(), syntheticSecret) {
		t.Fatal("returned CLI error leaked synthetic secret")
	}

	// 3. Returned error does NOT contain underlying mock text
	if strings.Contains(err.Error(), mockErrorPrefix) {
		t.Fatal("returned CLI error leaked underlying persistence error text")
	}

	// 4. Returned error contains only safe enrollment issuance context
	if !strings.Contains(err.Error(), "failed to issue enrollment token") {
		t.Errorf("expected error to provide safe issuance context, got %q", err.Error())
	}
}
