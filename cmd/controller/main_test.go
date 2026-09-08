package main

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"stackpilot/internal/enrollment"
	"stackpilot/internal/operator"
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
		err := run([]string{"unknown"}, nil, stdout, stderr)
		if err == nil {
			t.Fatal("expected error for unknown command, got nil")
		}
		if !strings.Contains(err.Error(), "unknown command") {
			t.Errorf("expected error to mention 'unknown command', got %q", err.Error())
		}
	})

	t.Run("missing enrollment-token subcommand returns error", func(t *testing.T) {
		err := run([]string{"enrollment-token"}, nil, stdout, stderr)
		if err == nil {
			t.Fatal("expected error for missing subcommand, got nil")
		}
		if !strings.Contains(err.Error(), "missing subcommand") {
			t.Errorf("expected error to mention 'missing subcommand', got %q", err.Error())
		}
	})

	t.Run("unknown enrollment-token subcommand returns error", func(t *testing.T) {
		err := run([]string{"enrollment-token", "list"}, nil, stdout, stderr)
		if err == nil {
			t.Fatal("expected error for unknown subcommand, got nil")
		}
		if !strings.Contains(err.Error(), "unknown enrollment-token subcommand") {
			t.Errorf("expected error to mention 'unknown enrollment-token subcommand', got %q", err.Error())
		}
	})

	t.Run("missing operator subcommand returns error", func(t *testing.T) {
		err := run([]string{"operator"}, nil, stdout, stderr)
		if err == nil {
			t.Fatal("expected error for missing subcommand, got nil")
		}
		if !strings.Contains(err.Error(), "missing subcommand") {
			t.Errorf("expected error to mention 'missing subcommand', got %q", err.Error())
		}
	})

	t.Run("unknown operator subcommand returns error", func(t *testing.T) {
		err := run([]string{"operator", "list"}, nil, stdout, stderr)
		if err == nil {
			t.Fatal("expected error for unknown subcommand, got nil")
		}
		if !strings.Contains(err.Error(), "unknown operator subcommand") {
			t.Errorf("expected error to mention 'unknown operator subcommand', got %q", err.Error())
		}
	})

	t.Run("no-command mode dispatches to server and checks configuration", func(t *testing.T) {
		t.Setenv("STACKPILOT_DATABASE_URL", "")
		err := run([]string{}, nil, stdout, stderr)
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
	if !strings.HasPrefix(output, enrollment.TokenPrefix) {
		t.Fatal("stdout does not begin with enrollment token prefix")
	}

	if !strings.HasSuffix(output, "\n") {
		t.Fatal("stdout does not end with newline")
	}

	if strings.Count(output, "\n") != 1 {
		t.Fatal("stdout does not end with exactly one newline")
	}

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

	// Security invariant: Plaintext token must not be written to stdout on failure.
	if stdout.Len() != 0 {
		t.Fatal("stdout was not empty on persistence failure")
	}

	// Security invariant: Returned error must not leak sensitive underlying database error details.
	if strings.Contains(err.Error(), syntheticSecret) {
		t.Fatal("returned CLI error leaked synthetic secret")
	}

	if strings.Contains(err.Error(), mockErrorPrefix) {
		t.Fatal("returned CLI error leaked underlying persistence error text")
	}

	if !strings.Contains(err.Error(), "failed to issue enrollment token") {
		t.Errorf("expected error to provide safe issuance context, got %q", err.Error())
	}
}

type mockOperatorCreator struct {
	createFunc func(ctx context.Context, username, passwordHash string, role operator.Role) (*operator.OperatorRecord, error)
}

func (m *mockOperatorCreator) CreateOperator(ctx context.Context, username, passwordHash string, role operator.Role) (*operator.OperatorRecord, error) {
	if m.createFunc != nil {
		return m.createFunc(ctx, username, passwordHash, role)
	}
	return &operator.OperatorRecord{
		ID:           "018f0000-0000-7000-8000-000000000001",
		Username:     username,
		PasswordHash: passwordHash,
		Role:         role,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}, nil
}

func TestOperatorCreate_Flags(t *testing.T) {
	t.Run("missing username flag rejected", func(t *testing.T) {
		_, err := parseOperatorCreateFlags([]string{"--role", "admin", "--password-stdin"})
		if err == nil || !strings.Contains(err.Error(), "--username") {
			t.Fatalf("expected error for missing --username, got %v", err)
		}
	})

	t.Run("missing role flag rejected", func(t *testing.T) {
		_, err := parseOperatorCreateFlags([]string{"--username", "admin", "--password-stdin"})
		if err == nil || !strings.Contains(err.Error(), "--role") {
			t.Fatalf("expected error for missing --role, got %v", err)
		}
	})

	t.Run("missing password-stdin flag rejected", func(t *testing.T) {
		_, err := parseOperatorCreateFlags([]string{"--username", "admin", "--role", "admin"})
		if err == nil || !strings.Contains(err.Error(), "--password-stdin") {
			t.Fatalf("expected error for missing --password-stdin, got %v", err)
		}
	})

	// Security invariant: Passwords must not be accepted via CLI arguments.
	t.Run("password argument flag rejected", func(t *testing.T) {
		_, err := parseOperatorCreateFlags([]string{"--username", "admin", "--role", "admin", "--password", "secret"})
		if err == nil || !strings.Contains(err.Error(), "--password flag is not supported") {
			t.Fatalf("expected error for --password flag, got %v", err)
		}
	})

	t.Run("password file flag rejected", func(t *testing.T) {
		_, err := parseOperatorCreateFlags([]string{"--username", "admin", "--role", "admin", "--password-file", "secret.txt"})
		if err == nil || !strings.Contains(err.Error(), "--password-file flag is not supported") {
			t.Fatalf("expected error for --password-file flag, got %v", err)
		}
	})

	t.Run("invalid username rejected", func(t *testing.T) {
		_, err := parseOperatorCreateFlags([]string{"--username", "a", "--role", "admin", "--password-stdin"})
		if err == nil || !strings.Contains(err.Error(), "invalid username") {
			t.Fatalf("expected error for invalid username, got %v", err)
		}
	})

	t.Run("invalid role rejected", func(t *testing.T) {
		_, err := parseOperatorCreateFlags([]string{"--username", "admin", "--role", "superuser", "--password-stdin"})
		if err == nil || !strings.Contains(err.Error(), "invalid role") {
			t.Fatalf("expected error for invalid role, got %v", err)
		}
	})

	t.Run("username normalization to lowercase", func(t *testing.T) {
		opts, err := parseOperatorCreateFlags([]string{"--username", "ADMIN", "--role", "admin", "--password-stdin"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if opts.username != "admin" {
			t.Fatalf("expected normalized username 'admin', got %q", opts.username)
		}
	})

	t.Run("valid roles accepted", func(t *testing.T) {
		for _, r := range []string{"viewer", "operator", "admin"} {
			o, err := parseOperatorCreateFlags([]string{"--username", "validuser", "--role", r, "--password-stdin"})
			if err != nil {
				t.Fatalf("unexpected error for role %s: %v", r, err)
			}
			if string(o.role) != r {
				t.Errorf("expected role %s, got %s", r, o.role)
			}
		}
	})
}

func TestOperatorCreate_Stdin(t *testing.T) {
	const validPW = "A-Valid-Password-123!"

	t.Run("LF line terminator accepted", func(t *testing.T) {
		pw, err := readPasswordFromStdin(strings.NewReader(validPW + "\n"))
		if err != nil {
			t.Fatalf("LF line ending rejected: %v", err)
		}
		if pw != validPW {
			t.Fatalf("expected %q, got %q", validPW, pw)
		}
	})

	t.Run("CRLF line terminator accepted", func(t *testing.T) {
		pw, err := readPasswordFromStdin(strings.NewReader(validPW + "\r\n"))
		if err != nil {
			t.Fatalf("CRLF line ending rejected: %v", err)
		}
		if pw != validPW {
			t.Fatalf("expected %q, got %q", validPW, pw)
		}
	})

	t.Run("multiple password lines rejected", func(t *testing.T) {
		_, err := readPasswordFromStdin(strings.NewReader(validPW + "\nsecondline\n"))
		if err == nil || !strings.Contains(err.Error(), "multiple password lines") {
			t.Fatalf("expected multiple password lines error, got %v", err)
		}
	})

	t.Run("empty password input rejected", func(t *testing.T) {
		_, err := readPasswordFromStdin(strings.NewReader(""))
		if err == nil || !strings.Contains(err.Error(), "empty password input") {
			t.Fatalf("expected empty input error, got %v", err)
		}
	})

	t.Run("missing newline terminator rejected", func(t *testing.T) {
		_, err := readPasswordFromStdin(strings.NewReader(validPW))
		if err == nil || !strings.Contains(err.Error(), "newline terminator") {
			t.Fatalf("expected missing newline error, got %v", err)
		}
	})

	t.Run("password under minimum length rejected", func(t *testing.T) {
		_, err := readPasswordFromStdin(strings.NewReader("short\n"))
		if err == nil || !strings.Contains(err.Error(), "at least 12 bytes") {
			t.Fatalf("expected too short error, got %v", err)
		}
	})

	t.Run("password over maximum length rejected", func(t *testing.T) {
		tooLong := strings.Repeat("a", 129) + "\n"
		_, err := readPasswordFromStdin(strings.NewReader(tooLong))
		if err == nil || !strings.Contains(err.Error(), "128 bytes") {
			t.Fatalf("expected too long error, got %v", err)
		}
	})

	t.Run("input exceeding buffer bounds rejected", func(t *testing.T) {
		overflow := strings.Repeat("a", 131) + "\n"
		_, err := readPasswordFromStdin(strings.NewReader(overflow))
		if err == nil || !strings.Contains(err.Error(), "128 bytes") {
			t.Fatalf("expected overflow error, got %v", err)
		}
	})

	t.Run("spaces preserved without trimming", func(t *testing.T) {
		spaced := "  password with spaces  "
		pw, err := readPasswordFromStdin(strings.NewReader(spaced + "\n"))
		if err != nil {
			t.Fatalf("spaced password rejected: %v", err)
		}
		if pw != spaced {
			t.Fatalf("expected untrimmed %q, got %q", spaced, pw)
		}
	})

	// Security invariant: Passwords must never leak into returned error strings.
	t.Run("password content omitted from error string", func(t *testing.T) {
		_, err := readPasswordFromStdin(strings.NewReader("short\n"))
		if strings.Contains(err.Error(), "short") {
			t.Fatal("password content leaked into error string")
		}
	})
}

func TestOperatorCreate_ExecutionAndOutput(t *testing.T) {
	creator := &mockOperatorCreator{}
	stdout := &bytes.Buffer{}
	const validPW = "Very-Strong-Password-123!"

	t.Run("operator creation output format", func(t *testing.T) {
		err := createAndPrintOperator(context.Background(), creator, "admin", validPW, operator.RoleAdmin, stdout)
		if err != nil {
			t.Fatalf("createAndPrintOperator failed: %v", err)
		}

		output := stdout.String()
		if !strings.Contains(output, "Operator created:") {
			t.Errorf("expected 'Operator created:', got %q", output)
		}
		if !strings.Contains(output, "Username: admin") {
			t.Errorf("expected 'Username: admin', got %q", output)
		}
		if !strings.Contains(output, "Role: admin") {
			t.Errorf("expected 'Role: admin', got %q", output)
		}
		if !strings.Contains(output, "ID: 018f0000-0000-7000-8000-000000000001") {
			t.Errorf("expected ID in output, got %q", output)
		}

		// Security invariant: Plaintext password, hash, and salt must never be written to stdout.
		if strings.Contains(output, validPW) {
			t.Fatal("plaintext password leaked to stdout")
		}
		if strings.Contains(output, "$argon2id$") {
			t.Fatal("password hash leaked to stdout")
		}
	})

	t.Run("duplicate username returns safe error", func(t *testing.T) {
		duplicateCreator := &mockOperatorCreator{
			createFunc: func(ctx context.Context, username, passwordHash string, role operator.Role) (*operator.OperatorRecord, error) {
				return nil, operator.ErrUsernameConflict
			},
		}
		stdout.Reset()
		err := createAndPrintOperator(context.Background(), duplicateCreator, "admin", validPW, operator.RoleAdmin, stdout)
		if err == nil {
			t.Fatal("expected error on duplicate username, got nil")
		}
		if !strings.Contains(err.Error(), "already exists") {
			t.Errorf("expected safe duplicate username error, got %v", err)
		}
		if strings.Contains(err.Error(), validPW) {
			t.Fatal("password leaked in duplicate error string")
		}
	})
}
