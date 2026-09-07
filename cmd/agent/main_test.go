package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"stackpilot/internal/agent"
	"stackpilot/internal/enrollment"
)

func TestAgentCLI_Dispatch(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	stdin := &bytes.Buffer{}

	t.Run("unknown command returns error", func(t *testing.T) {
		err := run([]string{"unknown"}, stdin, stdout, stderr)
		if err == nil {
			t.Fatal("expected error for unknown command, got nil")
		}
		if !strings.Contains(err.Error(), "unknown command") {
			t.Errorf("expected error to mention 'unknown command', got %q", err.Error())
		}
	})

	t.Run("enroll missing controller flag returns error", func(t *testing.T) {
		err := run([]string{"enroll", "--state-dir", "/tmp/foo"}, stdin, stdout, stderr)
		if err == nil {
			t.Fatal("expected error for missing --controller, got nil")
		}
		if !strings.Contains(err.Error(), "--controller") {
			t.Errorf("expected error to mention '--controller', got %q", err.Error())
		}
	})

	t.Run("enroll missing state-dir flag returns error", func(t *testing.T) {
		err := run([]string{"enroll", "--controller", "http://127.0.0.1:7447"}, stdin, stdout, stderr)
		if err == nil {
			t.Fatal("expected error for missing --state-dir, got nil")
		}
		if !strings.Contains(err.Error(), "--state-dir") {
			t.Errorf("expected error to mention '--state-dir', got %q", err.Error())
		}
	})

	t.Run("enroll success end-to-end via CLI", func(t *testing.T) {
		const mockAgentID = "018f0000-0000-7000-8000-000000000001"
		token := enrollment.TokenPrefix + strings.Repeat("E", 43)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"agent_id": mockAgentID})
		}))
		defer server.Close()

		tempDir := t.TempDir()
		stateDir := filepath.Join(tempDir, "state")
		stdin := strings.NewReader(token + "\n")
		outBuf := &bytes.Buffer{}
		errBuf := &bytes.Buffer{}

		err := run([]string{"enroll", "--controller", server.URL, "--state-dir", stateDir}, stdin, outBuf, errBuf)
		if err != nil {
			t.Fatalf("enroll command failed: %v", err)
		}

		outStr := outBuf.String()
		if !strings.Contains(outStr, mockAgentID) {
			t.Fatalf("expected stdout to contain agent_id %q, got %q", mockAgentID, outStr)
		}
		if !strings.Contains(outStr, "Agent enrolled successfully") {
			t.Fatalf("expected stdout to contain success message, got %q", outStr)
		}
		// Confirm token is not printed
		if strings.Contains(outStr, token) {
			t.Fatal("stdout printed enrollment token")
		}
	})

	t.Run("enroll positional arguments rejected without leaking secret", func(t *testing.T) {
		syntheticSecret := enrollment.TokenPrefix + "synthetic_argv_secret_token_12345"
		serverCalled := false
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serverCalled = true
			w.WriteHeader(http.StatusCreated)
		}))
		defer server.Close()

		tempDir := t.TempDir()
		stateDir := filepath.Join(tempDir, "state")
		outBuf := &bytes.Buffer{}
		errBuf := &bytes.Buffer{}
		stdin := strings.NewReader("")

		err := run([]string{"enroll", "--controller", server.URL, "--state-dir", stateDir, syntheticSecret}, stdin, outBuf, errBuf)
		if err == nil {
			t.Fatal("expected error on positional argument, got nil")
		}
		if serverCalled {
			t.Fatal("enrollment server was called despite unexpected positional arguments")
		}
		if strings.Contains(err.Error(), syntheticSecret) {
			t.Fatal("error message echoed secret positional argument")
		}
		if strings.Contains(outBuf.String(), syntheticSecret) {
			t.Fatal("stdout echoed secret positional argument")
		}
		if strings.Contains(errBuf.String(), syntheticSecret) {
			t.Fatal("stderr echoed secret positional argument")
		}
	})

	t.Run("daemon mode cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		outBuf := &bytes.Buffer{}
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))

		done := make(chan error, 1)
		go func() {
			done <- agent.Run(ctx, logger)
		}()

		// Cancel context shortly
		cancel()

		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("expected clean exit on cancellation, got: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("agent daemon did not exit within timeout")
		}
		_ = outBuf
	})
}
