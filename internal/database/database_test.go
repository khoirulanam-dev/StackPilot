package database

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"stackpilot/internal/protocol"
)

func TestConfigurePool(t *testing.T) {
	testURL := "postgres://stackpilot:secret@127.0.0.1:5432/stackpilot?sslmode=disable"
	cfg, err := configurePool(testURL)
	if err != nil {
		t.Fatalf("configurePool() failed: %v", err)
	}

	if cfg.MaxConns != 10 {
		t.Errorf("expected MaxConns = 10, got %d", cfg.MaxConns)
	}

	if cfg.MinConns != 0 {
		t.Errorf("expected MinConns = 0, got %d", cfg.MinConns)
	}

	appName := cfg.ConnConfig.RuntimeParams["application_name"]
	if appName != "stackpilot-controller" {
		t.Errorf("expected application_name = 'stackpilot-controller', got %q", appName)
	}

	if cfg.ConnConfig.RequireAuth != "scram-sha-256" {
		t.Errorf("expected RequireAuth = 'scram-sha-256', got %q", cfg.ConnConfig.RequireAuth)
	}
}

func TestConfigurePool_RequireAuthOverride(t *testing.T) {
	testURL := "postgres://stackpilot:secret@127.0.0.1:5432/stackpilot?sslmode=disable&require_auth=password"
	cfg, err := configurePool(testURL)
	if err != nil {
		t.Fatalf("configurePool() failed: %v", err)
	}

	if cfg.ConnConfig.RequireAuth != "scram-sha-256" {
		t.Errorf("expected RequireAuth policy to enforce 'scram-sha-256', got %q", cfg.ConnConfig.RequireAuth)
	}
}

func TestOpen_InvalidURLDoesNotLeakSecret(t *testing.T) {
	secretPassword := "stackpilot-super-secret-test-value"
	malformedURL := "postgres://stackpilot:" + secretPassword + "@[::1]:999999/db"

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := Open(ctx, malformedURL)
	if err == nil {
		t.Fatal("expected Open() to fail for malformed URL, got nil")
	}

	if strings.Contains(err.Error(), secretPassword) {
		t.Fatalf("secret password was leaked in Open() error: %s", err.Error())
	}
}

func TestOpen_ConnectionFailureDoesNotLeakSecret(t *testing.T) {
	secretPassword := "stackpilot-super-secret-test-value"

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener fixture: %v", err)
	}
	defer l.Close()

	go func() {
		conn, acceptErr := l.Accept()
		if acceptErr == nil && conn != nil {
			_ = conn.Close()
		}
	}()

	testURL := "postgres://stackpilot:" + secretPassword + "@" + l.Addr().String() + "/stackpilot?sslmode=disable"

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = Open(ctx, testURL)
	if err == nil {
		t.Fatal("expected Open() to fail for immediately closed connection, got nil")
	}

	if strings.Contains(err.Error(), secretPassword) {
		t.Fatalf("secret password was leaked in Open() connection failure: %s", err.Error())
	}
}

func TestSanitizeError(t *testing.T) {
	const secret = "stackpilot-super-secret-test-value"

	tests := []struct {
		name     string
		input    error
		contains string
	}{
		{
			name:     "password key-value pair",
			input:    errors.New("failed connection: password=" + secret + " host=localhost"),
			contains: "password=[REDACTED] host=localhost",
		},
		{
			name:     "userinfo URI format",
			input:    errors.New("connection failed to postgres://user:" + secret + "@localhost:5432/db"),
			contains: "postgres://user:[REDACTED]@localhost:5432/db",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeError(tt.input)
			if strings.Contains(got.Error(), secret) {
				t.Fatalf("sanitizeError() leaked secret: %s", got.Error())
			}
			if !strings.Contains(got.Error(), tt.contains) {
				t.Errorf("expected %q to contain %q", got.Error(), tt.contains)
			}
		})
	}
}

func TestFindAgentByPublicKey_Uninitialized(t *testing.T) {
	db := &DB{}
	var key [32]byte
	_, err := db.FindAgentByPublicKey(context.Background(), key)
	if err == nil {
		t.Fatal("expected error on uninitialized pool, got nil")
	}
}

func TestRecordAgentHeartbeat_Uninitialized(t *testing.T) {
	db := &DB{}
	var key [32]byte
	_, err := db.RecordAgentHeartbeat(context.Background(), key, 1)
	if err == nil {
		t.Fatal("expected error on uninitialized pool, got nil")
	}
}

func TestRecordAgentInventory_Uninitialized(t *testing.T) {
	db := &DB{}
	var key [32]byte
	req := &protocol.InventoryRequest{
		ProtocolVersion:  1,
		Hostname:         "node-01",
		OSID:             "linux",
		OSName:           "Linux",
		OSVersion:        "1.0",
		KernelRelease:    "6.8.0",
		Architecture:     "amd64",
		CPULogicalCores:  4,
		MemoryTotalBytes: 1024,
	}
	err := db.RecordAgentInventory(context.Background(), key, req)
	if err == nil {
		t.Fatal("expected error on uninitialized pool, got nil")
	}
}
