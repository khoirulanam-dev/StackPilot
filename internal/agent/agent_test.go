package agent

import (
	"context"
	"crypto/rand"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"
)

func TestAgent_Run(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tempDir := t.TempDir()
	stateDir := filepath.Join(tempDir, "state")
	if err := EnsureStateDir(stateDir); err != nil {
		t.Fatalf("EnsureStateDir failed: %v", err)
	}

	pub, _, err := LoadOrGenerateKey(stateDir, rand.Reader)
	if err != nil {
		t.Fatalf("LoadOrGenerateKey failed: %v", err)
	}

	meta := &IdentityMetadata{
		Version:       1,
		AgentID:       "018f0000-0000-7000-8000-000000000006",
		ControllerURL: "https://127.0.0.1:7448",
		PublicKey:     FormatPublicKeyBase64RawURL(pub),
	}
	if err := WriteIdentityMetadata(stateDir, meta); err != nil {
		t.Fatalf("WriteIdentityMetadata failed: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, logger, stateDir)
	}()

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("expected no error on shutdown, got %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for agent shutdown")
	}
}
