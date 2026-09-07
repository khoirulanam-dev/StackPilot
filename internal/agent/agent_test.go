package agent

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestAgent_Run(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, logger)
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
