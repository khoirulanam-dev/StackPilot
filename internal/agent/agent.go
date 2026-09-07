package agent

import (
	"context"
	"log/slog"
)

// Run starts the agent and blocks until ctx is canceled.
func Run(ctx context.Context, logger *slog.Logger) error {
	if logger != nil {
		logger.Info("agent initialized successfully")
	}
	<-ctx.Done()
	return nil
}
