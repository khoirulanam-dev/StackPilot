package agent

import (
	"context"
	"log/slog"
)

// Run starts the agent presence daemon for the specified state directory and blocks until ctx is canceled or a permanent failure occurs.
func Run(ctx context.Context, logger *slog.Logger, stateDir string) error {
	return RunPresence(ctx, logger, stateDir)
}
