package agent

import (
	"context"
	"log/slog"
)

// Run starts the agent presence daemon for the specified state directory and blocks until ctx is canceled or a permanent failure occurs.
func Run(ctx context.Context, logger *slog.Logger, stateDir string) error {
	return runWithSecurity(ctx, logger, stateDir, EnforceDaemonSecurity)
}

func runWithSecurity(ctx context.Context, logger *slog.Logger, stateDir string, enforce func() error) error {
	if err := enforce(); err != nil {
		return err
	}
	return RunPresence(ctx, logger, stateDir)
}
