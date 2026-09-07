package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"stackpilot/internal/controller"
	"syscall"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := controller.Run(ctx, logger); err != nil {
		logger.Error("controller error", "error", err)
		os.Exit(1)
	}
}
