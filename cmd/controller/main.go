package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"stackpilot/internal/controller"
	"syscall"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "controller startup error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := controller.LoadConfig()
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.LogLevel,
	}))

	logger.Info("starting stackpilot controller",
		"listen_address", cfg.ListenAddress,
		"log_level", cfg.LogLevel.String(),
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return controller.Run(ctx, cfg, logger)
}
