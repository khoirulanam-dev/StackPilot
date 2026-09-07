package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"stackpilot/internal/controller"
	"stackpilot/internal/database"
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := database.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("database connection failed: %w", err)
	}
	defer db.Close()

	logger.Info("database connected")

	if err := db.Migrate(ctx, logger); err != nil {
		return fmt.Errorf("database migration failed: %w", err)
	}

	logger.Info("database migrations complete")

	logger.Info("controller starting",
		"listen_address", cfg.ListenAddress,
		"log_level", cfg.LogLevel.String(),
	)

	return controller.Run(ctx, cfg, db, logger)
}
