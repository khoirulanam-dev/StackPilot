package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"stackpilot/internal/controller"
	"stackpilot/internal/database"
	"stackpilot/internal/enrollment"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "controller startup error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return runServer(stdout)
	}

	if args[0] == "enrollment-token" {
		if len(args) == 2 && args[1] == "create" {
			return runEnrollmentTokenCreate(stdout, stderr)
		}
		if len(args) == 1 {
			return fmt.Errorf("missing subcommand for enrollment-token (supported: create)")
		}
		return fmt.Errorf("unknown enrollment-token subcommand %q (supported: create)", args[1])
	}

	return fmt.Errorf("unknown command %q (supported: enrollment-token create)", strings.Join(args, " "))
}

func runServer(stdout io.Writer) error {
	cfg, err := controller.LoadConfig()
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(stdout, &slog.HandlerOptions{
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

func runEnrollmentTokenCreate(stdout, stderr io.Writer) error {
	cfg, err := controller.LoadConfig()
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{
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

	return issueAndPrintEnrollmentToken(ctx, db, stdout)
}

func issueAndPrintEnrollmentToken(ctx context.Context, persister enrollment.TokenPersister, stdout io.Writer) error {
	token, err := enrollment.IssueToken(ctx, persister)
	if err != nil {
		return fmt.Errorf("failed to issue enrollment token: %w", err)
	}

	if _, err := fmt.Fprintln(stdout, token); err != nil {
		return fmt.Errorf("failed to write enrollment token: %w", err)
	}

	return nil
}
