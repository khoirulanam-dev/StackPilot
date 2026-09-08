package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"stackpilot/internal/privilege"
)

type serverRunner func(ctx context.Context, cfg privilege.ServerConfig) error

func defaultServerRunner(ctx context.Context, cfg privilege.ServerConfig) error {
	srv, err := privilege.NewServer(cfg)
	if err != nil {
		return err
	}
	return srv.Serve(ctx)
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "helper error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	return runWithRunner(args, stdout, stderr, defaultServerRunner)
}

func runWithRunner(args []string, stdout, stderr io.Writer, runner serverRunner) error {
	fs := flag.NewFlagSet("stackpilot-agent-helper", flag.ContinueOnError)
	fs.SetOutput(stderr)

	runtimeDir := fs.String("runtime-dir", "", "Absolute path to helper runtime directory")
	allowedUIDStr := fs.String("allowed-uid", "", "Numeric UID of authorized non-root agent user")
	allowedGIDStr := fs.String("allowed-gid", "", "Numeric GID of authorized agent group")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() > 0 {
		return errors.New("unexpected positional arguments")
	}

	if *runtimeDir == "" {
		return errors.New("missing required flag --runtime-dir")
	}
	if *allowedUIDStr == "" {
		return errors.New("missing required flag --allowed-uid")
	}
	if *allowedGIDStr == "" {
		return errors.New("missing required flag --allowed-gid")
	}

	allowedUID, err := strconv.ParseUint(*allowedUIDStr, 10, 32)
	if err != nil {
		return fmt.Errorf("invalid numeric --allowed-uid %q: %w", *allowedUIDStr, err)
	}
	if allowedUID == 0 {
		return errors.New("allowed UID must be non-root (non-zero)")
	}

	allowedGID, err := strconv.ParseUint(*allowedGIDStr, 10, 32)
	if err != nil {
		return fmt.Errorf("invalid numeric --allowed-gid %q: %w", *allowedGIDStr, err)
	}

	cfg := privilege.ServerConfig{
		RuntimeDir: *runtimeDir,
		AllowedUID: uint32(allowedUID),
		AllowedGID: uint32(allowedGID),
		Logger:     slog.New(slog.NewTextHandler(stdout, nil)),
	}

	// Validate config before initiating signal handling or server execution
	if err := privilege.ValidateServerConfig(cfg); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return runner(ctx, cfg)
}
