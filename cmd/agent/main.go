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
	"syscall"

	"stackpilot/internal/agent"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "agent error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return runAgentDaemon(stdout)
	}

	if args[0] == "enroll" {
		return runEnroll(args[1:], stdin, stdout, stderr)
	}

	return fmt.Errorf("unknown command %q (supported: enroll)", args[0])
}

func runAgentDaemon(stdout io.Writer) error {
	logger := slog.New(slog.NewTextHandler(stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return agent.Run(ctx, logger)
}

func runEnroll(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)

	controllerURL := fs.String("controller", "", "Controller URL (e.g. http://127.0.0.1:7447)")
	stateDir := fs.String("state-dir", "", "Agent state directory for storing cryptographic identity")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() > 0 {
		return errors.New("unexpected positional arguments; enrollment token must be provided via stdin")
	}

	if *controllerURL == "" {
		return fmt.Errorf("missing required flag --controller")
	}
	if *stateDir == "" {
		return fmt.Errorf("missing required flag --state-dir")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	opts := agent.EnrollOptions{
		ControllerURL: *controllerURL,
		StateDir:      *stateDir,
		TokenReader:   stdin,
	}

	agentID, err := agent.Enroll(ctx, opts)
	if err != nil {
		return err
	}

	fmt.Fprintf(stdout, "Agent enrolled successfully: %s\n", agentID)
	return nil
}
