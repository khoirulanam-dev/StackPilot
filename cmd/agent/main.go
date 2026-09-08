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
	"strings"
	"syscall"

	"stackpilot/internal/agent"
	"stackpilot/internal/privilege"
)

type privilegeClientFactory func(cfg privilege.ClientConfig) (privilege.Client, error)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "agent error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return runAgentDaemon(args, stdout, stderr)
	}

	switch args[0] {
	case "enroll":
		return runEnroll(args[1:], stdin, stdout, stderr)
	case "transport-check":
		return runTransportCheck(args[1:], stdout, stderr)
	case "privilege-check":
		return runPrivilegeCheck(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown command %q (supported: enroll, transport-check, privilege-check)", args[0])
	}
}

type agentDaemonRunner func(ctx context.Context, logger *slog.Logger, stateDir string) error

func runAgentDaemon(args []string, stdout, stderr io.Writer) error {
	return runAgentDaemonWithRunner(args, stdout, stderr, agent.Run)
}

func runAgentDaemonWithRunner(args []string, stdout, stderr io.Writer, runner agentDaemonRunner) error {
	fs := flag.NewFlagSet("stackpilot-agent", flag.ContinueOnError)
	fs.SetOutput(stderr)

	stateDir := fs.String("state-dir", "", "Agent state directory containing enrolled cryptographic identity")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() > 0 {
		return errors.New("unexpected positional arguments")
	}

	if *stateDir == "" {
		return fmt.Errorf("missing required flag --state-dir")
	}

	logger := slog.New(slog.NewTextHandler(stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return runner(ctx, logger, *stateDir)
}

func runEnroll(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)

	controllerURL := fs.String("controller", "", "Controller URL (e.g. http://127.0.0.1:7447 or https://controller.example.com:7448)")
	stateDir := fs.String("state-dir", "", "Agent state directory for storing cryptographic identity")
	caFile := fs.String("ca-file", "", "Optional custom CA certificate file for controller TLS verification")

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
		CAFile:        *caFile,
		TokenReader:   stdin,
	}

	agentID, err := agent.Enroll(ctx, opts)
	if err != nil {
		return err
	}

	fmt.Fprintf(stdout, "Agent enrolled successfully: %s\n", agentID)
	return nil
}

func runTransportCheck(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("transport-check", flag.ContinueOnError)
	fs.SetOutput(stderr)

	stateDir := fs.String("state-dir", "", "Agent state directory containing enrolled cryptographic identity")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() > 0 {
		return errors.New("unexpected positional arguments")
	}

	if *stateDir == "" {
		return fmt.Errorf("missing required flag --state-dir")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	agentID, err := agent.TransportCheck(ctx, *stateDir)
	if err != nil {
		return err
	}

	fmt.Fprintf(stdout, "Secure transport verified: %s\n", agentID)
	return nil
}

func runPrivilegeCheck(args []string, stdout, stderr io.Writer) error {
	return runPrivilegeCheckWithFactory(args, stdout, stderr, privilege.NewClient)
}

func runPrivilegeCheckWithFactory(args []string, stdout, stderr io.Writer, factory privilegeClientFactory) error {
	fs := flag.NewFlagSet("privilege-check", flag.ContinueOnError)
	fs.SetOutput(stderr)

	runtimeDir := fs.String("runtime-dir", "", "Helper runtime directory containing agent-helper.sock")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() > 0 {
		return errors.New("unexpected positional arguments")
	}

	if *runtimeDir == "" {
		return fmt.Errorf("missing required flag --runtime-dir")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client, err := factory(privilege.ClientConfig{
		RuntimeDir: *runtimeDir,
	})
	if err != nil {
		return err
	}

	if err := client.Ping(ctx); err != nil {
		return err
	}

	fmt.Fprintln(stdout, "Privilege boundary verified")
	return nil
}
