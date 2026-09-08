package main

import (
	"context"
	"errors"
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
	"stackpilot/internal/operator"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "controller startup error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
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

	if args[0] == "operator" {
		if len(args) >= 2 && args[1] == "create" {
			return runOperatorCreate(args[2:], stdin, stdout, stderr)
		}
		if len(args) == 1 {
			return fmt.Errorf("missing subcommand for operator (supported: create)")
		}
		return fmt.Errorf("unknown operator subcommand %q (supported: create)", args[1])
	}

	return fmt.Errorf("unknown command %q (supported: enrollment-token create, operator create)", strings.Join(args, " "))
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

type operatorCreator interface {
	CreateOperator(ctx context.Context, username, passwordHash string, role operator.Role) (*operator.OperatorRecord, error)
}

type operatorCreateOptions struct {
	username      string
	role          operator.Role
	passwordStdin bool
}

func parseOperatorCreateFlags(args []string) (*operatorCreateOptions, error) {
	var (
		opts          operatorCreateOptions
		rawRole       string
		passwordStdin bool
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--username":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument for --username")
			}
			opts.username = args[i+1]
			i++
		case strings.HasPrefix(arg, "--username="):
			opts.username = strings.TrimPrefix(arg, "--username=")
		case arg == "--role":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("missing argument for --role")
			}
			rawRole = args[i+1]
			i++
		case strings.HasPrefix(arg, "--role="):
			rawRole = strings.TrimPrefix(arg, "--role=")
		case arg == "--password-stdin":
			passwordStdin = true
		case arg == "--password" || strings.HasPrefix(arg, "--password="):
			return nil, fmt.Errorf("--password flag is not supported; use --password-stdin")
		case arg == "--password-file" || strings.HasPrefix(arg, "--password-file="):
			return nil, fmt.Errorf("--password-file flag is not supported; use --password-stdin")
		default:
			return nil, fmt.Errorf("unknown flag %q", arg)
		}
	}

	if opts.username == "" {
		return nil, fmt.Errorf("missing required flag: --username")
	}
	opts.username = operator.NormalizeUsername(opts.username)
	if err := operator.ValidateUsername(opts.username); err != nil {
		return nil, fmt.Errorf("invalid username: %w", err)
	}

	if rawRole == "" {
		return nil, fmt.Errorf("missing required flag: --role")
	}
	parsedRole, err := operator.ParseRole(rawRole)
	if err != nil {
		return nil, fmt.Errorf("invalid role: %w", err)
	}
	opts.role = parsedRole

	if !passwordStdin {
		return nil, fmt.Errorf("missing required flag: --password-stdin")
	}
	opts.passwordStdin = true

	return &opts, nil
}

func readPasswordFromStdin(stdin io.Reader) (string, error) {
	if stdin == nil {
		return "", fmt.Errorf("stdin is not available")
	}
	limited := io.LimitReader(stdin, 131)
	data, err := io.ReadAll(limited)
	if err != nil {
		return "", fmt.Errorf("failed to read password from stdin: %w", err)
	}
	if len(data) == 0 {
		return "", fmt.Errorf("empty password input")
	}
	if len(data) > 130 {
		return "", fmt.Errorf("password exceeds maximum length of 128 bytes")
	}

	raw := string(data)
	var stripped string
	if strings.HasSuffix(raw, "\r\n") {
		stripped = strings.TrimSuffix(raw, "\r\n")
	} else if strings.HasSuffix(raw, "\n") {
		stripped = strings.TrimSuffix(raw, "\n")
	} else {
		return "", fmt.Errorf("password input must end with a newline terminator")
	}

	if strings.Contains(stripped, "\n") || strings.Contains(stripped, "\r") {
		return "", fmt.Errorf("multiple password lines are not allowed")
	}

	if err := operator.ValidatePassword(stripped); err != nil {
		return "", fmt.Errorf("invalid password: %w", err)
	}

	return stripped, nil
}

func createAndPrintOperator(ctx context.Context, creator operatorCreator, username string, password string, role operator.Role, stdout io.Writer) error {
	pwHash, err := operator.HashPassword(password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	rec, err := creator.CreateOperator(ctx, username, pwHash, role)
	if err != nil {
		if errors.Is(err, operator.ErrUsernameConflict) {
			return fmt.Errorf("operator %q already exists", username)
		}
		return fmt.Errorf("failed to create operator: %w", err)
	}

	fmt.Fprintf(stdout, "Operator created:\nID: %s\nUsername: %s\nRole: %s\n", rec.ID, rec.Username, rec.Role)
	return nil
}

func runOperatorCreate(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	opts, err := parseOperatorCreateFlags(args)
	if err != nil {
		return err
	}

	pw, err := readPasswordFromStdin(stdin)
	if err != nil {
		return err
	}

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

	return createAndPrintOperator(ctx, db, opts.username, pw, opts.role, stdout)
}
