package controller

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const (
	defaultListenAddress = "127.0.0.1:7447"
	defaultLogLevel      = slog.LevelInfo
)

// Config represents the validated runtime configuration for the controller.
type Config struct {
	ListenAddress      string
	LogLevel           slog.Level
	DatabaseURL        string
	AgentListenAddress string
	AgentTLSCertFile   string
	AgentTLSKeyFile    string
}

// RemoteEnabled returns true if remote Agent transport listener is configured.
func (cfg Config) RemoteEnabled() bool {
	return cfg.AgentListenAddress != ""
}

// LogValue implements slog.LogValuer to ensure secrets are never serialized into logs.
func (cfg Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("listen_address", cfg.ListenAddress),
		slog.String("agent_listen_address", cfg.AgentListenAddress),
		slog.Bool("agent_tls_enabled", cfg.RemoteEnabled()),
		slog.String("log_level", cfg.LogLevel.String()),
		slog.String("database_url", "[REDACTED]"),
	)
}

func defaultConfig() Config {
	return Config{
		ListenAddress: defaultListenAddress,
		LogLevel:      defaultLogLevel,
	}
}

func (cfg Config) validate() error {
	if cfg.ListenAddress == "" {
		return fmt.Errorf("listen address cannot be empty")
	}
	if err := validateListenAddress(cfg.ListenAddress); err != nil {
		return err
	}
	if err := validateLogLevel(cfg.LogLevel); err != nil {
		return err
	}
	if cfg.DatabaseURL == "" {
		return fmt.Errorf("invalid STACKPILOT_DATABASE_URL: cannot be empty")
	}
	if err := validateDatabaseURL(cfg.DatabaseURL); err != nil {
		return err
	}
	if cfg.AgentListenAddress != "" {
		if err := validateAgentListenAddress(cfg.AgentListenAddress); err != nil {
			return fmt.Errorf("invalid STACKPILOT_AGENT_LISTEN_ADDRESS: %w", err)
		}
		if cfg.AgentTLSCertFile == "" {
			return fmt.Errorf("invalid STACKPILOT_AGENT_TLS_CERT_FILE: cannot be empty when STACKPILOT_AGENT_LISTEN_ADDRESS is configured")
		}
		if cfg.AgentTLSKeyFile == "" {
			return fmt.Errorf("invalid STACKPILOT_AGENT_TLS_KEY_FILE: cannot be empty when STACKPILOT_AGENT_LISTEN_ADDRESS is configured")
		}
	}
	return nil
}

func validateLogLevel(level slog.Level) error {
	switch level {
	case slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError:
		return nil
	default:
		return fmt.Errorf("unsupported log level %v (allowed: debug, info, warn, error)", level)
	}
}

// LoadConfig loads and validates controller configuration from process environment variables.
func LoadConfig() (Config, error) {
	cfg := defaultConfig()

	dbURL, ok := os.LookupEnv("STACKPILOT_DATABASE_URL")
	if !ok {
		return Config{}, fmt.Errorf("missing required STACKPILOT_DATABASE_URL")
	}
	if dbURL == "" {
		return Config{}, fmt.Errorf("invalid STACKPILOT_DATABASE_URL: cannot be empty")
	}
	if err := validateDatabaseURL(dbURL); err != nil {
		return Config{}, err
	}
	cfg.DatabaseURL = dbURL

	if val, ok := os.LookupEnv("STACKPILOT_LISTEN_ADDRESS"); ok {
		if val == "" {
			return Config{}, fmt.Errorf("invalid STACKPILOT_LISTEN_ADDRESS: cannot be empty")
		}
		if err := validateListenAddress(val); err != nil {
			return Config{}, fmt.Errorf("invalid STACKPILOT_LISTEN_ADDRESS: %w", err)
		}
		cfg.ListenAddress = val
	}

	if val, ok := os.LookupEnv("STACKPILOT_LOG_LEVEL"); ok {
		if val == "" {
			return Config{}, fmt.Errorf("invalid STACKPILOT_LOG_LEVEL: cannot be empty")
		}
		level, err := parseLogLevel(val)
		if err != nil {
			return Config{}, fmt.Errorf("invalid STACKPILOT_LOG_LEVEL: %w", err)
		}
		cfg.LogLevel = level
	}

	if val, ok := os.LookupEnv("STACKPILOT_AGENT_LISTEN_ADDRESS"); ok {
		if val == "" {
			return Config{}, fmt.Errorf("invalid STACKPILOT_AGENT_LISTEN_ADDRESS: cannot be empty")
		}
		if err := validateAgentListenAddress(val); err != nil {
			return Config{}, fmt.Errorf("invalid STACKPILOT_AGENT_LISTEN_ADDRESS: %w", err)
		}
		cfg.AgentListenAddress = val
	}

	if val, ok := os.LookupEnv("STACKPILOT_AGENT_TLS_CERT_FILE"); ok {
		cfg.AgentTLSCertFile = val
	}

	if val, ok := os.LookupEnv("STACKPILOT_AGENT_TLS_KEY_FILE"); ok {
		cfg.AgentTLSKeyFile = val
	}

	if err := cfg.validate(); err != nil {
		return Config{}, fmt.Errorf("invalid controller configuration: %w", err)
	}

	return cfg, nil
}

func validateListenAddress(addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("must be a valid host:port string: %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("port must be an integer between 1 and 65535")
	}

	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("host must be a literal IP address: %w", err)
	}

	if !ip.IsLoopback() {
		return fmt.Errorf("address must use a loopback IP")
	}

	return nil
}

func validateAgentListenAddress(addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("must be a valid host:port string: %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("port must be an integer between 1 and 65535")
	}

	_, err = netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("host must be a literal IP address: %w", err)
	}

	return nil
}

func parseLogLevel(val string) (slog.Level, error) {
	switch strings.ToLower(val) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unsupported value %q (allowed: debug, info, warn, error)", val)
	}
}

func validateDatabaseURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid STACKPILOT_DATABASE_URL: invalid PostgreSQL connection URL")
	}

	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return fmt.Errorf("invalid STACKPILOT_DATABASE_URL: scheme must be postgres or postgresql")
	}

	if u.Hostname() == "" {
		return fmt.Errorf("invalid STACKPILOT_DATABASE_URL: host cannot be empty")
	}

	dbName := strings.TrimPrefix(u.Path, "/")
	if dbName == "" {
		return fmt.Errorf("invalid STACKPILOT_DATABASE_URL: database name cannot be empty")
	}

	return nil
}
