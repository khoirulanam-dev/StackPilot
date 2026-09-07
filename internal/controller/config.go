package controller

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
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
	ListenAddress string
	LogLevel      slog.Level
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
	return validateLogLevel(cfg.LogLevel)
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
