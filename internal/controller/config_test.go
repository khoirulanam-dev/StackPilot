package controller

import (
	"log/slog"
	"os"
	"strings"
	"testing"
)

func unsetEnv(t *testing.T, key string) {
	t.Helper()
	if val, ok := os.LookupEnv(key); ok {
		t.Cleanup(func() {
			if err := os.Setenv(key, val); err != nil {
				t.Fatalf("failed to restore environment variable %s: %v", key, err)
			}
		})
	} else {
		t.Cleanup(func() {
			if err := os.Unsetenv(key); err != nil {
				t.Fatalf("failed to clean up environment variable %s: %v", key, err)
			}
		})
	}
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("failed to unset environment variable %s: %v", key, err)
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	unsetEnv(t, "STACKPILOT_LISTEN_ADDRESS")
	unsetEnv(t, "STACKPILOT_LOG_LEVEL")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() returned unexpected error: %v", err)
	}

	wantAddr := "127.0.0.1:7447"
	if cfg.ListenAddress != wantAddr {
		t.Errorf("ListenAddress = %q, want %q", cfg.ListenAddress, wantAddr)
	}

	wantLevel := slog.LevelInfo
	if cfg.LogLevel != wantLevel {
		t.Errorf("LogLevel = %v, want %v", cfg.LogLevel, wantLevel)
	}
}

func TestLoadConfig_ListenAddressValid(t *testing.T) {
	unsetEnv(t, "STACKPILOT_LOG_LEVEL")

	tests := []struct {
		name     string
		input    string
		wantAddr string
	}{
		{
			name:     "custom IPv4 loopback port",
			input:    "127.0.0.1:9001",
			wantAddr: "127.0.0.1:9001",
		},
		{
			name:     "alternative IPv4 loopback IP",
			input:    "127.0.0.2:8000",
			wantAddr: "127.0.0.2:8000",
		},
		{
			name:     "IPv6 loopback literal",
			input:    "[::1]:7447",
			wantAddr: "[::1]:7447",
		},
		{
			name:     "IPv6 loopback custom port",
			input:    "[::1]:8080",
			wantAddr: "[::1]:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("STACKPILOT_LISTEN_ADDRESS", tt.input)

			cfg, err := LoadConfig()
			if err != nil {
				t.Fatalf("LoadConfig() returned unexpected error: %v", err)
			}
			if cfg.ListenAddress != tt.wantAddr {
				t.Errorf("ListenAddress = %q, want %q", cfg.ListenAddress, tt.wantAddr)
			}
		})
	}
}

func TestLoadConfig_ListenAddressInvalid(t *testing.T) {
	unsetEnv(t, "STACKPILOT_LOG_LEVEL")

	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name:    "empty string",
			input:   "",
			wantErr: "cannot be empty",
		},
		{
			name:    "wildcard IPv4",
			input:   "0.0.0.0:7447",
			wantErr: "loopback",
		},
		{
			name:    "wildcard IPv6",
			input:   "[::]:7447",
			wantErr: "loopback",
		},
		{
			name:    "LAN IPv4 class C",
			input:   "192.168.1.10:7447",
			wantErr: "loopback",
		},
		{
			name:    "LAN IPv4 class A",
			input:   "10.0.0.1:7447",
			wantErr: "loopback",
		},
		{
			name:    "public IPv4",
			input:   "8.8.8.8:7447",
			wantErr: "loopback",
		},
		{
			name:    "hostname domain",
			input:   "example.com:7447",
			wantErr: "literal IP",
		},
		{
			name:    "localhost hostname",
			input:   "localhost:7447",
			wantErr: "literal IP",
		},
		{
			name:    "missing port",
			input:   "127.0.0.1",
			wantErr: "host:port",
		},
		{
			name:    "port 0",
			input:   "127.0.0.1:0",
			wantErr: "between 1 and 65535",
		},
		{
			name:    "port above 65535",
			input:   "127.0.0.1:65536",
			wantErr: "between 1 and 65535",
		},
		{
			name:    "non-numeric port",
			input:   "127.0.0.1:invalid",
			wantErr: "between 1 and 65535",
		},
		{
			name:    "missing host",
			input:   ":7447",
			wantErr: "literal IP",
		},
		{
			name:    "malformed IPv6",
			input:   "[::1:7447",
			wantErr: "host:port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("STACKPILOT_LISTEN_ADDRESS", tt.input)

			_, err := LoadConfig()
			if err == nil {
				t.Fatalf("LoadConfig() with input %q expected error, got nil", tt.input)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain expected substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestLoadConfig_LogLevelValid(t *testing.T) {
	unsetEnv(t, "STACKPILOT_LISTEN_ADDRESS")

	tests := []struct {
		name      string
		input     string
		wantLevel slog.Level
	}{
		{name: "debug lowercase", input: "debug", wantLevel: slog.LevelDebug},
		{name: "debug uppercase", input: "DEBUG", wantLevel: slog.LevelDebug},
		{name: "info lowercase", input: "info", wantLevel: slog.LevelInfo},
		{name: "info uppercase", input: "INFO", wantLevel: slog.LevelInfo},
		{name: "warn lowercase", input: "warn", wantLevel: slog.LevelWarn},
		{name: "warn uppercase", input: "WARN", wantLevel: slog.LevelWarn},
		{name: "error lowercase", input: "error", wantLevel: slog.LevelError},
		{name: "error uppercase", input: "ERROR", wantLevel: slog.LevelError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("STACKPILOT_LOG_LEVEL", tt.input)

			cfg, err := LoadConfig()
			if err != nil {
				t.Fatalf("LoadConfig() returned unexpected error: %v", err)
			}
			if cfg.LogLevel != tt.wantLevel {
				t.Errorf("LogLevel = %v, want %v", cfg.LogLevel, tt.wantLevel)
			}
		})
	}
}

func TestLoadConfig_LogLevelInvalid(t *testing.T) {
	unsetEnv(t, "STACKPILOT_LISTEN_ADDRESS")

	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{name: "empty string", input: "", wantErr: "cannot be empty"},
		{name: "verbose unsupported", input: "verbose", wantErr: "unsupported value"},
		{name: "unknown value", input: "unknown", wantErr: "unsupported value"},
		{name: "trace unsupported", input: "trace", wantErr: "unsupported value"},
		{name: "numeric value", input: "1", wantErr: "unsupported value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("STACKPILOT_LOG_LEVEL", tt.input)

			_, err := LoadConfig()
			if err == nil {
				t.Fatalf("LoadConfig() with input %q expected error, got nil", tt.input)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain expected substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}
