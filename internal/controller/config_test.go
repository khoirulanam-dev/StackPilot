package controller

import (
	"log/slog"
	"os"
	"strings"
	"testing"
)

const testDefaultDatabaseURL = "postgres://stackpilot:secret@127.0.0.1:5432/stackpilot?sslmode=disable"

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

func isolateRemoteAgentEnv(t *testing.T) {
	t.Helper()
	unsetEnv(t, "STACKPILOT_AGENT_LISTEN_ADDRESS")
	unsetEnv(t, "STACKPILOT_AGENT_TLS_CERT_FILE")
	unsetEnv(t, "STACKPILOT_AGENT_TLS_KEY_FILE")
}

func TestLoadConfig_Defaults(t *testing.T) {
	isolateRemoteAgentEnv(t)
	unsetEnv(t, "STACKPILOT_LISTEN_ADDRESS")
	unsetEnv(t, "STACKPILOT_LOG_LEVEL")
	t.Setenv("STACKPILOT_DATABASE_URL", testDefaultDatabaseURL)

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

	if cfg.DatabaseURL != testDefaultDatabaseURL {
		t.Errorf("DatabaseURL = %q, want %q", cfg.DatabaseURL, testDefaultDatabaseURL)
	}
}

func TestLoadConfig_ListenAddressValid(t *testing.T) {
	isolateRemoteAgentEnv(t)
	unsetEnv(t, "STACKPILOT_LOG_LEVEL")
	t.Setenv("STACKPILOT_DATABASE_URL", testDefaultDatabaseURL)

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
	isolateRemoteAgentEnv(t)
	unsetEnv(t, "STACKPILOT_LOG_LEVEL")
	t.Setenv("STACKPILOT_DATABASE_URL", testDefaultDatabaseURL)

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
	isolateRemoteAgentEnv(t)
	unsetEnv(t, "STACKPILOT_LISTEN_ADDRESS")
	t.Setenv("STACKPILOT_DATABASE_URL", testDefaultDatabaseURL)

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
	isolateRemoteAgentEnv(t)
	unsetEnv(t, "STACKPILOT_LISTEN_ADDRESS")
	t.Setenv("STACKPILOT_DATABASE_URL", testDefaultDatabaseURL)

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

func TestLoadConfig_DatabaseURLMissing(t *testing.T) {
	isolateRemoteAgentEnv(t)
	unsetEnv(t, "STACKPILOT_DATABASE_URL")

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("LoadConfig() expected error when STACKPILOT_DATABASE_URL is absent, got nil")
	}
	if !strings.Contains(err.Error(), "missing required STACKPILOT_DATABASE_URL") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestLoadConfig_DatabaseURLEmpty(t *testing.T) {
	isolateRemoteAgentEnv(t)
	t.Setenv("STACKPILOT_DATABASE_URL", "")

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("LoadConfig() expected error when STACKPILOT_DATABASE_URL is empty, got nil")
	}
	if !strings.Contains(err.Error(), "cannot be empty") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestLoadConfig_DatabaseURLValid(t *testing.T) {
	isolateRemoteAgentEnv(t)
	tests := []struct {
		name     string
		input    string
		wantHost string
	}{
		{
			name:  "standard postgres loopback",
			input: "postgres://stackpilot:password@127.0.0.1:5432/stackpilot?sslmode=disable",
		},
		{
			name:  "standard postgresql remote host",
			input: "postgresql://stackpilot:password@db.internal:5432/stackpilot?sslmode=verify-full",
		},
		{
			name:  "no password specified",
			input: "postgres://stackpilot@127.0.0.1:5432/stackpilot",
		},
		{
			name:  "hostname without port",
			input: "postgres://stackpilot:password@db.internal/stackpilot",
		},
		{
			name:  "IPv6 host literal",
			input: "postgresql://user:pass@[::1]:5432/stackpilot",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("STACKPILOT_DATABASE_URL", tt.input)

			cfg, err := LoadConfig()
			if err != nil {
				t.Fatalf("LoadConfig() returned unexpected error: %v", err)
			}
			if cfg.DatabaseURL != tt.input {
				t.Errorf("DatabaseURL = %q, want %q", cfg.DatabaseURL, tt.input)
			}
		})
	}
}

func TestLoadConfig_DatabaseURLInvalid(t *testing.T) {
	isolateRemoteAgentEnv(t)
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name:    "unsupported scheme http",
			input:   "http://localhost:5432/stackpilot",
			wantErr: "scheme must be postgres or postgresql",
		},
		{
			name:    "unsupported scheme mysql",
			input:   "mysql://user:pass@localhost:5432/stackpilot",
			wantErr: "scheme must be postgres or postgresql",
		},
		{
			name:    "missing scheme",
			input:   "localhost:5432/stackpilot",
			wantErr: "scheme must be postgres or postgresql",
		},
		{
			name:    "missing host",
			input:   "postgres:///stackpilot",
			wantErr: "host cannot be empty",
		},
		{
			name:    "missing host with user",
			input:   "postgres://user:pass@/stackpilot",
			wantErr: "host cannot be empty",
		},
		{
			name:    "missing database name with trailing slash",
			input:   "postgres://user:pass@localhost:5432/",
			wantErr: "database name cannot be empty",
		},
		{
			name:    "missing database name without trailing slash",
			input:   "postgres://user:pass@localhost:5432",
			wantErr: "database name cannot be empty",
		},
		{
			name:    "malformed url with control chars",
			input:   "postgres://localhost:5432/\x7f",
			wantErr: "invalid PostgreSQL connection URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("STACKPILOT_DATABASE_URL", tt.input)

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

func TestLoadConfig_DatabaseURLSecretRedaction(t *testing.T) {
	isolateRemoteAgentEnv(t)
	const secret = "stackpilot-super-secret-test-value"

	invalidURLs := []string{
		"postgres://admin:" + secret + "@/invalid",
		"http://admin:" + secret + "@localhost:5432/stackpilot",
		"postgres://admin:" + secret + "@localhost:5432/",
		"postgres://admin:" + secret + "@localhost:5432/\x7f",
	}

	for _, rawURL := range invalidURLs {
		t.Setenv("STACKPILOT_DATABASE_URL", rawURL)

		_, err := LoadConfig()
		if err == nil {
			t.Fatalf("expected error for invalid URL %q, got nil", rawURL)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error message leaked secret: %s", err.Error())
		}
	}

	// Verify LogValue redaction on Config
	validURL := "postgres://admin:" + secret + "@127.0.0.1:5432/stackpilot"
	t.Setenv("STACKPILOT_DATABASE_URL", validURL)
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("unexpected error loading config: %v", err)
	}

	logVal := cfg.LogValue()
	if strings.Contains(logVal.String(), secret) {
		t.Fatalf("LogValue leaked secret: %s", logVal.String())
	}
}

func TestLoadConfig_AgentRemoteListener(t *testing.T) {
	isolateRemoteAgentEnv(t)
	t.Setenv("STACKPILOT_DATABASE_URL", testDefaultDatabaseURL)

	// 1. Omitted: remote disabled
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RemoteEnabled() {
		t.Errorf("expected RemoteEnabled() to be false when agent listen address is omitted")
	}

	// 2. Configured without cert: validation failure
	t.Setenv("STACKPILOT_AGENT_LISTEN_ADDRESS", "0.0.0.0:7448")
	_, err = LoadConfig()
	if err == nil {
		t.Fatal("expected error when agent listen address is configured without cert/key")
	}

	// 3. Configured with cert but without key: validation failure
	t.Setenv("STACKPILOT_AGENT_TLS_CERT_FILE", "/path/to/cert.pem")
	_, err = LoadConfig()
	if err == nil {
		t.Fatal("expected error when agent listen address is configured without key")
	}

	// 4. Configured with cert and key: valid
	t.Setenv("STACKPILOT_AGENT_TLS_KEY_FILE", "/path/to/key.pem")
	cfg, err = LoadConfig()
	if err != nil {
		t.Fatalf("unexpected error with cert and key configured: %v", err)
	}
	if !cfg.RemoteEnabled() {
		t.Errorf("expected RemoteEnabled() to be true")
	}
	if cfg.AgentListenAddress != "0.0.0.0:7448" {
		t.Errorf("expected agent listen address 0.0.0.0:7448, got %q", cfg.AgentListenAddress)
	}

	// 5. Check LogValue
	logStr := cfg.LogValue().String()
	if !strings.Contains(logStr, "agent_listen_address=0.0.0.0:7448") {
		t.Errorf("LogValue missing agent_listen_address: %s", logStr)
	}
	if !strings.Contains(logStr, "agent_tls_enabled=true") {
		t.Errorf("LogValue missing agent_tls_enabled=true: %s", logStr)
	}
	if strings.Contains(logStr, "/path/to/key.pem") {
		t.Errorf("LogValue should not leak TLS key file path: %s", logStr)
	}

	// 6. Valid remote addresses: 0.0.0.0, LAN IP, loopback, IPv6 wildcard
	validAddrs := []string{
		"0.0.0.0:7448",
		"10.0.0.10:7448",
		"192.168.1.50:8443",
		"127.0.0.1:7448",
		"[::]:7448",
		"[::1]:7448",
	}
	for _, addr := range validAddrs {
		t.Setenv("STACKPILOT_AGENT_LISTEN_ADDRESS", addr)
		cfg, err := LoadConfig()
		if err != nil {
			t.Errorf("valid agent address %q failed: %v", addr, err)
		}
		if cfg.AgentListenAddress != addr {
			t.Errorf("expected %q, got %q", addr, cfg.AgentListenAddress)
		}
	}

	// 7. Invalid remote addresses: DNS hostname, invalid port, missing port
	invalidAddrs := []string{
		"example.com:7448",
		"0.0.0.0:0",
		"0.0.0.0:70000",
		"0.0.0.0",
		":7448",
	}
	for _, addr := range invalidAddrs {
		t.Setenv("STACKPILOT_AGENT_LISTEN_ADDRESS", addr)
		_, err := LoadConfig()
		if err == nil {
			t.Errorf("expected error for invalid agent address %q, got nil", addr)
		}
	}

	// 8. Regression: Local listen address STILL rejects 0.0.0.0:7447
	t.Setenv("STACKPILOT_LISTEN_ADDRESS", "0.0.0.0:7447")
	unsetEnv(t, "STACKPILOT_AGENT_LISTEN_ADDRESS")
	_, err = LoadConfig()
	if err == nil {
		t.Fatal("expected local listener to reject 0.0.0.0:7447, got nil")
	}
}
