package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"stackpilot/internal/protocol"
)

func TestReadBoundedFile_Oversized(t *testing.T) {
	tempDir := t.TempDir()

	t.Run("oversized_os_release", func(t *testing.T) {
		path := filepath.Join(tempDir, "os-release-large")
		largeData := strings.Repeat("A", maxOSReleaseBytes+2)
		if err := os.WriteFile(path, []byte(largeData), 0644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		_, err := readBoundedFile(path, maxOSReleaseBytes)
		if err == nil {
			t.Fatal("expected error for oversized os-release, got nil")
		}
		if !strings.Contains(err.Error(), "exceeds maximum allowed size") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	t.Run("oversized_kernel_release", func(t *testing.T) {
		path := filepath.Join(tempDir, "osrelease-large")
		largeData := strings.Repeat("K", maxKernelReleaseBytes+2)
		if err := os.WriteFile(path, []byte(largeData), 0644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		_, err := readKernelRelease(path)
		if err == nil {
			t.Fatal("expected error for oversized kernel release, got nil")
		}
		if !strings.Contains(err.Error(), "exceeds maximum allowed size") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	t.Run("oversized_meminfo", func(t *testing.T) {
		path := filepath.Join(tempDir, "meminfo-large")
		largeData := strings.Repeat("M", maxMeminfoBytes+2)
		if err := os.WriteFile(path, []byte(largeData), 0644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		_, err := readMeminfoTotal(path)
		if err == nil {
			t.Fatal("expected error for oversized meminfo, got nil")
		}
		if !strings.Contains(err.Error(), "exceeds maximum allowed size") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})
}

func TestParseOSReleaseValue(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		expected  string
		expectErr bool
	}{
		{"unquoted_simple", "ubuntu", "ubuntu", false},
		{"unquoted_with_comment", "ubuntu # distro", "ubuntu", false},
		{"double_quoted_simple", `"Ubuntu"`, "Ubuntu", false},
		{"double_quoted_escaped_quotes", `"Example \"Linux\""`, `Example "Linux"`, false},
		{"double_quoted_escaped_backslash", `"Example \\ Backslash"`, `Example \ Backslash`, false},
		{"single_quoted_simple", `'Arch Linux'`, "Arch Linux", false},
		{"single_quoted_with_double_quotes", `'Example "Linux"'`, `Example "Linux"`, false},
		{"unclosed_double_quote", `"Ubuntu`, "", true},
		{"unclosed_single_quote", `'Ubuntu`, "", true},
		{"trailing_chars_after_quote", `"Ubuntu" extra`, "", true},
		{"empty_value", "", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			val, err := parseOSReleaseValue(tc.input)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error for input %q, got nil (result: %q)", tc.input, val)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error for input %q: %v", tc.input, err)
				}
				if val != tc.expected {
					t.Fatalf("input %q: expected %q, got %q", tc.input, tc.expected, val)
				}
			}
		})
	}
}

func TestParseOSRelease(t *testing.T) {
	t.Run("valid_standard_ubuntu", func(t *testing.T) {
		input := `
NAME="Ubuntu"
VERSION="24.04 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 24.04 LTS"
VERSION_ID="24.04"
HOME_URL="https://www.ubuntu.com/"
`
		osID, osName, osVersion, err := parseOSRelease(strings.NewReader(input))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if osID != "ubuntu" {
			t.Errorf("expected osID=ubuntu, got %q", osID)
		}
		if osName != "Ubuntu" {
			t.Errorf("expected osName=Ubuntu, got %q", osName)
		}
		if osVersion != "24.04" {
			t.Errorf("expected osVersion=24.04, got %q", osVersion)
		}
	})

	t.Run("fallback_to_version_if_no_version_id", func(t *testing.T) {
		input := `
# Comment line
NAME='Arch Linux'
ID=arch
VERSION=rolling
`
		osID, osName, osVersion, err := parseOSRelease(strings.NewReader(input))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if osID != "arch" {
			t.Errorf("expected osID=arch, got %q", osID)
		}
		if osName != "Arch Linux" {
			t.Errorf("expected osName='Arch Linux', got %q", osName)
		}
		if osVersion != "rolling" {
			t.Errorf("expected osVersion=rolling, got %q", osVersion)
		}
	})

	t.Run("escaped_quotes_in_name", func(t *testing.T) {
		input := `
NAME="Custom \"Super\" Linux"
ID=custom
VERSION_ID="1.0"
`
		osID, osName, osVersion, err := parseOSRelease(strings.NewReader(input))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if osName != `Custom "Super" Linux` {
			t.Errorf("expected unescaped name, got %q", osName)
		}
		if osID != "custom" || osVersion != "1.0" {
			t.Errorf("unexpected id/version: %q / %q", osID, osVersion)
		}
	})

	t.Run("empty_version_allowed", func(t *testing.T) {
		input := `
NAME=MinimalLinux
ID=minimal
`
		osID, osName, osVersion, err := parseOSRelease(strings.NewReader(input))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if osID != "minimal" {
			t.Errorf("expected osID=minimal, got %q", osID)
		}
		if osName != "MinimalLinux" {
			t.Errorf("expected osName=MinimalLinux, got %q", osName)
		}
		if osVersion != "" {
			t.Errorf("expected empty osVersion, got %q", osVersion)
		}
	})

	t.Run("missing_id_fails", func(t *testing.T) {
		input := `NAME=TestLinux`
		_, _, _, err := parseOSRelease(strings.NewReader(input))
		if err == nil {
			t.Fatal("expected error for missing ID, got nil")
		}
	})

	t.Run("missing_name_fails", func(t *testing.T) {
		input := `ID=debian`
		_, _, _, err := parseOSRelease(strings.NewReader(input))
		if err == nil {
			t.Fatal("expected error for missing NAME, got nil")
		}
	})

	t.Run("malformed_quote_fails", func(t *testing.T) {
		input := "NAME=\"Unclosed\nID=test\n"
		_, _, _, err := parseOSRelease(strings.NewReader(input))
		if err == nil {
			t.Fatal("expected error for malformed quote, got nil")
		}
	})
}

func TestParseMeminfoTotal(t *testing.T) {
	t.Run("valid_memtotal", func(t *testing.T) {
		input := []byte("MemTotal:       16384216 kB\nMemFree:         4123456 kB\n")
		total, err := parseMeminfoTotal(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := int64(16384216) * 1024
		if total != expected {
			t.Fatalf("expected %d bytes, got %d", expected, total)
		}
	})

	t.Run("missing_memtotal", func(t *testing.T) {
		input := []byte("MemFree:         4123456 kB\n")
		_, err := parseMeminfoTotal(input)
		if err == nil {
			t.Fatal("expected error for missing MemTotal, got nil")
		}
	})

	t.Run("malformed_integer", func(t *testing.T) {
		input := []byte("MemTotal:       abc kB\n")
		_, err := parseMeminfoTotal(input)
		if err == nil {
			t.Fatal("expected error for malformed integer, got nil")
		}
	})

	t.Run("zero_value", func(t *testing.T) {
		input := []byte("MemTotal:       0 kB\n")
		_, err := parseMeminfoTotal(input)
		if err == nil {
			t.Fatal("expected error for zero MemTotal, got nil")
		}
	})

	t.Run("negative_value", func(t *testing.T) {
		input := []byte("MemTotal:       -100 kB\n")
		_, err := parseMeminfoTotal(input)
		if err == nil {
			t.Fatal("expected error for negative MemTotal, got nil")
		}
	})

	t.Run("wrong_unit_MB", func(t *testing.T) {
		input := []byte("MemTotal:       1024 MB\n")
		_, err := parseMeminfoTotal(input)
		if err == nil {
			t.Fatal("expected error for wrong unit MB, got nil")
		}
	})

	t.Run("wrong_unit_case", func(t *testing.T) {
		input := []byte("MemTotal:       1024 kb\n")
		_, err := parseMeminfoTotal(input)
		if err == nil {
			t.Fatal("expected error for wrong unit kb, got nil")
		}
	})

	t.Run("overflow_value", func(t *testing.T) {
		input := []byte(fmt.Sprintf("MemTotal:       %d kB\n", math.MaxInt64))
		_, err := parseMeminfoTotal(input)
		if err == nil {
			t.Fatal("expected error for overflow MemTotal, got nil")
		}
	})
}

func TestOSReleasePath_Fallback(t *testing.T) {
	tempDir := t.TempDir()

	nonExistentPath := filepath.Join(tempDir, "no-such-os-release")
	validFallbackPath := filepath.Join(tempDir, "fallback-os-release")

	fallbackContent := "NAME=FallbackLinux\nID=fallback\nVERSION_ID=1.0\n"
	if err := os.WriteFile(validFallbackPath, []byte(fallbackContent), 0644); err != nil {
		t.Fatalf("failed to write fallback: %v", err)
	}

	kernelReleasePath := filepath.Join(tempDir, "osrelease")
	_ = os.WriteFile(kernelReleasePath, []byte("6.8.0-40-generic\n"), 0644)

	meminfoPath := filepath.Join(tempDir, "meminfo")
	_ = os.WriteFile(meminfoPath, []byte("MemTotal:       8388608 kB\n"), 0644)

	cfg := inventoryCollectorConfig{
		osReleasePaths:    []string{nonExistentPath, validFallbackPath},
		kernelReleasePath: kernelReleasePath,
		meminfoPath:       meminfoPath,
		hostnameFunc:      func() (string, error) { return "node-01", nil },
		numCPUFunc:        func() int { return 4 },
		arch:              "amd64",
	}

	req, err := collectInventoryWithConfig(cfg)
	if err != nil {
		t.Fatalf("expected fallback to succeed, got: %v", err)
	}
	if req.OSID != "fallback" || req.OSName != "FallbackLinux" {
		t.Fatalf("unexpected inventory from fallback: %+v", req)
	}
}

func TestCollectInventory_ValidationFailure(t *testing.T) {
	tempDir := t.TempDir()

	osReleasePath := filepath.Join(tempDir, "os-release")
	_ = os.WriteFile(osReleasePath, []byte("NAME=Ubuntu\nID=ubuntu\nVERSION_ID=24.04\n"), 0644)

	kernelReleasePath := filepath.Join(tempDir, "osrelease")
	_ = os.WriteFile(kernelReleasePath, []byte("6.8.0-generic\n"), 0644)

	meminfoPath := filepath.Join(tempDir, "meminfo")
	_ = os.WriteFile(meminfoPath, []byte("MemTotal:       8388608 kB\n"), 0644)

	baseCfg := func() inventoryCollectorConfig {
		return inventoryCollectorConfig{
			osReleasePaths:    []string{osReleasePath},
			kernelReleasePath: kernelReleasePath,
			meminfoPath:       meminfoPath,
			hostnameFunc:      func() (string, error) { return "valid-host", nil },
			numCPUFunc:        func() int { return 4 },
			arch:              "amd64",
		}
	}

	t.Run("hostname_error", func(t *testing.T) {
		cfg := baseCfg()
		cfg.hostnameFunc = func() (string, error) { return "", errors.New("cannot determine hostname") }
		_, err := collectInventoryWithConfig(cfg)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("empty_hostname", func(t *testing.T) {
		cfg := baseCfg()
		cfg.hostnameFunc = func() (string, error) { return "   ", nil }
		_, err := collectInventoryWithConfig(cfg)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if strings.Contains(err.Error(), "%!w") {
			t.Fatalf("error contains formatting artifact %%!w: %v", err)
		}
		if !strings.Contains(err.Error(), "hostname is empty") {
			t.Fatalf("expected 'hostname is empty', got %v", err)
		}
	})

	t.Run("overlong_hostname", func(t *testing.T) {
		cfg := baseCfg()
		cfg.hostnameFunc = func() (string, error) { return strings.Repeat("h", 256), nil }
		_, err := collectInventoryWithConfig(cfg)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("hostname_control_character", func(t *testing.T) {
		cfg := baseCfg()
		cfg.hostnameFunc = func() (string, error) { return "host\nname", nil }
		_, err := collectInventoryWithConfig(cfg)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("cpu_zero", func(t *testing.T) {
		cfg := baseCfg()
		cfg.numCPUFunc = func() int { return 0 }
		_, err := collectInventoryWithConfig(cfg)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("cpu_negative", func(t *testing.T) {
		cfg := baseCfg()
		cfg.numCPUFunc = func() int { return -1 }
		_, err := collectInventoryWithConfig(cfg)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("cpu_excessive", func(t *testing.T) {
		cfg := baseCfg()
		cfg.numCPUFunc = func() int { return 1048577 }
		_, err := collectInventoryWithConfig(cfg)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("architecture_empty", func(t *testing.T) {
		cfg := baseCfg()
		cfg.arch = "   "
		_, err := collectInventoryWithConfig(cfg)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("architecture_oversized", func(t *testing.T) {
		cfg := baseCfg()
		cfg.arch = strings.Repeat("a", 33)
		_, err := collectInventoryWithConfig(cfg)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func setupTestAgentHTTPS(t *testing.T, handler http.Handler) (string, *httptest.Server) {
	t.Helper()
	_, caPEM, ts := setupTestCAAndServer(t, handler)
	stateDir, _, _ := setupTestEnrolledState(t, ts.URL)
	caFile := filepath.Join(stateDir, "custom-ca.pem")
	_ = os.WriteFile(caFile, caPEM, 0644)
	if err := ValidateAndPersistCAFile(stateDir, caFile); err != nil {
		t.Fatalf("ValidateAndPersistCAFile failed: %v", err)
	}
	return stateDir, ts
}

func TestPresenceLoop_InventoryLifecycle(t *testing.T) {
	t.Run("first_heartbeat_triggers_immediate_inventory_and_shares_client", func(t *testing.T) {
		var (
			heartbeatCount atomic.Int32
			inventoryCount atomic.Int32
		)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case protocol.HeartbeatEndpointPath:
				heartbeatCount.Add(1)
				w.WriteHeader(http.StatusNoContent)
			case protocol.InventoryEndpointPath:
				inventoryCount.Add(1)
				w.WriteHeader(http.StatusNoContent)
			default:
				http.NotFound(w, r)
			}
		})

		stateDir, ts := setupTestAgentHTTPS(t, handler)
		defer ts.Close()

		now := time.Now()
		ctx, cancel := context.WithCancel(context.Background())

		cycle := 0
		timerCh := make(chan time.Time, 1)

		mockCollector := func() (*protocol.InventoryRequest, error) {
			return &protocol.InventoryRequest{
				ProtocolVersion:  protocol.CurrentVersion,
				Hostname:         "mock-host",
				OSID:             "ubuntu",
				OSName:           "Ubuntu",
				OSVersion:        "24.04",
				KernelRelease:    "6.8.0",
				Architecture:     "amd64",
				CPULogicalCores:  4,
				MemoryTotalBytes: 8192000,
			}, nil
		}

		cfg := presenceConfig{
			nowFunc: func() time.Time {
				return now.Add(time.Duration(cycle) * 30 * time.Second)
			},
			timerFunc: func(d time.Duration) (<-chan time.Time, func() bool) {
				cycle++
				if cycle >= 3 {
					cancel()
				} else {
					timerCh <- now.Add(time.Duration(cycle) * 30 * time.Second)
				}
				return timerCh, func() bool { return true }
			},
			jitterFunc: func(base time.Duration, pct float64) time.Duration {
				return base
			},
			randReader:             rand.Reader,
			baseInterval:           30 * time.Second,
			maxBackoff:             30 * time.Second,
			inventoryInterval:      1 * time.Hour,
			inventoryRetryInterval: 1 * time.Minute,
			collector:              mockCollector,
		}

		err := runPresenceWithConfig(ctx, nil, stateDir, cfg)
		if err != nil {
			t.Fatalf("runPresenceWithConfig failed: %v", err)
		}

		if hb := heartbeatCount.Load(); hb != 3 {
			t.Fatalf("expected 3 heartbeats, got %d", hb)
		}
		if inv := inventoryCount.Load(); inv != 1 {
			t.Fatalf("expected exactly 1 inventory call, got %d", inv)
		}
	})

	t.Run("heartbeat_failure_prevents_inventory", func(t *testing.T) {
		var (
			heartbeatCount atomic.Int32
			inventoryCount atomic.Int32
		)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case protocol.HeartbeatEndpointPath:
				heartbeatCount.Add(1)
				w.WriteHeader(http.StatusServiceUnavailable)
			case protocol.InventoryEndpointPath:
				inventoryCount.Add(1)
				w.WriteHeader(http.StatusNoContent)
			default:
				http.NotFound(w, r)
			}
		})

		stateDir, ts := setupTestAgentHTTPS(t, handler)
		defer ts.Close()

		ctx, cancel := context.WithCancel(context.Background())
		timerCh := make(chan time.Time, 1)

		cfg := presenceConfig{
			nowFunc: time.Now,
			timerFunc: func(d time.Duration) (<-chan time.Time, func() bool) {
				cancel()
				return timerCh, func() bool { return true }
			},
			jitterFunc:             func(base time.Duration, pct float64) time.Duration { return base },
			randReader:             rand.Reader,
			baseInterval:           30 * time.Second,
			maxBackoff:             30 * time.Second,
			inventoryInterval:      1 * time.Hour,
			inventoryRetryInterval: 1 * time.Minute,
		}

		_ = runPresenceWithConfig(ctx, nil, stateDir, cfg)

		if hb := heartbeatCount.Load(); hb == 0 {
			t.Fatal("expected at least 1 heartbeat attempt")
		}
		if inv := inventoryCount.Load(); inv != 0 {
			t.Fatalf("inventory must NOT run after failed heartbeat; got %d calls", inv)
		}
	})

	t.Run("transient_inventory_failure_does_not_stop_agent_and_retries", func(t *testing.T) {
		var (
			heartbeatCount atomic.Int32
			inventoryCount atomic.Int32
		)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case protocol.HeartbeatEndpointPath:
				heartbeatCount.Add(1)
				w.WriteHeader(http.StatusNoContent)
			case protocol.InventoryEndpointPath:
				count := inventoryCount.Add(1)
				if count == 1 {
					w.WriteHeader(http.StatusInternalServerError)
				} else {
					w.WriteHeader(http.StatusNoContent)
				}
			default:
				http.NotFound(w, r)
			}
		})

		stateDir, ts := setupTestAgentHTTPS(t, handler)
		defer ts.Close()

		ctx, cancel := context.WithCancel(context.Background())
		now := time.Now()
		cycle := 0
		timerCh := make(chan time.Time, 1)

		mockCollector := func() (*protocol.InventoryRequest, error) {
			return &protocol.InventoryRequest{
				ProtocolVersion:  1,
				Hostname:         "mock-host",
				OSID:             "ubuntu",
				OSName:           "Ubuntu",
				OSVersion:        "24.04",
				KernelRelease:    "6.8.0",
				Architecture:     "amd64",
				CPULogicalCores:  4,
				MemoryTotalBytes: 8192000,
			}, nil
		}

		cfg := presenceConfig{
			nowFunc: func() time.Time {
				return now.Add(time.Duration(cycle) * 30 * time.Second)
			},
			timerFunc: func(d time.Duration) (<-chan time.Time, func() bool) {
				cycle++
				if cycle >= 4 {
					cancel()
				} else {
					timerCh <- now.Add(time.Duration(cycle) * 30 * time.Second)
				}
				return timerCh, func() bool { return true }
			},
			jitterFunc:             func(base time.Duration, pct float64) time.Duration { return base },
			randReader:             rand.Reader,
			baseInterval:           30 * time.Second,
			maxBackoff:             30 * time.Second,
			inventoryInterval:      1 * time.Hour,
			inventoryRetryInterval: 1 * time.Minute,
			collector:              mockCollector,
		}

		err := runPresenceWithConfig(ctx, nil, stateDir, cfg)
		if err != nil {
			t.Fatalf("unexpected daemon error on transient inventory failure: %v", err)
		}

		if inv := inventoryCount.Load(); inv != 2 {
			t.Fatalf("expected 2 inventory attempts (1 failure + 1 retry success), got %d", inv)
		}
	})

	t.Run("permanent_inventory_failure_terminates_agent", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case protocol.HeartbeatEndpointPath:
				w.WriteHeader(http.StatusNoContent)
			case protocol.InventoryEndpointPath:
				w.WriteHeader(http.StatusUnauthorized)
			default:
				http.NotFound(w, r)
			}
		})

		stateDir, ts := setupTestAgentHTTPS(t, handler)
		defer ts.Close()

		cfg := presenceConfig{
			nowFunc:                time.Now,
			timerFunc:              realTimer,
			jitterFunc:             func(base time.Duration, pct float64) time.Duration { return base },
			randReader:             rand.Reader,
			baseInterval:           30 * time.Second,
			maxBackoff:             30 * time.Second,
			inventoryInterval:      1 * time.Hour,
			inventoryRetryInterval: 1 * time.Minute,
			collector: func() (*protocol.InventoryRequest, error) {
				return &protocol.InventoryRequest{
					ProtocolVersion:  1,
					Hostname:         "mock-host",
					OSID:             "ubuntu",
					OSName:           "Ubuntu",
					OSVersion:        "24.04",
					KernelRelease:    "6.8.0",
					Architecture:     "amd64",
					CPULogicalCores:  4,
					MemoryTotalBytes: 8192000,
				}, nil
			},
		}

		err := runPresenceWithConfig(context.Background(), nil, stateDir, cfg)
		if err == nil {
			t.Fatal("expected error on permanent inventory failure, got nil")
		}
		if !errors.Is(err, ErrAuthRejected) && !IsPermanentError(err) {
			t.Fatalf("expected ErrAuthRejected / permanent error, got: %v", err)
		}
	})
}

func TestPresenceLoop_NormalInventoryRefresh_Recollection(t *testing.T) {
	var (
		inventoryCount atomic.Int32
		receivedBodies []string
		mu             sync.Mutex
	)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case protocol.HeartbeatEndpointPath:
			w.WriteHeader(http.StatusNoContent)
		case protocol.InventoryEndpointPath:
			inventoryCount.Add(1)
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			receivedBodies = append(receivedBodies, string(body))
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	})

	stateDir, ts := setupTestAgentHTTPS(t, handler)
	defer ts.Close()

	now := time.Now()
	ctx, cancel := context.WithCancel(context.Background())

	var currentTime time.Time = now
	cycle := 0
	collectorInvocations := 0
	timerCh := make(chan time.Time, 1)

	mockCollector := func() (*protocol.InventoryRequest, error) {
		collectorInvocations++
		hostname := fmt.Sprintf("host-version-%d", collectorInvocations)
		return &protocol.InventoryRequest{
			ProtocolVersion:  protocol.CurrentVersion,
			Hostname:         hostname,
			OSID:             "ubuntu",
			OSName:           "Ubuntu",
			OSVersion:        "24.04",
			KernelRelease:    "6.8.0",
			Architecture:     "amd64",
			CPULogicalCores:  4,
			MemoryTotalBytes: 8192000,
		}, nil
	}

	cfg := presenceConfig{
		nowFunc: func() time.Time {
			return currentTime
		},
		timerFunc: func(d time.Duration) (<-chan time.Time, func() bool) {
			cycle++
			switch cycle {
			case 1:
				// Advance time by 30 seconds (inventory not due yet, next due at now+1h)
				currentTime = now.Add(30 * time.Second)
				timerCh <- currentTime
			case 2:
				// Advance time by 30 minutes (still not due)
				currentTime = now.Add(30 * time.Minute)
				timerCh <- currentTime
			case 3:
				// Advance time to 1 hour + 1 second (inventory is now due!)
				currentTime = now.Add(1*time.Hour + time.Second)
				timerCh <- currentTime
			default:
				cancel()
			}
			return timerCh, func() bool { return true }
		},
		jitterFunc: func(base time.Duration, pct float64) time.Duration {
			return base // no jitter for deterministic check
		},
		randReader:             rand.Reader,
		baseInterval:           30 * time.Second,
		maxBackoff:             30 * time.Second,
		inventoryInterval:      1 * time.Hour,
		inventoryRetryInterval: 1 * time.Minute,
		collector:              mockCollector,
	}

	err := runPresenceWithConfig(ctx, nil, stateDir, cfg)
	if err != nil {
		t.Fatalf("runPresenceWithConfig failed: %v", err)
	}

	if collectorInvocations != 2 {
		t.Fatalf("expected collector invocation count == 2, got %d", collectorInvocations)
	}
	if inv := inventoryCount.Load(); inv != 2 {
		t.Fatalf("expected inventory PUT count == 2, got %d", inv)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(receivedBodies) != 2 {
		t.Fatalf("expected 2 received bodies, got %d", len(receivedBodies))
	}
	if !strings.Contains(receivedBodies[0], "host-version-1") {
		t.Errorf("expected body 1 to contain host-version-1, got: %s", receivedBodies[0])
	}
	if !strings.Contains(receivedBodies[1], "host-version-2") {
		t.Errorf("expected body 2 to contain host-version-2, got: %s", receivedBodies[1])
	}
}

func TestPresenceLoop_InventoryJitter(t *testing.T) {
	var scheduledInterval time.Duration
	var mu sync.Mutex

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	stateDir, ts := setupTestAgentHTTPS(t, handler)
	defer ts.Close()

	now := time.Now()
	ctx, cancel := context.WithCancel(context.Background())

	mockJitter := func(base time.Duration, pct float64) time.Duration {
		if base == 1*time.Hour {
			mu.Lock()
			scheduledInterval = time.Duration(float64(base) * (1.0 + pct))
			mu.Unlock()
			return scheduledInterval
		}
		return base
	}

	timerCh := make(chan time.Time, 1)

	cfg := presenceConfig{
		nowFunc: func() time.Time {
			return now
		},
		timerFunc: func(d time.Duration) (<-chan time.Time, func() bool) {
			cancel()
			return timerCh, func() bool { return true }
		},
		jitterFunc:             mockJitter,
		randReader:             rand.Reader,
		baseInterval:           30 * time.Second,
		maxBackoff:             30 * time.Second,
		inventoryInterval:      1 * time.Hour,
		inventoryRetryInterval: 1 * time.Minute,
		collector: func() (*protocol.InventoryRequest, error) {
			return &protocol.InventoryRequest{
				ProtocolVersion:  1,
				Hostname:         "host-01",
				OSID:             "ubuntu",
				OSName:           "Ubuntu",
				OSVersion:        "24.04",
				KernelRelease:    "6.8.0",
				Architecture:     "amd64",
				CPULogicalCores:  4,
				MemoryTotalBytes: 8192000,
			}, nil
		},
	}

	_ = runPresenceWithConfig(ctx, nil, stateDir, cfg)

	mu.Lock()
	defer mu.Unlock()
	expected := 66 * time.Minute // 1 hour + 10%
	if scheduledInterval != expected {
		t.Fatalf("expected jittered interval %v, got %v", expected, scheduledInterval)
	}
}

func TestPresenceLoop_LocalCollectionFailureLogging_Recovery(t *testing.T) {
	var (
		logBuffer bytes.Buffer
		mu        sync.Mutex
	)

	logger := slog.New(slog.NewTextHandler(&logBuffer, nil))

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	stateDir, ts := setupTestAgentHTTPS(t, handler)
	defer ts.Close()

	now := time.Now()
	ctx, cancel := context.WithCancel(context.Background())

	cycle := 0
	timerCh := make(chan time.Time, 1)

	mockCollector := func() (*protocol.InventoryRequest, error) {
		mu.Lock()
		c := cycle
		mu.Unlock()
		if c < 2 {
			return nil, errors.New("simulated local collector failure")
		}
		return &protocol.InventoryRequest{
			ProtocolVersion:  1,
			Hostname:         "recovered-host",
			OSID:             "ubuntu",
			OSName:           "Ubuntu",
			OSVersion:        "24.04",
			KernelRelease:    "6.8.0",
			Architecture:     "amd64",
			CPULogicalCores:  4,
			MemoryTotalBytes: 8192000,
		}, nil
	}

	cfg := presenceConfig{
		nowFunc: func() time.Time {
			return now.Add(time.Duration(cycle) * 2 * time.Minute)
		},
		timerFunc: func(d time.Duration) (<-chan time.Time, func() bool) {
			mu.Lock()
			cycle++
			c := cycle
			mu.Unlock()
			if c >= 3 {
				cancel()
			} else {
				timerCh <- now.Add(time.Duration(c) * 2 * time.Minute)
			}
			return timerCh, func() bool { return true }
		},
		jitterFunc:             func(base time.Duration, pct float64) time.Duration { return base },
		randReader:             rand.Reader,
		baseInterval:           30 * time.Second,
		maxBackoff:             30 * time.Second,
		inventoryInterval:      1 * time.Hour,
		inventoryRetryInterval: 1 * time.Minute,
		collector:              mockCollector,
	}

	err := runPresenceWithConfig(ctx, logger, stateDir, cfg)
	if err != nil {
		t.Fatalf("unexpected daemon error: %v", err)
	}

	logs := logBuffer.String()
	warnCount := strings.Count(logs, "agent inventory collection failed; will retry")
	if warnCount != 1 {
		t.Fatalf("expected exactly 1 warning for repeated collection failures, got %d. Logs:\n%s", warnCount, logs)
	}

	recoveryCount := strings.Count(logs, "agent inventory delivery recovered")
	if recoveryCount != 1 {
		t.Fatalf("expected exactly 1 recovery message, got %d. Logs:\n%s", recoveryCount, logs)
	}
}

func TestPresenceLoop_SharedHTTPClient(t *testing.T) {
	var (
		clientPointerHeartbeat string
		clientPointerInventory string
		mu                     sync.Mutex
	)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case protocol.HeartbeatEndpointPath:
			w.WriteHeader(http.StatusNoContent)
		case protocol.InventoryEndpointPath:
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	})

	stateDir, ts := setupTestAgentHTTPS(t, handler)
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	timerCh := make(chan time.Time, 1)

	// Tracking round tripper to capture client instance
	var builtClient *http.Client
	customBuilder := func(rootCAs *x509.CertPool, cert *tls.Certificate) *http.Client {
		c := BuildAgentHTTPClient(rootCAs, cert)
		builtClient = c
		originalTransport := c.Transport
		c.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
			mu.Lock()
			if req.URL.Path == protocol.HeartbeatEndpointPath {
				clientPointerHeartbeat = fmt.Sprintf("%p", c)
			} else if req.URL.Path == protocol.InventoryEndpointPath {
				clientPointerInventory = fmt.Sprintf("%p", c)
			}
			mu.Unlock()
			return originalTransport.RoundTrip(req)
		})
		return c
	}

	cfg := presenceConfig{
		nowFunc: time.Now,
		timerFunc: func(d time.Duration) (<-chan time.Time, func() bool) {
			cancel()
			return timerCh, func() bool { return true }
		},
		jitterFunc:             func(base time.Duration, pct float64) time.Duration { return base },
		randReader:             rand.Reader,
		clientBuilder:          customBuilder,
		baseInterval:           30 * time.Second,
		maxBackoff:             30 * time.Second,
		inventoryInterval:      1 * time.Hour,
		inventoryRetryInterval: 1 * time.Minute,
		collector: func() (*protocol.InventoryRequest, error) {
			return &protocol.InventoryRequest{
				ProtocolVersion:  1,
				Hostname:         "same-client-host",
				OSID:             "ubuntu",
				OSName:           "Ubuntu",
				OSVersion:        "24.04",
				KernelRelease:    "6.8.0",
				Architecture:     "amd64",
				CPULogicalCores:  4,
				MemoryTotalBytes: 8192000,
			}, nil
		},
	}

	err := runPresenceWithConfig(ctx, nil, stateDir, cfg)
	if err != nil {
		t.Fatalf("runPresenceWithConfig failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if clientPointerHeartbeat == "" || clientPointerInventory == "" {
		t.Fatalf("expected both heartbeat and inventory to execute. Got hb=%q, inv=%q", clientPointerHeartbeat, clientPointerInventory)
	}
	if clientPointerHeartbeat != clientPointerInventory {
		t.Fatalf("heartbeat client (%s) and inventory client (%s) differ; must use the SAME client instance", clientPointerHeartbeat, clientPointerInventory)
	}
	if clientPointerHeartbeat != fmt.Sprintf("%p", builtClient) {
		t.Fatalf("expected client pointer to match built client %p, got %s", builtClient, clientPointerHeartbeat)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
