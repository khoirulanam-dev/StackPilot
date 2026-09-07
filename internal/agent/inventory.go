package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"stackpilot/internal/protocol"
)

const (
	DefaultInventoryInterval      = 1 * time.Hour
	DefaultInventoryRetryInterval = 1 * time.Minute
	maxOSReleaseBytes             = 64 * 1024  // 64 KiB
	maxKernelReleaseBytes         = 4 * 1024   // 4 KiB
	maxMeminfoBytes               = 128 * 1024 // 128 KiB
)

type inventoryCollectorConfig struct {
	osReleasePaths    []string
	kernelReleasePath string
	meminfoPath       string
	hostnameFunc      func() (string, error)
	numCPUFunc        func() int
	arch              string
}

func defaultCollectorConfig() inventoryCollectorConfig {
	return inventoryCollectorConfig{
		osReleasePaths:    []string{"/etc/os-release", "/usr/lib/os-release"},
		kernelReleasePath: "/proc/sys/kernel/osrelease",
		meminfoPath:       "/proc/meminfo",
		hostnameFunc:      os.Hostname,
		numCPUFunc:        runtime.NumCPU,
		arch:              runtime.GOARCH,
	}
}

func collectLinuxInventory() (*protocol.InventoryRequest, error) {
	return collectInventoryWithConfig(defaultCollectorConfig())
}

func collectInventoryWithConfig(cfg inventoryCollectorConfig) (*protocol.InventoryRequest, error) {
	hostname, err := cfg.hostnameFunc()
	if err != nil {
		return nil, fmt.Errorf("failed to collect hostname: %w", err)
	}
	if strings.TrimSpace(hostname) == "" {
		return nil, errors.New("hostname is empty")
	}
	hostname = strings.TrimSpace(hostname)

	osID, osName, osVersion, err := readOSRelease(cfg.osReleasePaths)
	if err != nil {
		return nil, fmt.Errorf("failed to read os-release: %w", err)
	}

	kernelRelease, err := readKernelRelease(cfg.kernelReleasePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read kernel release: %w", err)
	}

	memBytes, err := readMeminfoTotal(cfg.meminfoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read memory total: %w", err)
	}

	cores := cfg.numCPUFunc()
	if cores <= 0 {
		return nil, errors.New("invalid cpu count: <= 0")
	}

	arch := strings.TrimSpace(cfg.arch)
	if arch == "" {
		return nil, errors.New("architecture is empty")
	}

	req := &protocol.InventoryRequest{
		ProtocolVersion:  protocol.CurrentVersion,
		Hostname:         hostname,
		OSID:             osID,
		OSName:           osName,
		OSVersion:        osVersion,
		KernelRelease:    kernelRelease,
		Architecture:     arch,
		CPULogicalCores:  cores,
		MemoryTotalBytes: memBytes,
	}

	if err := protocol.ValidateInventoryRequest(req); err != nil {
		return nil, fmt.Errorf("collected inventory violates wire invariants: %w", err)
	}

	return req, nil
}

func readBoundedFile(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file %s exceeds maximum allowed size of %d bytes", path, maxBytes)
	}
	return data, nil
}

func readOSRelease(paths []string) (osID, osName, osVersion string, err error) {
	var data []byte
	for _, p := range paths {
		b, rErr := readBoundedFile(p, maxOSReleaseBytes)
		if rErr == nil {
			data = b
			break
		}
		if errors.Is(rErr, os.ErrNotExist) {
			continue
		}
		return "", "", "", rErr
	}
	if data == nil {
		return "", "", "", errors.New("neither /etc/os-release nor fallback found")
	}

	return parseOSRelease(bytes.NewReader(data))
}

func parseOSReleaseValue(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}

	// Double-quoted string with escape support
	if strings.HasPrefix(raw, "\"") {
		if len(raw) < 2 {
			return "", errors.New("unclosed double quote in os-release value")
		}
		var sb strings.Builder
		escaped := false
		closed := false

		for i := 1; i < len(raw); i++ {
			b := raw[i]
			if escaped {
				switch b {
				case '"':
					sb.WriteByte('"')
				case '\\':
					sb.WriteByte('\\')
				default:
					sb.WriteByte('\\')
					sb.WriteByte(b)
				}
				escaped = false
			} else if b == '\\' {
				escaped = true
			} else if b == '"' {
				closed = true
				rest := strings.TrimSpace(raw[i+1:])
				if rest != "" && !strings.HasPrefix(rest, "#") {
					return "", errors.New("trailing characters after closing quote in os-release value")
				}
				break
			} else {
				sb.WriteByte(b)
			}
		}

		if !closed || escaped {
			return "", errors.New("unclosed double quote in os-release value")
		}
		return sb.String(), nil
	}

	// Single-quoted string treated literally until closing quote
	if strings.HasPrefix(raw, "'") {
		if len(raw) < 2 {
			return "", errors.New("unclosed single quote in os-release value")
		}
		end := strings.IndexByte(raw[1:], '\'')
		if end == -1 {
			return "", errors.New("unclosed single quote in os-release value")
		}
		content := raw[1 : 1+end]
		rest := strings.TrimSpace(raw[1+end+1:])
		if rest != "" && !strings.HasPrefix(rest, "#") {
			return "", errors.New("trailing characters after closing quote in os-release value")
		}
		return content, nil
	}

	// Unquoted: take until comment or whitespace
	if idx := strings.IndexByte(raw, '#'); idx != -1 {
		raw = strings.TrimSpace(raw[:idx])
	}
	return raw, nil
}

func parseOSRelease(r io.Reader) (osID, osName, osVersion string, err error) {
	scanner := bufio.NewScanner(r)
	var versionFallback string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		parsedVal, pErr := parseOSReleaseValue(val)
		if pErr != nil {
			return "", "", "", fmt.Errorf("failed to parse os-release key %s: %w", key, pErr)
		}

		switch key {
		case "ID":
			osID = strings.ToLower(strings.TrimSpace(parsedVal))
		case "NAME":
			osName = strings.TrimSpace(parsedVal)
		case "VERSION_ID":
			osVersion = strings.TrimSpace(parsedVal)
		case "VERSION":
			versionFallback = strings.TrimSpace(parsedVal)
		}
	}
	if err := scanner.Err(); err != nil {
		return "", "", "", err
	}

	if osVersion == "" {
		osVersion = versionFallback
	}

	if osID == "" {
		return "", "", "", errors.New("os-release missing ID field")
	}
	if osName == "" {
		return "", "", "", errors.New("os-release missing NAME field")
	}

	return osID, osName, osVersion, nil
}

func readKernelRelease(path string) (string, error) {
	data, err := readBoundedFile(path, maxKernelReleaseBytes)
	if err != nil {
		return "", err
	}
	release := strings.TrimSpace(string(data))
	if release == "" {
		return "", errors.New("kernel release is empty")
	}
	return release, nil
}

func readMeminfoTotal(path string) (int64, error) {
	data, err := readBoundedFile(path, maxMeminfoBytes)
	if err != nil {
		return 0, err
	}
	return parseMeminfoTotal(data)
}

func parseMeminfoTotal(data []byte) (int64, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) != 3 {
				return 0, fmt.Errorf("invalid MemTotal line format: expected 3 fields, got %d", len(fields))
			}
			if fields[2] != "kB" {
				return 0, fmt.Errorf("invalid MemTotal unit %q: expected kB", fields[2])
			}

			kb, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid MemTotal integer %q: %w", fields[1], err)
			}
			if kb <= 0 {
				return 0, fmt.Errorf("invalid MemTotal value %d: must be positive", kb)
			}
			if kb > math.MaxInt64/1024 {
				return 0, fmt.Errorf("MemTotal value %d kB causes int64 overflow", kb)
			}
			return kb * 1024, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("MemTotal not found in meminfo")
}

func sendInventory(ctx context.Context, client *http.Client, targetURL string, req *protocol.InventoryRequest) error {
	reqPayload, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("%w: failed to marshal inventory payload", ErrPermanentFailure)
	}

	reqCtx, reqCancel := context.WithTimeout(ctx, DefaultClientTimeout)
	defer reqCancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPut, targetURL, bytes.NewReader(reqPayload))
	if err != nil {
		return fmt.Errorf("%w: failed to construct inventory request: %v", ErrPermanentFailure, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return err // Transient network/TLS error
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil
	case http.StatusUnauthorized:
		return ErrAuthRejected
	case http.StatusConflict:
		return ErrProtocolMismatch
	case http.StatusBadRequest:
		return fmt.Errorf("%w: inventory request rejected by controller (400)", ErrPermanentFailure)
	case http.StatusTooManyRequests:
		return errors.New("inventory rate limited by controller (429)")
	default:
		if resp.StatusCode >= 500 && resp.StatusCode <= 599 {
			return fmt.Errorf("controller error (status %d)", resp.StatusCode)
		}
		if resp.StatusCode >= 400 && resp.StatusCode <= 499 {
			return fmt.Errorf("%w: unexpected client error (status %d)", ErrPermanentFailure, resp.StatusCode)
		}
		return fmt.Errorf("unexpected inventory response status %d", resp.StatusCode)
	}
}
