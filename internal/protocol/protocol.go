package protocol

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// CurrentVersion is the currently supported Agent protocol version.
const CurrentVersion = 1

// HeartbeatEndpointPath is the HTTP path for Agent presence heartbeat requests on the remote TLS listener.
const HeartbeatEndpointPath = "/api/v1/agent/heartbeat"

// InventoryEndpointPath is the HTTP path for Agent inventory reports on the remote TLS listener.
const InventoryEndpointPath = "/api/v1/agent/inventory"

// TelemetryEndpointPath is the HTTP path for Agent runtime telemetry reports on the remote TLS listener.
const TelemetryEndpointPath = "/api/v1/agent/telemetry"

// HeartbeatRequest defines the JSON payload sent by an Agent during presence heartbeats.
type HeartbeatRequest struct {
	ProtocolVersion int `json:"protocol_version"`
}

// InventoryRequest defines the JSON payload sent by an Agent during inventory reporting.
type InventoryRequest struct {
	ProtocolVersion  int    `json:"protocol_version"`
	Hostname         string `json:"hostname"`
	OSID             string `json:"os_id"`
	OSName           string `json:"os_name"`
	OSVersion        string `json:"os_version"`
	KernelRelease    string `json:"kernel_release"`
	Architecture     string `json:"architecture"`
	CPULogicalCores  int    `json:"cpu_logical_cores"`
	MemoryTotalBytes int64  `json:"memory_total_bytes"`
}

// TelemetryRequest defines the JSON payload sent by an Agent during runtime telemetry reporting.
type TelemetryRequest struct {
	ProtocolVersion              int   `json:"protocol_version"`
	CPUUsageBasisPoints          int   `json:"cpu_usage_basis_points"`
	MemoryTotalBytes             int64 `json:"memory_total_bytes"`
	MemoryUsedBytes              int64 `json:"memory_used_bytes"`
	MemoryAvailableBytes         int64 `json:"memory_available_bytes"`
	Load1mMilli                  int64 `json:"load_1m_milli"`
	Load5mMilli                  int64 `json:"load_5m_milli"`
	Load15mMilli                 int64 `json:"load_15m_milli"`
	RootFilesystemTotalBytes     int64 `json:"root_filesystem_total_bytes"`
	RootFilesystemUsedBytes      int64 `json:"root_filesystem_used_bytes"`
	RootFilesystemAvailableBytes int64 `json:"root_filesystem_available_bytes"`
	NetworkReceiveBytesTotal     int64 `json:"network_receive_bytes_total"`
	NetworkTransmitBytesTotal    int64 `json:"network_transmit_bytes_total"`
	UptimeSeconds                int64 `json:"uptime_seconds"`
	SampleWindowMS               int64 `json:"sample_window_ms"`
}

// ValidateInventoryString checks that a string satisfies length, control character, and whitespace constraints.
// Length constraints are evaluated in Unicode characters (runes), matching PostgreSQL length(text).
func ValidateInventoryString(s string, minLen, maxLen int) error {
	if !utf8.ValidString(s) {
		return errors.New("invalid UTF-8")
	}
	charCount := utf8.RuneCountInString(s)
	if charCount < minLen || charCount > maxLen {
		return errors.New("length out of range")
	}
	if s != strings.TrimSpace(s) {
		return errors.New("leading or trailing whitespace not allowed")
	}
	for _, r := range s {
		if r == 0 || unicode.IsControl(r) {
			return errors.New("control characters not allowed")
		}
	}
	return nil
}

// ValidateOSID enforces 1..64 lowercase ASCII letters, digits, dot, underscore, or hyphen.
func ValidateOSID(s string) error {
	if err := ValidateInventoryString(s, 1, 64); err != nil {
		return err
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		isLower := b >= 'a' && b <= 'z'
		isDigit := b >= '0' && b <= '9'
		isSpecial := b == '.' || b == '_' || b == '-'
		if !isLower && !isDigit && !isSpecial {
			return errors.New("must contain only lowercase ASCII letters, digits, dot, underscore, or hyphen")
		}
	}
	return nil
}

// ValidateInventoryRequest checks that an InventoryRequest conforms to server-side wire invariants.
func ValidateInventoryRequest(req *InventoryRequest) error {
	if req == nil {
		return errors.New("inventory request is nil")
	}
	if req.ProtocolVersion <= 0 {
		return errors.New("invalid protocol version")
	}
	if err := ValidateInventoryString(req.Hostname, 1, 255); err != nil {
		return fmt.Errorf("invalid hostname: %w", err)
	}
	if err := ValidateOSID(req.OSID); err != nil {
		return fmt.Errorf("invalid os_id: %w", err)
	}
	if err := ValidateInventoryString(req.OSName, 1, 128); err != nil {
		return fmt.Errorf("invalid os_name: %w", err)
	}
	if err := ValidateInventoryString(req.OSVersion, 0, 128); err != nil {
		return fmt.Errorf("invalid os_version: %w", err)
	}
	if err := ValidateInventoryString(req.KernelRelease, 1, 128); err != nil {
		return fmt.Errorf("invalid kernel_release: %w", err)
	}
	if err := ValidateInventoryString(req.Architecture, 1, 32); err != nil {
		return fmt.Errorf("invalid architecture: %w", err)
	}
	if req.CPULogicalCores <= 0 || req.CPULogicalCores > 1048576 {
		return errors.New("invalid cpu_logical_cores: must be between 1 and 1048576")
	}
	if req.MemoryTotalBytes <= 0 {
		return errors.New("invalid memory_total_bytes: must be > 0")
	}
	return nil
}

// ValidateTelemetryRequest checks that a TelemetryRequest conforms to server-side wire invariants.
func ValidateTelemetryRequest(req *TelemetryRequest) error {
	if req == nil {
		return errors.New("telemetry request is nil")
	}
	if req.ProtocolVersion <= 0 {
		return errors.New("invalid protocol version")
	}
	if req.CPUUsageBasisPoints < 0 || req.CPUUsageBasisPoints > 10000 {
		return errors.New("invalid cpu_usage_basis_points: must be between 0 and 10000")
	}
	if req.MemoryTotalBytes <= 0 {
		return errors.New("invalid memory_total_bytes: must be > 0")
	}
	if req.MemoryAvailableBytes < 0 || req.MemoryAvailableBytes > req.MemoryTotalBytes {
		return errors.New("invalid memory_available_bytes: must be between 0 and memory_total_bytes")
	}
	if req.MemoryUsedBytes < 0 || req.MemoryUsedBytes != req.MemoryTotalBytes-req.MemoryAvailableBytes {
		return errors.New("invalid memory_used_bytes: must equal memory_total_bytes - memory_available_bytes")
	}
	if req.Load1mMilli < 0 || req.Load5mMilli < 0 || req.Load15mMilli < 0 {
		return errors.New("invalid load average: must be non-negative")
	}
	if req.RootFilesystemTotalBytes <= 0 {
		return errors.New("invalid root_filesystem_total_bytes: must be > 0")
	}
	if req.RootFilesystemUsedBytes < 0 || req.RootFilesystemUsedBytes > req.RootFilesystemTotalBytes {
		return errors.New("invalid root_filesystem_used_bytes: must be between 0 and root_filesystem_total_bytes")
	}
	if req.RootFilesystemAvailableBytes < 0 || req.RootFilesystemAvailableBytes > req.RootFilesystemTotalBytes-req.RootFilesystemUsedBytes {
		return errors.New("invalid root_filesystem_available_bytes: must be between 0 and total - used")
	}
	if req.NetworkReceiveBytesTotal < 0 || req.NetworkTransmitBytesTotal < 0 {
		return errors.New("invalid network byte counters: must be non-negative")
	}
	if req.UptimeSeconds < 0 {
		return errors.New("invalid uptime_seconds: must be non-negative")
	}
	if req.SampleWindowMS < 1 || req.SampleWindowMS > 300000 {
		return errors.New("invalid sample_window_ms: must be between 1 and 300000")
	}
	return nil
}
