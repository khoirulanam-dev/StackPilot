package protocol

import (
	"encoding/json"
	"testing"
)

func TestProtocolDefinitions(t *testing.T) {
	if CurrentVersion != 2 {
		t.Fatalf("expected CurrentVersion = 2, got %d", CurrentVersion)
	}

	if HeartbeatEndpointPath != "/api/v1/agent/heartbeat" {
		t.Fatalf("unexpected HeartbeatEndpointPath: %s", HeartbeatEndpointPath)
	}

	if InventoryEndpointPath != "/api/v1/agent/inventory" {
		t.Fatalf("unexpected InventoryEndpointPath: %s", InventoryEndpointPath)
	}

	if AgentJobStartEndpointPath != "/api/v1/agent/job/start" {
		t.Fatalf("unexpected AgentJobStartEndpointPath: %s", AgentJobStartEndpointPath)
	}

	if AgentJobCompleteEndpointPath != "/api/v1/agent/job/complete" {
		t.Fatalf("unexpected AgentJobCompleteEndpointPath: %s", AgentJobCompleteEndpointPath)
	}

	req := HeartbeatRequest{ProtocolVersion: CurrentVersion}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal HeartbeatRequest: %v", err)
	}

	var parsed HeartbeatRequest
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal HeartbeatRequest: %v", err)
	}

	if parsed.ProtocolVersion != CurrentVersion {
		t.Fatalf("expected protocol version %d, got %d", CurrentVersion, parsed.ProtocolVersion)
	}

	invReq := InventoryRequest{
		ProtocolVersion:  CurrentVersion,
		Hostname:         "node-01.example.com",
		OSID:             "ubuntu",
		OSName:           "Ubuntu",
		OSVersion:        "24.04",
		KernelRelease:    "6.8.0-40-generic",
		Architecture:     "amd64",
		CPULogicalCores:  8,
		MemoryTotalBytes: 16777216000,
	}
	invData, err := json.Marshal(invReq)
	if err != nil {
		t.Fatalf("failed to marshal InventoryRequest: %v", err)
	}

	var parsedInv InventoryRequest
	if err := json.Unmarshal(invData, &parsedInv); err != nil {
		t.Fatalf("failed to unmarshal InventoryRequest: %v", err)
	}

	if parsedInv != invReq {
		t.Fatalf("unmarshaled InventoryRequest mismatch: got %+v, want %+v", parsedInv, invReq)
	}
}

func TestValidateInventoryString_UnicodeAndCharacters(t *testing.T) {
	// ASCII boundaries remain correct
	if err := ValidateInventoryString("", 1, 128); err == nil {
		t.Fatal("expected error for empty string with minLen 1")
	}
	if err := ValidateInventoryString("a", 1, 128); err != nil {
		t.Fatalf("unexpected error for 1-char ASCII string: %v", err)
	}
	ascii128 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := ValidateInventoryString(ascii128, 1, 128); err != nil {
		t.Fatalf("unexpected error for 128-char ASCII string: %v", err)
	}
	if err := ValidateInventoryString(ascii128+"a", 1, 128); err == nil {
		t.Fatal("expected error for 129-char ASCII string with maxLen 128")
	}

	// A Unicode os_name with <= 128 characters is accepted even when its UTF-8 byte length exceeds 128.
	// '日' is 3 bytes in UTF-8. 100 '日' = 100 characters, 300 bytes.
	unicode100Chars := ""
	for i := 0; i < 100; i++ {
		unicode100Chars += "日"
	}
	if len(unicode100Chars) <= 128 {
		t.Fatalf("expected byte length > 128, got %d", len(unicode100Chars))
	}
	if err := ValidateInventoryString(unicode100Chars, 1, 128); err != nil {
		t.Fatalf("expected Unicode 100-character string (300 bytes) to be accepted: %v", err)
	}

	// A Unicode os_name with 128 characters is accepted (128 runes, 384 bytes).
	unicode128Chars := ""
	for i := 0; i < 128; i++ {
		unicode128Chars += "日"
	}
	if err := ValidateInventoryString(unicode128Chars, 1, 128); err != nil {
		t.Fatalf("expected Unicode 128-character string (384 bytes) to be accepted: %v", err)
	}

	// A Unicode os_name with > 128 characters is rejected (129 runes, 387 bytes).
	unicode129Chars := unicode128Chars + "日"
	if err := ValidateInventoryString(unicode129Chars, 1, 128); err == nil {
		t.Fatal("expected Unicode 129-character string to be rejected for maxLen 128")
	}

	// Invalid UTF-8 is rejected
	invalidUTF8 := string([]byte{0xff, 0xfe, 0xfd})
	if err := ValidateInventoryString(invalidUTF8, 1, 128); err == nil {
		t.Fatal("expected invalid UTF-8 string to be rejected")
	}

	// Validate via ValidateInventoryRequest
	baseReq := InventoryRequest{
		ProtocolVersion:  CurrentVersion,
		Hostname:         "node-01.internal",
		OSID:             "debian",
		OSName:           unicode100Chars,
		OSVersion:        "12",
		KernelRelease:    "6.1.0",
		Architecture:     "amd64",
		CPULogicalCores:  4,
		MemoryTotalBytes: 1024,
	}
	if err := ValidateInventoryRequest(&baseReq); err != nil {
		t.Fatalf("expected ValidateInventoryRequest with 100-rune OSName (300 bytes) to succeed: %v", err)
	}

	baseReq.OSName = unicode129Chars
	if err := ValidateInventoryRequest(&baseReq); err == nil {
		t.Fatal("expected ValidateInventoryRequest with 129-rune OSName to fail")
	}

	baseReq.OSName = invalidUTF8
	if err := ValidateInventoryRequest(&baseReq); err == nil {
		t.Fatal("expected ValidateInventoryRequest with invalid UTF-8 OSName to fail")
	}
}

func TestTelemetryProtocolDefinitions(t *testing.T) {
	if TelemetryEndpointPath != "/api/v1/agent/telemetry" {
		t.Fatalf("unexpected TelemetryEndpointPath: %s", TelemetryEndpointPath)
	}

	validReq := TelemetryRequest{
		ProtocolVersion:              CurrentVersion,
		CPUUsageBasisPoints:          2500,
		MemoryTotalBytes:             16777216000,
		MemoryUsedBytes:              8388608000,
		MemoryAvailableBytes:         8388608000,
		Load1mMilli:                  1250,
		Load5mMilli:                  1100,
		Load15mMilli:                 950,
		RootFilesystemTotalBytes:     107374182400,
		RootFilesystemUsedBytes:      42949672960,
		RootFilesystemAvailableBytes: 59055800320,
		NetworkReceiveBytesTotal:     104857600,
		NetworkTransmitBytesTotal:    52428800,
		UptimeSeconds:                86400,
		SampleWindowMS:               30000,
	}

	data, err := json.Marshal(validReq)
	if err != nil {
		t.Fatalf("failed to marshal TelemetryRequest: %v", err)
	}

	var parsed TelemetryRequest
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal TelemetryRequest: %v", err)
	}

	if parsed != validReq {
		t.Fatalf("unmarshaled TelemetryRequest mismatch: got %+v, want %+v", parsed, validReq)
	}
}

func TestValidateTelemetryRequest(t *testing.T) {
	validReq := func() TelemetryRequest {
		return TelemetryRequest{
			ProtocolVersion:              CurrentVersion,
			CPUUsageBasisPoints:          2500,
			MemoryTotalBytes:             1000,
			MemoryUsedBytes:              600,
			MemoryAvailableBytes:         400,
			Load1mMilli:                  1000,
			Load5mMilli:                  1000,
			Load15mMilli:                 1000,
			RootFilesystemTotalBytes:     10000,
			RootFilesystemUsedBytes:      4000,
			RootFilesystemAvailableBytes: 5000, // 5000 <= 10000-4000 (reserved blocks)
			NetworkReceiveBytesTotal:     200,
			NetworkTransmitBytesTotal:    300,
			UptimeSeconds:                120,
			SampleWindowMS:               30000,
		}
	}

	if err := ValidateTelemetryRequest(nil); err == nil {
		t.Fatal("expected error for nil request")
	}

	t.Run("valid_request", func(t *testing.T) {
		r := validReq()
		if err := ValidateTelemetryRequest(&r); err != nil {
			t.Fatalf("unexpected validation error: %v", err)
		}
	})

	t.Run("protocol_version", func(t *testing.T) {
		r := validReq()
		r.ProtocolVersion = 0
		if err := ValidateTelemetryRequest(&r); err == nil {
			t.Fatal("expected error for protocol_version 0")
		}
		r.ProtocolVersion = -1
		if err := ValidateTelemetryRequest(&r); err == nil {
			t.Fatal("expected error for negative protocol_version")
		}
	})

	t.Run("cpu_usage_basis_points", func(t *testing.T) {
		r := validReq()
		r.CPUUsageBasisPoints = -1
		if err := ValidateTelemetryRequest(&r); err == nil {
			t.Fatal("expected error for negative CPUUsageBasisPoints")
		}
		r.CPUUsageBasisPoints = 0
		if err := ValidateTelemetryRequest(&r); err != nil {
			t.Fatalf("unexpected error for 0 basis points: %v", err)
		}
		r.CPUUsageBasisPoints = 10000
		if err := ValidateTelemetryRequest(&r); err != nil {
			t.Fatalf("unexpected error for 10000 basis points: %v", err)
		}
		r.CPUUsageBasisPoints = 10001
		if err := ValidateTelemetryRequest(&r); err == nil {
			t.Fatal("expected error for 10001 CPUUsageBasisPoints")
		}
	})

	t.Run("memory", func(t *testing.T) {
		r := validReq()
		r.MemoryTotalBytes = 0
		if err := ValidateTelemetryRequest(&r); err == nil {
			t.Fatal("expected error for zero total memory")
		}
		r = validReq()
		r.MemoryTotalBytes = -100
		if err := ValidateTelemetryRequest(&r); err == nil {
			t.Fatal("expected error for negative total memory")
		}

		r = validReq()
		r.MemoryAvailableBytes = -1
		if err := ValidateTelemetryRequest(&r); err == nil {
			t.Fatal("expected error for negative available memory")
		}

		r = validReq()
		r.MemoryAvailableBytes = r.MemoryTotalBytes + 1
		if err := ValidateTelemetryRequest(&r); err == nil {
			t.Fatal("expected error for available > total memory")
		}

		r = validReq()
		r.MemoryUsedBytes = -1
		if err := ValidateTelemetryRequest(&r); err == nil {
			t.Fatal("expected error for negative used memory")
		}

		r = validReq()
		r.MemoryUsedBytes = r.MemoryTotalBytes - r.MemoryAvailableBytes + 1
		if err := ValidateTelemetryRequest(&r); err == nil {
			t.Fatal("expected error for inconsistent used memory != total - available")
		}
	})

	t.Run("load", func(t *testing.T) {
		r := validReq()
		r.Load1mMilli = -1
		if err := ValidateTelemetryRequest(&r); err == nil {
			t.Fatal("expected error for negative Load1mMilli")
		}
		r = validReq()
		r.Load5mMilli = -1
		if err := ValidateTelemetryRequest(&r); err == nil {
			t.Fatal("expected error for negative Load5mMilli")
		}
		r = validReq()
		r.Load15mMilli = -1
		if err := ValidateTelemetryRequest(&r); err == nil {
			t.Fatal("expected error for negative Load15mMilli")
		}
	})

	t.Run("filesystem", func(t *testing.T) {
		r := validReq()
		r.RootFilesystemTotalBytes = 0
		if err := ValidateTelemetryRequest(&r); err == nil {
			t.Fatal("expected error for zero total filesystem")
		}
		r = validReq()
		r.RootFilesystemTotalBytes = -1
		if err := ValidateTelemetryRequest(&r); err == nil {
			t.Fatal("expected error for negative total filesystem")
		}

		r = validReq()
		r.RootFilesystemUsedBytes = -1
		if err := ValidateTelemetryRequest(&r); err == nil {
			t.Fatal("expected error for negative used filesystem")
		}

		r = validReq()
		r.RootFilesystemUsedBytes = r.RootFilesystemTotalBytes + 1
		if err := ValidateTelemetryRequest(&r); err == nil {
			t.Fatal("expected error for used > total filesystem")
		}

		r = validReq()
		r.RootFilesystemAvailableBytes = -1
		if err := ValidateTelemetryRequest(&r); err == nil {
			t.Fatal("expected error for negative available filesystem")
		}

		r = validReq()
		r.RootFilesystemAvailableBytes = r.RootFilesystemTotalBytes - r.RootFilesystemUsedBytes + 1
		if err := ValidateTelemetryRequest(&r); err == nil {
			t.Fatal("expected error for available > total - used")
		}

		// Reserved-blocks case: available < total - used must be valid
		r = validReq()
		r.RootFilesystemAvailableBytes = r.RootFilesystemTotalBytes - r.RootFilesystemUsedBytes - 100
		if err := ValidateTelemetryRequest(&r); err != nil {
			t.Fatalf("unexpected error for reserved-blocks case (available < total - used): %v", err)
		}
	})

	t.Run("network", func(t *testing.T) {
		r := validReq()
		r.NetworkReceiveBytesTotal = -1
		if err := ValidateTelemetryRequest(&r); err == nil {
			t.Fatal("expected error for negative NetworkReceiveBytesTotal")
		}
		r = validReq()
		r.NetworkTransmitBytesTotal = -1
		if err := ValidateTelemetryRequest(&r); err == nil {
			t.Fatal("expected error for negative NetworkTransmitBytesTotal")
		}
	})

	t.Run("uptime", func(t *testing.T) {
		r := validReq()
		r.UptimeSeconds = -1
		if err := ValidateTelemetryRequest(&r); err == nil {
			t.Fatal("expected error for negative UptimeSeconds")
		}
		r.UptimeSeconds = 0
		if err := ValidateTelemetryRequest(&r); err != nil {
			t.Fatalf("unexpected error for 0 UptimeSeconds: %v", err)
		}
	})

	t.Run("sample_window_ms", func(t *testing.T) {
		r := validReq()
		r.SampleWindowMS = 0
		if err := ValidateTelemetryRequest(&r); err == nil {
			t.Fatal("expected error for sample_window_ms = 0")
		}
		r.SampleWindowMS = 1
		if err := ValidateTelemetryRequest(&r); err != nil {
			t.Fatalf("unexpected error for sample_window_ms = 1: %v", err)
		}
		r.SampleWindowMS = 300000
		if err := ValidateTelemetryRequest(&r); err != nil {
			t.Fatalf("unexpected error for sample_window_ms = 300000: %v", err)
		}
		r.SampleWindowMS = 300001
		if err := ValidateTelemetryRequest(&r); err == nil {
			t.Fatal("expected error for sample_window_ms = 300001")
		}
	})
}

func TestValidateJobStartRequest(t *testing.T) {
	validID := "0191bc8d-0a70-7115-9988-123456789abc"

	t.Run("valid_request", func(t *testing.T) {
		req := &JobStartRequest{
			ProtocolVersion: CurrentVersion,
			JobID:           validID,
			Attempt:         1,
		}
		if err := ValidateJobStartRequest(req); err != nil {
			t.Fatalf("expected valid start request: %v", err)
		}
	})

	t.Run("nil_request", func(t *testing.T) {
		if err := ValidateJobStartRequest(nil); err == nil {
			t.Fatal("expected error for nil request")
		}
	})

	t.Run("invalid_version", func(t *testing.T) {
		req := &JobStartRequest{
			ProtocolVersion: CurrentVersion + 1,
			JobID:           validID,
			Attempt:         1,
		}
		if err := ValidateJobStartRequest(req); err == nil {
			t.Fatal("expected error for mismatched protocol version")
		}
	})

	t.Run("invalid_job_id", func(t *testing.T) {
		req := &JobStartRequest{
			ProtocolVersion: CurrentVersion,
			JobID:           "invalid-uuid",
			Attempt:         1,
		}
		if err := ValidateJobStartRequest(req); err == nil {
			t.Fatal("expected error for invalid job_id")
		}
	})

	t.Run("attempt_out_of_range", func(t *testing.T) {
		req := &JobStartRequest{
			ProtocolVersion: CurrentVersion,
			JobID:           validID,
			Attempt:         0,
		}
		if err := ValidateJobStartRequest(req); err == nil {
			t.Fatal("expected error for attempt 0")
		}
		req.Attempt = 6
		if err := ValidateJobStartRequest(req); err == nil {
			t.Fatal("expected error for attempt 6")
		}
	})
}

func TestValidateJobCompleteRequest(t *testing.T) {
	validID := "0191bc8d-0a70-7115-9988-123456789abc"

	t.Run("valid_succeeded", func(t *testing.T) {
		req := &JobCompleteRequest{
			ProtocolVersion: CurrentVersion,
			JobID:           validID,
			Attempt:         1,
			Outcome:         "succeeded",
		}
		if err := ValidateJobCompleteRequest(req); err != nil {
			t.Fatalf("expected valid succeeded request: %v", err)
		}
	})

	t.Run("valid_failed", func(t *testing.T) {
		req := &JobCompleteRequest{
			ProtocolVersion: CurrentVersion,
			JobID:           validID,
			Attempt:         1,
			Outcome:         "failed",
			FailureCode:     "executor_error",
		}
		if err := ValidateJobCompleteRequest(req); err != nil {
			t.Fatalf("expected valid failed request: %v", err)
		}
	})

	t.Run("succeeded_with_failure_code_rejected", func(t *testing.T) {
		req := &JobCompleteRequest{
			ProtocolVersion: CurrentVersion,
			JobID:           validID,
			Attempt:         1,
			Outcome:         "succeeded",
			FailureCode:     "executor_error",
		}
		if err := ValidateJobCompleteRequest(req); err == nil {
			t.Fatal("expected error for succeeded outcome with failure code")
		}
	})

	t.Run("failed_without_failure_code_rejected", func(t *testing.T) {
		req := &JobCompleteRequest{
			ProtocolVersion: CurrentVersion,
			JobID:           validID,
			Attempt:         1,
			Outcome:         "failed",
		}
		if err := ValidateJobCompleteRequest(req); err == nil {
			t.Fatal("expected error for failed outcome without failure code")
		}
	})

	t.Run("failed_with_wrong_failure_code_rejected", func(t *testing.T) {
		req := &JobCompleteRequest{
			ProtocolVersion: CurrentVersion,
			JobID:           validID,
			Attempt:         1,
			Outcome:         "failed",
			FailureCode:     "dispatch_exhausted",
		}
		if err := ValidateJobCompleteRequest(req); err == nil {
			t.Fatal("expected error for failed outcome with non-executor_error failure code")
		}
	})

	t.Run("invalid_outcome", func(t *testing.T) {
		req := &JobCompleteRequest{
			ProtocolVersion: CurrentVersion,
			JobID:           validID,
			Attempt:         1,
			Outcome:         "cancelled",
		}
		if err := ValidateJobCompleteRequest(req); err == nil {
			t.Fatal("expected error for invalid outcome")
		}
	})
}
