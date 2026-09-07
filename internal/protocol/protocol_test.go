package protocol

import (
	"encoding/json"
	"testing"
)

func TestProtocolDefinitions(t *testing.T) {
	if CurrentVersion != 1 {
		t.Fatalf("expected CurrentVersion = 1, got %d", CurrentVersion)
	}

	if HeartbeatEndpointPath != "/api/v1/agent/heartbeat" {
		t.Fatalf("unexpected HeartbeatEndpointPath: %s", HeartbeatEndpointPath)
	}

	if InventoryEndpointPath != "/api/v1/agent/inventory" {
		t.Fatalf("unexpected InventoryEndpointPath: %s", InventoryEndpointPath)
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
