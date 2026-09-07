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
}
