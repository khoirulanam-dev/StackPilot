package privilege

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestProtocol_EncodeDecodeRequest_Valid(t *testing.T) {
	reqID := uuid.NewString()
	req := Request{
		Version:   ProtocolVersion,
		RequestID: reqID,
		Operation: OpBoundaryPing,
	}

	data, err := EncodeRequest(req)
	if err != nil {
		t.Fatalf("EncodeRequest failed: %v", err)
	}

	decoded, err := DecodeRequest(data)
	if err != nil {
		t.Fatalf("DecodeRequest failed: %v", err)
	}

	if decoded.Version != ProtocolVersion {
		t.Errorf("expected version %d, got %d", ProtocolVersion, decoded.Version)
	}
	if decoded.RequestID != reqID {
		t.Errorf("expected request_id %q, got %q", reqID, decoded.RequestID)
	}
	if decoded.Operation != OpBoundaryPing {
		t.Errorf("expected operation %q, got %q", OpBoundaryPing, decoded.Operation)
	}
}

func TestProtocol_DecodeRequest_StrictFailures(t *testing.T) {
	validID := uuid.NewString()

	cases := []struct {
		name    string
		payload []byte
		wantErr string
	}{
		{
			name:    "empty packet",
			payload: []byte(""),
			wantErr: "request payload is empty",
		},
		{
			name:    "invalid utf8",
			payload: []byte{0xff, 0xfe, 0xfd},
			wantErr: "invalid UTF-8",
		},
		{
			name:    "oversized packet",
			payload: []byte(strings.Repeat("a", MaxPacketSize+1)),
			wantErr: "exceeds maximum size",
		},
		{
			name:    "malformed json",
			payload: []byte(`{"version": 1,`),
			wantErr: "failed to decode request JSON",
		},
		{
			name:    "wrong version 0",
			payload: []byte(`{"version": 0, "request_id": "` + validID + `", "operation": "boundary.ping"}`),
			wantErr: "unsupported protocol version",
		},
		{
			name:    "wrong version 2",
			payload: []byte(`{"version": 2, "request_id": "` + validID + `", "operation": "boundary.ping"}`),
			wantErr: "unsupported protocol version",
		},
		{
			name:    "empty request_id",
			payload: []byte(`{"version": 1, "request_id": "", "operation": "boundary.ping"}`),
			wantErr: "request_id cannot be empty",
		},
		{
			name:    "uppercase uuid non-canonical",
			payload: []byte(`{"version": 1, "request_id": "` + strings.ToUpper(validID) + `", "operation": "boundary.ping"}`),
			wantErr: "canonical lowercase UUID",
		},
		{
			name:    "invalid uuid string",
			payload: []byte(`{"version": 1, "request_id": "not-a-valid-uuid-here", "operation": "boundary.ping"}`),
			wantErr: "canonical lowercase UUID",
		},
		{
			name:    "unknown operation",
			payload: []byte(`{"version": 1, "request_id": "` + validID + `", "operation": "server.reboot"}`),
			wantErr: "unknown operation",
		},
		{
			name:    "agent.ping rejected for helper",
			payload: []byte(`{"version": 1, "request_id": "` + validID + `", "operation": "agent.ping"}`),
			wantErr: "unknown operation",
		},
		{
			name:    "unknown field rejected",
			payload: []byte(`{"version": 1, "request_id": "` + validID + `", "operation": "boundary.ping", "extra": "payload"}`),
			wantErr: "unknown field",
		},
		{
			name:    "trailing second json object",
			payload: []byte(`{"version": 1, "request_id": "` + validID + `", "operation": "boundary.ping"}{"version": 1}`),
			wantErr: "unexpected trailing",
		},
		{
			name:    "trailing tokens",
			payload: []byte(`{"version": 1, "request_id": "` + validID + `", "operation": "boundary.ping"} 12345`),
			wantErr: "unexpected trailing",
		},
		{
			name:    "trailing garbage",
			payload: []byte(`{"version": 1, "request_id": "` + validID + `", "operation": "boundary.ping"}garbage`),
			wantErr: "unexpected trailing",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeRequest(tc.payload)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestProtocol_EncodeRequest_Validation(t *testing.T) {
	validID := uuid.NewString()

	t.Run("wrong version", func(t *testing.T) {
		req := Request{Version: 2, RequestID: validID, Operation: OpBoundaryPing}
		if _, err := EncodeRequest(req); err == nil {
			t.Fatal("expected error for wrong version")
		}
	})

	t.Run("non-canonical UUID", func(t *testing.T) {
		req := Request{Version: 1, RequestID: strings.ToUpper(validID), Operation: OpBoundaryPing}
		if _, err := EncodeRequest(req); err == nil {
			t.Fatal("expected error for uppercase UUID")
		}
	})

	t.Run("unsupported operation", func(t *testing.T) {
		req := Request{Version: 1, RequestID: validID, Operation: "other"}
		if _, err := EncodeRequest(req); err == nil {
			t.Fatal("expected error for unsupported operation")
		}
	})
}

func TestProtocol_EncodeDecodeResponse_Valid(t *testing.T) {
	reqID := uuid.NewString()
	resp := Response{
		Version:   ProtocolVersion,
		RequestID: reqID,
		Status:    StatusOk,
	}

	data, err := EncodeResponse(resp)
	if err != nil {
		t.Fatalf("EncodeResponse failed: %v", err)
	}

	decoded, err := DecodeResponse(data)
	if err != nil {
		t.Fatalf("DecodeResponse failed: %v", err)
	}

	if decoded.Version != ProtocolVersion {
		t.Errorf("expected version %d, got %d", ProtocolVersion, decoded.Version)
	}
	if decoded.RequestID != reqID {
		t.Errorf("expected request_id %q, got %q", reqID, decoded.RequestID)
	}
	if decoded.Status != StatusOk {
		t.Errorf("expected status %q, got %q", StatusOk, decoded.Status)
	}
}

func TestProtocol_DecodeResponse_StrictFailures(t *testing.T) {
	validID := uuid.NewString()

	cases := []struct {
		name    string
		payload []byte
		wantErr string
	}{
		{
			name:    "empty packet",
			payload: []byte(""),
			wantErr: "response payload is empty",
		},
		{
			name:    "invalid utf8",
			payload: []byte{0xff, 0xfe},
			wantErr: "invalid UTF-8",
		},
		{
			name:    "oversized packet",
			payload: []byte(strings.Repeat("x", MaxPacketSize+1)),
			wantErr: "exceeds maximum size",
		},
		{
			name:    "wrong version",
			payload: []byte(`{"version": 9, "request_id": "` + validID + `", "status": "ok"}`),
			wantErr: "unsupported protocol version",
		},
		{
			name:    "wrong status",
			payload: []byte(`{"version": 1, "request_id": "` + validID + `", "status": "error"}`),
			wantErr: "unexpected response status",
		},
		{
			name:    "unknown field rejected",
			payload: []byte(`{"version": 1, "request_id": "` + validID + `", "status": "ok", "arbitrary": 123}`),
			wantErr: "unknown field",
		},
		{
			name:    "trailing data",
			payload: []byte(`{"version": 1, "request_id": "` + validID + `", "status": "ok"} {"extra": 1}`),
			wantErr: "unexpected trailing",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeResponse(tc.payload)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}
