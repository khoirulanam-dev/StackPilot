package privilege

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	ProtocolVersion          uint = 1
	OpBoundaryPing                = "boundary.ping"
	StatusOk                      = "ok"
	MaxPacketSize                 = 1024
	SocketFileName                = "agent-helper.sock"
	DefaultTimeout                = 2 * time.Second
	MaxConcurrentConnections      = 8
	MaxSocketPathLen              = 107
)

type Request struct {
	Version   uint   `json:"version"`
	RequestID string `json:"request_id"`
	Operation string `json:"operation"`
}

type Response struct {
	Version   uint   `json:"version"`
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
}

// emptyTrailingCheck is used as a strictly typed target to detect trailing JSON tokens.
type emptyTrailingCheck struct{}

// ValidateRequestID ensures the request ID is a non-empty, canonical lowercase UUID.
// It deliberately does not reflect the input value in error messages to avoid echoing untrusted input.
func ValidateRequestID(id string) error {
	if id == "" {
		return errors.New("request_id cannot be empty")
	}
	parsed, err := uuid.Parse(id)
	if err != nil || parsed.String() != id {
		return errors.New("request_id must be a canonical lowercase UUID")
	}
	return nil
}

func EncodeRequest(req Request) ([]byte, error) {
	if req.Version != ProtocolVersion {
		return nil, fmt.Errorf("unsupported protocol version %d (expected %d)", req.Version, ProtocolVersion)
	}
	if err := ValidateRequestID(req.RequestID); err != nil {
		return nil, err
	}
	if req.Operation != OpBoundaryPing {
		return nil, fmt.Errorf("unsupported operation %q (expected %q)", req.Operation, OpBoundaryPing)
	}

	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request: %w", err)
	}
	if len(data) > MaxPacketSize {
		return nil, fmt.Errorf("encoded request exceeds maximum packet size (%d > %d)", len(data), MaxPacketSize)
	}
	return data, nil
}

func DecodeRequest(data []byte) (Request, error) {
	if len(data) == 0 {
		return Request{}, errors.New("request payload is empty")
	}
	if len(data) > MaxPacketSize {
		return Request{}, fmt.Errorf("request payload exceeds maximum size (%d > %d)", len(data), MaxPacketSize)
	}
	if !utf8.Valid(data) {
		return Request{}, errors.New("request payload contains invalid UTF-8")
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var req Request
	if err := dec.Decode(&req); err != nil {
		return Request{}, fmt.Errorf("failed to decode request JSON: %w", err)
	}

	var trailing emptyTrailingCheck
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Request{}, errors.New("unexpected trailing content after request JSON")
	}

	if req.Version != ProtocolVersion {
		return Request{}, fmt.Errorf("unsupported protocol version %d (expected %d)", req.Version, ProtocolVersion)
	}
	if err := ValidateRequestID(req.RequestID); err != nil {
		return Request{}, err
	}
	if req.Operation != OpBoundaryPing {
		return Request{}, fmt.Errorf("unknown operation %q (only %q is supported)", req.Operation, OpBoundaryPing)
	}

	return req, nil
}

func EncodeResponse(resp Response) ([]byte, error) {
	if resp.Version != ProtocolVersion {
		return nil, fmt.Errorf("unsupported protocol version %d (expected %d)", resp.Version, ProtocolVersion)
	}
	if err := ValidateRequestID(resp.RequestID); err != nil {
		return nil, err
	}
	if resp.Status != StatusOk {
		return nil, fmt.Errorf("unsupported response status %q (expected %q)", resp.Status, StatusOk)
	}

	data, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to encode response: %w", err)
	}
	if len(data) > MaxPacketSize {
		return nil, fmt.Errorf("encoded response exceeds maximum packet size (%d > %d)", len(data), MaxPacketSize)
	}
	return data, nil
}

func DecodeResponse(data []byte) (Response, error) {
	if len(data) == 0 {
		return Response{}, errors.New("response payload is empty")
	}
	if len(data) > MaxPacketSize {
		return Response{}, fmt.Errorf("response payload exceeds maximum size (%d > %d)", len(data), MaxPacketSize)
	}
	if !utf8.Valid(data) {
		return Response{}, errors.New("response payload contains invalid UTF-8")
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var resp Response
	if err := dec.Decode(&resp); err != nil {
		return Response{}, fmt.Errorf("failed to decode response JSON: %w", err)
	}

	var trailing emptyTrailingCheck
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Response{}, errors.New("unexpected trailing content after response JSON")
	}

	if resp.Version != ProtocolVersion {
		return Response{}, fmt.Errorf("unsupported protocol version %d (expected %d)", resp.Version, ProtocolVersion)
	}
	if err := ValidateRequestID(resp.RequestID); err != nil {
		return Response{}, err
	}
	if resp.Status != StatusOk {
		return Response{}, fmt.Errorf("unexpected response status %q (expected %q)", resp.Status, StatusOk)
	}

	return resp, nil
}
