package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"stackpilot/internal/protocol"
)

const (
	DefaultTelemetryClientTimeout = 3 * time.Second
)

type telemetrySampler interface {
	Sample(now time.Time) (*protocol.TelemetryRequest, bool, error)
}

type noopTelemetrySampler struct{}

func (s *noopTelemetrySampler) Sample(now time.Time) (*protocol.TelemetryRequest, bool, error) {
	return nil, false, nil
}

func sendTelemetry(ctx context.Context, client *http.Client, targetURL string, req *protocol.TelemetryRequest) error {
	reqPayload, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("%w: failed to marshal telemetry payload", ErrPermanentFailure)
	}

	reqCtx, reqCancel := context.WithTimeout(ctx, DefaultTelemetryClientTimeout)
	defer reqCancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPut, targetURL, bytes.NewReader(reqPayload))
	if err != nil {
		return fmt.Errorf("%w: failed to construct telemetry request: %v", ErrPermanentFailure, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return err
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
		return fmt.Errorf("%w: telemetry request rejected by controller (400)", ErrPermanentFailure)
	case http.StatusTooManyRequests:
		return errors.New("telemetry rate limited by controller (429)")
	default:
		if resp.StatusCode >= 500 && resp.StatusCode <= 599 {
			return fmt.Errorf("controller error (status %d)", resp.StatusCode)
		}
		if resp.StatusCode >= 400 && resp.StatusCode <= 499 {
			return fmt.Errorf("%w: unexpected client error (status %d)", ErrPermanentFailure, resp.StatusCode)
		}
		return fmt.Errorf("unexpected telemetry response status %d", resp.StatusCode)
	}
}
