//go:build !linux

package agent

import (
	"errors"
	"time"

	"stackpilot/internal/protocol"
)

type unsupportedTelemetrySampler struct{}

func (s *unsupportedTelemetrySampler) Sample(now time.Time) (*protocol.TelemetryRequest, bool, error) {
	return nil, false, errors.New("telemetry collection is unsupported on non-Linux platforms")
}

func newTelemetrySampler() telemetrySampler {
	return &unsupportedTelemetrySampler{}
}
