package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"time"

	"stackpilot/internal/protocol"
)

const (
	DefaultHeartbeatInterval    = 30 * time.Second
	DefaultSuccessJitterPercent = 0.10 // ±10%
	DefaultMaxBackoff           = 30 * time.Second
	DefaultClientTimeout        = 10 * time.Second
)

var (
	// ErrAuthRejected is returned when controller rejects agent authentication (HTTP 401).
	ErrAuthRejected = errors.New("agent authentication rejected by controller")
	// ErrProtocolMismatch is returned when controller rejects agent protocol version (HTTP 409).
	ErrProtocolMismatch = errors.New("controller rejected agent protocol version")
	// ErrPermanentFailure marks unrecoverable heartbeat errors.
	ErrPermanentFailure = errors.New("permanent heartbeat error")
)

// IsPermanentError reports whether an error indicates a permanent failure that should terminate the daemon.
func IsPermanentError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrAuthRejected) ||
		errors.Is(err, ErrProtocolMismatch) ||
		errors.Is(err, ErrPermanentFailure)
}

type certManager struct {
	privKey       ed25519.PrivateKey
	rootCAs       *x509.CertPool
	client        *http.Client
	currentCert   tls.Certificate
	certExpiresAt time.Time
	refreshAt     time.Time
	nowFunc       func() time.Time
	randReader    io.Reader
	refreshMargin time.Duration
	clientBuilder func(rootCAs *x509.CertPool, cert *tls.Certificate) *http.Client
}

func newCertManager(
	privKey ed25519.PrivateKey,
	rootCAs *x509.CertPool,
	nowFunc func() time.Time,
	randReader io.Reader,
	refreshMargin time.Duration,
	clientBuilder func(rootCAs *x509.CertPool, cert *tls.Certificate) *http.Client,
) *certManager {
	if nowFunc == nil {
		nowFunc = time.Now
	}
	if randReader == nil {
		randReader = rand.Reader
	}
	if refreshMargin <= 0 {
		refreshMargin = DefaultCertRefreshMargin
	}

	return &certManager{
		privKey:       privKey,
		rootCAs:       rootCAs,
		nowFunc:       nowFunc,
		randReader:    randReader,
		refreshMargin: refreshMargin,
		clientBuilder: clientBuilder,
	}
}

func (cm *certManager) buildCert(now time.Time) (tls.Certificate, time.Time, error) {
	cert, err := buildEphemeralClientCertWithSource(cm.privKey, cm.randReader, func() time.Time { return now })
	if err != nil {
		return tls.Certificate{}, time.Time{}, err
	}
	if cert.Leaf == nil {
		parsed, parseErr := x509.ParseCertificate(cert.Certificate[0])
		if parseErr != nil {
			return tls.Certificate{}, time.Time{}, fmt.Errorf("failed to parse client certificate: %w", parseErr)
		}
		cert.Leaf = parsed
	}
	return cert, cert.Leaf.NotAfter, nil
}

func (cm *certManager) getClient() (*http.Client, error) {
	now := cm.nowFunc()
	if cm.client == nil || !now.Before(cm.refreshAt) {
		cert, expiresAt, err := cm.buildCert(now)
		if err != nil {
			return nil, err
		}

		oldClient := cm.client
		builder := cm.clientBuilder
		if builder == nil {
			builder = BuildAgentHTTPClient
		}
		cm.client = builder(cm.rootCAs, &cert)
		cm.currentCert = cert
		cm.certExpiresAt = expiresAt
		cm.refreshAt = expiresAt.Add(-cm.refreshMargin)

		if oldClient != nil {
			oldClient.CloseIdleConnections()
		}
	}
	return cm.client, nil
}

func (cm *certManager) close() {
	if cm.client != nil {
		cm.client.CloseIdleConnections()
	}
}

// presenceConfig exposes deterministic seams for unit and integration testing.
type presenceConfig struct {
	nowFunc       func() time.Time
	timerFunc     func(d time.Duration) (<-chan time.Time, func() bool)
	jitterFunc    func(base time.Duration, pct float64) time.Duration
	randReader    io.Reader
	refreshMargin time.Duration
	baseInterval  time.Duration
	maxBackoff    time.Duration
	clientBuilder func(rootCAs *x509.CertPool, cert *tls.Certificate) *http.Client
}

func defaultPresenceConfig() presenceConfig {
	return presenceConfig{
		nowFunc:       time.Now,
		timerFunc:     realTimer,
		jitterFunc:    defaultJitter,
		randReader:    rand.Reader,
		refreshMargin: DefaultCertRefreshMargin,
		baseInterval:  DefaultHeartbeatInterval,
		maxBackoff:    DefaultMaxBackoff,
		clientBuilder: BuildAgentHTTPClient,
	}
}

func realTimer(d time.Duration) (<-chan time.Time, func() bool) {
	t := time.NewTimer(d)
	return t.C, t.Stop
}

func defaultJitter(base time.Duration, pct float64) time.Duration {
	if pct <= 0 {
		return base
	}
	delta := int64(float64(base.Nanoseconds()) * pct)
	if delta <= 0 {
		return base
	}
	limit := new(big.Int).SetInt64(2*delta + 1)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return base
	}
	offset := n.Int64() - delta
	result := base.Nanoseconds() + offset
	if result < 0 {
		return base
	}
	return time.Duration(result)
}

func computeBackoff(failCount int, maxBackoff time.Duration, jitterFunc func(time.Duration, float64) time.Duration) time.Duration {
	base := 1 * time.Second
	if failCount > 1 {
		shift := failCount - 1
		if shift > 5 {
			shift = 5
		}
		base = (1 << shift) * time.Second
	}
	if base > maxBackoff {
		base = maxBackoff
	}
	result := base
	if jitterFunc != nil {
		result = jitterFunc(base, 0.10)
	}
	if result > maxBackoff {
		result = maxBackoff
	}
	if result < 0 {
		result = 0
	}
	return result
}

// RunPresence executes the agent presence daemon loop.
func RunPresence(ctx context.Context, logger *slog.Logger, stateDir string) error {
	return runPresenceWithConfig(ctx, logger, stateDir, defaultPresenceConfig())
}

func runPresenceWithConfig(ctx context.Context, logger *slog.Logger, stateDir string, cfg presenceConfig) error {
	if stateDir == "" {
		return errors.New("state directory is required")
	}

	meta, err := LoadIdentityMetadata(stateDir)
	if err != nil {
		return fmt.Errorf("failed to load agent identity: %w", err)
	}

	ctrlURL, err := ValidateControllerURL(meta.ControllerURL)
	if err != nil {
		return fmt.Errorf("invalid controller URL in identity: %w", err)
	}

	if ctrlURL.Scheme != "https" {
		return errors.New("agent presence requires HTTPS controller URL; found HTTP loopback identity")
	}

	rootCAs, err := LoadControllerTrustRoots(stateDir)
	if err != nil {
		return fmt.Errorf("failed to load controller trust roots: %w", err)
	}

	privKey, err := loadExistingPrivateKey(stateDir)
	if err != nil {
		return fmt.Errorf("failed to load agent private key: %w", err)
	}

	cm := newCertManager(privKey, rootCAs, cfg.nowFunc, cfg.randReader, cfg.refreshMargin, cfg.clientBuilder)
	defer cm.close()

	if logger != nil {
		logger.Info("agent presence daemon started", "agent_id", meta.AgentID, "controller", meta.ControllerURL)
	}

	heartbeatURL := ctrlURL.ResolveReference(&url.URL{Path: protocol.HeartbeatEndpointPath}).String()

	consecutiveFailures := 0
	loggedFailure := false

	for {
		if ctx.Err() != nil {
			return nil
		}

		client, err := cm.getClient()
		if err != nil {
			if logger != nil {
				logger.Error("failed to obtain client certificate", "error", err)
			}
			return fmt.Errorf("%w: %v", ErrPermanentFailure, err)
		}

		hbErr := sendHeartbeat(ctx, client, heartbeatURL)
		if hbErr != nil {
			if ctx.Err() != nil {
				return nil
			}

			if IsPermanentError(hbErr) {
				if logger != nil {
					logger.Error("permanent heartbeat failure; stopping daemon", "error", hbErr)
				}
				return hbErr
			}

			consecutiveFailures++
			if !loggedFailure {
				if logger != nil {
					logger.Warn("controller heartbeat failed; backing off", "error", hbErr)
				}
				loggedFailure = true
			}

			waitDur := computeBackoff(consecutiveFailures, cfg.maxBackoff, cfg.jitterFunc)
			ch, stop := cfg.timerFunc(waitDur)
			select {
			case <-ctx.Done():
				stop()
				return nil
			case <-ch:
			}
		} else {
			if loggedFailure {
				if logger != nil {
					logger.Info("controller heartbeat recovered", "agent_id", meta.AgentID)
				}
				loggedFailure = false
			}
			consecutiveFailures = 0

			waitDur := cfg.baseInterval
			if cfg.jitterFunc != nil {
				waitDur = cfg.jitterFunc(cfg.baseInterval, DefaultSuccessJitterPercent)
			}

			ch, stop := cfg.timerFunc(waitDur)
			select {
			case <-ctx.Done():
				stop()
				return nil
			case <-ch:
			}
		}
	}
}

func sendHeartbeat(ctx context.Context, client *http.Client, targetURL string) error {
	reqPayload, err := json.Marshal(protocol.HeartbeatRequest{
		ProtocolVersion: protocol.CurrentVersion,
	})
	if err != nil {
		return fmt.Errorf("%w: failed to marshal heartbeat payload", ErrPermanentFailure)
	}

	reqCtx, reqCancel := context.WithTimeout(ctx, DefaultClientTimeout)
	defer reqCancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, targetURL, bytes.NewReader(reqPayload))
	if err != nil {
		return fmt.Errorf("%w: failed to construct heartbeat request: %v", ErrPermanentFailure, err)
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
		return fmt.Errorf("%w: request rejected by controller (400)", ErrPermanentFailure)
	case http.StatusTooManyRequests:
		return errors.New("heartbeat rate limited by controller (429)")
	default:
		if resp.StatusCode >= 500 && resp.StatusCode <= 599 {
			return fmt.Errorf("controller error (status %d)", resp.StatusCode)
		}
		if resp.StatusCode >= 400 && resp.StatusCode <= 499 {
			return fmt.Errorf("%w: unexpected client error (status %d)", ErrPermanentFailure, resp.StatusCode)
		}
		return fmt.Errorf("unexpected heartbeat response status %d", resp.StatusCode)
	}
}
