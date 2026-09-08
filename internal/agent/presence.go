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
	"unicode/utf8"

	"stackpilot/internal/job"
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
	// ErrPermanentFailure marks unrecoverable agent loop errors.
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
	nowFunc                func() time.Time
	timerFunc              func(d time.Duration) (<-chan time.Time, func() bool)
	jitterFunc             func(base time.Duration, pct float64) time.Duration
	randReader             io.Reader
	refreshMargin          time.Duration
	baseInterval           time.Duration
	maxBackoff             time.Duration
	clientBuilder          func(rootCAs *x509.CertPool, cert *tls.Certificate) *http.Client
	inventoryInterval      time.Duration
	inventoryRetryInterval time.Duration
	collector              func() (*protocol.InventoryRequest, error)
	sampler                telemetrySampler
	executor               TypedExecutor
}

func defaultPresenceConfig() presenceConfig {
	return presenceConfig{
		nowFunc:                time.Now,
		timerFunc:              realTimer,
		jitterFunc:             defaultJitter,
		randReader:             rand.Reader,
		refreshMargin:          DefaultCertRefreshMargin,
		baseInterval:           DefaultHeartbeatInterval,
		maxBackoff:             DefaultMaxBackoff,
		clientBuilder:          BuildAgentHTTPClient,
		inventoryInterval:      DefaultInventoryInterval,
		inventoryRetryInterval: DefaultInventoryRetryInterval,
		collector:              collectLinuxInventory,
		sampler:                newTelemetrySampler(),
		executor:               NewExecutor(),
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
	inventoryURL := ctrlURL.ResolveReference(&url.URL{Path: protocol.InventoryEndpointPath}).String()
	telemetryURL := ctrlURL.ResolveReference(&url.URL{Path: protocol.TelemetryEndpointPath}).String()
	jobStartURL := ctrlURL.ResolveReference(&url.URL{Path: protocol.AgentJobStartEndpointPath}).String()
	jobCompleteURL := ctrlURL.ResolveReference(&url.URL{Path: protocol.AgentJobCompleteEndpointPath}).String()

	sampler := cfg.sampler
	if sampler == nil {
		sampler = &noopTelemetrySampler{}
	}
	executor := cfg.executor
	if executor == nil {
		executor = NewExecutor()
	}

	consecutiveFailures := 0
	loggedFailure := false

	var nextInventoryAt time.Time
	inventoryFailureLogged := false
	telemetryFailureLogged := false

	var pendingCompletion *protocol.JobCompleteRequest

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

		assignment, hbErr := sendHeartbeat(ctx, client, heartbeatURL)
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

			if pendingCompletion != nil {
				compErr := sendJobComplete(ctx, client, jobCompleteURL, pendingCompletion)
				if compErr != nil {
					if IsPermanentError(compErr) {
						return compErr
					}
					// If terminal conflict (e.g. late completion became unknown), drop pending completion
					if errors.Is(compErr, job.ErrJobConflict) {
						pendingCompletion = nil
					}
				} else {
					pendingCompletion = nil
				}
			}

			if pendingCompletion == nil && assignment != nil {
				if err := protocol.ValidateJobAssignment(assignment); err != nil {
					return fmt.Errorf("%w: invalid job assignment: %v", ErrPermanentFailure, err)
				}

				// At-most-once execution contract: heartbeat delivery does not authorize execution; start must return HTTP 204
				startErr := sendJobStart(ctx, client, jobStartURL, assignment.JobID, assignment.Attempt)
				if startErr != nil {
					if IsPermanentError(startErr) {
						return startErr
					}
					// If start returned 409 or network error: drop assignment safely, do not execute
					assignment = nil
				} else {
					var execOutcome string
					var execFailureCode string
					if err := executor.Execute(ctx, assignment.Action); err != nil {
						execOutcome = "failed"
						execFailureCode = "executor_error"
					} else {
						execOutcome = "succeeded"
						execFailureCode = ""
					}

					completionReq := &protocol.JobCompleteRequest{
						ProtocolVersion: protocol.CurrentVersion,
						JobID:           assignment.JobID,
						Attempt:         assignment.Attempt,
						Outcome:         execOutcome,
						FailureCode:     execFailureCode,
					}

					compErr := sendJobComplete(ctx, client, jobCompleteURL, completionReq)
					if compErr != nil {
						if IsPermanentError(compErr) {
							return compErr
						}
						// Transient network/timeout/5xx: retain in memory for next heartbeat retry
						if !errors.Is(compErr, job.ErrJobConflict) {
							pendingCompletion = completionReq
						}
					}
				}
			}

			inventoryNow := cfg.nowFunc()
			if nextInventoryAt.IsZero() || !inventoryNow.Before(nextInventoryAt) {
				var invReport *protocol.InventoryRequest
				var collectErr error
				if cfg.collector != nil {
					invReport, collectErr = cfg.collector()
				} else {
					invReport, collectErr = collectLinuxInventory()
				}

				if collectErr != nil {
					if !inventoryFailureLogged {
						if logger != nil {
							logger.Warn("agent inventory collection failed; will retry", "error", collectErr)
						}
						inventoryFailureLogged = true
					}
					retryDur := cfg.inventoryRetryInterval
					if retryDur <= 0 {
						retryDur = DefaultInventoryRetryInterval
					}
					if cfg.jitterFunc != nil {
						retryDur = cfg.jitterFunc(retryDur, 0.10)
					}
					nextInventoryAt = inventoryNow.Add(retryDur)
				} else {
					invErr := sendInventory(ctx, client, inventoryURL, invReport)
					if invErr != nil {
						if ctx.Err() != nil {
							return nil
						}
						if IsPermanentError(invErr) {
							if logger != nil {
								logger.Error("permanent inventory failure; stopping daemon", "error", invErr)
							}
							return invErr
						}

						if !inventoryFailureLogged {
							if logger != nil {
								logger.Warn("agent inventory delivery failed; will retry", "error", invErr)
							}
							inventoryFailureLogged = true
						}
						retryDur := cfg.inventoryRetryInterval
						if retryDur <= 0 {
							retryDur = DefaultInventoryRetryInterval
						}
						if cfg.jitterFunc != nil {
							retryDur = cfg.jitterFunc(retryDur, 0.10)
						}
						nextInventoryAt = inventoryNow.Add(retryDur)
					} else {
						if inventoryFailureLogged {
							if logger != nil {
								logger.Info("agent inventory delivery recovered", "agent_id", meta.AgentID)
							}
							inventoryFailureLogged = false
						}
						interval := cfg.inventoryInterval
						if interval <= 0 {
							interval = DefaultInventoryInterval
						}
						if cfg.jitterFunc != nil {
							interval = cfg.jitterFunc(interval, 0.10)
						}
						nextInventoryAt = inventoryNow.Add(interval)
					}
				}
			}

			telemetryNow := cfg.nowFunc()
			telemReport, ready, telemErr := sampler.Sample(telemetryNow)
			if telemErr != nil {
				if !telemetryFailureLogged {
					if logger != nil {
						logger.Warn("agent telemetry collection failed; will retry", "error", telemErr)
					}
					telemetryFailureLogged = true
				}
			} else if ready && telemReport != nil {
				sendErr := sendTelemetry(ctx, client, telemetryURL, telemReport)
				if sendErr != nil {
					if ctx.Err() != nil {
						return nil
					}
					if IsPermanentError(sendErr) {
						if logger != nil {
							logger.Error("permanent telemetry failure; stopping daemon", "error", sendErr)
						}
						return sendErr
					}

					if !telemetryFailureLogged {
						if logger != nil {
							logger.Warn("agent telemetry delivery failed; will retry", "error", sendErr)
						}
						telemetryFailureLogged = true
					}
				} else {
					if telemetryFailureLogged {
						if logger != nil {
							logger.Info("agent telemetry recovered", "agent_id", meta.AgentID)
						}
						telemetryFailureLogged = false
					}
				}
			}

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

func sendHeartbeat(ctx context.Context, client *http.Client, targetURL string) (*protocol.JobAssignment, error) {
	reqPayload, err := json.Marshal(protocol.HeartbeatRequest{
		ProtocolVersion: protocol.CurrentVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: failed to marshal heartbeat payload", ErrPermanentFailure)
	}

	reqCtx, reqCancel := context.WithTimeout(ctx, DefaultClientTimeout)
	defer reqCancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, targetURL, bytes.NewReader(reqPayload))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to construct heartbeat request: %v", ErrPermanentFailure, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err // Transient network/TLS error
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil, nil
	case http.StatusOK:
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1025))
		if err != nil {
			return nil, fmt.Errorf("%w: failed to read heartbeat response body: %v", ErrPermanentFailure, err)
		}
		if len(bodyBytes) > 1024 {
			return nil, fmt.Errorf("%w: heartbeat response body too large", ErrPermanentFailure)
		}
		if !utf8.Valid(bodyBytes) {
			return nil, fmt.Errorf("%w: heartbeat response is not valid UTF-8", ErrPermanentFailure)
		}
		var hbResp protocol.HeartbeatResponse
		dec := json.NewDecoder(bytes.NewReader(bodyBytes))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&hbResp); err != nil {
			return nil, fmt.Errorf("%w: malformed heartbeat response: %v", ErrPermanentFailure, err)
		}
		var extra any
		if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: trailing data in heartbeat response", ErrPermanentFailure)
		}
		if hbResp.ProtocolVersion != protocol.CurrentVersion {
			return nil, ErrProtocolMismatch
		}
		if hbResp.Job == nil {
			return nil, fmt.Errorf("%w: HTTP 200 heartbeat missing job assignment", ErrPermanentFailure)
		}
		if err := protocol.ValidateJobAssignment(hbResp.Job); err != nil {
			return nil, fmt.Errorf("%w: invalid job assignment: %v", ErrPermanentFailure, err)
		}
		return hbResp.Job, nil
	case http.StatusUnauthorized:
		return nil, ErrAuthRejected
	case http.StatusConflict:
		return nil, ErrProtocolMismatch
	case http.StatusBadRequest:
		return nil, fmt.Errorf("%w: request rejected by controller (400)", ErrPermanentFailure)
	case http.StatusTooManyRequests:
		return nil, errors.New("heartbeat rate limited by controller (429)")
	default:
		if resp.StatusCode >= 500 && resp.StatusCode <= 599 {
			return nil, fmt.Errorf("controller error (status %d)", resp.StatusCode)
		}
		if resp.StatusCode >= 400 && resp.StatusCode <= 499 {
			return nil, fmt.Errorf("%w: unexpected client error (status %d)", ErrPermanentFailure, resp.StatusCode)
		}
		return nil, fmt.Errorf("unexpected heartbeat response status %d", resp.StatusCode)
	}
}

// sendJobStart issues POST /api/v1/agent/job/start with bounded 5s timeout.
// Returns nil on HTTP 204 (authorizing execution), or an error.
func sendJobStart(ctx context.Context, client *http.Client, targetURL string, jobID string, attempt int) error {
	reqPayload, err := json.Marshal(protocol.JobStartRequest{
		ProtocolVersion: protocol.CurrentVersion,
		JobID:           jobID,
		Attempt:         attempt,
	})
	if err != nil {
		return fmt.Errorf("%w: failed to marshal start payload", ErrPermanentFailure)
	}

	reqCtx, reqCancel := context.WithTimeout(ctx, 5*time.Second)
	defer reqCancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, targetURL, bytes.NewReader(reqPayload))
	if err != nil {
		return fmt.Errorf("%w: failed to construct start request: %v", ErrPermanentFailure, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return err // Transient network error
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
		// Job-state 409 or protocol conflict: caller will inspect or drop assignment safely
		return job.ErrJobConflict
	case http.StatusTooManyRequests:
		return errors.New("start rate limited by controller (429)")
	default:
		if resp.StatusCode >= 500 && resp.StatusCode <= 599 {
			return fmt.Errorf("controller start error (status %d)", resp.StatusCode)
		}
		if resp.StatusCode >= 400 && resp.StatusCode <= 499 {
			return fmt.Errorf("%w: unexpected client error (status %d)", ErrPermanentFailure, resp.StatusCode)
		}
		return fmt.Errorf("unexpected start response status %d", resp.StatusCode)
	}
}

// sendJobComplete issues POST /api/v1/agent/job/complete with bounded 5s timeout.
// Returns nil on HTTP 204 (completion accepted/replayed).
func sendJobComplete(ctx context.Context, client *http.Client, targetURL string, req *protocol.JobCompleteRequest) error {
	reqPayload, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("%w: failed to marshal complete payload", ErrPermanentFailure)
	}

	reqCtx, reqCancel := context.WithTimeout(ctx, 5*time.Second)
	defer reqCancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, targetURL, bytes.NewReader(reqPayload))
	if err != nil {
		return fmt.Errorf("%w: failed to construct complete request: %v", ErrPermanentFailure, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return err // Transient network error
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
		return job.ErrJobConflict
	case http.StatusTooManyRequests:
		return errors.New("complete rate limited by controller (429)")
	default:
		if resp.StatusCode >= 500 && resp.StatusCode <= 599 {
			return fmt.Errorf("controller complete error (status %d)", resp.StatusCode)
		}
		if resp.StatusCode >= 400 && resp.StatusCode <= 499 {
			return fmt.Errorf("%w: unexpected client error (status %d)", ErrPermanentFailure, resp.StatusCode)
		}
		return fmt.Errorf("unexpected complete response status %d", resp.StatusCode)
	}
}
