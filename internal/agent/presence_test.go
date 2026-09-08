package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"stackpilot/internal/job"
	"stackpilot/internal/protocol"
)

func setupTestEnrolledState(t *testing.T, controllerURL string) (string, [32]byte, []byte) {
	t.Helper()

	tempDir := t.TempDir()
	stateDir := filepath.Join(tempDir, "state")
	if err := EnsureStateDir(stateDir); err != nil {
		t.Fatalf("EnsureStateDir failed: %v", err)
	}

	pub, _, err := LoadOrGenerateKey(stateDir, rand.Reader)
	if err != nil {
		t.Fatalf("LoadOrGenerateKey failed: %v", err)
	}

	meta := &IdentityMetadata{
		Version:       1,
		AgentID:       "018f0000-0000-7000-8000-000000000005",
		ControllerURL: controllerURL,
		PublicKey:     FormatPublicKeyBase64RawURL(pub),
	}
	if err := WriteIdentityMetadata(stateDir, meta); err != nil {
		t.Fatalf("WriteIdentityMetadata failed: %v", err)
	}

	var pubKey [32]byte
	copy(pubKey[:], pub)
	return stateDir, pubKey, nil
}

func setupTestCAAndServer(t *testing.T, handler http.Handler) (*tls.Certificate, []byte, *httptest.Server) {
	t.Helper()

	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey failed: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "StackPilot Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caPriv)
	if err != nil {
		t.Fatalf("CreateCertificate CA failed: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	srvPub, srvPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey srv failed: %v", err)
	}
	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(101),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, srvPub, caPriv)
	if err != nil {
		t.Fatalf("CreateCertificate srv failed: %v", err)
	}
	srvTLSCert := tls.Certificate{
		Certificate: [][]byte{srvDER},
		PrivateKey:  srvPriv,
	}

	ts := httptest.NewUnstartedServer(handler)
	ts.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{srvTLSCert},
		ClientAuth:   tls.RequestClientCert,
	}
	ts.StartTLS()

	return &srvTLSCert, caPEM, ts
}

func TestPresence_StartupValidation(t *testing.T) {
	t.Run("missing state directory rejected", func(t *testing.T) {
		err := RunPresence(context.Background(), nil, "")
		if err == nil {
			t.Fatal("expected error for empty stateDir, got nil")
		}
	})

	t.Run("corrupt identity fails immediately without network", func(t *testing.T) {
		tempDir := t.TempDir()
		stateDir := filepath.Join(tempDir, "state")
		_ = EnsureStateDir(stateDir)
		_ = os.WriteFile(filepath.Join(stateDir, IdentityJSONFileName), []byte("corrupt"), 0600)

		err := RunPresence(context.Background(), nil, stateDir)
		if err == nil {
			t.Fatal("expected error for corrupt identity, got nil")
		}
	})

	t.Run("http loopback controller URL rejected", func(t *testing.T) {
		stateDir, _, _ := setupTestEnrolledState(t, "http://127.0.0.1:7447")
		err := RunPresence(context.Background(), nil, stateDir)
		if err == nil {
			t.Fatal("expected error for HTTP controller URL, got nil")
		}
		if !strings.Contains(err.Error(), "HTTPS controller URL") {
			t.Fatalf("expected error to mention HTTPS requirement, got %v", err)
		}
	})
}

func TestPresence_DeterministicLoop(t *testing.T) {
	// Tests deterministic presence behavior using mock timers and mock HTTP responses.
	t.Run("first heartbeat is immediate and success schedules normal jittered interval", func(t *testing.T) {
		var (
			heartbeatCount int
			durations      []time.Duration
			mu             sync.Mutex
		)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			heartbeatCount++
			mu.Unlock()
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNoContent)
		})

		_, caPEM, ts := setupTestCAAndServer(t, handler)
		defer ts.Close()

		stateDir, _, _ := setupTestEnrolledState(t, ts.URL)
		caFile := filepath.Join(stateDir, "custom-ca.pem")
		_ = os.WriteFile(caFile, caPEM, 0644)
		if err := ValidateAndPersistCAFile(stateDir, caFile); err != nil {
			t.Fatalf("ValidateAndPersistCAFile failed: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cfg := defaultPresenceConfig()
		cfg.timerFunc = func(d time.Duration) (<-chan time.Time, func() bool) {
			mu.Lock()
			durations = append(durations, d)
			mu.Unlock()
			ch := make(chan time.Time, 1)
			if len(durations) >= 2 {
				// Cancel after observing immediate first heartbeat + scheduled interval
				cancel()
			} else {
				ch <- time.Now()
			}
			return ch, func() bool { return true }
		}
		cfg.jitterFunc = func(base time.Duration, pct float64) time.Duration {
			return base // deterministic
		}

		err := runPresenceWithConfig(ctx, nil, stateDir, cfg)
		if err != nil {
			t.Fatalf("expected clean exit, got: %v", err)
		}

		mu.Lock()
		defer mu.Unlock()
		if heartbeatCount < 1 {
			t.Fatalf("expected at least 1 immediate heartbeat, got %d", heartbeatCount)
		}
		if len(durations) < 1 {
			t.Fatal("expected at least 1 duration recorded")
		}
		if durations[0] != DefaultHeartbeatInterval {
			t.Fatalf("expected normal interval %v, got %v", DefaultHeartbeatInterval, durations[0])
		}
	})

	t.Run("transient 500 error triggers exponential backoff capped at max", func(t *testing.T) {
		var (
			durations []time.Duration
			mu        sync.Mutex
		)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})

		_, caPEM, ts := setupTestCAAndServer(t, handler)
		defer ts.Close()

		stateDir, _, _ := setupTestEnrolledState(t, ts.URL)
		caFile := filepath.Join(stateDir, "custom-ca.pem")
		_ = os.WriteFile(caFile, caPEM, 0644)
		_ = ValidateAndPersistCAFile(stateDir, caFile)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cfg := defaultPresenceConfig()
		cfg.timerFunc = func(d time.Duration) (<-chan time.Time, func() bool) {
			mu.Lock()
			durations = append(durations, d)
			count := len(durations)
			mu.Unlock()

			ch := make(chan time.Time, 1)
			if count >= 7 {
				cancel()
			} else {
				ch <- time.Now()
			}
			return ch, func() bool { return true }
		}
		cfg.jitterFunc = func(base time.Duration, pct float64) time.Duration {
			return base // deterministic
		}

		_ = runPresenceWithConfig(ctx, nil, stateDir, cfg)

		mu.Lock()
		defer mu.Unlock()
		// Expected progression: 1s, 2s, 4s, 8s, 16s, 30s, 30s
		expected := []time.Duration{
			1 * time.Second,
			2 * time.Second,
			4 * time.Second,
			8 * time.Second,
			16 * time.Second,
			30 * time.Second,
			30 * time.Second,
		}
		if len(durations) != len(expected) {
			t.Fatalf("expected exactly %d backoff durations, got %d", len(expected), len(durations))
		}
		for i, want := range expected {
			if durations[i] != want {
				t.Errorf("duration[%d]: got %v, want %v", i, durations[i], want)
			}
		}
	})

	t.Run("success resets backoff", func(t *testing.T) {
		var (
			failNext  = true
			durations []time.Duration
			mu        sync.Mutex
		)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			shouldFail := failNext
			failNext = false // succeed next
			mu.Unlock()

			if shouldFail {
				w.WriteHeader(http.StatusServiceUnavailable)
			} else {
				w.WriteHeader(http.StatusNoContent)
			}
		})

		_, caPEM, ts := setupTestCAAndServer(t, handler)
		defer ts.Close()

		stateDir, _, _ := setupTestEnrolledState(t, ts.URL)
		caFile := filepath.Join(stateDir, "custom-ca.pem")
		_ = os.WriteFile(caFile, caPEM, 0644)
		_ = ValidateAndPersistCAFile(stateDir, caFile)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cfg := defaultPresenceConfig()
		cfg.timerFunc = func(d time.Duration) (<-chan time.Time, func() bool) {
			mu.Lock()
			durations = append(durations, d)
			count := len(durations)
			mu.Unlock()

			ch := make(chan time.Time, 1)
			if count >= 2 {
				cancel()
			} else {
				ch <- time.Now()
			}
			return ch, func() bool { return true }
		}
		cfg.jitterFunc = func(base time.Duration, pct float64) time.Duration {
			return base
		}

		_ = runPresenceWithConfig(ctx, nil, stateDir, cfg)

		mu.Lock()
		defer mu.Unlock()
		if len(durations) != 2 {
			t.Fatalf("expected exactly 2 durations, got %d", len(durations))
		}
		if durations[0] != 1*time.Second {
			t.Errorf("expected first duration 1s, got %v", durations[0])
		}
		if durations[1] != DefaultHeartbeatInterval {
			t.Errorf("expected reset to %v on success, got %v", DefaultHeartbeatInterval, durations[1])
		}
	})

	t.Run("401 auth rejected stops loop immediately as permanent failure", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		})

		_, caPEM, ts := setupTestCAAndServer(t, handler)
		defer ts.Close()

		stateDir, _, _ := setupTestEnrolledState(t, ts.URL)
		caFile := filepath.Join(stateDir, "custom-ca.pem")
		_ = os.WriteFile(caFile, caPEM, 0644)
		_ = ValidateAndPersistCAFile(stateDir, caFile)

		err := RunPresence(context.Background(), nil, stateDir)
		if err == nil {
			t.Fatal("expected error on 401 unauthorized, got nil")
		}
		if !errors.Is(err, ErrAuthRejected) {
			t.Fatalf("expected ErrAuthRejected, got: %v", err)
		}
	})

	t.Run("409 protocol mismatch stops loop immediately as permanent failure", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusConflict)
		})

		_, caPEM, ts := setupTestCAAndServer(t, handler)
		defer ts.Close()

		stateDir, _, _ := setupTestEnrolledState(t, ts.URL)
		caFile := filepath.Join(stateDir, "custom-ca.pem")
		_ = os.WriteFile(caFile, caPEM, 0644)
		_ = ValidateAndPersistCAFile(stateDir, caFile)

		err := RunPresence(context.Background(), nil, stateDir)
		if err == nil {
			t.Fatal("expected error on 409 conflict, got nil")
		}
		if !errors.Is(err, ErrProtocolMismatch) {
			t.Fatalf("expected ErrProtocolMismatch, got: %v", err)
		}
	})

	t.Run("logging behavior: no flood on repeated failure and single recovery message", func(t *testing.T) {
		failCount := 0
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if failCount < 3 {
				failCount++
				w.WriteHeader(http.StatusInternalServerError)
			} else {
				w.WriteHeader(http.StatusNoContent)
			}
		})

		_, caPEM, ts := setupTestCAAndServer(t, handler)
		defer ts.Close()

		stateDir, _, _ := setupTestEnrolledState(t, ts.URL)
		caFile := filepath.Join(stateDir, "custom-ca.pem")
		_ = os.WriteFile(caFile, caPEM, 0644)
		_ = ValidateAndPersistCAFile(stateDir, caFile)

		logBuf := &bytes.Buffer{}
		logger := slog.New(slog.NewTextHandler(logBuf, nil))

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		callCount := 0
		cfg := defaultPresenceConfig()
		cfg.timerFunc = func(d time.Duration) (<-chan time.Time, func() bool) {
			callCount++
			ch := make(chan time.Time, 1)
			if callCount >= 4 {
				cancel()
			} else {
				ch <- time.Now()
			}
			return ch, func() bool { return true }
		}
		cfg.jitterFunc = func(base time.Duration, pct float64) time.Duration {
			return base
		}
		cfg.sampler = &noopTelemetrySampler{}

		_ = runPresenceWithConfig(ctx, logger, stateDir, cfg)

		logStr := logBuf.String()
		// Count warnings
		warnCount := strings.Count(logStr, "level=WARN")
		if warnCount != 1 {
			t.Errorf("expected exactly 1 warning on repeated failures, got %d. Logs:\n%s", warnCount, logStr)
		}

		// Verify recovery message logged once
		recoveryCount := strings.Count(logStr, "controller heartbeat recovered")
		if recoveryCount != 1 {
			t.Errorf("expected exactly 1 recovery log message, got %d. Logs:\n%s", recoveryCount, logStr)
		}
	})
}

type trackingRoundTripper struct {
	mu         sync.Mutex
	closeCount int
}

func (t *trackingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(nil)),
	}, nil
}

func (t *trackingRoundTripper) CloseIdleConnections() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closeCount++
}

func (t *trackingRoundTripper) getCloseCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closeCount
}

func TestPresence_CertificateRotation(t *testing.T) {
	// Section 46: Certificate rotation testability
	// Tests that:
	// - initial client certificate exists
	// - same client reused before refresh threshold (client2 == client1)
	// - client replaced after crossing refresh threshold (client3 != client1)
	// - certificate rotates before expiration
	// - old idle connections closed safely (count == 0 before rotation, count == 1 after)
	// - new certificate uses SAME Agent Ed25519 identity
	// - no certificate file appears in state-dir
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey failed: %v", err)
	}

	currentTime := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	nowFunc := func() time.Time {
		return currentTime
	}

	tempDir := t.TempDir()
	stateDir := filepath.Join(tempDir, "state")
	_ = EnsureStateDir(stateDir)

	rootPool := x509.NewCertPool()

	var (
		trackersMu sync.Mutex
		trackers   []*trackingRoundTripper
	)
	testClientBuilder := func(pool *x509.CertPool, tlsCert *tls.Certificate) *http.Client {
		c := BuildAgentHTTPClient(pool, tlsCert)
		tracker := &trackingRoundTripper{}
		c.Transport = tracker
		trackersMu.Lock()
		trackers = append(trackers, tracker)
		trackersMu.Unlock()
		return c
	}

	cm := newCertManager(priv, rootPool, nowFunc, rand.Reader, 10*time.Minute, testClientBuilder)
	defer cm.close()

	// 1. Initial client created
	client1, err := cm.getClient()
	if err != nil {
		t.Fatalf("first getClient failed: %v", err)
	}
	trackersMu.Lock()
	if len(trackers) != 1 {
		t.Fatalf("expected 1 client tracker, got %d", len(trackers))
	}
	initialTracker := trackers[0]
	trackersMu.Unlock()

	if initialTracker.getCloseCount() != 0 {
		t.Fatalf("before rotation: expected old client close count == 0, got %d", initialTracker.getCloseCount())
	}

	cert1 := cm.currentCert
	if len(cert1.Certificate) == 0 {
		t.Fatal("expected cert1 to contain DER bytes")
	}

	parsed1, err := x509.ParseCertificate(cert1.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse cert1: %v", err)
	}
	if !parsed1.PublicKey.(ed25519.PublicKey).Equal(pub) {
		t.Fatal("cert1 public key does not match agent public key")
	}

	// 2. Advance time to 40 minutes (before 50-minute refresh margin) -> same client & cert reused
	currentTime = currentTime.Add(40 * time.Minute)
	client2, err := cm.getClient()
	if err != nil {
		t.Fatalf("second getClient failed: %v", err)
	}
	if client2 != client1 {
		t.Fatal("expected client to be reused before refresh threshold: client2 == client1")
	}
	if !bytes.Equal(cm.currentCert.Certificate[0], cert1.Certificate[0]) {
		t.Fatal("expected certificate to remain identical before refresh threshold")
	}
	if initialTracker.getCloseCount() != 0 {
		t.Fatalf("before rotation: expected old client close count == 0, got %d", initialTracker.getCloseCount())
	}

	// 3. Advance time to 51 minutes (past 50-minute refresh threshold, 9 minutes before expiry) -> rotates
	currentTime = currentTime.Add(11 * time.Minute)
	client3, err := cm.getClient()
	if err != nil {
		t.Fatalf("third getClient failed: %v", err)
	}
	if client3 == client1 {
		t.Fatal("expected new client after crossing refresh threshold: client3 != client1")
	}
	if initialTracker.getCloseCount() != 1 {
		t.Fatalf("after rotation: expected old client close count == 1, got %d", initialTracker.getCloseCount())
	}

	trackersMu.Lock()
	if len(trackers) != 2 {
		t.Fatalf("expected 2 client trackers, got %d", len(trackers))
	}
	newTracker := trackers[1]
	trackersMu.Unlock()

	if newTracker.getCloseCount() != 0 {
		t.Fatalf("after rotation: expected new client close count == 0, got %d", newTracker.getCloseCount())
	}

	cert3 := cm.currentCert
	if bytes.Equal(cert3.Certificate[0], cert1.Certificate[0]) {
		t.Fatal("expected new certificate after crossing refresh threshold, but DER is identical")
	}

	parsed3, err := x509.ParseCertificate(cert3.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse cert3: %v", err)
	}

	// Verify new certificate uses SAME permanent public key
	if !parsed3.PublicKey.(ed25519.PublicKey).Equal(pub) {
		t.Fatal("cert3 public key does not match agent public key")
	}

	// Verify serial numbers differ
	if parsed3.SerialNumber.Cmp(parsed1.SerialNumber) == 0 {
		t.Fatal("expected rotated certificate to have different serial number")
	}

	// Verify NO certificate files appeared in stateDir
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatalf("failed to read stateDir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".crt") || strings.HasSuffix(name, ".cert") || strings.HasSuffix(name, ".pem") {
			t.Fatalf("ephemeral certificate leaked to stateDir: %s", name)
		}
	}
}

func TestJitter_Distribution(t *testing.T) {
	base := 30 * time.Second
	pct := 0.10

	for i := 0; i < 100; i++ {
		got := defaultJitter(base, pct)
		if got < 27*time.Second || got > 33*time.Second {
			t.Fatalf("jitter out of expected ±10%% range (27s-33s): %v", got)
		}
	}
}

func TestComputeBackoff_MaxJitterCap(t *testing.T) {
	maxBackoff := 30 * time.Second

	// Case 1: base reaches maxBackoff and jitter attempts to exceed maxBackoff (e.g. 33s) -> clamped to 30s
	jitterAbove := func(base time.Duration, pct float64) time.Duration {
		return 33 * time.Second
	}
	gotAbove := computeBackoff(6, maxBackoff, jitterAbove)
	if gotAbove != 30*time.Second {
		t.Fatalf("expected backoff exceeding max to be capped at %v, got %v", maxBackoff, gotAbove)
	}

	// Case 2: jitter returns a value below cap (e.g. 27s) -> remains unchanged
	jitterBelow := func(base time.Duration, pct float64) time.Duration {
		return 27 * time.Second
	}
	gotBelow := computeBackoff(6, maxBackoff, jitterBelow)
	if gotBelow != 27*time.Second {
		t.Fatalf("expected backoff below max to remain %v, got %v", 27*time.Second, gotBelow)
	}
}

type fakeSeamExecutor struct {
	mu         sync.Mutex
	callCount  int
	lastAction string
	executeErr error
}

func (f *fakeSeamExecutor) Execute(ctx context.Context, action string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callCount++
	f.lastAction = action
	return f.executeErr
}

func TestPresence_JobLifecycle(t *testing.T) {
	t.Run("heartbeat assignment triggers start, execute, and complete", func(t *testing.T) {
		var (
			mu            sync.Mutex
			hbCount       int
			startCount    int
			completeCount int
			lastComplete  protocol.JobCompleteRequest
		)

		jobID := "018f0000-0000-7000-8000-000000000099"

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()

			switch r.URL.Path {
			case protocol.HeartbeatEndpointPath:
				hbCount++
				if hbCount == 1 {
					// Return job assignment on first heartbeat
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(protocol.HeartbeatResponse{
						ProtocolVersion: protocol.CurrentVersion,
						Job: &protocol.JobAssignment{
							JobID:   jobID,
							Attempt: 1,
							Action:  string(job.ActionAgentPing),
						},
					})
					return
				}
				w.WriteHeader(http.StatusNoContent)

			case protocol.AgentJobStartEndpointPath:
				startCount++
				w.WriteHeader(http.StatusNoContent)

			case protocol.AgentJobCompleteEndpointPath:
				completeCount++
				_ = json.NewDecoder(r.Body).Decode(&lastComplete)
				w.WriteHeader(http.StatusNoContent)

			default:
				w.WriteHeader(http.StatusNoContent)
			}
		})

		_, caPEM, ts := setupTestCAAndServer(t, handler)
		defer ts.Close()

		stateDir, _, _ := setupTestEnrolledState(t, ts.URL)
		caFile := filepath.Join(stateDir, "custom-ca.pem")
		_ = os.WriteFile(caFile, caPEM, 0644)
		_ = ValidateAndPersistCAFile(stateDir, caFile)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mockExec := &fakeSeamExecutor{}
		cfg := defaultPresenceConfig()
		cfg.executor = mockExec
		cfg.timerFunc = func(d time.Duration) (<-chan time.Time, func() bool) {
			cancel() // cancel after first pass
			ch := make(chan time.Time)
			return ch, func() bool { return true }
		}

		err := runPresenceWithConfig(ctx, nil, stateDir, cfg)
		if err != nil {
			t.Fatalf("expected clean exit, got %v", err)
		}

		mu.Lock()
		defer mu.Unlock()

		if hbCount < 1 {
			t.Errorf("expected heartbeat called, got %d", hbCount)
		}
		if startCount != 1 {
			t.Errorf("expected exactly 1 start request, got %d", startCount)
		}
		if mockExec.callCount != 1 {
			t.Errorf("expected executor called exactly once, got %d", mockExec.callCount)
		}
		if mockExec.lastAction != string(job.ActionAgentPing) {
			t.Errorf("expected action agent.ping, got %q", mockExec.lastAction)
		}
		if completeCount != 1 {
			t.Errorf("expected exactly 1 complete request, got %d", completeCount)
		}
		if lastComplete.Outcome != "succeeded" {
			t.Errorf("expected outcome succeeded, got %q", lastComplete.Outcome)
		}
		if lastComplete.JobID != jobID {
			t.Errorf("expected job ID %q, got %q", jobID, lastComplete.JobID)
		}
	})

	t.Run("start conflict drops assignment without executing", func(t *testing.T) {
		var (
			mu         sync.Mutex
			startCount int
		)

		jobID := "018f0000-0000-7000-8000-000000000098"

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()

			switch r.URL.Path {
			case protocol.HeartbeatEndpointPath:
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(protocol.HeartbeatResponse{
					ProtocolVersion: protocol.CurrentVersion,
					Job: &protocol.JobAssignment{
						JobID:   jobID,
						Attempt: 1,
						Action:  string(job.ActionAgentPing),
					},
				})

			case protocol.AgentJobStartEndpointPath:
				startCount++
				// Controller rejects start (e.g. stale lease or duplicate start)
				w.WriteHeader(http.StatusConflict)

			default:
				w.WriteHeader(http.StatusNoContent)
			}
		})

		_, caPEM, ts := setupTestCAAndServer(t, handler)
		defer ts.Close()

		stateDir, _, _ := setupTestEnrolledState(t, ts.URL)
		caFile := filepath.Join(stateDir, "custom-ca.pem")
		_ = os.WriteFile(caFile, caPEM, 0644)
		_ = ValidateAndPersistCAFile(stateDir, caFile)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mockExec := &fakeSeamExecutor{}
		cfg := defaultPresenceConfig()
		cfg.executor = mockExec
		cfg.timerFunc = func(d time.Duration) (<-chan time.Time, func() bool) {
			cancel()
			ch := make(chan time.Time)
			return ch, func() bool { return true }
		}

		err := runPresenceWithConfig(ctx, nil, stateDir, cfg)
		if err != nil {
			t.Fatalf("expected clean exit, got %v", err)
		}

		if startCount != 1 {
			t.Errorf("expected 1 start call, got %d", startCount)
		}
		if mockExec.callCount != 0 {
			t.Errorf("expected executor NOT called on start conflict, got %d", mockExec.callCount)
		}
	})
}
