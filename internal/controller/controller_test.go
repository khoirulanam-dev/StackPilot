package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"stackpilot/internal/agent"
	"stackpilot/internal/database"
	"stackpilot/internal/enrollment"
)

type fakeReadinessChecker struct {
	pingErr error
}

func (f *fakeReadinessChecker) Ping(ctx context.Context) error {
	return f.pingErr
}

type fakeEnrollmentRegistrar struct {
	registerFunc func(ctx context.Context, tokenHash [32]byte, publicKey [32]byte) (*enrollment.AgentRecord, bool, error)
}

func (f *fakeEnrollmentRegistrar) RegisterAgent(ctx context.Context, tokenHash [32]byte, publicKey [32]byte) (*enrollment.AgentRecord, bool, error) {
	if f.registerFunc != nil {
		return f.registerFunc(ctx, tokenHash, publicKey)
	}
	return &enrollment.AgentRecord{
		ID:        "mock-agent-id",
		PublicKey: publicKey,
		CreatedAt: time.Now(),
	}, true, nil
}

func TestHealthzEndpoint(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := newHandler(logger, nil, nil)

	tests := []struct {
		name       string
		method     string
		wantStatus int
		wantAllow  string
		wantBody   string
	}{
		{
			name:       "valid GET request",
			method:     http.MethodGet,
			wantStatus: http.StatusOK,
			wantAllow:  "",
			wantBody:   "OK",
		},
		{
			name:       "invalid POST request",
			method:     http.MethodPost,
			wantStatus: http.StatusMethodNotAllowed,
			wantAllow:  "GET",
			wantBody:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/healthz", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if status := rr.Code; status != tt.wantStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.wantStatus)
			}

			if tt.wantAllow != "" {
				if allow := rr.Header().Get("Allow"); allow != tt.wantAllow {
					t.Errorf("handler returned wrong Allow header: got %v want %v", allow, tt.wantAllow)
				}
			}

			bodyBytes, err := io.ReadAll(rr.Body)
			if err != nil {
				t.Fatalf("failed to read response body: %v", err)
			}
			body := string(bodyBytes)
			if body != tt.wantBody {
				t.Errorf("handler returned unexpected body: got %q want %q", body, tt.wantBody)
			}
		})
	}
}

func TestReadyzEndpoint(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	const secret = "stackpilot-super-secret-test-value"

	t.Run("database healthy", func(t *testing.T) {
		checker := &fakeReadinessChecker{pingErr: nil}
		handler := newHandler(logger, checker, nil)

		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
		}
		if body := rr.Body.String(); body != "OK" {
			t.Errorf("expected body %q, got %q", "OK", body)
		}
	})

	t.Run("database unavailable does not leak secret", func(t *testing.T) {
		checker := &fakeReadinessChecker{
			pingErr: fmt.Errorf("password authentication failed for %s", secret),
		}
		handler := newHandler(logger, checker, nil)

		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, rr.Code)
		}
		body := rr.Body.String()
		if body != "NOT READY" {
			t.Errorf("expected body %q, got %q", "NOT READY", body)
		}
		if strings.Contains(body, secret) {
			t.Fatalf("response body leaked secret: %s", body)
		}
	})

	t.Run("nil checker returns 503 NOT READY", func(t *testing.T) {
		handler := newHandler(logger, nil, nil)

		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, rr.Code)
		}
		if body := rr.Body.String(); body != "NOT READY" {
			t.Errorf("expected body %q, got %q", "NOT READY", body)
		}
	})

	t.Run("POST /readyz returns 405 Method Not Allowed with Allow GET", func(t *testing.T) {
		checker := &fakeReadinessChecker{pingErr: nil}
		handler := newHandler(logger, checker, nil)

		req := httptest.NewRequest(http.MethodPost, "/readyz", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
		}
		if allow := rr.Header().Get("Allow"); allow != "GET" {
			t.Errorf("expected Allow header 'GET', got %q", allow)
		}
	})

	t.Run("healthz remains 200 OK even if readiness fails", func(t *testing.T) {
		checker := &fakeReadinessChecker{
			pingErr: fmt.Errorf("database connection lost: %s", secret),
		}
		handler := newHandler(logger, checker, nil)

		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected /healthz status %d, got %d", http.StatusOK, rr.Code)
		}
		if body := rr.Body.String(); body != "OK" {
			t.Errorf("expected body %q, got %q", "OK", body)
		}
	})
}

func TestServe_GracefulShutdown(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	checker := &fakeReadinessChecker{pingErr: nil}

	errCh := make(chan error, 1)
	go func() {
		errCh <- serve(ctx, l, checker, nil, logger)
	}()

	client := &http.Client{
		Timeout: 2 * time.Second,
	}

	resp, err := client.Get("http://" + l.Addr().String() + "/healthz")
	if err != nil {
		t.Fatalf("failed to execute GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200 OK, got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	if string(body) != "OK" {
		t.Errorf("expected body %q, got %q", "OK", string(body))
	}

	readyResp, err := client.Get("http://" + l.Addr().String() + "/readyz")
	if err != nil {
		t.Fatalf("failed to execute GET /readyz: %v", err)
	}
	defer readyResp.Body.Close()

	if readyResp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200 OK on /readyz, got %d", readyResp.StatusCode)
	}

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("serve returned unexpected error on shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not shut down within timeout")
	}
}

func TestRun_ListenFailure(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate listener: %v", err)
	}
	defer l.Close()

	cfg := Config{
		ListenAddress: l.Addr().String(),
		LogLevel:      slog.LevelInfo,
		DatabaseURL:   "postgres://stackpilot:secret@127.0.0.1:5432/stackpilot",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = Run(ctx, cfg, nil, logger)
	if err == nil {
		t.Fatal("expected Run() to fail on occupied address, got nil")
	}
	if !strings.Contains(err.Error(), "failed to listen on") {
		t.Errorf("error %q does not contain expected context 'failed to listen on'", err.Error())
	}
}

func TestRun_DirectConfigValidation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	t.Run("rejects non-loopback wildcard directly constructed", func(t *testing.T) {
		cfg := Config{
			ListenAddress: "0.0.0.0:7447",
			LogLevel:      slog.LevelInfo,
			DatabaseURL:   "postgres://stackpilot:secret@127.0.0.1:5432/stackpilot",
		}
		err := Run(ctx, cfg, nil, logger)
		if err == nil {
			t.Fatal("expected Run() to reject 0.0.0.0, got nil")
		}
		if !strings.Contains(err.Error(), "loopback") {
			t.Errorf("error %q does not mention loopback", err.Error())
		}
	})

	t.Run("rejects invalid manually constructed log level", func(t *testing.T) {
		cfg := Config{
			ListenAddress: "127.0.0.1:7447",
			LogLevel:      slog.Level(100),
			DatabaseURL:   "postgres://stackpilot:secret@127.0.0.1:5432/stackpilot",
		}
		err := Run(ctx, cfg, nil, logger)
		if err == nil {
			t.Fatal("expected Run() to reject invalid slog.Level(100), got nil")
		}
		if !strings.Contains(err.Error(), "unsupported") {
			t.Errorf("error %q does not mention unsupported", err.Error())
		}
	})

	t.Run("rejects empty database URL directly constructed", func(t *testing.T) {
		cfg := Config{
			ListenAddress: "127.0.0.1:7447",
			LogLevel:      slog.LevelInfo,
			DatabaseURL:   "",
		}
		err := Run(ctx, cfg, nil, logger)
		if err == nil {
			t.Fatal("expected Run() to reject empty DatabaseURL, got nil")
		}
		if !strings.Contains(err.Error(), "cannot be empty") {
			t.Errorf("error %q does not mention cannot be empty", err.Error())
		}
	})

	t.Run("rejects invalid database URL directly constructed", func(t *testing.T) {
		cfg := Config{
			ListenAddress: "127.0.0.1:7447",
			LogLevel:      slog.LevelInfo,
			DatabaseURL:   "invalid-url",
		}
		err := Run(ctx, cfg, nil, logger)
		if err == nil {
			t.Fatal("expected Run() to reject invalid DatabaseURL, got nil")
		}
		if !strings.Contains(err.Error(), "scheme must be postgres or postgresql") {
			t.Errorf("error %q does not mention scheme requirement", err.Error())
		}
	})
}

func TestEnrollEndpoint(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	validToken := enrollment.TokenPrefix + strings.Repeat("A", 43)
	validPubKey := strings.Repeat("B", 43) // 43 rawURL characters decodes to 32 bytes or base64 rawurl

	// Helper to make 32 valid base64 raw url bytes
	raw32 := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32))

	t.Run("POST success returns 201 Created and agent_id", func(t *testing.T) {
		registrar := &fakeEnrollmentRegistrar{
			registerFunc: func(ctx context.Context, tokenHash [32]byte, publicKey [32]byte) (*enrollment.AgentRecord, bool, error) {
				return &enrollment.AgentRecord{ID: "018f-uuid-v7"}, true, nil
			},
		}
		handler := newHandler(logger, nil, registrar)

		body := fmt.Sprintf(`{"token":%q,"public_key":%q}`, validToken, raw32)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/enroll", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusCreated {
			t.Fatalf("expected 201 Created, got %d", rr.Code)
		}
		ct := rr.Header().Get("Content-Type")
		mediaType, _, err := mime.ParseMediaType(ct)
		if err != nil || mediaType != "application/json" {
			t.Fatalf("expected Content-Type application/json, got %q (err: %v)", ct, err)
		}
		if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("expected Cache-Control 'no-store', got %q", cc)
		}
		if cors := rr.Header().Get("Access-Control-Allow-Origin"); cors != "" {
			t.Errorf("expected no CORS wildcard header, got %q", cors)
		}
		if strings.Contains(rr.Body.String(), validToken) {
			t.Fatal("response body echoed token")
		}
		if !strings.Contains(rr.Body.String(), "018f-uuid-v7") {
			t.Fatalf("response body missing agent_id: %s", rr.Body.String())
		}
	})

	t.Run("idempotent retry returns 200 OK", func(t *testing.T) {
		registrar := &fakeEnrollmentRegistrar{
			registerFunc: func(ctx context.Context, tokenHash [32]byte, publicKey [32]byte) (*enrollment.AgentRecord, bool, error) {
				return &enrollment.AgentRecord{ID: "018f-uuid-v7"}, false, nil
			},
		}
		handler := newHandler(logger, nil, registrar)

		body := fmt.Sprintf(`{"token":%q,"public_key":%q}`, validToken, raw32)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/enroll", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for idempotent retry, got %d", rr.Code)
		}
		ct := rr.Header().Get("Content-Type")
		mediaType, _, err := mime.ParseMediaType(ct)
		if err != nil || mediaType != "application/json" {
			t.Fatalf("expected Content-Type application/json, got %q (err: %v)", ct, err)
		}
		if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("expected Cache-Control 'no-store', got %q", cc)
		}
	})

	t.Run("invalid token returns 401 generic rejection", func(t *testing.T) {
		registrar := &fakeEnrollmentRegistrar{}
		handler := newHandler(logger, nil, registrar)

		body := fmt.Sprintf(`{"token":"sp_enroll_too_short","public_key":%q}`, raw32)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/enroll", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", rr.Code)
		}
		if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %q", ct)
		}
		if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("expected Cache-Control 'no-store', got %q", cc)
		}
		if strings.Contains(rr.Body.String(), "sp_enroll_too_short") {
			t.Fatal("response echoed invalid token")
		}
	})

	t.Run("domain enrollment rejection returns 401", func(t *testing.T) {
		registrar := &fakeEnrollmentRegistrar{
			registerFunc: func(ctx context.Context, tokenHash [32]byte, publicKey [32]byte) (*enrollment.AgentRecord, bool, error) {
				return nil, false, enrollment.ErrEnrollmentRejected
			},
		}
		handler := newHandler(logger, nil, registrar)

		body := fmt.Sprintf(`{"token":%q,"public_key":%q}`, validToken, raw32)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/enroll", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", rr.Code)
		}
	})

	t.Run("identity conflict returns 409", func(t *testing.T) {
		registrar := &fakeEnrollmentRegistrar{
			registerFunc: func(ctx context.Context, tokenHash [32]byte, publicKey [32]byte) (*enrollment.AgentRecord, bool, error) {
				return nil, false, enrollment.ErrIdentityConflict
			},
		}
		handler := newHandler(logger, nil, registrar)

		body := fmt.Sprintf(`{"token":%q,"public_key":%q}`, validToken, raw32)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/enroll", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusConflict {
			t.Fatalf("expected 409 Conflict, got %d", rr.Code)
		}
	})

	t.Run("wrong key length returns 400", func(t *testing.T) {
		registrar := &fakeEnrollmentRegistrar{}
		handler := newHandler(logger, nil, registrar)

		shortKey := base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x02})
		body := fmt.Sprintf(`{"token":%q,"public_key":%q}`, validToken, shortKey)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/enroll", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request, got %d", rr.Code)
		}
	})

	t.Run("malformed base64 public key returns 400", func(t *testing.T) {
		registrar := &fakeEnrollmentRegistrar{}
		handler := newHandler(logger, nil, registrar)

		body := fmt.Sprintf(`{"token":%q,"public_key":"invalid!base64"}`, validToken)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/enroll", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request, got %d", rr.Code)
		}
	})

	t.Run("malformed JSON returns 400", func(t *testing.T) {
		registrar := &fakeEnrollmentRegistrar{}
		handler := newHandler(logger, nil, registrar)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/enroll", strings.NewReader("not json"))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request, got %d", rr.Code)
		}
	})

	t.Run("unknown JSON field returns 400", func(t *testing.T) {
		registrar := &fakeEnrollmentRegistrar{}
		handler := newHandler(logger, nil, registrar)

		body := fmt.Sprintf(`{"token":%q,"public_key":%q,"extra_field":"evil"}`, validToken, validPubKey)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/enroll", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request for unknown field, got %d", rr.Code)
		}
	})

	t.Run("trailing JSON returns 400", func(t *testing.T) {
		registrar := &fakeEnrollmentRegistrar{}
		handler := newHandler(logger, nil, registrar)

		body := fmt.Sprintf(`{"token":%q,"public_key":%q} {"second": true}`, validToken, validPubKey)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/enroll", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request for trailing JSON, got %d", rr.Code)
		}
	})

	t.Run("wrong Content-Type returns 415", func(t *testing.T) {
		registrar := &fakeEnrollmentRegistrar{}
		handler := newHandler(logger, nil, registrar)

		body := fmt.Sprintf(`{"token":%q,"public_key":%q}`, validToken, raw32)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/enroll", strings.NewReader(body))
		req.Header.Set("Content-Type", "text/plain")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("expected 415 Unsupported Media Type, got %d", rr.Code)
		}
	})

	t.Run("malformed Content-Type parameter returns 415", func(t *testing.T) {
		registrar := &fakeEnrollmentRegistrar{}
		handler := newHandler(logger, nil, registrar)

		body := fmt.Sprintf(`{"token":%q,"public_key":%q}`, validToken, raw32)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/enroll", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json; invalid;;")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("expected 415 Unsupported Media Type for malformed parameter, got %d", rr.Code)
		}
	})

	t.Run("unsupported charset parameter returns 415", func(t *testing.T) {
		registrar := &fakeEnrollmentRegistrar{}
		handler := newHandler(logger, nil, registrar)

		body := fmt.Sprintf(`{"token":%q,"public_key":%q}`, validToken, raw32)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/enroll", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json; charset=iso-8859-1")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("expected 415 Unsupported Media Type for unsupported charset, got %d", rr.Code)
		}
		if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %q", ct)
		}
		if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("expected Cache-Control 'no-store', got %q", cc)
		}
	})

	t.Run("oversized body returns error", func(t *testing.T) {
		registrar := &fakeEnrollmentRegistrar{}
		handler := newHandler(logger, nil, registrar)

		oversized := strings.Repeat("X", 5000)
		body := fmt.Sprintf(`{"token":%q,"public_key":%q,"padding":%q}`, validToken, validPubKey, oversized)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/enroll", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request on oversized body, got %d", rr.Code)
		}
	})

	t.Run("GET method returns 405", func(t *testing.T) {
		registrar := &fakeEnrollmentRegistrar{}
		handler := newHandler(logger, nil, registrar)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/enroll", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", rr.Code)
		}
		if allow := rr.Header().Get("Allow"); allow != "POST" {
			t.Errorf("expected Allow header 'POST', got %q", allow)
		}
	})

	t.Run("PUT method returns 405", func(t *testing.T) {
		registrar := &fakeEnrollmentRegistrar{}
		handler := newHandler(logger, nil, registrar)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/agent/enroll", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", rr.Code)
		}
		if allow := rr.Header().Get("Allow"); allow != "POST" {
			t.Errorf("expected Allow header 'POST', got %q", allow)
		}
	})

	t.Run("internal persistence error returns 500 and does not leak secret", func(t *testing.T) {
		const syntheticSecret = "super-secret-database-token"
		registrar := &fakeEnrollmentRegistrar{
			registerFunc: func(ctx context.Context, tokenHash [32]byte, publicKey [32]byte) (*enrollment.AgentRecord, bool, error) {
				return nil, false, fmt.Errorf("database crash with secret %s", syntheticSecret)
			},
		}
		handler := newHandler(logger, nil, registrar)

		body := fmt.Sprintf(`{"token":%q,"public_key":%q}`, validToken, raw32)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/enroll", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 Internal Server Error, got %d", rr.Code)
		}
		if strings.Contains(rr.Body.String(), syntheticSecret) {
			t.Fatal("response body leaked synthetic secret")
		}
	})
}

func TestEnrollEndpoint_PostgreSQLIntegration(t *testing.T) {
	testURL, ok := os.LookupEnv("STACKPILOT_TEST_DATABASE_URL")
	if !ok || testURL == "" {
		t.Skip("skipping integration test: STACKPILOT_TEST_DATABASE_URL not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	db, err := database.Open(ctx, testURL)
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}
	defer db.Close()

	if err := db.Migrate(ctx, nil); err != nil {
		t.Fatalf("migration failed: %v", err)
	}

	handler := newHandler(logger, db, db)
	server := httptest.NewServer(handler)
	defer server.Close()

	// 1. Issue enrollment token
	token, err := enrollment.IssueToken(ctx, db)
	if err != nil {
		t.Fatalf("failed to issue token: %v", err)
	}

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate random ed25519 key: %v", err)
	}
	raw32 := base64.RawURLEncoding.EncodeToString(pubKey)
	reqBody := fmt.Sprintf(`{"token":%q,"public_key":%q}`, token, raw32)

	// 2. HTTP POST -> 201 Created
	resp, err := http.Post(server.URL+"/api/v1/agent/enroll", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("POST /api/v1/agent/enroll failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d", resp.StatusCode)
	}

	// 3. HTTP POST Retry -> 200 OK
	respRetry, err := http.Post(server.URL+"/api/v1/agent/enroll", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("retry POST /api/v1/agent/enroll failed: %v", err)
	}
	defer respRetry.Body.Close()

	if respRetry.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on idempotent retry, got %d", respRetry.StatusCode)
	}
}

func TestEnroll_RealAgentControllerCompatibility(t *testing.T) {
	const expectedAgentID = "018f0000-0000-7000-8000-000000000001"
	validToken := enrollment.TokenPrefix + strings.Repeat("K", 43)

	var registeredKey [32]byte
	registrar := &fakeEnrollmentRegistrar{
		registerFunc: func(ctx context.Context, tokenHash [32]byte, publicKey [32]byte) (*enrollment.AgentRecord, bool, error) {
			registeredKey = publicKey
			return &enrollment.AgentRecord{
				ID:        expectedAgentID,
				PublicKey: publicKey,
				CreatedAt: time.Now(),
			}, true, nil
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := newHandler(logger, nil, registrar)
	server := httptest.NewServer(handler)
	defer server.Close()

	tempDir := t.TempDir()
	stateDir := filepath.Join(tempDir, "agent-state")

	opts := agent.EnrollOptions{
		ControllerURL: server.URL,
		StateDir:      stateDir,
		TokenReader:   strings.NewReader(validToken + "\n"),
	}

	agentID, err := agent.Enroll(context.Background(), opts)
	if err != nil {
		t.Fatalf("real Agent Enroll against real Controller handler failed: %v", err)
	}

	if agentID != expectedAgentID {
		t.Fatalf("expected agent ID %s, got %s", expectedAgentID, agentID)
	}

	meta, err := agent.LoadIdentityMetadata(stateDir)
	if err != nil {
		t.Fatalf("failed to load identity metadata: %v", err)
	}
	if meta.AgentID != expectedAgentID {
		t.Fatalf("metadata agent ID mismatch: expected %s, got %s", expectedAgentID, meta.AgentID)
	}
	if meta.PublicKey != agent.FormatPublicKeyBase64RawURL(registeredKey[:]) {
		t.Fatal("metadata public key mismatch with registered key")
	}
}
