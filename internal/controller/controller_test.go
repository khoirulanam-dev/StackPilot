package controller

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeReadinessChecker struct {
	pingErr error
}

func (f *fakeReadinessChecker) Ping(ctx context.Context) error {
	return f.pingErr
}

func TestHealthzEndpoint(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := newHandler(logger, nil)

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
		handler := newHandler(logger, checker)

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
		handler := newHandler(logger, checker)

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
		handler := newHandler(logger, nil)

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
		handler := newHandler(logger, checker)

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
		handler := newHandler(logger, checker)

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
		errCh <- serve(ctx, l, checker, logger)
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
