package controller

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHealthzEndpoint(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := newHandler(logger)

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

func TestServe_GracefulShutdown(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- serve(ctx, l, logger)
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
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = Run(ctx, cfg, logger)
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
		}
		err := Run(ctx, cfg, logger)
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
		}
		err := Run(ctx, cfg, logger)
		if err == nil {
			t.Fatal("expected Run() to reject invalid slog.Level(100), got nil")
		}
		if !strings.Contains(err.Error(), "unsupported") {
			t.Errorf("error %q does not mention unsupported", err.Error())
		}
	})
}
