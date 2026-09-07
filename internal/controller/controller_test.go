package controller

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
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
