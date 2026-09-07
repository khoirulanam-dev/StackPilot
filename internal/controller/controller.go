package controller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"stackpilot/internal/enrollment"
)

type readinessChecker interface {
	Ping(context.Context) error
}

type enrollmentRegistrar interface {
	RegisterAgent(ctx context.Context, tokenHash [32]byte, publicKey [32]byte) (*enrollment.AgentRecord, bool, error)
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func newHandler(logger *slog.Logger, checker readinessChecker, registrar enrollmentRegistrar) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("OK")); err != nil {
			logger.Error("failed to write healthz response", "error", err)
		}
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "text/plain")

		if checker == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			if _, err := w.Write([]byte("NOT READY")); err != nil {
				logger.Error("failed to write readyz response", "error", err)
			}
			return
		}

		pingCtx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()

		if err := checker.Ping(pingCtx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			if _, writeErr := w.Write([]byte("NOT READY")); writeErr != nil {
				logger.Error("failed to write readyz response", "error", writeErr)
			}
			return
		}

		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("OK")); err != nil {
			logger.Error("failed to write readyz response", "error", err)
		}
	})

	mux.HandleFunc("/api/v1/agent/enroll", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Verify Content-Type using standard library mime.ParseMediaType
		ct := r.Header.Get("Content-Type")
		mediaType, params, err := mime.ParseMediaType(ct)
		if err != nil || mediaType != "application/json" {
			writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "unsupported media type"})
			return
		}
		if charset, ok := params["charset"]; ok && strings.ToLower(charset) != "utf-8" {
			writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "unsupported media type"})
			return
		}

		// Bound request size to 4 KiB
		r.Body = http.MaxBytesReader(w, r.Body, 4096)

		// Decode JSON with DisallowUnknownFields
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		var req struct {
			Token     string `json:"token"`
			PublicKey string `json:"public_key"`
		}

		if err := decoder.Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
			return
		}

		// Reject trailing JSON or multiple documents
		if decoder.More() {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
			return
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
			return
		}

		// Validate token format
		if err := enrollment.ValidateToken(req.Token); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "enrollment rejected"})
			return
		}

		// Validate public key format (RawURLEncoding, no padding, exactly 32 bytes)
		if strings.Contains(req.PublicKey, "=") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid public key format"})
			return
		}

		pubKeyBytes, err := base64.RawURLEncoding.DecodeString(req.PublicKey)
		if err != nil || len(pubKeyBytes) != 32 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid public key format"})
			return
		}

		if registrar == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "service unavailable"})
			return
		}

		tokenHash := enrollment.HashToken(req.Token)
		var pubKey [32]byte
		copy(pubKey[:], pubKeyBytes)

		dbCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		record, created, err := registrar.RegisterAgent(dbCtx, tokenHash, pubKey)
		if err != nil {
			if errors.Is(err, enrollment.ErrEnrollmentRejected) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "enrollment rejected"})
				return
			}
			if errors.Is(err, enrollment.ErrIdentityConflict) {
				writeJSON(w, http.StatusConflict, map[string]string{"error": "identity conflict"})
				return
			}

			logger.Error("agent enrollment persistence failure")
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
			return
		}

		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}

		writeJSON(w, status, map[string]string{
			"agent_id": record.ID,
		})
	})

	return mux
}

func serve(ctx context.Context, l net.Listener, checker readinessChecker, registrar enrollmentRegistrar, logger *slog.Logger) error {
	srv := &http.Server{
		Handler:           newHandler(logger, checker, registrar),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(l)
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		shutdownErr := srv.Shutdown(shutdownCtx)
		serveErr := <-errCh
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			return serveErr
		}
		return shutdownErr
	}
}

type runtimeBackend interface {
	readinessChecker
	enrollmentRegistrar
}

// Run starts the controller components and blocks until ctx is canceled.
func Run(ctx context.Context, cfg Config, backend runtimeBackend, logger *slog.Logger) error {
	if err := cfg.validate(); err != nil {
		return fmt.Errorf("invalid controller configuration: %w", err)
	}

	var checker readinessChecker
	var registrar enrollmentRegistrar
	if backend != nil {
		checker = backend
		registrar = backend
	}

	l, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", cfg.ListenAddress, err)
	}

	return serve(ctx, l, checker, registrar, logger)
}
