package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

func newHandler(logger *slog.Logger) http.Handler {
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
	return mux
}

func serve(ctx context.Context, l net.Listener, logger *slog.Logger) error {
	srv := &http.Server{
		Handler:           newHandler(logger),
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

// Run starts the controller components and blocks until ctx is canceled.
func Run(ctx context.Context, cfg Config, logger *slog.Logger) error {
	if err := cfg.validate(); err != nil {
		return fmt.Errorf("invalid controller configuration: %w", err)
	}

	l, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", cfg.ListenAddress, err)
	}

	return serve(ctx, l, logger)
}
