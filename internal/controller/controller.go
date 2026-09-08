package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"stackpilot/internal/enrollment"
	"stackpilot/internal/operator"
	"stackpilot/internal/protocol"
)

type readinessChecker interface {
	Ping(context.Context) error
}

type enrollmentRegistrar interface {
	RegisterAgent(ctx context.Context, tokenHash [32]byte, publicKey [32]byte) (*enrollment.AgentRecord, bool, error)
}

type agentAuthenticator interface {
	FindAgentByPublicKey(ctx context.Context, publicKey [32]byte) (*enrollment.AgentRecord, error)
	RecordAgentHeartbeat(ctx context.Context, publicKey [32]byte, protocolVersion int) (*enrollment.AgentRecord, error)
	RecordAgentInventory(ctx context.Context, publicKey [32]byte, req *protocol.InventoryRequest) error
	RecordAgentTelemetry(ctx context.Context, publicKey [32]byte, req *protocol.TelemetryRequest) error
}

type operatorBackend interface {
	GetOperatorByUsername(ctx context.Context, username string) (*operator.OperatorRecord, error)
	CreateOperatorSession(ctx context.Context, operatorID string, tokenHash [32]byte) (*operator.SessionRecord, error)
	FindOperatorSessionByTokenHash(ctx context.Context, tokenHash [32]byte) (*operator.Principal, error)
	RevokeOperatorSession(ctx context.Context, sessionID string, operatorID string, username string) error
	RecordAndListAuditEvents(ctx context.Context, actorOperatorID string, actorUsername string, limit int) ([]operator.AuditEventRecord, error)
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func handleEnroll(w http.ResponseWriter, r *http.Request, registrar enrollmentRegistrar, logger *slog.Logger) {
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
}

func handleOperatorLogin(w http.ResponseWriter, r *http.Request, opBackend operatorBackend, limiter *operator.ConcurrencyLimiter, logger *slog.Logger) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

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

	limited := io.LimitReader(r.Body, 1025)
	bodyBytes, err := io.ReadAll(limited)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read request body"})
		return
	}
	if len(bodyBytes) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "empty request body"})
		return
	}
	if len(bodyBytes) > 1024 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "request body too large"})
		return
	}

	if !utf8.Valid(bodyBytes) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	dec := json.NewDecoder(bytes.NewReader(bodyBytes))
	dec.DisallowUnknownFields()
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return
	}
	if dec.More() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "trailing data in request body"})
		return
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "trailing data in request body"})
		return
	}

	if limiter == nil {
		limiter = operator.NewConcurrencyLimiter(2)
	}
	release, ok := limiter.TryAcquire()
	if !ok {
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many requests"})
		return
	}
	defer release()

	if opBackend == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "service unavailable"})
		return
	}

	normUsername := operator.NormalizeUsername(req.Username)
	dbCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	op, err := opBackend.GetOperatorByUsername(dbCtx, normUsername)
	if err != nil {
		if errors.Is(err, operator.ErrOperatorNotFound) {
			operator.DummyPasswordDerivation(req.Password)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
			return
		}
		logger.Error("operator login query failure")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}
	if op == nil {
		logger.Error("operator lookup returned nil operator")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	if err := operator.VerifyPassword(op.PasswordHash, req.Password); err != nil || op.DisabledAt != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	rawToken, err := operator.GenerateSessionToken()
	if err != nil {
		logger.Error("failed to generate session token")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	tokenHash := operator.HashSessionToken(rawToken)
	sessionRec, err := opBackend.CreateOperatorSession(dbCtx, op.ID, tokenHash)
	if err != nil {
		if errors.Is(err, operator.ErrAuthenticationFailed) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
			return
		}
		logger.Error("operator session persistence failure")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"token":      rawToken,
		"expires_at": sessionRec.ExpiresAt.Format(time.RFC3339Nano),
		"operator": map[string]string{
			"id":       op.ID,
			"username": op.Username,
			"role":     string(op.Role),
		},
	})
}

func authenticateOperator(r *http.Request, opBackend operatorBackend, logger *slog.Logger) (*operator.Principal, int, string) {
	if opBackend == nil {
		return nil, http.StatusServiceUnavailable, "service unavailable"
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, http.StatusUnauthorized, "authentication required"
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" || parts[1] == "" {
		return nil, http.StatusUnauthorized, "authentication required"
	}

	rawToken := parts[1]
	if err := operator.ValidateSessionToken(rawToken); err != nil {
		return nil, http.StatusUnauthorized, "authentication required"
	}

	tokenHash := operator.HashSessionToken(rawToken)
	dbCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	principal, err := opBackend.FindOperatorSessionByTokenHash(dbCtx, tokenHash)
	if err != nil {
		if errors.Is(err, operator.ErrAuthenticationFailed) {
			return nil, http.StatusUnauthorized, "authentication required"
		}
		if logger != nil {
			logger.Error("operator session lookup failure")
		}
		return nil, http.StatusInternalServerError, "internal server error"
	}
	// Security invariant: Defensive role validation fails closed if principal has unknown/corrupt role.
	if principal == nil || !principal.Role.Valid() {
		return nil, http.StatusUnauthorized, "authentication required"
	}

	return principal, http.StatusOK, ""
}

func handleOperatorMe(w http.ResponseWriter, r *http.Request, opBackend operatorBackend, logger *slog.Logger) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	principal, status, errMsg := authenticateOperator(r, opBackend, logger)
	if principal == nil {
		writeJSON(w, status, map[string]string{"error": errMsg})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"id":                 principal.OperatorID,
		"username":           principal.Username,
		"role":               string(principal.Role),
		"session_expires_at": principal.ExpiresAt.Format(time.RFC3339Nano),
	})
}

func handleOperatorLogout(w http.ResponseWriter, r *http.Request, opBackend operatorBackend, logger *slog.Logger) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	principal, status, errMsg := authenticateOperator(r, opBackend, logger)
	if principal == nil {
		writeJSON(w, status, map[string]string{"error": errMsg})
		return
	}

	dbCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if err := opBackend.RevokeOperatorSession(dbCtx, principal.SessionID, principal.OperatorID, principal.Username); err != nil {
		if errors.Is(err, operator.ErrSessionNotFound) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
		logger.Error("operator session revocation failure")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func handleOperatorAudit(w http.ResponseWriter, r *http.Request, opBackend operatorBackend, logger *slog.Logger) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	principal, status, errMsg := authenticateOperator(r, opBackend, logger)
	if principal == nil {
		writeJSON(w, status, map[string]string{"error": errMsg})
		return
	}

	if !principal.Role.HasPermission(operator.PermissionAuditRead) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}

	query := r.URL.Query()
	for k := range query {
		if k != "limit" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown query parameter"})
			return
		}
	}

	limit := 100
	if query.Has("limit") {
		var err error
		limit, err = strconv.Atoi(query.Get("limit"))
		if err != nil || limit < 1 || limit > 200 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid limit query parameter (must be 1..200)"})
			return
		}
	}

	dbCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	events, err := opBackend.RecordAndListAuditEvents(dbCtx, principal.OperatorID, principal.Username, limit)
	if err != nil {
		logger.Error("operator audit query failure")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	writeJSON(w, http.StatusOK, events)
}

func newHandler(logger *slog.Logger, checker readinessChecker, registrar enrollmentRegistrar, opBackends ...operatorBackend) http.Handler {
	var opBackend operatorBackend
	if len(opBackends) > 0 {
		opBackend = opBackends[0]
	} else if b, ok := registrar.(operatorBackend); ok {
		opBackend = b
	} else if b, ok := checker.(operatorBackend); ok {
		opBackend = b
	}

	loginLimiter := operator.NewConcurrencyLimiter(2)

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
		handleEnroll(w, r, registrar, logger)
	})

	mux.HandleFunc("/api/v1/operator/login", func(w http.ResponseWriter, r *http.Request) {
		handleOperatorLogin(w, r, opBackend, loginLimiter, logger)
	})

	mux.HandleFunc("/api/v1/operator/me", func(w http.ResponseWriter, r *http.Request) {
		handleOperatorMe(w, r, opBackend, logger)
	})

	mux.HandleFunc("/api/v1/operator/logout", func(w http.ResponseWriter, r *http.Request) {
		handleOperatorLogout(w, r, opBackend, logger)
	})

	mux.HandleFunc("/api/v1/operator/audit", func(w http.ResponseWriter, r *http.Request) {
		handleOperatorAudit(w, r, opBackend, logger)
	})

	return mux
}

var errAuthFailed = errors.New("agent authentication failed")

func extractAuthenticatedPeerPublicKey(r *http.Request) ([32]byte, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return [32]byte{}, errAuthFailed
	}

	cert := r.TLS.PeerCertificates[0]

	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return [32]byte{}, errAuthFailed
	}

	if len(cert.ExtKeyUsage) > 0 {
		hasClientAuth := false
		for _, eku := range cert.ExtKeyUsage {
			if eku == x509.ExtKeyUsageClientAuth {
				hasClientAuth = true
				break
			}
		}
		if !hasClientAuth {
			return [32]byte{}, errAuthFailed
		}
	}

	edPubKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || len(edPubKey) != ed25519.PublicKeySize {
		return [32]byte{}, errAuthFailed
	}

	var pubKey [32]byte
	copy(pubKey[:], edPubKey)
	return pubKey, nil
}

func newRemoteHandler(logger *slog.Logger, registrar enrollmentRegistrar, authenticator agentAuthenticator) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/agent/enroll", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tls required"})
			return
		}
		handleEnroll(w, r, registrar, logger)
	})

	mux.HandleFunc("/api/v1/agent/self", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tls required"})
			return
		}

		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		pubKey, err := extractAuthenticatedPeerPublicKey(r)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "agent authentication failed"})
			return
		}

		if authenticator == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "service unavailable"})
			return
		}

		dbCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		record, err := authenticator.FindAgentByPublicKey(dbCtx, pubKey)
		if err != nil {
			if errors.Is(err, enrollment.ErrAgentNotFound) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "agent authentication failed"})
				return
			}
			logger.Error("agent authentication lookup failure")
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"agent_id": record.ID,
		})
	})

	mux.HandleFunc(protocol.HeartbeatEndpointPath, func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tls required"})
			return
		}

		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		pubKey, err := extractAuthenticatedPeerPublicKey(r)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "agent authentication failed"})
			return
		}

		ct := r.Header.Get("Content-Type")
		mediaType, params, err := mime.ParseMediaType(ct)
		if err != nil || mediaType != "application/json" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid content type"})
			return
		}
		if charset, ok := params["charset"]; ok && strings.ToLower(charset) != "utf-8" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported charset"})
			return
		}

		limited := io.LimitReader(r.Body, 1025)
		bodyBytes, err := io.ReadAll(limited)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read request body"})
			return
		}
		if len(bodyBytes) > 1024 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "request body too large"})
			return
		}

		dec := json.NewDecoder(bytes.NewReader(bodyBytes))
		dec.DisallowUnknownFields()
		var req protocol.HeartbeatRequest
		if err := dec.Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		var extra any
		if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "trailing data in request body"})
			return
		}

		if req.ProtocolVersion <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid protocol version"})
			return
		}
		if req.ProtocolVersion != protocol.CurrentVersion {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "unsupported agent protocol"})
			return
		}

		if authenticator == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "service unavailable"})
			return
		}

		dbCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		_, err = authenticator.RecordAgentHeartbeat(dbCtx, pubKey, req.ProtocolVersion)
		if err != nil {
			if errors.Is(err, enrollment.ErrAgentNotFound) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "agent authentication failed"})
				return
			}
			logger.Error("agent heartbeat database failure")
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
			return
		}

		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc(protocol.InventoryEndpointPath, func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tls required"})
			return
		}

		if r.Method != http.MethodPut {
			w.Header().Set("Allow", "PUT")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		pubKey, err := extractAuthenticatedPeerPublicKey(r)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "agent authentication failed"})
			return
		}

		ct := r.Header.Get("Content-Type")
		mediaType, params, err := mime.ParseMediaType(ct)
		if err != nil || mediaType != "application/json" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid content type"})
			return
		}
		if charset, ok := params["charset"]; ok && strings.ToLower(charset) != "utf-8" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported charset"})
			return
		}

		limited := io.LimitReader(r.Body, 8193)
		bodyBytes, err := io.ReadAll(limited)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read request body"})
			return
		}
		if len(bodyBytes) > 8192 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "request body too large"})
			return
		}

		if !utf8.Valid(bodyBytes) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}

		dec := json.NewDecoder(bytes.NewReader(bodyBytes))
		dec.DisallowUnknownFields()
		var req protocol.InventoryRequest
		if err := dec.Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		var extra any
		if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "trailing data in request body"})
			return
		}

		if req.ProtocolVersion <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid protocol version"})
			return
		}
		if req.ProtocolVersion != protocol.CurrentVersion {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "unsupported agent protocol"})
			return
		}

		if err := protocol.ValidateInventoryRequest(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		if authenticator == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "service unavailable"})
			return
		}

		dbCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		err = authenticator.RecordAgentInventory(dbCtx, pubKey, &req)
		if err != nil {
			if errors.Is(err, enrollment.ErrAgentNotFound) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "agent authentication failed"})
				return
			}
			logger.Error("agent inventory database failure")
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
			return
		}

		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc(protocol.TelemetryEndpointPath, func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tls required"})
			return
		}

		if r.Method != http.MethodPut {
			w.Header().Set("Allow", "PUT")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		pubKey, err := extractAuthenticatedPeerPublicKey(r)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "agent authentication failed"})
			return
		}

		ct := r.Header.Get("Content-Type")
		mediaType, params, err := mime.ParseMediaType(ct)
		if err != nil || mediaType != "application/json" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid content type"})
			return
		}
		if charset, ok := params["charset"]; ok && strings.ToLower(charset) != "utf-8" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported charset"})
			return
		}

		limited := io.LimitReader(r.Body, 4097)
		bodyBytes, err := io.ReadAll(limited)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read request body"})
			return
		}
		if len(bodyBytes) > 4096 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "request body too large"})
			return
		}

		if !utf8.Valid(bodyBytes) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}

		dec := json.NewDecoder(bytes.NewReader(bodyBytes))
		dec.DisallowUnknownFields()
		var req protocol.TelemetryRequest
		if err := dec.Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		var extra any
		if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "trailing data in request body"})
			return
		}

		if req.ProtocolVersion <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid protocol version"})
			return
		}
		if req.ProtocolVersion != protocol.CurrentVersion {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "unsupported agent protocol"})
			return
		}

		if err := protocol.ValidateTelemetryRequest(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid telemetry request"})
			return
		}

		if authenticator == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "service unavailable"})
			return
		}

		dbCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		err = authenticator.RecordAgentTelemetry(dbCtx, pubKey, &req)
		if err != nil {
			if errors.Is(err, enrollment.ErrAgentNotFound) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "agent authentication failed"})
				return
			}
			logger.Error("agent telemetry database failure")
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
			return
		}

		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
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

func serveDual(ctx context.Context, localListener, remoteListener net.Listener, checker readinessChecker, registrar enrollmentRegistrar, authenticator agentAuthenticator, logger *slog.Logger) error {
	localSrv := &http.Server{
		Handler:           newHandler(logger, checker, registrar),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	remoteSrv := &http.Server{
		Handler:           newRemoteHandler(logger, registrar, authenticator),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() {
		errCh <- localSrv.Serve(localListener)
	}()
	go func() {
		errCh <- remoteSrv.Serve(remoteListener)
	}()

	select {
	case err := <-errCh:
		// One server stopped unexpectedly; shut down the other server
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = localSrv.Shutdown(shutdownCtx)
		_ = remoteSrv.Shutdown(shutdownCtx)
		err2 := <-errCh
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		if err2 != nil && !errors.Is(err2, http.ErrServerClosed) {
			return err2
		}
		return nil

	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err1 := localSrv.Shutdown(shutdownCtx)
		err2 := remoteSrv.Shutdown(shutdownCtx)
		sErr1 := <-errCh
		sErr2 := <-errCh
		if sErr1 != nil && !errors.Is(sErr1, http.ErrServerClosed) {
			return sErr1
		}
		if sErr2 != nil && !errors.Is(sErr2, http.ErrServerClosed) {
			return sErr2
		}
		if err1 != nil {
			return err1
		}
		return err2
	}
}

type runtimeBackend interface {
	readinessChecker
	enrollmentRegistrar
	agentAuthenticator
	operatorBackend
}

// Run starts the controller components and blocks until ctx is canceled.
func Run(ctx context.Context, cfg Config, backend runtimeBackend, logger *slog.Logger) error {
	if err := cfg.validate(); err != nil {
		return fmt.Errorf("invalid controller configuration: %w", err)
	}

	var (
		checker       readinessChecker
		registrar     enrollmentRegistrar
		authenticator agentAuthenticator
	)
	if backend != nil {
		checker = backend
		registrar = backend
		authenticator = backend
	}

	var remoteTLSConfig *tls.Config
	if cfg.RemoteEnabled() {
		var err error
		remoteTLSConfig, err = buildRemoteTLSConfig(cfg.AgentTLSCertFile, cfg.AgentTLSKeyFile)
		if err != nil {
			return err
		}
	}

	localListener, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", cfg.ListenAddress, err)
	}

	if !cfg.RemoteEnabled() {
		return serve(ctx, localListener, checker, registrar, logger)
	}

	remoteListener, err := tls.Listen("tcp", cfg.AgentListenAddress, remoteTLSConfig)
	if err != nil {
		localListener.Close()
		return fmt.Errorf("failed to listen on agent address %s: %w", cfg.AgentListenAddress, err)
	}

	return serveDual(ctx, localListener, remoteListener, checker, registrar, authenticator, logger)
}

func buildRemoteTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load agent TLS certificate: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequestClientCert,
	}, nil
}
