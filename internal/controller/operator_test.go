package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"stackpilot/internal/operator"
	"stackpilot/internal/protocol"
)

type mockOperatorBackend struct {
	mu          sync.Mutex
	operators   map[string]*operator.OperatorRecord
	sessions    map[[32]byte]*operator.Principal
	tokenHashes map[string][32]byte
	auditEvents []operator.AuditEventRecord

	getOpErr      error
	createSessErr error
	findSessErr   error
	revokeErr     error
	auditErr      error
}

func newMockOperatorBackend() *mockOperatorBackend {
	return &mockOperatorBackend{
		operators:   make(map[string]*operator.OperatorRecord),
		sessions:    make(map[[32]byte]*operator.Principal),
		tokenHashes: make(map[string][32]byte),
	}
}

func (m *mockOperatorBackend) addOperator(username, password string, role operator.Role, disabled bool) *operator.OperatorRecord {
	m.mu.Lock()
	defer m.mu.Unlock()

	hash, _ := operator.HashPassword(password)
	var disabledAt *time.Time
	if disabled {
		t := time.Now()
		disabledAt = &t
	}
	rec := &operator.OperatorRecord{
		ID:           fmt.Sprintf("op-id-%s", username),
		Username:     operator.NormalizeUsername(username),
		PasswordHash: hash,
		Role:         role,
		DisabledAt:   disabledAt,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	m.operators[rec.Username] = rec
	return rec
}

func (m *mockOperatorBackend) GetOperatorByUsername(ctx context.Context, username string) (*operator.OperatorRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.getOpErr != nil {
		return nil, m.getOpErr
	}
	rec, ok := m.operators[operator.NormalizeUsername(username)]
	if !ok {
		return nil, operator.ErrOperatorNotFound
	}
	return rec, nil
}

func (m *mockOperatorBackend) CreateOperatorSession(ctx context.Context, operatorID string, tokenHash [32]byte) (*operator.SessionRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.createSessErr != nil {
		return nil, m.createSessErr
	}

	var rec *operator.OperatorRecord
	for _, op := range m.operators {
		if op.ID == operatorID {
			rec = op
			break
		}
	}
	// Security invariant: Re-verify operator exists and is not disabled inside session transaction to prevent TOCTOU race.
	if rec == nil || rec.DisabledAt != nil {
		return nil, operator.ErrAuthenticationFailed
	}

	sessionID := fmt.Sprintf("sess-%d", len(m.sessions)+1)
	expiresAt := time.Now().Add(operator.SessionLifetime)

	m.sessions[tokenHash] = &operator.Principal{
		OperatorID: operatorID,
		Username:   rec.Username,
		Role:       rec.Role,
		SessionID:  sessionID,
		ExpiresAt:  expiresAt,
	}
	m.tokenHashes[sessionID] = tokenHash

	m.auditEvents = append(m.auditEvents, operator.AuditEventRecord{
		ID:               fmt.Sprintf("audit-%d", len(m.auditEvents)+1),
		OccurredAt:       time.Now(),
		ActorOperatorID:  &operatorID,
		ActorUsername:    rec.Username,
		Action:           operator.ActionOperatorLogin,
		TargetOperatorID: &operatorID,
		TargetUsername:   &rec.Username,
		Outcome:          operator.OutcomeSuccess,
	})

	return &operator.SessionRecord{
		ID:         sessionID,
		OperatorID: operatorID,
		CreatedAt:  time.Now(),
		ExpiresAt:  expiresAt,
	}, nil
}

func (m *mockOperatorBackend) FindOperatorSessionByTokenHash(ctx context.Context, tokenHash [32]byte) (*operator.Principal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.findSessErr != nil {
		return nil, m.findSessErr
	}

	p, ok := m.sessions[tokenHash]
	if !ok {
		return nil, operator.ErrAuthenticationFailed
	}
	if time.Now().After(p.ExpiresAt) {
		return nil, operator.ErrAuthenticationFailed
	}
	if op, ok := m.operators[p.Username]; ok && op.DisabledAt != nil {
		return nil, operator.ErrAuthenticationFailed
	}
	return p, nil
}

func (m *mockOperatorBackend) RevokeOperatorSession(ctx context.Context, sessionID string, operatorID string, username string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.revokeErr != nil {
		return m.revokeErr
	}

	tokHash, ok := m.tokenHashes[sessionID]
	if !ok {
		return operator.ErrSessionNotFound
	}
	principal, exists := m.sessions[tokHash]
	if !exists || principal.OperatorID != operatorID {
		return operator.ErrSessionNotFound
	}

	delete(m.sessions, tokHash)
	delete(m.tokenHashes, sessionID)

	m.auditEvents = append(m.auditEvents, operator.AuditEventRecord{
		ID:              fmt.Sprintf("audit-%d", len(m.auditEvents)+1),
		OccurredAt:      time.Now(),
		ActorOperatorID: &operatorID,
		ActorUsername:   username,
		Action:          operator.ActionOperatorLogout,
		Outcome:         operator.OutcomeSuccess,
	})

	return nil
}

func (m *mockOperatorBackend) RecordAndListAuditEvents(ctx context.Context, actorOperatorID string, actorUsername string, limit int) ([]operator.AuditEventRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.auditErr != nil {
		return nil, m.auditErr
	}

	readAudit := operator.AuditEventRecord{
		ID:              fmt.Sprintf("audit-%d", len(m.auditEvents)+1),
		OccurredAt:      time.Now(),
		ActorOperatorID: &actorOperatorID,
		ActorUsername:   actorUsername,
		Action:          operator.ActionOperatorAuditRead,
		Outcome:         operator.OutcomeSuccess,
	}
	m.auditEvents = append(m.auditEvents, readAudit)

	n := len(m.auditEvents)
	var out []operator.AuditEventRecord
	for i := n - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, m.auditEvents[i])
	}
	return out, nil
}

func TestOperatorLogin_Handler(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := newMockOperatorBackend()
	const validPW = "Strong-Password-123!"
	backend.addOperator("admin", validPW, operator.RoleAdmin, false)
	backend.addOperator("disabled_op", validPW, operator.RoleOperator, true)

	handler := newHandler(logger, nil, nil, backend)

	t.Run("GET method not allowed with Allow POST", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/operator/login", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", rec.Code)
		}
		if rec.Header().Get("Allow") != "POST" {
			t.Errorf("expected Allow: POST, got %q", rec.Header().Get("Allow"))
		}
	})

	t.Run("unsupported Content-Type returns 415", func(t *testing.T) {
		body := bytes.NewBufferString(`{"username":"admin","password":"` + validPW + `"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/operator/login", body)
		req.Header.Set("Content-Type", "text/plain")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("expected 415, got %d", rec.Code)
		}
	})

	t.Run("unsupported charset returns 415", func(t *testing.T) {
		body := bytes.NewBufferString(`{"username":"admin","password":"` + validPW + `"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/operator/login", body)
		req.Header.Set("Content-Type", "application/json; charset=iso-8859-1")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("expected 415, got %d", rec.Code)
		}
	})

	t.Run("raw invalid UTF-8 returns 400", func(t *testing.T) {
		body := bytes.NewBuffer([]byte("{\"username\":\"\xff\xfe\",\"password\":\"" + validPW + "\"}"))
		req := httptest.NewRequest(http.MethodPost, "/api/v1/operator/login", body)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("body exceeds size limit returns 400", func(t *testing.T) {
		oversized := strings.Repeat("a", 1025)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/operator/login", strings.NewReader(oversized))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("malformed JSON returns 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/operator/login", strings.NewReader(`{invalid}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("unknown JSON field rejected with 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/operator/login", strings.NewReader(`{"username":"admin","password":"`+validPW+`","extra":"value"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("trailing JSON data rejected with 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/operator/login", strings.NewReader(`{"username":"admin","password":"`+validPW+`"}{"another":"doc"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("empty request body returns 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/operator/login", strings.NewReader(``))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("successful login returns 200 with session token and metadata", func(t *testing.T) {
		body := `{"username":"admin","password":"` + validPW + `"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/operator/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d (body: %s)", rec.Code, rec.Body.String())
		}

		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("expected Cache-Control: no-store, got %q", rec.Header().Get("Cache-Control"))
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("expected X-Content-Type-Options: nosniff, got %q", rec.Header().Get("X-Content-Type-Options"))
		}
		if rec.Header().Get("Set-Cookie") != "" {
			t.Errorf("Set-Cookie must not be present, got %q", rec.Header().Get("Set-Cookie"))
		}
		if rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("CORS headers must not be present, got %q", rec.Header().Get("Access-Control-Allow-Origin"))
		}

		var resp struct {
			Token     string `json:"token"`
			ExpiresAt string `json:"expires_at"`
			Operator  struct {
				ID       string `json:"id"`
				Username string `json:"username"`
				Role     string `json:"role"`
			} `json:"operator"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode login response: %v", err)
		}

		if err := operator.ValidateSessionToken(resp.Token); err != nil {
			t.Errorf("returned session token is invalid: %v", err)
		}
		if resp.Operator.Username != "admin" || resp.Operator.Role != "admin" {
			t.Errorf("unexpected operator data in response: %+v", resp.Operator)
		}
		if resp.ExpiresAt == "" {
			t.Error("expires_at must be present")
		}
	})
}

func TestOperatorLogin_ExactFailureResponseAndBackendOutage(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := newMockOperatorBackend()
	const validPW = "Strong-Password-123!"
	backend.addOperator("admin", validPW, operator.RoleAdmin, false)
	backend.addOperator("disabled_op", validPW, operator.RoleOperator, true)

	handler := newHandler(logger, nil, nil, backend)

	// Security invariant: Protect against username enumeration regressions by requiring
	// status code and response body to be byte-for-byte identical across unknown user,
	// wrong password, and disabled operator.
	t.Run("identical generic response for unknown user, wrong password, and disabled operator", func(t *testing.T) {
		reqUnknown := httptest.NewRequest(http.MethodPost, "/api/v1/operator/login", strings.NewReader(`{"username":"nonexistent_user","password":"`+validPW+`"}`))
		reqUnknown.Header.Set("Content-Type", "application/json")
		recUnknown := httptest.NewRecorder()
		handler.ServeHTTP(recUnknown, reqUnknown)

		reqWrongPW := httptest.NewRequest(http.MethodPost, "/api/v1/operator/login", strings.NewReader(`{"username":"admin","password":"WrongPassword123!"}`))
		reqWrongPW.Header.Set("Content-Type", "application/json")
		recWrongPW := httptest.NewRecorder()
		handler.ServeHTTP(recWrongPW, reqWrongPW)

		reqDisabled := httptest.NewRequest(http.MethodPost, "/api/v1/operator/login", strings.NewReader(`{"username":"disabled_op","password":"`+validPW+`"}`))
		reqDisabled.Header.Set("Content-Type", "application/json")
		recDisabled := httptest.NewRecorder()
		handler.ServeHTTP(recDisabled, reqDisabled)

		if recUnknown.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for unknown user, got %d", recUnknown.Code)
		}
		if recWrongPW.Code != recUnknown.Code {
			t.Fatalf("expected status code %d for wrong password, got %d", recUnknown.Code, recWrongPW.Code)
		}
		if recDisabled.Code != recUnknown.Code {
			t.Fatalf("expected status code %d for disabled user, got %d", recUnknown.Code, recDisabled.Code)
		}

		bodyUnknown := recUnknown.Body.String()
		bodyWrongPW := recWrongPW.Body.String()
		bodyDisabled := recDisabled.Body.String()

		if bodyUnknown != bodyWrongPW {
			t.Fatalf("mismatched login failure body between unknown user and wrong password:\nunknown: %q\nwrong:   %q", bodyUnknown, bodyWrongPW)
		}
		if bodyUnknown != bodyDisabled {
			t.Fatalf("mismatched login failure body between unknown user and disabled user:\nunknown:  %q\ndisabled: %q", bodyUnknown, bodyDisabled)
		}

		expectedBody := "{\"error\":\"invalid credentials\"}\n"
		if bodyUnknown != expectedBody {
			t.Fatalf("expected exact JSON body %q, got %q", expectedBody, bodyUnknown)
		}
	})

	t.Run("database outage yields generic 500 without leaking error details or credentials", func(t *testing.T) {
		const dbLeakMsg = "pq: connection refused to postgres:5432 with credentials secret_db_role:secret_db_pass"
		backend.getOpErr = errors.New(dbLeakMsg)
		defer func() { backend.getOpErr = nil }()

		const candidatePW = "UserSuppliedPassword123!"
		req := httptest.NewRequest(http.MethodPost, "/api/v1/operator/login", strings.NewReader(`{"username":"admin","password":"`+candidatePW+`"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 on database failure, got %d", rec.Code)
		}

		respBody := rec.Body.String()
		expectedBody := "{\"error\":\"internal server error\"}\n"
		if respBody != expectedBody {
			t.Fatalf("expected exact 500 body %q, got %q", expectedBody, respBody)
		}
		if strings.Contains(respBody, "postgres") || strings.Contains(respBody, "connection refused") || strings.Contains(respBody, "secret_db_pass") {
			t.Fatalf("response body leaked internal database error details: %s", respBody)
		}
		if strings.Contains(respBody, candidatePW) {
			t.Fatalf("response body leaked password: %s", respBody)
		}
	})

	t.Run("session creation race with disabled operator returns identical 401", func(t *testing.T) {
		backend.createSessErr = operator.ErrAuthenticationFailed
		defer func() { backend.createSessErr = nil }()

		req := httptest.NewRequest(http.MethodPost, "/api/v1/operator/login", strings.NewReader(`{"username":"admin","password":"`+validPW+`"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 on session race failure, got %d", rec.Code)
		}
		expectedBody := "{\"error\":\"invalid credentials\"}\n"
		if rec.Body.String() != expectedBody {
			t.Fatalf("expected exact 401 body %q, got %q", expectedBody, rec.Body.String())
		}
	})

	t.Run("session creation database failure yields generic 500", func(t *testing.T) {
		backend.createSessErr = errors.New("pq: disk full or session write failure")
		defer func() { backend.createSessErr = nil }()

		req := httptest.NewRequest(http.MethodPost, "/api/v1/operator/login", strings.NewReader(`{"username":"admin","password":"`+validPW+`"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 on session persistence error, got %d", rec.Code)
		}
		expectedBody := "{\"error\":\"internal server error\"}\n"
		if rec.Body.String() != expectedBody {
			t.Fatalf("expected exact 500 body %q, got %q", expectedBody, rec.Body.String())
		}
	})

	t.Run("corrupt database role lookup yields generic 500 without leaking error details", func(t *testing.T) {
		backend.getOpErr = errors.New("corrupt operator role: invalid role \"corrupt_role_value\"")
		defer func() { backend.getOpErr = nil }()

		req := httptest.NewRequest(http.MethodPost, "/api/v1/operator/login", strings.NewReader(`{"username":"admin","password":"`+validPW+`"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 on corrupt role, got %d", rec.Code)
		}
		expectedBody := "{\"error\":\"internal server error\"}\n"
		if rec.Body.String() != expectedBody {
			t.Fatalf("expected exact 500 body %q, got %q", expectedBody, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "corrupt") || strings.Contains(rec.Body.String(), "corrupt_role_value") {
			t.Fatalf("response body leaked internal role corruption error: %s", rec.Body.String())
		}
	})
}

func TestOperatorLogin_Argon2ConcurrencySaturated(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := newMockOperatorBackend()
	backend.addOperator("admin", "Strong-Password-123!", operator.RoleAdmin, false)

	limiter := operator.NewConcurrencyLimiter(2)
	rel1, _ := limiter.TryAcquire()
	rel2, _ := limiter.TryAcquire()
	defer rel1()
	defer rel2()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/operator/login", strings.NewReader(`{"username":"admin","password":"Strong-Password-123!"}`))
	r.Header.Set("Content-Type", "application/json")

	handleOperatorLogin(w, r, backend, limiter, logger)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 when concurrency saturated, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") != "1" {
		t.Errorf("expected Retry-After: 1, got %q", w.Header().Get("Retry-After"))
	}
}

func TestOperatorAuth_HeaderValidation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := newMockOperatorBackend()
	backend.addOperator("admin", "Strong-Password-123!", operator.RoleAdmin, false)

	tok, _ := operator.GenerateSessionToken()
	h := operator.HashSessionToken(tok)
	_, _ = backend.CreateOperatorSession(context.Background(), "op-id-admin", h)

	handler := newHandler(logger, nil, nil, backend)

	t.Run("missing Authorization header returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/operator/me", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("Basic auth header returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/operator/me", nil)
		req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("Bearer missing token returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/operator/me", nil)
		req.Header.Set("Authorization", "Bearer ")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("malformed token returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/operator/me", nil)
		req.Header.Set("Authorization", "Bearer invalid-token-format")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("unknown validly-formatted token returns 401", func(t *testing.T) {
		otherTok, _ := operator.GenerateSessionToken()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/operator/me", nil)
		req.Header.Set("Authorization", "Bearer "+otherTok)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("token in query only returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/operator/me?token="+tok, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("token in cookie only returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/operator/me", nil)
		req.AddCookie(&http.Cookie{Name: "session", Value: tok})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("valid Bearer token returns 200", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/operator/me", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
	})
}

func TestOperatorAuth_BackendOutage(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := newMockOperatorBackend()
	backend.addOperator("admin", "Strong-Password-123!", operator.RoleAdmin, false)

	tok, _ := operator.GenerateSessionToken()
	h := operator.HashSessionToken(tok)
	_, _ = backend.CreateOperatorSession(context.Background(), "op-id-admin", h)

	const mockDBError = "synthetic postgres connection failure secret-value"
	backend.findSessErr = errors.New(mockDBError)
	handler := newHandler(logger, nil, nil, backend)

	routes := []struct {
		name   string
		method string
		path   string
	}{
		{"GET /me session database outage returns 500", http.MethodGet, "/api/v1/operator/me"},
		{"POST /logout session database outage returns 500", http.MethodPost, "/api/v1/operator/logout"},
		{"GET /audit session database outage returns 500", http.MethodGet, "/api/v1/operator/audit"},
	}

	for _, tc := range routes {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("expected 500 on session lookup backend failure, got %d", rec.Code)
			}
			expectedBody := "{\"error\":\"internal server error\"}\n"
			if rec.Body.String() != expectedBody {
				t.Fatalf("expected exact 500 body %q, got %q", expectedBody, rec.Body.String())
			}

			bodyStr := rec.Body.String()
			prohibited := []string{"postgres", "connection failure", "secret-value", tok, "Authorization"}
			for _, p := range prohibited {
				if strings.Contains(bodyStr, p) {
					t.Errorf("response body leaked sensitive item %q: %s", p, bodyStr)
				}
			}
		})
	}
}

func TestOperatorAuth_DefensivePrincipalRoleValidation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := newMockOperatorBackend()
	backend.addOperator("admin", "Strong-Password-123!", operator.RoleAdmin, false)

	tok, _ := operator.GenerateSessionToken()
	h := operator.HashSessionToken(tok)
	_, _ = backend.CreateOperatorSession(context.Background(), "op-id-admin", h)

	// Inject a principal with an unrecognized/corrupt role
	backend.mu.Lock()
	backend.sessions[h] = &operator.Principal{
		OperatorID: "op-id-admin",
		Username:   "admin",
		Role:       operator.Role("custom_role"),
		SessionID:  "sess-corrupt",
		ExpiresAt:  time.Now().Add(12 * time.Hour),
	}
	backend.mu.Unlock()

	handler := newHandler(logger, nil, nil, backend)

	// Security invariant: Unrecognized principal role fails closed with 401 and prevents privileged data access.
	t.Run("/me with invalid principal role returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/operator/me", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for invalid principal role on /me, got %d", rec.Code)
		}
		expectedBody := "{\"error\":\"authentication required\"}\n"
		if rec.Body.String() != expectedBody {
			t.Fatalf("expected exact 401 body %q, got %q", expectedBody, rec.Body.String())
		}
	})

	t.Run("/audit with invalid principal role returns 401 and denies privileged data", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/operator/audit", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for invalid principal role on /audit, got %d", rec.Code)
		}
		expectedBody := "{\"error\":\"authentication required\"}\n"
		if rec.Body.String() != expectedBody {
			t.Fatalf("expected exact 401 body %q, got %q", expectedBody, rec.Body.String())
		}
	})
}

func TestOperatorMe_Endpoint(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := newMockOperatorBackend()
	backend.addOperator("admin", "Strong-Password-123!", operator.RoleAdmin, false)

	tok, _ := operator.GenerateSessionToken()
	h := operator.HashSessionToken(tok)
	_, _ = backend.CreateOperatorSession(context.Background(), "op-id-admin", h)

	handler := newHandler(logger, nil, nil, backend)

	t.Run("POST returns 405 with Allow GET", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/operator/me", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", rec.Code)
		}
		if rec.Header().Get("Allow") != "GET" {
			t.Errorf("expected Allow: GET, got %q", rec.Header().Get("Allow"))
		}
	})

	t.Run("valid GET returns safe fields only", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/operator/me", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}

		bodyStr := rec.Body.String()
		prohibitedSecrets := []string{"password", "password_hash", "token_hash", "sp_session_"}
		for _, s := range prohibitedSecrets {
			if strings.Contains(bodyStr, s) {
				t.Errorf("response body leaks %q: %s", s, bodyStr)
			}
		}

		var meResp struct {
			ID               string `json:"id"`
			Username         string `json:"username"`
			Role             string `json:"role"`
			SessionExpiresAt string `json:"session_expires_at"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &meResp); err != nil {
			t.Fatalf("failed to decode me response: %v", err)
		}
		if meResp.Username != "admin" || meResp.Role != "admin" || meResp.ID != "op-id-admin" {
			t.Errorf("unexpected me response fields: %+v", meResp)
		}
	})
}

func TestOperatorLogout_Endpoint(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := newMockOperatorBackend()
	backend.addOperator("admin", "Strong-Password-123!", operator.RoleAdmin, false)

	tok1, _ := operator.GenerateSessionToken()
	h1 := operator.HashSessionToken(tok1)
	_, _ = backend.CreateOperatorSession(context.Background(), "op-id-admin", h1)

	tok2, _ := operator.GenerateSessionToken()
	h2 := operator.HashSessionToken(tok2)
	_, _ = backend.CreateOperatorSession(context.Background(), "op-id-admin", h2)

	handler := newHandler(logger, nil, nil, backend)

	t.Run("revoking current session succeeds and emits audit event", func(t *testing.T) {
		initialAuditCount := len(backend.auditEvents)

		logoutReq := httptest.NewRequest(http.MethodPost, "/api/v1/operator/logout", nil)
		logoutReq.Header.Set("Authorization", "Bearer "+tok1)
		logoutRec := httptest.NewRecorder()
		handler.ServeHTTP(logoutRec, logoutReq)

		if logoutRec.Code != http.StatusNoContent {
			t.Fatalf("expected 204 on logout, got %d", logoutRec.Code)
		}
		if logoutRec.Body.Len() != 0 {
			t.Errorf("expected empty body on 204 logout, got %q", logoutRec.Body.String())
		}
		if logoutRec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("expected Cache-Control: no-store, got %q", logoutRec.Header().Get("Cache-Control"))
		}

		if len(backend.auditEvents) != initialAuditCount+1 {
			t.Fatalf("expected 1 new audit event for logout, got total %d", len(backend.auditEvents))
		}
		lastEvent := backend.auditEvents[len(backend.auditEvents)-1]
		if lastEvent.Action != operator.ActionOperatorLogout || lastEvent.Outcome != operator.OutcomeSuccess {
			t.Errorf("unexpected audit event on logout: %+v", lastEvent)
		}
	})

	t.Run("revoked token is rejected with 401", func(t *testing.T) {
		meReq1 := httptest.NewRequest(http.MethodGet, "/api/v1/operator/me", nil)
		meReq1.Header.Set("Authorization", "Bearer "+tok1)
		meRec1 := httptest.NewRecorder()
		handler.ServeHTTP(meRec1, meReq1)
		if meRec1.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 after logout with same token, got %d", meRec1.Code)
		}
	})

	t.Run("other active session remains valid", func(t *testing.T) {
		meReq2 := httptest.NewRequest(http.MethodGet, "/api/v1/operator/me", nil)
		meReq2.Header.Set("Authorization", "Bearer "+tok2)
		meRec2 := httptest.NewRecorder()
		handler.ServeHTTP(meRec2, meReq2)
		if meRec2.Code != http.StatusOK {
			t.Fatalf("expected 200 for other active session, got %d", meRec2.Code)
		}
	})

	t.Run("repeated logout of already-revoked session fails safely without audit event", func(t *testing.T) {
		initialAuditCount := len(backend.auditEvents)

		logoutReq := httptest.NewRequest(http.MethodPost, "/api/v1/operator/logout", nil)
		logoutReq.Header.Set("Authorization", "Bearer "+tok1)
		logoutRec := httptest.NewRecorder()
		handler.ServeHTTP(logoutRec, logoutReq)

		if logoutRec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for revoked token logout attempt, got %d", logoutRec.Code)
		}
		if len(backend.auditEvents) != initialAuditCount {
			t.Fatalf("expected no new audit event on failed logout, event count changed from %d to %d", initialAuditCount, len(backend.auditEvents))
		}
	})
}

func TestOperatorAudit_RBACAndLimits(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := newMockOperatorBackend()
	backend.addOperator("admin", "Strong-Password-123!", operator.RoleAdmin, false)
	backend.addOperator("op", "Strong-Password-123!", operator.RoleOperator, false)
	backend.addOperator("viewer", "Strong-Password-123!", operator.RoleViewer, false)

	tokAdmin, _ := operator.GenerateSessionToken()
	_, _ = backend.CreateOperatorSession(context.Background(), "op-id-admin", operator.HashSessionToken(tokAdmin))

	tokOp, _ := operator.GenerateSessionToken()
	_, _ = backend.CreateOperatorSession(context.Background(), "op-id-op", operator.HashSessionToken(tokOp))

	tokViewer, _ := operator.GenerateSessionToken()
	_, _ = backend.CreateOperatorSession(context.Background(), "op-id-viewer", operator.HashSessionToken(tokViewer))

	handler := newHandler(logger, nil, nil, backend)

	t.Run("viewer role returns 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/operator/audit", nil)
		req.Header.Set("Authorization", "Bearer "+tokViewer)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rec.Code)
		}
	})

	t.Run("operator role returns 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/operator/audit", nil)
		req.Header.Set("Authorization", "Bearer "+tokOp)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rec.Code)
		}
	})

	t.Run("admin role returns 200", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/operator/audit", nil)
		req.Header.Set("Authorization", "Bearer "+tokAdmin)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}

		var events []operator.AuditEventRecord
		if err := json.Unmarshal(rec.Body.Bytes(), &events); err != nil {
			t.Fatalf("failed to decode audit events: %v", err)
		}
		if len(events) == 0 {
			t.Fatal("expected audit events returned")
		}

		if events[0].Action != operator.ActionOperatorAuditRead {
			t.Errorf("expected first event to be operator.audit.read, got %q", events[0].Action)
		}
	})

	cases := []struct {
		url        string
		expectCode int
	}{
		{"/api/v1/operator/audit?limit=100", http.StatusOK},
		{"/api/v1/operator/audit?limit=1", http.StatusOK},
		{"/api/v1/operator/audit?limit=200", http.StatusOK},
		{"/api/v1/operator/audit?limit=0", http.StatusBadRequest},
		{"/api/v1/operator/audit?limit=201", http.StatusBadRequest},
		{"/api/v1/operator/audit?limit=-5", http.StatusBadRequest},
		{"/api/v1/operator/audit?limit=abc", http.StatusBadRequest},
		{"/api/v1/operator/audit?unknown=1", http.StatusBadRequest},
	}

	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, tc.url, nil)
		req.Header.Set("Authorization", "Bearer "+tokAdmin)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tc.expectCode {
			t.Errorf("GET %s: expected %d, got %d", tc.url, tc.expectCode, rec.Code)
		}
	}
}

func TestRemoteHandler_TrustDomainIsolation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := &fakeAuthBackend{}
	remoteHandler := newRemoteHandler(logger, backend, backend)

	now := time.Now()
	_, _, validAgentCert := helperGenerateEd25519Cert(t, now.Add(-5*time.Minute), now.Add(1*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, "Agent-Client", nil)

	// Security invariant: Remote listener rejects operator endpoints unconditionally even when
	// presenting a valid Agent mTLS client certificate.
	t.Run("remote listener returns 404 for all operator endpoints with valid agent cert", func(t *testing.T) {
		operatorEndpoints := []string{
			"/api/v1/operator/login",
			"/api/v1/operator/logout",
			"/api/v1/operator/me",
			"/api/v1/operator/audit",
		}

		for _, ep := range operatorEndpoints {
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				req := httptest.NewRequest(method, ep, nil)
				req.TLS = &tls.ConnectionState{
					HandshakeComplete: true,
					PeerCertificates:  []*x509.Certificate{validAgentCert},
				}
				rec := httptest.NewRecorder()
				remoteHandler.ServeHTTP(rec, req)
				if rec.Code != http.StatusNotFound {
					t.Errorf("remoteHandler %s %s: expected 404 with agent cert, got %d", method, ep, rec.Code)
				}
			}
		}
	})

	// Security invariant: Operator Bearer tokens cannot authorize Agent endpoints without valid mTLS client cert.
	t.Run("operator Bearer token does not authorize agent endpoints", func(t *testing.T) {
		opTok, err := operator.GenerateSessionToken()
		if err != nil {
			t.Fatalf("failed to generate operator token: %v", err)
		}

		agentEndpoints := []struct {
			method string
			path   string
		}{
			{http.MethodGet, "/api/v1/agent/self"},
			{http.MethodPost, protocol.HeartbeatEndpointPath},
			{http.MethodPut, protocol.InventoryEndpointPath},
			{http.MethodPut, protocol.TelemetryEndpointPath},
		}

		for _, ep := range agentEndpoints {
			reqNoTLS := httptest.NewRequest(ep.method, ep.path, nil)
			reqNoTLS.Header.Set("Authorization", "Bearer "+opTok)
			recNoTLS := httptest.NewRecorder()
			remoteHandler.ServeHTTP(recNoTLS, reqNoTLS)
			if recNoTLS.Code != http.StatusBadRequest {
				t.Errorf("%s %s with Bearer without TLS: expected 400 (tls required), got %d", ep.method, ep.path, recNoTLS.Code)
			}

			reqTLSNoCert := httptest.NewRequest(ep.method, ep.path, nil)
			reqTLSNoCert.Header.Set("Authorization", "Bearer "+opTok)
			reqTLSNoCert.TLS = &tls.ConnectionState{HandshakeComplete: true}
			recTLSNoCert := httptest.NewRecorder()
			remoteHandler.ServeHTTP(recTLSNoCert, reqTLSNoCert)
			if recTLSNoCert.Code != http.StatusUnauthorized {
				t.Errorf("%s %s with Bearer with TLS but no cert: expected 401, got %d", ep.method, ep.path, recTLSNoCert.Code)
			}
		}
	})
}

func TestOperator_AuditFailureFailsClosed(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := newMockOperatorBackend()
	backend.addOperator("admin", "Strong-Password-123!", operator.RoleAdmin, false)

	tokAdmin, _ := operator.GenerateSessionToken()
	_, _ = backend.CreateOperatorSession(context.Background(), "op-id-admin", operator.HashSessionToken(tokAdmin))

	backend.auditErr = errors.New("audit persistence failed")

	handler := newHandler(logger, nil, nil, backend)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/operator/audit", nil)
	req.Header.Set("Authorization", "Bearer "+tokAdmin)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Security invariant: Fail-closed on audit logging failure.
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when audit logging fails, got %d", rec.Code)
	}
}

func TestRealHTTP_EndToEndFlow(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := newMockOperatorBackend()
	const password = "Very-Strong-Password-123!"
	backend.addOperator("admin", password, operator.RoleAdmin, false)

	handler := newHandler(logger, nil, nil, backend)
	server := httptest.NewServer(handler)
	defer server.Close()

	client := server.Client()

	loginBody := `{"username":"admin","password":"` + password + `"}`
	loginResp, err := client.Post(server.URL+"/api/v1/operator/login", "application/json", strings.NewReader(loginBody))
	if err != nil {
		t.Fatalf("login POST failed: %v", err)
	}
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("login failed: expected 200, got %d", loginResp.StatusCode)
	}

	var loginData struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(loginResp.Body).Decode(&loginData); err != nil {
		t.Fatalf("failed to decode login response: %v", err)
	}
	loginResp.Body.Close()

	if loginData.Token == "" {
		t.Fatal("empty token returned on login")
	}

	meReq, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/operator/me", nil)
	meReq.Header.Set("Authorization", "Bearer "+loginData.Token)
	meResp, err := client.Do(meReq)
	if err != nil {
		t.Fatalf("GET /me failed: %v", err)
	}
	if meResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on /me, got %d", meResp.StatusCode)
	}
	meResp.Body.Close()

	auditReq, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/operator/audit", nil)
	auditReq.Header.Set("Authorization", "Bearer "+loginData.Token)
	auditResp, err := client.Do(auditReq)
	if err != nil {
		t.Fatalf("GET /audit failed: %v", err)
	}
	if auditResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on /audit, got %d", auditResp.StatusCode)
	}
	auditResp.Body.Close()

	logoutReq, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/operator/logout", nil)
	logoutReq.Header.Set("Authorization", "Bearer "+loginData.Token)
	logoutResp, err := client.Do(logoutReq)
	if err != nil {
		t.Fatalf("POST /logout failed: %v", err)
	}
	if logoutResp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 on /logout, got %d", logoutResp.StatusCode)
	}
	logoutResp.Body.Close()

	meReqAfter, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/operator/me", nil)
	meReqAfter.Header.Set("Authorization", "Bearer "+loginData.Token)
	meRespAfter, err := client.Do(meReqAfter)
	if err != nil {
		t.Fatalf("GET /me after logout failed: %v", err)
	}
	if meRespAfter.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 after logout, got %d", meRespAfter.StatusCode)
	}
	meRespAfter.Body.Close()
}
