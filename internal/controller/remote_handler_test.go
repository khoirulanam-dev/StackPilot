package controller

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
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

	"stackpilot/internal/agent"
	"stackpilot/internal/enrollment"
)

type fakeAuthBackend struct {
	mu           sync.Mutex
	agents       map[[32]byte]*enrollment.AgentRecord
	lastQueryKey [32]byte
	findErr      error
	registerErr  error
}

func (f *fakeAuthBackend) RegisterAgent(ctx context.Context, tokenHash [32]byte, publicKey [32]byte) (*enrollment.AgentRecord, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.registerErr != nil {
		return nil, false, f.registerErr
	}

	rec := &enrollment.AgentRecord{
		ID:        "018f0000-0000-7000-8000-000000000001",
		PublicKey: publicKey,
		CreatedAt: time.Now().UTC(),
	}
	if f.agents == nil {
		f.agents = make(map[[32]byte]*enrollment.AgentRecord)
	}
	f.agents[publicKey] = rec
	return rec, true, nil
}

func (f *fakeAuthBackend) FindAgentByPublicKey(ctx context.Context, publicKey [32]byte) (*enrollment.AgentRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.lastQueryKey = publicKey
	if f.findErr != nil {
		return nil, f.findErr
	}

	if f.agents != nil {
		if rec, ok := f.agents[publicKey]; ok {
			return rec, nil
		}
	}
	return nil, enrollment.ErrAgentNotFound
}

func (f *fakeAuthBackend) Ping(ctx context.Context) error {
	return nil
}

func helperGenerateEd25519Cert(t *testing.T, notBefore, notAfter time.Time, extKeyUsage []x509.ExtKeyUsage, cn string, sanDNS []string) (ed25519.PublicKey, ed25519.PrivateKey, *x509.Certificate) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey failed: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		DNSNames:              sanDNS,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate failed: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	return pub, priv, cert
}

func helperGenerateECDSACert(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey failed: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(101),
		Subject: pkix.Name{
			CommonName: "ECDSA Test Cert",
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate ECDSA failed: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate ECDSA failed: %v", err)
	}

	return priv, cert
}

// ============================================================================
// Section 6: Real Controller Remote Handler Tests (Cases A through K)
// ============================================================================

func TestRemoteHandler_Scenarios(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := &fakeAuthBackend{}
	handler := newRemoteHandler(logger, backend, backend)

	now := time.Now()
	validPub, _, validCert := helperGenerateEd25519Cert(t, now.Add(-5*time.Minute), now.Add(1*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, "", nil)

	var validPubKeyBytes [32]byte
	copy(validPubKeyBytes[:], validPub)

	// Pre-enroll valid agent in backend
	backend.mu.Lock()
	backend.agents = map[[32]byte]*enrollment.AgentRecord{
		validPubKeyBytes: {
			ID:        "018f0000-0000-7000-8000-000000000001",
			PublicKey: validPubKeyBytes,
			CreatedAt: now.UTC(),
		},
	}
	backend.mu.Unlock()

	// A. Plaintext invocation: remote enroll/self invoked without r.TLS -> safely rejected (400)
	t.Run("A_plaintext_invocation_rejected", func(t *testing.T) {
		// Test enroll without TLS
		reqEnroll := httptest.NewRequest(http.MethodPost, "/api/v1/agent/enroll", strings.NewReader("{}"))
		reqEnroll.Header.Set("Content-Type", "application/json")
		recEnroll := httptest.NewRecorder()
		handler.ServeHTTP(recEnroll, reqEnroll)
		if recEnroll.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for plaintext enroll, got %d", recEnroll.Code)
		}

		// Test self GET without TLS -> 400
		reqSelf := httptest.NewRequest(http.MethodGet, "/api/v1/agent/self", nil)
		recSelf := httptest.NewRecorder()
		handler.ServeHTTP(recSelf, reqSelf)
		if recSelf.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for plaintext self GET, got %d", recSelf.Code)
		}

		// Test self POST without TLS -> 400 (TLS gate BEFORE method check)
		reqSelfPost := httptest.NewRequest(http.MethodPost, "/api/v1/agent/self", nil)
		recSelfPost := httptest.NewRecorder()
		handler.ServeHTTP(recSelfPost, reqSelfPost)
		if recSelfPost.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for plaintext self POST, got %d", recSelfPost.Code)
		}
	})

	// B. GET /api/v1/agent/self: valid Ed25519 cert + enrolled public key -> 200 + returned Agent ID
	t.Run("B_valid_ed25519_cert_and_enrolled_key_succeeds", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/self", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{validCert},
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}

		var respData struct {
			AgentID string `json:"agent_id"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &respData); err != nil {
			t.Fatalf("failed to decode JSON response: %v", err)
		}
		if respData.AgentID != "018f0000-0000-7000-8000-000000000001" {
			t.Errorf("expected agent ID 018f0000-0000-7000-8000-000000000001, got %q", respData.AgentID)
		}
	})

	// C. Missing client cert -> 401 generic
	t.Run("C_missing_client_cert_rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/self", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: nil,
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "agent authentication failed") {
			t.Errorf("expected generic error message, got %s", rec.Body.String())
		}
	})

	// D. Wrong key type, e.g. ECDSA certificate -> 401 generic
	t.Run("D_wrong_key_type_ecdsa_rejected", func(t *testing.T) {
		_, ecdsaCert := helperGenerateECDSACert(t)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/self", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{ecdsaCert},
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "agent authentication failed") {
			t.Errorf("expected generic error message, got %s", rec.Body.String())
		}
	})

	// E. Unknown Ed25519 public key -> 401 generic
	t.Run("E_unknown_ed25519_key_rejected", func(t *testing.T) {
		_, _, unknownCert := helperGenerateEd25519Cert(t, now.Add(-5*time.Minute), now.Add(1*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, "", nil)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/self", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{unknownCert},
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "agent authentication failed") {
			t.Errorf("expected generic error message, got %s", rec.Body.String())
		}
	})

	// F. Expired certificate -> 401 generic
	t.Run("F_expired_cert_rejected", func(t *testing.T) {
		_, _, expiredCert := helperGenerateEd25519Cert(t, now.Add(-2*time.Hour), now.Add(-1*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, "", nil)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/self", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{expiredCert},
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
		}
	})

	// G. Not-yet-valid certificate -> 401 generic
	t.Run("G_not_yet_valid_cert_rejected", func(t *testing.T) {
		_, _, futureCert := helperGenerateEd25519Cert(t, now.Add(1*time.Hour), now.Add(2*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, "", nil)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/self", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{futureCert},
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
		}
	})

	// H. ExtKeyUsage present but not ClientAuth -> 401 generic
	t.Run("H_missing_client_auth_ext_key_usage_rejected", func(t *testing.T) {
		_, _, serverAuthCert := helperGenerateEd25519Cert(t, now.Add(-5*time.Minute), now.Add(1*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, "", nil)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/self", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{serverAuthCert},
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
		}
	})

	// I. Backend/database synthetic failure -> generic 500, synthetic secret text MUST NOT appear
	t.Run("I_backend_synthetic_failure_no_secret_leakage", func(t *testing.T) {
		const secretText = "SUPER_SECRET_DATABASE_FAILURE_TOKEN_XYZ_123"
		backend.mu.Lock()
		backend.findErr = errors.New("synthetic db error: " + secretText)
		backend.mu.Unlock()
		defer func() {
			backend.mu.Lock()
			backend.findErr = nil
			backend.mu.Unlock()
		}()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/self", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{validCert},
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 Internal Server Error, got %d", rec.Code)
		}
		if strings.Contains(rec.Body.String(), secretText) {
			t.Fatalf("leak detected: response body contains synthetic secret text: %s", rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "internal server error") {
			t.Errorf("expected generic internal server error message, got %s", rec.Body.String())
		}
	})

	// J. POST /api/v1/agent/self -> 405 + Allow: GET
	t.Run("J_method_not_allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/self", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{validCert},
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405 Method Not Allowed, got %d", rec.Code)
		}
		if allow := rec.Header().Get("Allow"); allow != "GET" {
			t.Errorf("expected Allow: GET, got %q", allow)
		}
	})

	// K. Successful /self: Content-Type application/json, Cache-Control no-store, no Access-Control-Allow-Origin wildcard
	t.Run("K_successful_headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/self", nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{validCert},
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", rec.Code)
		}
		ct := rec.Header().Get("Content-Type")
		if !strings.HasPrefix(ct, "application/json") {
			t.Errorf("expected Content-Type application/json, got %q", ct)
		}
		cc := rec.Header().Get("Cache-Control")
		if cc != "no-store" {
			t.Errorf("expected Cache-Control no-store, got %q", cc)
		}
		if acao := rec.Header().Get("Access-Control-Allow-Origin"); acao != "" {
			t.Errorf("unexpected Access-Control-Allow-Origin header present: %q", acao)
		}
	})
}

// ============================================================================
// Section 7: Certificate Text Impersonation Test
// ============================================================================

func TestRemoteHandler_CertificateTextImpersonationRejected(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := &fakeAuthBackend{}
	handler := newRemoteHandler(logger, backend, backend)

	now := time.Now()

	// 1. Agent A in backend
	pubA, _, _ := helperGenerateEd25519Cert(t, now.Add(-5*time.Minute), now.Add(1*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, "Agent A", nil)
	var keyA [32]byte
	copy(keyA[:], pubA)
	const agentAID = "018f0000-0000-7000-8000-00000000000A"

	backend.mu.Lock()
	backend.agents = map[[32]byte]*enrollment.AgentRecord{
		keyA: {
			ID:        agentAID,
			PublicKey: keyA,
			CreatedAt: now.UTC(),
		},
	}
	backend.mu.Unlock()

	// 2. Attacker generates key B, but crafts client cert with Subject CommonName = Agent A ID, SAN = agent-a
	pubB, _, certB := helperGenerateEd25519Cert(t, now.Add(-5*time.Minute), now.Add(1*time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, agentAID, []string{agentAID, "agent-a"})

	var keyB [32]byte
	copy(keyB[:], pubB)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/self", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{certB},
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Must be rejected with 401 Unauthorized
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for cert text impersonation attempt, got %d", rec.Code)
	}

	// Verify backend lookup received key B (NOT key A, NOT common name)
	backend.mu.Lock()
	lookupKey := backend.lastQueryKey
	backend.mu.Unlock()

	if !bytes.Equal(lookupKey[:], keyB[:]) {
		t.Fatalf("expected backend lookup to receive public key B, but got different key")
	}
	if bytes.Equal(lookupKey[:], keyA[:]) {
		t.Fatalf("backend lookup received key A instead of key B; server authorized based on certificate text!")
	}
}

// ============================================================================
// Section 8: True StackPilot TLS End-to-End Test
// ============================================================================

func TestStackPilotTLS_EndToEnd(t *testing.T) {
	// 1. Generate temporary test CA
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "StackPilot E2E Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caPriv)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA cert: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caDER,
	})

	// 2. Generate server cert valid for 127.0.0.1
	srvPub, srvPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}
	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "127.0.0.1",
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, srvPub, caPriv)
	if err != nil {
		t.Fatalf("failed to sign server cert: %v", err)
	}
	srvTLSCert := tls.Certificate{
		Certificate: [][]byte{srvDER},
		PrivateKey:  srvPriv,
	}

	// 3. Fake backend
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := &fakeAuthBackend{}

	// 4. Start HTTPS server using actual newRemoteHandler with TLS 1.3 and RequestClientCert
	actualHandler := newRemoteHandler(logger, backend, backend)
	ts := httptest.NewUnstartedServer(actualHandler)
	ts.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{srvTLSCert},
		ClientAuth:   tls.RequestClientCert,
	}
	ts.StartTLS()
	defer ts.Close()

	tempDir := t.TempDir()
	stateDir := filepath.Join(tempDir, "agent-state")
	caFilePath := filepath.Join(tempDir, "ca.pem")
	if err := os.WriteFile(caFilePath, caPEM, 0644); err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}

	// 5. Create real one-time enrollment input
	rawToken := enrollment.TokenPrefix + strings.Repeat("A", 43)

	// 6. Agent Enroll over HTTPS using --ca-file
	opts := agent.EnrollOptions{
		ControllerURL: ts.URL,
		StateDir:      stateDir,
		CAFile:        caFilePath,
		TokenReader:   strings.NewReader(rawToken + "\n"),
	}

	agentID, err := agent.Enroll(context.Background(), opts)
	if err != nil {
		t.Fatalf("real agent.Enroll failed: %v", err)
	}

	// 7. Deterministic UUIDv7 returned
	if agentID != "018f0000-0000-7000-8000-000000000001" {
		t.Fatalf("unexpected agent ID from enroll: %q", agentID)
	}

	// 8. Verify identity.key and identity.json created
	idKeyPath := filepath.Join(stateDir, agent.IdentityKeyFileName)
	if _, err := os.Stat(idKeyPath); err != nil {
		t.Fatalf("identity.key missing: %v", err)
	}
	idJSONPath := filepath.Join(stateDir, agent.IdentityJSONFileName)
	if _, err := os.Stat(idJSONPath); err != nil {
		t.Fatalf("identity.json missing: %v", err)
	}

	// 9. controller-ca.pem created with mode 0600
	caDestPath := filepath.Join(stateDir, agent.ControllerCAPEMFileName)
	caFi, err := os.Lstat(caDestPath)
	if err != nil {
		t.Fatalf("controller-ca.pem missing: %v", err)
	}
	if caFi.Mode().Perm() != 0600 {
		t.Errorf("expected controller-ca.pem mode 0600, got %04o", caFi.Mode().Perm())
	}

	// 10-14. TransportCheck creates ephemeral client cert, calls GET /api/v1/agent/self, succeeds
	selfAgentID, err := agent.TransportCheck(context.Background(), stateDir)
	if err != nil {
		t.Fatalf("real agent.TransportCheck failed: %v", err)
	}
	if selfAgentID != agentID {
		t.Fatalf("TransportCheck returned different agent ID: got %q, want %q", selfAgentID, agentID)
	}

	// Verify assertions:
	// - Persisted state contains NO client certificate file
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		t.Fatalf("failed to read state dir: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".crt") || strings.HasSuffix(name, ".cert") || (strings.HasSuffix(name, ".pem") && name != agent.ControllerCAPEMFileName) {
			t.Errorf("persisted state contains prohibited client certificate file: %s", name)
		}
		if name != agent.IdentityKeyFileName && name != agent.IdentityJSONFileName && name != agent.ControllerCAPEMFileName {
			t.Errorf("unexpected file in state directory: %s", name)
		}
	}

	// - Token not present in state files
	for _, fname := range []string{agent.IdentityKeyFileName, agent.IdentityJSONFileName, agent.ControllerCAPEMFileName} {
		content, readErr := os.ReadFile(filepath.Join(stateDir, fname))
		if readErr != nil {
			t.Fatalf("failed to read %s: %v", fname, readErr)
		}
		if strings.Contains(string(content), rawToken) {
			t.Fatalf("token found in persisted file %s", fname)
		}
	}

	// - Private key not present in identity.json
	metaBytes, err := os.ReadFile(idJSONPath)
	if err != nil {
		t.Fatalf("failed to read identity.json: %v", err)
	}
	keyBytes, err := os.ReadFile(idKeyPath)
	if err != nil {
		t.Fatalf("failed to read identity.key: %v", err)
	}
	if bytes.Contains(metaBytes, keyBytes) {
		t.Fatal("identity.json contains raw private key bytes")
	}
	var meta agent.IdentityMetadata
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		t.Fatalf("failed to unmarshal identity.json: %v", err)
	}
	if meta.AgentID != agentID {
		t.Errorf("identity.json agent_id mismatch: got %q, want %q", meta.AgentID, agentID)
	}
}
