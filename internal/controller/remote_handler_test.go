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
	"stackpilot/internal/protocol"
)

type fakeAuthBackend struct {
	mu                  sync.Mutex
	agents              map[[32]byte]*enrollment.AgentRecord
	lastQueryKey        [32]byte
	findErr             error
	registerErr         error
	heartbeatErr        error
	lastHeartbeatKey    [32]byte
	lastProtocolVersion int
	inventoryErr        error
	lastInventoryKey    [32]byte
	lastInventoryReq    *protocol.InventoryRequest
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

func (f *fakeAuthBackend) RecordAgentHeartbeat(ctx context.Context, publicKey [32]byte, protocolVersion int) (*enrollment.AgentRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.lastHeartbeatKey = publicKey
	f.lastProtocolVersion = protocolVersion

	if f.heartbeatErr != nil {
		return nil, f.heartbeatErr
	}

	if f.agents != nil {
		if rec, ok := f.agents[publicKey]; ok {
			now := time.Now().UTC()
			pv := protocolVersion
			rec.LastSeenAt = &now
			rec.ProtocolVersion = &pv
			return rec, nil
		}
	}
	return nil, enrollment.ErrAgentNotFound
}

func (f *fakeAuthBackend) RecordAgentInventory(ctx context.Context, publicKey [32]byte, req *protocol.InventoryRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.inventoryErr != nil {
		return f.inventoryErr
	}

	if f.agents != nil {
		if _, ok := f.agents[publicKey]; ok {
			f.lastInventoryKey = publicKey
			f.lastInventoryReq = req
			return nil
		}
	}
	return enrollment.ErrAgentNotFound
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

func TestRemoteHandler_HeartbeatEndpoint(t *testing.T) {
	now := time.Now()
	backend := &fakeAuthBackend{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := newRemoteHandler(logger, backend, backend)

	// Enroll Agent A
	_, _, validCertA := helperGenerateEd25519Cert(t, now.Add(-5*time.Minute), now.Add(1*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, "", nil)
	pubKeyA := validCertA.PublicKey.(ed25519.PublicKey)
	var keyA [32]byte
	copy(keyA[:], pubKeyA)

	const agentIDA = "018f0000-0000-7000-8000-000000000001"
	backend.agents = map[[32]byte]*enrollment.AgentRecord{
		keyA: {
			ID:        agentIDA,
			PublicKey: keyA,
			CreatedAt: now.Add(-10 * time.Minute),
		},
	}

	validBody := `{"protocol_version": 1}`

	// 1. Plaintext POST heartbeat -> TLS rejection (400)
	t.Run("plaintext_post_heartbeat_rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, protocol.HeartbeatEndpointPath, strings.NewReader(validBody))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for plaintext heartbeat, got %d", rec.Code)
		}
	})

	// 2. TLS GET heartbeat -> 405 Allow POST
	t.Run("tls_get_heartbeat_method_not_allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, protocol.HeartbeatEndpointPath, nil)
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{validCertA},
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405 Method Not Allowed, got %d", rec.Code)
		}
		if allow := rec.Header().Get("Allow"); allow != "POST" {
			t.Errorf("expected Allow: POST header, got %q", allow)
		}
	})

	// 3. Missing client cert -> 401
	t.Run("missing_client_cert_rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, protocol.HeartbeatEndpointPath, strings.NewReader(validBody))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: nil}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
		}
	})

	// 4. Wrong crypto key type (e.g. ECDSA) -> 401
	t.Run("wrong_key_type_rejected", func(t *testing.T) {
		_, ecdsaCert := helperGenerateECDSACert(t)
		req := httptest.NewRequest(http.MethodPost, protocol.HeartbeatEndpointPath, strings.NewReader(validBody))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{ecdsaCert}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for ECDSA cert, got %d", rec.Code)
		}
	})

	// 5. Unknown Ed25519 key -> 401
	t.Run("unknown_ed25519_key_rejected", func(t *testing.T) {
		_, _, unknownCert := helperGenerateEd25519Cert(t, now.Add(-5*time.Minute), now.Add(1*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, "", nil)
		req := httptest.NewRequest(http.MethodPost, protocol.HeartbeatEndpointPath, strings.NewReader(validBody))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{unknownCert}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for unknown key, got %d", rec.Code)
		}
	})

	// 6. Expired client cert -> 401
	t.Run("expired_client_cert_rejected", func(t *testing.T) {
		_, _, expiredCert := helperGenerateEd25519Cert(t, now.Add(-2*time.Hour), now.Add(-1*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, "", nil)
		req := httptest.NewRequest(http.MethodPost, protocol.HeartbeatEndpointPath, strings.NewReader(validBody))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{expiredCert}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for expired cert, got %d", rec.Code)
		}
	})

	// 7. Future client cert -> 401
	t.Run("future_client_cert_rejected", func(t *testing.T) {
		_, _, futureCert := helperGenerateEd25519Cert(t, now.Add(1*time.Hour), now.Add(2*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, "", nil)
		req := httptest.NewRequest(http.MethodPost, protocol.HeartbeatEndpointPath, strings.NewReader(validBody))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{futureCert}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for future cert, got %d", rec.Code)
		}
	})

	// 8. Wrong EKU -> 401
	t.Run("wrong_eku_rejected", func(t *testing.T) {
		_, _, serverOnlyCert := helperGenerateEd25519Cert(t, now.Add(-5*time.Minute), now.Add(1*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, "", nil)
		req := httptest.NewRequest(http.MethodPost, protocol.HeartbeatEndpointPath, strings.NewReader(validBody))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{serverOnlyCert}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for server auth only cert, got %d", rec.Code)
		}
	})

	// 9. Valid cert + protocol 1 -> 204
	t.Run("valid_cert_and_protocol_1_succeeds", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, protocol.HeartbeatEndpointPath, strings.NewReader(validBody))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{validCertA}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected 204 No Content, got %d", rec.Code)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("expected Cache-Control: no-store, got %q", cc)
		}
		if rec.Body.Len() > 0 {
			t.Errorf("expected empty body for 204, got %s", rec.Body.String())
		}
		if backend.lastHeartbeatKey != keyA {
			t.Errorf("backend did not receive expected public key")
		}
		if backend.lastProtocolVersion != 1 {
			t.Errorf("backend did not receive protocol_version 1")
		}
	})

	// 10. Unsupported protocol version -> 409
	t.Run("unsupported_protocol_version_rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, protocol.HeartbeatEndpointPath, strings.NewReader(`{"protocol_version": 2}`))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{validCertA}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusConflict {
			t.Fatalf("expected 409 Conflict, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "unsupported agent protocol") {
			t.Errorf("expected error message to mention unsupported protocol, got %s", rec.Body.String())
		}
	})

	// 11. Unknown JSON field -> 400
	t.Run("unknown_json_field_rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, protocol.HeartbeatEndpointPath, strings.NewReader(`{"protocol_version": 1, "extra": "field"}`))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{validCertA}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for unknown field, got %d", rec.Code)
		}
	})

	// 12. Oversized body -> 400
	t.Run("oversized_body_rejected", func(t *testing.T) {
		oversized := `{"protocol_version": 1, "padding": "` + strings.Repeat("x", 2000) + `"}`
		req := httptest.NewRequest(http.MethodPost, protocol.HeartbeatEndpointPath, strings.NewReader(oversized))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{validCertA}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code < 400 || rec.Code >= 500 {
			t.Fatalf("expected 4xx for oversized body, got %d", rec.Code)
		}
	})

	// 13. Malformed Content-Type -> 400
	t.Run("malformed_content_type_rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, protocol.HeartbeatEndpointPath, strings.NewReader(validBody))
		req.Header.Set("Content-Type", "text/plain")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{validCertA}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for text/plain, got %d", rec.Code)
		}

		req2 := httptest.NewRequest(http.MethodPost, protocol.HeartbeatEndpointPath, strings.NewReader(validBody))
		req2.Header.Set("Content-Type", "application/json; charset=iso-8859-1")
		req2.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{validCertA}}
		rec2 := httptest.NewRecorder()
		handler.ServeHTTP(rec2, req2)

		if rec2.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for non-utf8 charset, got %d", rec2.Code)
		}
	})

	// 14. Database failure -> generic 500
	t.Run("database_failure_returns_500", func(t *testing.T) {
		backend.heartbeatErr = errors.New("db pool broken")
		defer func() { backend.heartbeatErr = nil }()

		req := httptest.NewRequest(http.MethodPost, protocol.HeartbeatEndpointPath, strings.NewReader(validBody))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{validCertA}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 for db failure, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "internal server error") {
			t.Errorf("expected generic error message, got %s", rec.Body.String())
		}
	})

	// 15. Section 43: Certificate text impersonation regression
	t.Run("certificate_text_impersonation_rejected", func(t *testing.T) {
		backend.agents[keyA].LastSeenAt = nil
		// Key B is generated, but certificate CommonName / SAN claims Agent A ("018f0000-0000-7000-8000-000000000001")
		_, _, spoofCert := helperGenerateEd25519Cert(t, now.Add(-5*time.Minute), now.Add(1*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, agentIDA, []string{agentIDA})

		req := httptest.NewRequest(http.MethodPost, protocol.HeartbeatEndpointPath, strings.NewReader(validBody))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{spoofCert}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized for spoofed certificate text, got %d", rec.Code)
		}
		// Confirm Agent A heartbeat was not updated
		if backend.agents[keyA].LastSeenAt != nil {
			t.Fatal("Agent A heartbeat was updated by unauthorized key B!")
		}
	})

	// 16. No CORS wildcard
	t.Run("no_cors_wildcard", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, protocol.HeartbeatEndpointPath, strings.NewReader(validBody))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{validCertA}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if acao := rec.Header().Get("Access-Control-Allow-Origin"); acao == "*" {
			t.Fatal("handler emits CORS wildcard")
		}
	})
}

func TestRealTLSHeartbeat_E2E(t *testing.T) {
	// Section 44: Real TLS heartbeat E2E test using standard library only
	// 1. Generate test CA
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(500),
		Subject:               pkix.Name{CommonName: "StackPilot Real TLS CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caPriv)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	// 2. Generate server TLS certificate signed by CA
	srvPub, srvPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate srv key: %v", err)
	}
	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(501),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, srvPub, caPriv)
	if err != nil {
		t.Fatalf("failed to create srv cert: %v", err)
	}
	srvTLSCert := tls.Certificate{
		Certificate: [][]byte{srvDER},
		PrivateKey:  srvPriv,
	}

	// 3. Start real HTTPS server with newRemoteHandler
	backend := &fakeAuthBackend{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	remoteHandler := newRemoteHandler(logger, backend, backend)

	ts := httptest.NewUnstartedServer(remoteHandler)
	ts.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{srvTLSCert},
		ClientAuth:   tls.RequestClientCert,
	}
	ts.StartTLS()
	defer ts.Close()

	// 4. Enroll Agent in local state and in backend
	tempDir := t.TempDir()
	stateDir := filepath.Join(tempDir, "state")
	if err := agent.EnsureStateDir(stateDir); err != nil {
		t.Fatalf("EnsureStateDir failed: %v", err)
	}

	pub, priv, err := agent.LoadOrGenerateKey(stateDir, rand.Reader)
	if err != nil {
		t.Fatalf("LoadOrGenerateKey failed: %v", err)
	}

	var key32 [32]byte
	copy(key32[:], pub)

	const agentID = "018f0000-0000-7000-8000-000000000099"
	backend.agents = map[[32]byte]*enrollment.AgentRecord{
		key32: {
			ID:        agentID,
			PublicKey: key32,
			CreatedAt: time.Now().UTC(),
		},
	}

	meta := &agent.IdentityMetadata{
		Version:       1,
		AgentID:       agentID,
		ControllerURL: ts.URL,
		PublicKey:     agent.FormatPublicKeyBase64RawURL(pub),
	}
	if err := agent.WriteIdentityMetadata(stateDir, meta); err != nil {
		t.Fatalf("WriteIdentityMetadata failed: %v", err)
	}

	caPath := filepath.Join(tempDir, "controller-ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0644); err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}
	if err := agent.ValidateAndPersistCAFile(stateDir, caPath); err != nil {
		t.Fatalf("ValidateAndPersistCAFile failed: %v", err)
	}

	// 5. Build ephemeral client cert from agent's private key
	clientCert, err := agent.BuildEphemeralClientCert(priv)
	if err != nil {
		t.Fatalf("BuildEphemeralClientCert failed: %v", err)
	}

	rootCAs, err := agent.LoadControllerTrustRoots(stateDir)
	if err != nil {
		t.Fatalf("LoadControllerTrustRoots failed: %v", err)
	}

	client := agent.BuildAgentHTTPClient(rootCAs, &clientCert)

	// 6. Perform real TLS POST /api/v1/agent/heartbeat
	hbURL := ts.URL + protocol.HeartbeatEndpointPath
	payload, _ := json.Marshal(protocol.HeartbeatRequest{ProtocolVersion: protocol.CurrentVersion})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, hbURL, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("failed to construct HTTP request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("real TLS heartbeat request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 No Content, got %d", resp.StatusCode)
	}

	// 7. Verify backend received the correct public key and updated presence
	if backend.lastHeartbeatKey != key32 {
		t.Errorf("backend received key mismatch: got %x, want %x", backend.lastHeartbeatKey, key32)
	}
	if backend.lastProtocolVersion != 1 {
		t.Errorf("backend received protocol version %d, want 1", backend.lastProtocolVersion)
	}
	if backend.agents[key32].LastSeenAt == nil {
		t.Fatal("backend record LastSeenAt was not updated")
	}
}

func TestRemoteHandler_InventoryEndpoint(t *testing.T) {
	now := time.Now()
	backend := &fakeAuthBackend{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := newRemoteHandler(logger, backend, backend)

	// Enroll Agent A
	_, _, validCertA := helperGenerateEd25519Cert(t, now.Add(-5*time.Minute), now.Add(1*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, "", nil)
	pubKeyA := validCertA.PublicKey.(ed25519.PublicKey)
	var keyA [32]byte
	copy(keyA[:], pubKeyA)

	const agentIDA = "018f0000-0000-7000-8000-000000000001"
	backend.agents = map[[32]byte]*enrollment.AgentRecord{
		keyA: {
			ID:        agentIDA,
			PublicKey: keyA,
			CreatedAt: now.Add(-10 * time.Minute),
		},
	}

	validReq := protocol.InventoryRequest{
		ProtocolVersion:  protocol.CurrentVersion,
		Hostname:         "node-01.example.internal",
		OSID:             "ubuntu",
		OSName:           "Ubuntu",
		OSVersion:        "24.04",
		KernelRelease:    "6.8.0-40-generic",
		Architecture:     "amd64",
		CPULogicalCores:  8,
		MemoryTotalBytes: 16777216000,
	}
	validBodyBytes, _ := json.Marshal(validReq)
	validBody := string(validBodyBytes)

	t.Run("plaintext_put_inventory_rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, protocol.InventoryEndpointPath, strings.NewReader(validBody))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for plaintext inventory, got %d", rec.Code)
		}
	})

	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		t.Run("method_not_allowed_"+method, func(t *testing.T) {
			req := httptest.NewRequest(method, protocol.InventoryEndpointPath, strings.NewReader(validBody))
			req.TLS = &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{validCertA},
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("expected 405 Method Not Allowed, got %d", rec.Code)
			}
			if allow := rec.Header().Get("Allow"); allow != "PUT" {
				t.Errorf("expected Allow: PUT header, got %q", allow)
			}
		})
	}

	t.Run("missing_client_cert_rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, protocol.InventoryEndpointPath, strings.NewReader(validBody))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: nil}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
		}
	})

	t.Run("unknown_agent_rejected", func(t *testing.T) {
		_, _, unknownCert := helperGenerateEd25519Cert(t, now.Add(-5*time.Minute), now.Add(1*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, "", nil)
		req := httptest.NewRequest(http.MethodPut, protocol.InventoryEndpointPath, strings.NewReader(validBody))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{unknownCert}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized, got %d", rec.Code)
		}
	})

	t.Run("wrong_key_type_rejected", func(t *testing.T) {
		_, ecdsaCert := helperGenerateECDSACert(t)
		req := httptest.NewRequest(http.MethodPut, protocol.InventoryEndpointPath, strings.NewReader(validBody))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{ecdsaCert}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for ECDSA cert, got %d", rec.Code)
		}
	})

	t.Run("expired_client_cert_rejected", func(t *testing.T) {
		_, _, expiredCert := helperGenerateEd25519Cert(t, now.Add(-2*time.Hour), now.Add(-1*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, "", nil)
		req := httptest.NewRequest(http.MethodPut, protocol.InventoryEndpointPath, strings.NewReader(validBody))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{expiredCert}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for expired cert, got %d", rec.Code)
		}
	})

	t.Run("future_client_cert_rejected", func(t *testing.T) {
		_, _, futureCert := helperGenerateEd25519Cert(t, now.Add(1*time.Hour), now.Add(2*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, "", nil)
		req := httptest.NewRequest(http.MethodPut, protocol.InventoryEndpointPath, strings.NewReader(validBody))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{futureCert}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for future cert, got %d", rec.Code)
		}
	})

	t.Run("wrong_eku_rejected", func(t *testing.T) {
		_, _, serverOnlyCert := helperGenerateEd25519Cert(t, now.Add(-5*time.Minute), now.Add(1*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, "", nil)
		req := httptest.NewRequest(http.MethodPut, protocol.InventoryEndpointPath, strings.NewReader(validBody))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{serverOnlyCert}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for server auth only cert, got %d", rec.Code)
		}
	})

	// Authorization relies solely on the authenticated Ed25519 public key.
	// CommonName and SAN values claiming another agent identity must not grant authorization.
	t.Run("cert_text_impersonation_rejected", func(t *testing.T) {
		backend.lastInventoryKey = [32]byte{}
		backend.lastInventoryReq = nil

		_, _, imposterCert := helperGenerateEd25519Cert(t, now.Add(-5*time.Minute), now.Add(1*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, agentIDA, []string{agentIDA, "node-01.example.internal"})
		imposterReq := validReq
		imposterReq.Hostname = "imposter-host"
		imposterBody, _ := json.Marshal(imposterReq)

		req := httptest.NewRequest(http.MethodPut, protocol.InventoryEndpointPath, bytes.NewReader(imposterBody))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{imposterCert}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized for unenrolled key B impersonating Agent A, got %d", rec.Code)
		}
		if backend.lastInventoryKey == keyA {
			t.Fatalf("Agent A inventory was updated by imposter certificate with key B!")
		}
		if backend.lastInventoryReq != nil {
			t.Fatalf("backend recorded inventory for unauthorized request: %+v", backend.lastInventoryReq)
		}
	})

	t.Run("invalid_content_type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, protocol.InventoryEndpointPath, strings.NewReader(validBody))
		req.Header.Set("Content-Type", "text/plain")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{validCertA}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for text/plain, got %d", rec.Code)
		}
	})

	t.Run("invalid_charset", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, protocol.InventoryEndpointPath, strings.NewReader(validBody))
		req.Header.Set("Content-Type", "application/json; charset=iso-8859-1")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{validCertA}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for iso-8859-1 charset, got %d", rec.Code)
		}
	})

	t.Run("body_too_large", func(t *testing.T) {
		largeBody := strings.Repeat("a", 8193)
		req := httptest.NewRequest(http.MethodPut, protocol.InventoryEndpointPath, strings.NewReader(largeBody))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{validCertA}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for body > 8192 bytes, got %d", rec.Code)
		}
	})

	// Malformed raw UTF-8 must be rejected at the HTTP boundary before JSON decoding
	// can silently replace invalid sequences with U+FFFD.
	t.Run("invalid_raw_utf8_rejected", func(t *testing.T) {
		backend.lastInventoryKey = [32]byte{}
		backend.lastInventoryReq = nil

		rawInvalidUTF8Body := []byte(`{"protocol_version":1,"hostname":"valid-node","os_id":"ubuntu","os_name":"Ubuntu` + "\xff" + `Linux","os_version":"24.04","kernel_release":"6.8.0","architecture":"amd64","cpu_logical_cores":4,"memory_total_bytes":8192000}`)

		req := httptest.NewRequest(http.MethodPut, protocol.InventoryEndpointPath, bytes.NewReader(rawInvalidUTF8Body))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{validCertA}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request for raw invalid UTF-8, got %d (body: %s)", rec.Code, rec.Body.String())
		}
		var errResp map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
			t.Fatalf("failed to decode error response: %v", err)
		}
		if errResp["error"] != "invalid request body" {
			t.Fatalf("expected generic safe error 'invalid request body', got %q", errResp["error"])
		}
		if backend.lastInventoryReq != nil || backend.lastInventoryKey != [32]byte{} {
			t.Fatal("backend RecordAgentInventory was invoked for invalid UTF-8 payload")
		}
	})

	t.Run("malformed_json", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, protocol.InventoryEndpointPath, strings.NewReader(`{"protocol_version":`))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{validCertA}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for malformed json, got %d", rec.Code)
		}
	})

	t.Run("unknown_field", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, protocol.InventoryEndpointPath, strings.NewReader(`{"protocol_version": 1, "extra": "forbidden"}`))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{validCertA}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for unknown field, got %d", rec.Code)
		}
	})

	t.Run("trailing_data", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, protocol.InventoryEndpointPath, strings.NewReader(validBody+`{"second": 1}`))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{validCertA}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for trailing data, got %d", rec.Code)
		}
	})

	// 8. Protocol version checks
	t.Run("protocol_version_zero", func(t *testing.T) {
		badReq := validReq
		badReq.ProtocolVersion = 0
		badBytes, _ := json.Marshal(badReq)

		req := httptest.NewRequest(http.MethodPut, protocol.InventoryEndpointPath, bytes.NewReader(badBytes))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{validCertA}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for protocol_version 0, got %d", rec.Code)
		}
	})

	t.Run("protocol_version_mismatch", func(t *testing.T) {
		badReq := validReq
		badReq.ProtocolVersion = 2
		badBytes, _ := json.Marshal(badReq)

		req := httptest.NewRequest(http.MethodPut, protocol.InventoryEndpointPath, bytes.NewReader(badBytes))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{validCertA}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusConflict {
			t.Fatalf("expected 409 Conflict for unsupported protocol, got %d", rec.Code)
		}
	})

	testCases := []struct {
		name    string
		mutate  func(*protocol.InventoryRequest)
		expCode int
	}{
		{"empty_hostname", func(r *protocol.InventoryRequest) { r.Hostname = "" }, http.StatusBadRequest},
		{"long_hostname", func(r *protocol.InventoryRequest) { r.Hostname = strings.Repeat("h", 256) }, http.StatusBadRequest},
		{"hostname_with_null", func(r *protocol.InventoryRequest) { r.Hostname = "host\x00name" }, http.StatusBadRequest},
		{"hostname_with_newline", func(r *protocol.InventoryRequest) { r.Hostname = "host\nname" }, http.StatusBadRequest},
		{"hostname_leading_space", func(r *protocol.InventoryRequest) { r.Hostname = " hostname" }, http.StatusBadRequest},
		{"hostname_trailing_space", func(r *protocol.InventoryRequest) { r.Hostname = "hostname " }, http.StatusBadRequest},

		{"empty_os_id", func(r *protocol.InventoryRequest) { r.OSID = "" }, http.StatusBadRequest},
		{"uppercase_os_id", func(r *protocol.InventoryRequest) { r.OSID = "Ubuntu" }, http.StatusBadRequest},
		{"space_in_os_id", func(r *protocol.InventoryRequest) { r.OSID = "os id" }, http.StatusBadRequest},
		{"invalid_char_os_id", func(r *protocol.InventoryRequest) { r.OSID = "os@id" }, http.StatusBadRequest},
		{"long_os_id", func(r *protocol.InventoryRequest) { r.OSID = strings.Repeat("o", 65) }, http.StatusBadRequest},

		{"empty_os_name", func(r *protocol.InventoryRequest) { r.OSName = "" }, http.StatusBadRequest},
		{"long_os_name", func(r *protocol.InventoryRequest) { r.OSName = strings.Repeat("n", 129) }, http.StatusBadRequest},
		{"os_name_control_char", func(r *protocol.InventoryRequest) { r.OSName = "OS\tName" }, http.StatusBadRequest},

		{"empty_os_version_allowed", func(r *protocol.InventoryRequest) { r.OSVersion = "" }, http.StatusNoContent},
		{"long_os_version", func(r *protocol.InventoryRequest) { r.OSVersion = strings.Repeat("v", 129) }, http.StatusBadRequest},
		{"os_version_control_char", func(r *protocol.InventoryRequest) { r.OSVersion = "1.0\r" }, http.StatusBadRequest},

		{"empty_kernel_release", func(r *protocol.InventoryRequest) { r.KernelRelease = "" }, http.StatusBadRequest},
		{"long_kernel_release", func(r *protocol.InventoryRequest) { r.KernelRelease = strings.Repeat("k", 129) }, http.StatusBadRequest},

		{"empty_architecture", func(r *protocol.InventoryRequest) { r.Architecture = "" }, http.StatusBadRequest},
		{"long_architecture", func(r *protocol.InventoryRequest) { r.Architecture = strings.Repeat("a", 33) }, http.StatusBadRequest},

		{"zero_cpu_cores", func(r *protocol.InventoryRequest) { r.CPULogicalCores = 0 }, http.StatusBadRequest},
		{"negative_cpu_cores", func(r *protocol.InventoryRequest) { r.CPULogicalCores = -1 }, http.StatusBadRequest},
		{"excessive_cpu_cores", func(r *protocol.InventoryRequest) { r.CPULogicalCores = 1048577 }, http.StatusBadRequest},

		{"zero_memory", func(r *protocol.InventoryRequest) { r.MemoryTotalBytes = 0 }, http.StatusBadRequest},
		{"negative_memory", func(r *protocol.InventoryRequest) { r.MemoryTotalBytes = -100 }, http.StatusBadRequest},
	}

	for _, tc := range testCases {
		t.Run("validation_"+tc.name, func(t *testing.T) {
			r := validReq
			tc.mutate(&r)
			data, _ := json.Marshal(r)

			req := httptest.NewRequest(http.MethodPut, protocol.InventoryEndpointPath, bytes.NewReader(data))
			req.Header.Set("Content-Type", "application/json")
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{validCertA}}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.expCode {
				t.Fatalf("expected code %d for %s, got %d (body: %s)", tc.expCode, tc.name, rec.Code, rec.Body.String())
			}
		})
	}

	t.Run("success_returns_204", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, protocol.InventoryEndpointPath, strings.NewReader(validBody))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{validCertA}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected 204 No Content, got %d", rec.Code)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("expected Cache-Control: no-store, got %q", cc)
		}
		if rec.Body.Len() != 0 {
			t.Fatalf("expected empty body for 204, got %d bytes", rec.Body.Len())
		}
		if backend.lastInventoryKey != keyA {
			t.Errorf("backend key mismatch: got %x, want %x", backend.lastInventoryKey, keyA)
		}
		if backend.lastInventoryReq == nil || backend.lastInventoryReq.Hostname != validReq.Hostname {
			t.Errorf("backend inventory request mismatch: got %+v", backend.lastInventoryReq)
		}
	})

	t.Run("database_failure_returns_500", func(t *testing.T) {
		backend.inventoryErr = errors.New("db connection down")
		defer func() { backend.inventoryErr = nil }()

		req := httptest.NewRequest(http.MethodPut, protocol.InventoryEndpointPath, strings.NewReader(validBody))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{validCertA}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 for database error, got %d", rec.Code)
		}
	})

	t.Run("local_listener_has_no_inventory_route", func(t *testing.T) {
		localHandler := newHandler(logger, backend, backend)
		req := httptest.NewRequest(http.MethodPut, protocol.InventoryEndpointPath, strings.NewReader(validBody))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		localHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for inventory on local listener, got %d", rec.Code)
		}
	})
}

func TestRealTLSInventory_E2E(t *testing.T) {
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(600),
		Subject:               pkix.Name{CommonName: "StackPilot Real TLS Inventory CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caPriv)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	srvPub, srvPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate srv key: %v", err)
	}
	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(601),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, srvPub, caPriv)
	if err != nil {
		t.Fatalf("failed to create srv cert: %v", err)
	}
	srvTLSCert := tls.Certificate{
		Certificate: [][]byte{srvDER},
		PrivateKey:  srvPriv,
	}

	backend := &fakeAuthBackend{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	remoteHandler := newRemoteHandler(logger, backend, backend)

	ts := httptest.NewUnstartedServer(remoteHandler)
	ts.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{srvTLSCert},
		ClientAuth:   tls.RequestClientCert,
	}
	ts.StartTLS()
	defer ts.Close()

	tempDir := t.TempDir()
	stateDir := filepath.Join(tempDir, "state")
	if err := agent.EnsureStateDir(stateDir); err != nil {
		t.Fatalf("EnsureStateDir failed: %v", err)
	}

	pub, priv, err := agent.LoadOrGenerateKey(stateDir, rand.Reader)
	if err != nil {
		t.Fatalf("LoadOrGenerateKey failed: %v", err)
	}

	var key32 [32]byte
	copy(key32[:], pub)

	const agentID = "018f0000-0000-7000-8000-000000000077"
	backend.agents = map[[32]byte]*enrollment.AgentRecord{
		key32: {
			ID:        agentID,
			PublicKey: key32,
			CreatedAt: time.Now().UTC(),
		},
	}

	meta := &agent.IdentityMetadata{
		Version:       1,
		AgentID:       agentID,
		ControllerURL: ts.URL,
		PublicKey:     agent.FormatPublicKeyBase64RawURL(pub),
	}
	if err := agent.WriteIdentityMetadata(stateDir, meta); err != nil {
		t.Fatalf("WriteIdentityMetadata failed: %v", err)
	}

	caPath := filepath.Join(tempDir, "controller-ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0644); err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}
	if err := agent.ValidateAndPersistCAFile(stateDir, caPath); err != nil {
		t.Fatalf("ValidateAndPersistCAFile failed: %v", err)
	}

	clientCert, err := agent.BuildEphemeralClientCert(priv)
	if err != nil {
		t.Fatalf("BuildEphemeralClientCert failed: %v", err)
	}

	rootCAs, err := agent.LoadControllerTrustRoots(stateDir)
	if err != nil {
		t.Fatalf("LoadControllerTrustRoots failed: %v", err)
	}

	client := agent.BuildAgentHTTPClient(rootCAs, &clientCert)

	invURL := ts.URL + protocol.InventoryEndpointPath
	invReq := protocol.InventoryRequest{
		ProtocolVersion:  protocol.CurrentVersion,
		Hostname:         "node-tls-e2e.example.internal",
		OSID:             "debian",
		OSName:           "Debian GNU/Linux",
		OSVersion:        "12",
		KernelRelease:    "6.1.0-21-amd64",
		Architecture:     "amd64",
		CPULogicalCores:  4,
		MemoryTotalBytes: 8589934592,
	}
	payload, err := json.Marshal(invReq)
	if err != nil {
		t.Fatalf("failed to marshal inventory request: %v", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, invURL, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("failed to construct HTTP request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("real TLS inventory request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 No Content, got %d", resp.StatusCode)
	}

	// 7. Verify backend received the correct public key and exact inventory values
	if backend.lastInventoryKey != key32 {
		t.Errorf("backend received key mismatch: got %x, want %x", backend.lastInventoryKey, key32)
	}
	if backend.lastInventoryReq == nil {
		t.Fatal("backend lastInventoryReq is nil")
	}
	if backend.lastInventoryReq.ProtocolVersion != invReq.ProtocolVersion {
		t.Errorf("protocol version mismatch: got %d, want %d", backend.lastInventoryReq.ProtocolVersion, invReq.ProtocolVersion)
	}
	if backend.lastInventoryReq.Hostname != invReq.Hostname {
		t.Errorf("hostname mismatch: got %q, want %q", backend.lastInventoryReq.Hostname, invReq.Hostname)
	}
	if backend.lastInventoryReq.OSID != invReq.OSID {
		t.Errorf("os_id mismatch: got %q, want %q", backend.lastInventoryReq.OSID, invReq.OSID)
	}
	if backend.lastInventoryReq.OSName != invReq.OSName {
		t.Errorf("os_name mismatch: got %q, want %q", backend.lastInventoryReq.OSName, invReq.OSName)
	}
	if backend.lastInventoryReq.OSVersion != invReq.OSVersion {
		t.Errorf("os_version mismatch: got %q, want %q", backend.lastInventoryReq.OSVersion, invReq.OSVersion)
	}
	if backend.lastInventoryReq.KernelRelease != invReq.KernelRelease {
		t.Errorf("kernel_release mismatch: got %q, want %q", backend.lastInventoryReq.KernelRelease, invReq.KernelRelease)
	}
	if backend.lastInventoryReq.Architecture != invReq.Architecture {
		t.Errorf("architecture mismatch: got %q, want %q", backend.lastInventoryReq.Architecture, invReq.Architecture)
	}
	if backend.lastInventoryReq.CPULogicalCores != invReq.CPULogicalCores {
		t.Errorf("cpu_logical_cores mismatch: got %d, want %d", backend.lastInventoryReq.CPULogicalCores, invReq.CPULogicalCores)
	}
	if backend.lastInventoryReq.MemoryTotalBytes != invReq.MemoryTotalBytes {
		t.Errorf("memory_total_bytes mismatch: got %d, want %d", backend.lastInventoryReq.MemoryTotalBytes, invReq.MemoryTotalBytes)
	}
}
