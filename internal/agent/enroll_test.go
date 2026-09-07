package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"stackpilot/internal/enrollment"
)

func TestValidateControllerURL(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"valid loopback ipv4", "http://127.0.0.1:7447", false},
		{"valid loopback ipv6", "http://[::1]:7447", false},
		{"missing scheme", "127.0.0.1:7447", true},
		{"https scheme", "https://127.0.0.1:7447", true},
		{"credentials present", "http://user:pass@127.0.0.1:7447", true},
		{"query present", "http://127.0.0.1:7447?foo=bar", true},
		{"fragment present", "http://127.0.0.1:7447#frag", true},
		{"localhost rejected", "http://localhost:7447", true},
		{"dns hostname rejected", "http://controller.local:7447", true},
		{"lan ip rejected", "http://192.168.1.50:7447", true},
		{"public ip rejected", "http://8.8.8.8:7447", true},
		{"wildcard ip rejected", "http://0.0.0.0:7447", true},
		{"missing port", "http://127.0.0.1", true},
		{"zero port", "http://127.0.0.1:0", true},
		{"invalid port", "http://127.0.0.1:99999", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateControllerURL(tc.url)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateControllerURL(%q) err = %v, wantErr = %v", tc.url, err, tc.wantErr)
			}
		})
	}
}

func TestReadAndValidateTokenFromStdin(t *testing.T) {
	validToken := enrollment.TokenPrefix + strings.Repeat("A", 43)

	t.Run("valid single token with newline", func(t *testing.T) {
		r := strings.NewReader(validToken + "\n")
		got, err := ReadAndValidateTokenFromStdin(r)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != validToken {
			t.Fatal("token mismatch")
		}
	})

	t.Run("valid single token with crlf", func(t *testing.T) {
		r := strings.NewReader(validToken + "\r\n")
		got, err := ReadAndValidateTokenFromStdin(r)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != validToken {
			t.Fatal("token mismatch")
		}
	})

	t.Run("valid single token without newline", func(t *testing.T) {
		r := strings.NewReader(validToken)
		got, err := ReadAndValidateTokenFromStdin(r)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != validToken {
			t.Fatal("token mismatch")
		}
	})

	t.Run("chunked reader regression test with extra data", func(t *testing.T) {
		// Section 3: Regression test that would FAIL against pre-remediation single-read code.
		// First read returns valid token + newline; second read returns extra-data.
		// Complete stream MUST be rejected.
		chunk1 := strings.NewReader(validToken + "\n")
		chunk2 := strings.NewReader("extra-data\n")
		multi := io.MultiReader(chunk1, chunk2)

		_, err := ReadAndValidateTokenFromStdin(multi)
		if err == nil {
			t.Fatal("expected multi-chunk reader with extra data to be rejected, got nil")
		}
	})

	t.Run("oversized input exceeds MaxStdinTokenBytes", func(t *testing.T) {
		oversized := validToken + strings.Repeat("X", MaxStdinTokenBytes+10)
		_, err := ReadAndValidateTokenFromStdin(strings.NewReader(oversized))
		if err == nil {
			t.Fatal("expected oversized input to be rejected, got nil")
		}
	})

	t.Run("empty stdin", func(t *testing.T) {
		r := strings.NewReader("")
		_, err := ReadAndValidateTokenFromStdin(r)
		if err == nil {
			t.Fatal("expected error on empty stdin, got nil")
		}
	})

	t.Run("multiple lines rejected", func(t *testing.T) {
		r := strings.NewReader(validToken + "\nextra line\n")
		_, err := ReadAndValidateTokenFromStdin(r)
		if err == nil {
			t.Fatal("expected error on multiple lines, got nil")
		}
	})

	t.Run("extra spaces rejected", func(t *testing.T) {
		r := strings.NewReader(validToken + " \n")
		_, err := ReadAndValidateTokenFromStdin(r)
		if err == nil {
			t.Fatal("expected error on trailing space, got nil")
		}
	})

	t.Run("error message does not leak token", func(t *testing.T) {
		invalidToken := "sp_enroll_invalid_too_short"
		r := strings.NewReader(invalidToken + "\n")
		_, err := ReadAndValidateTokenFromStdin(r)
		if err == nil {
			t.Fatal("expected error on invalid token, got nil")
		}
		if strings.Contains(err.Error(), invalidToken) {
			t.Fatal("error message leaked token")
		}
	})
}

func TestEnroll_RedirectSecurityRejection(t *testing.T) {
	// Mandatory test verifying agent enrollment client rejects redirects
	// and never sends the enrollment token to the redirected target.
	var redirectTargetReceivedToken bool

	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "sp_enroll_") {
			redirectTargetReceivedToken = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer redirectTarget.Close()

	// Redirecting server returns 302 Found pointing to redirectTarget
	redirectingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusFound)
	}))
	defer redirectingServer.Close()

	tempDir := t.TempDir()
	token := enrollment.TokenPrefix + strings.Repeat("B", 43)

	opts := EnrollOptions{
		ControllerURL: redirectingServer.URL,
		StateDir:      tempDir,
		TokenReader:   strings.NewReader(token + "\n"),
	}

	_, err := Enroll(context.Background(), opts)
	if err == nil {
		t.Fatal("expected redirect to be rejected with error, got nil")
	}

	if redirectTargetReceivedToken {
		t.Fatal("SECURITY VIOLATION: enrollment token was forwarded to redirect target!")
	}
}

func TestEnroll_FailClosedOnExistingMetadataErrors(t *testing.T) {
	// Section 8: Proves that if identity.json exists but identity or state dir is invalid/insecure,
	// enrollment fails closed, NO HTTP request occurs, and NO existing identity is overwritten.
	var serverRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverRequests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	const validUUID = "018f0000-0000-7000-8000-000000000001"
	validToken := enrollment.TokenPrefix + strings.Repeat("C", 43)

	createValidIdentity := func(t *testing.T, dir string) (ed25519.PublicKey, ed25519.PrivateKey) {
		t.Helper()
		pub, priv, err := LoadOrGenerateKey(dir, nil)
		if err != nil {
			t.Fatalf("LoadOrGenerateKey failed: %v", err)
		}
		meta := &IdentityMetadata{
			Version:       1,
			AgentID:       validUUID,
			ControllerURL: "http://127.0.0.1:7447",
			PublicKey:     FormatPublicKeyBase64RawURL(pub),
		}
		if err := WriteIdentityMetadata(dir, meta); err != nil {
			t.Fatalf("WriteIdentityMetadata failed: %v", err)
		}
		return pub, priv
	}

	t.Run("state dir 0755 fails closed without HTTP request", func(t *testing.T) {
		serverRequests = 0
		tempDir := t.TempDir()
		stateDir := filepath.Join(tempDir, "state")
		createValidIdentity(t, stateDir)

		if err := os.Chmod(stateDir, 0755); err != nil {
			t.Fatalf("failed to chmod: %v", err)
		}

		opts := EnrollOptions{
			ControllerURL: server.URL,
			StateDir:      stateDir,
			TokenReader:   strings.NewReader(validToken + "\n"),
		}
		_, err := Enroll(context.Background(), opts)
		if err == nil {
			t.Fatal("expected error on 0755 state dir, got nil")
		}
		if serverRequests != 0 {
			t.Fatalf("expected 0 HTTP requests, got %d", serverRequests)
		}
	})

	t.Run("state dir symlink fails closed without HTTP request", func(t *testing.T) {
		serverRequests = 0
		tempDir := t.TempDir()
		realDir := filepath.Join(tempDir, "real-state")
		createValidIdentity(t, realDir)

		symlinkDir := filepath.Join(tempDir, "symlink-state")
		if err := os.Symlink(realDir, symlinkDir); err != nil {
			t.Skipf("symlinks not supported: %v", err)
		}

		opts := EnrollOptions{
			ControllerURL: server.URL,
			StateDir:      symlinkDir,
			TokenReader:   strings.NewReader(validToken + "\n"),
		}
		_, err := Enroll(context.Background(), opts)
		if err == nil {
			t.Fatal("expected error on symlink state dir, got nil")
		}
		if serverRequests != 0 {
			t.Fatalf("expected 0 HTTP requests, got %d", serverRequests)
		}
	})

	t.Run("identity.key missing fails closed without HTTP request", func(t *testing.T) {
		serverRequests = 0
		tempDir := t.TempDir()
		stateDir := filepath.Join(tempDir, "state")
		createValidIdentity(t, stateDir)

		keyPath := filepath.Join(stateDir, IdentityKeyFileName)
		if err := os.Remove(keyPath); err != nil {
			t.Fatalf("failed to remove identity.key: %v", err)
		}

		opts := EnrollOptions{
			ControllerURL: server.URL,
			StateDir:      stateDir,
			TokenReader:   strings.NewReader(validToken + "\n"),
		}
		_, err := Enroll(context.Background(), opts)
		if err == nil {
			t.Fatal("expected error on missing identity.key, got nil")
		}
		if serverRequests != 0 {
			t.Fatalf("expected 0 HTTP requests, got %d", serverRequests)
		}
		// Ensure identity.key was NOT created
		if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
			t.Fatal("identity.key was unexpectedly created")
		}
	})

	t.Run("identity.key 0644 fails closed without HTTP request", func(t *testing.T) {
		serverRequests = 0
		tempDir := t.TempDir()
		stateDir := filepath.Join(tempDir, "state")
		createValidIdentity(t, stateDir)

		keyPath := filepath.Join(stateDir, IdentityKeyFileName)
		if err := os.Chmod(keyPath, 0644); err != nil {
			t.Fatalf("failed to chmod identity.key: %v", err)
		}

		opts := EnrollOptions{
			ControllerURL: server.URL,
			StateDir:      stateDir,
			TokenReader:   strings.NewReader(validToken + "\n"),
		}
		_, err := Enroll(context.Background(), opts)
		if err == nil {
			t.Fatal("expected error on 0644 identity.key, got nil")
		}
		if serverRequests != 0 {
			t.Fatalf("expected 0 HTTP requests, got %d", serverRequests)
		}
		// Ensure permissions were not silently altered
		fi, err := os.Lstat(keyPath)
		if err != nil || fi.Mode().Perm() != 0644 {
			t.Fatal("identity.key permissions were unexpectedly modified")
		}
	})

	t.Run("identity.key symlink fails closed without HTTP request", func(t *testing.T) {
		serverRequests = 0
		tempDir := t.TempDir()
		stateDir := filepath.Join(tempDir, "state")
		createValidIdentity(t, stateDir)

		keyPath := filepath.Join(stateDir, IdentityKeyFileName)
		realKeyPath := filepath.Join(tempDir, "external.key")
		if err := os.Rename(keyPath, realKeyPath); err != nil {
			t.Fatalf("failed to move key: %v", err)
		}
		if err := os.Symlink(realKeyPath, keyPath); err != nil {
			t.Skipf("symlinks not supported: %v", err)
		}

		opts := EnrollOptions{
			ControllerURL: server.URL,
			StateDir:      stateDir,
			TokenReader:   strings.NewReader(validToken + "\n"),
		}
		_, err := Enroll(context.Background(), opts)
		if err == nil {
			t.Fatal("expected error on symlink identity.key, got nil")
		}
		if serverRequests != 0 {
			t.Fatalf("expected 0 HTTP requests, got %d", serverRequests)
		}
	})

	t.Run("identity.key malformed fails closed without HTTP request", func(t *testing.T) {
		serverRequests = 0
		tempDir := t.TempDir()
		stateDir := filepath.Join(tempDir, "state")
		createValidIdentity(t, stateDir)

		keyPath := filepath.Join(stateDir, IdentityKeyFileName)
		if err := os.WriteFile(keyPath, []byte("garbage not pkcs8"), 0600); err != nil {
			t.Fatalf("failed to corrupt key: %v", err)
		}

		opts := EnrollOptions{
			ControllerURL: server.URL,
			StateDir:      stateDir,
			TokenReader:   strings.NewReader(validToken + "\n"),
		}
		_, err := Enroll(context.Background(), opts)
		if err == nil {
			t.Fatal("expected error on malformed identity.key, got nil")
		}
		if serverRequests != 0 {
			t.Fatalf("expected 0 HTTP requests, got %d", serverRequests)
		}
	})

	t.Run("identity.key public key mismatch fails closed without HTTP request", func(t *testing.T) {
		serverRequests = 0
		tempDir := t.TempDir()
		stateDir := filepath.Join(tempDir, "state")
		createValidIdentity(t, stateDir)

		// Overwrite identity.key with a different valid key
		_, priv2, err := GenerateKey(nil)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
		pem2, err := EncodePrivateKeyPKCS8PEM(priv2)
		if err != nil {
			t.Fatalf("EncodePrivateKeyPKCS8PEM failed: %v", err)
		}
		keyPath := filepath.Join(stateDir, IdentityKeyFileName)
		if err := os.WriteFile(keyPath, pem2, 0600); err != nil {
			t.Fatalf("failed to write mismatched key: %v", err)
		}

		opts := EnrollOptions{
			ControllerURL: server.URL,
			StateDir:      stateDir,
			TokenReader:   strings.NewReader(validToken + "\n"),
		}
		_, err = Enroll(context.Background(), opts)
		if err == nil {
			t.Fatal("expected error on public key mismatch, got nil")
		}
		if serverRequests != 0 {
			t.Fatalf("expected 0 HTTP requests, got %d", serverRequests)
		}
	})
}

func TestEnroll_SuccessAndIdempotentRetry(t *testing.T) {
	tempDir := t.TempDir()
	stateDir := filepath.Join(tempDir, "state")
	validToken := enrollment.TokenPrefix + strings.Repeat("C", 43)

	const expectedAgentID = "018f0000-0000-7000-8000-000000000001"
	var requestCount int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.URL.Path != EnrollmentEndpointPath {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var req enrollRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if req.Token != validToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if requestCount == 1 {
			w.WriteHeader(http.StatusCreated)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		_ = json.NewEncoder(w).Encode(enrollResponse{AgentID: expectedAgentID})
	}))
	defer server.Close()

	opts := EnrollOptions{
		ControllerURL: server.URL,
		StateDir:      stateDir,
		TokenReader:   strings.NewReader(validToken + "\n"),
	}

	// 1. Initial enrollment
	agentID, err := Enroll(context.Background(), opts)
	if err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}
	if agentID != expectedAgentID {
		t.Fatalf("expected agent ID %q, got %q", expectedAgentID, agentID)
	}

	// Verify identity.key and identity.json exist
	keyPath := filepath.Join(stateDir, IdentityKeyFileName)
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("identity.key was not persisted: %v", err)
	}

	meta, err := LoadIdentityMetadata(stateDir)
	if err != nil {
		t.Fatalf("failed to load identity.json: %v", err)
	}
	if meta.AgentID != expectedAgentID {
		t.Fatalf("expected metadata agent_id %q, got %q", expectedAgentID, meta.AgentID)
	}

	// 2. Second enrollment when identity.json already exists: must be refused!
	opts2 := EnrollOptions{
		ControllerURL: server.URL,
		StateDir:      stateDir,
		TokenReader:   strings.NewReader(validToken + "\n"),
	}
	_, err = Enroll(context.Background(), opts2)
	if err == nil {
		t.Fatal("expected error on re-enrolling already enrolled agent, got nil")
	}
	if !strings.Contains(err.Error(), "already enrolled") {
		t.Fatalf("expected ErrAlreadyEnrolled, got %v", err)
	}
}

func TestEnroll_PendingKeyReusedOnRetry(t *testing.T) {
	tempDir := t.TempDir()
	stateDir := filepath.Join(tempDir, "state")
	validToken := enrollment.TokenPrefix + strings.Repeat("D", 43)
	const retryAgentID = "018f0000-0000-7000-8000-000000000002"

	var capturedPublicKeys []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req enrollRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		capturedPublicKeys = append(capturedPublicKeys, req.PublicKey)

		if len(capturedPublicKeys) == 1 {
			// Simulate initial failure
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(enrollResponse{AgentID: retryAgentID})
	}))
	defer server.Close()

	// Attempt 1: server fails with 500
	opts1 := EnrollOptions{
		ControllerURL: server.URL,
		StateDir:      stateDir,
		TokenReader:   strings.NewReader(validToken + "\n"),
	}
	_, err := Enroll(context.Background(), opts1)
	if err == nil {
		t.Fatal("expected error on 500 server response, got nil")
	}

	// Verify identity.key was persisted before the request failed
	keyPath := filepath.Join(stateDir, IdentityKeyFileName)
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("identity.key should exist even if network request failed: %v", err)
	}

	// Verify identity.json does not exist yet
	jsonPath := filepath.Join(stateDir, IdentityJSONFileName)
	if _, err := os.Stat(jsonPath); !os.IsNotExist(err) {
		t.Fatal("identity.json should not exist after failed enrollment")
	}

	// Attempt 2: retry with same pending key
	opts2 := EnrollOptions{
		ControllerURL: server.URL,
		StateDir:      stateDir,
		TokenReader:   strings.NewReader(validToken + "\n"),
	}
	agentID, err := Enroll(context.Background(), opts2)
	if err != nil {
		t.Fatalf("retry Enroll failed: %v", err)
	}
	if agentID != retryAgentID {
		t.Fatalf("unexpected agent ID: %q", agentID)
	}

	// Both attempts MUST have sent the exact same public key!
	if len(capturedPublicKeys) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(capturedPublicKeys))
	}
	if capturedPublicKeys[0] != capturedPublicKeys[1] {
		t.Fatal("public key changed between retries")
	}
}

func TestEnroll_ResponseValidation(t *testing.T) {
	validToken := enrollment.TokenPrefix + strings.Repeat("F", 43)

	cases := []struct {
		name        string
		contentType string
		body        string
	}{
		{"missing content type", "", `{"agent_id":"018f0000-0000-7000-8000-000000000001"}`},
		{"non-json content type", "text/plain", `{"agent_id":"018f0000-0000-7000-8000-000000000001"}`},
		{"malformed content type", "application/json; invalid;;", `{"agent_id":"018f0000-0000-7000-8000-000000000001"}`},
		{"oversized body", "application/json", strings.Repeat(" ", MaxHTTPResponseBody+10)},
		{"malformed json", "application/json", `{not-json}`},
		{"trailing json document", "application/json", `{"agent_id":"018f0000-0000-7000-8000-000000000001"}{"extra":true}`},
		{"empty agent_id", "application/json", `{"agent_id":""}`},
		{"invalid uuidv7 agent_id", "application/json", `{"agent_id":"018f0000-0000-4000-8000-000000000001"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.contentType != "" {
					w.Header().Set("Content-Type", tc.contentType)
				}
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			tempDir := t.TempDir()
			stateDir := filepath.Join(tempDir, "state")
			opts := EnrollOptions{
				ControllerURL: server.URL,
				StateDir:      stateDir,
				TokenReader:   strings.NewReader(validToken + "\n"),
			}

			_, err := Enroll(context.Background(), opts)
			if err == nil {
				t.Fatalf("expected error for case %s, got nil", tc.name)
			}

			// Ensure identity.json was NOT created
			jsonPath := filepath.Join(stateDir, IdentityJSONFileName)
			if _, err := os.Stat(jsonPath); !os.IsNotExist(err) {
				t.Fatalf("identity.json must not be created on failed response validation in case %s", tc.name)
			}
		})
	}
}
