package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"stackpilot/internal/agent"
	"stackpilot/internal/enrollment"
)

func TestAgentCLI_Dispatch(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	stdin := &bytes.Buffer{}

	t.Run("unknown command returns error", func(t *testing.T) {
		err := run([]string{"unknown"}, stdin, stdout, stderr)
		if err == nil {
			t.Fatal("expected error for unknown command, got nil")
		}
		if !strings.Contains(err.Error(), "unknown command") {
			t.Errorf("expected error to mention 'unknown command', got %q", err.Error())
		}
	})

	t.Run("enroll missing controller flag returns error", func(t *testing.T) {
		err := run([]string{"enroll", "--state-dir", "/tmp/foo"}, stdin, stdout, stderr)
		if err == nil {
			t.Fatal("expected error for missing --controller, got nil")
		}
		if !strings.Contains(err.Error(), "--controller") {
			t.Errorf("expected error to mention '--controller', got %q", err.Error())
		}
	})

	t.Run("enroll missing state-dir flag returns error", func(t *testing.T) {
		err := run([]string{"enroll", "--controller", "http://127.0.0.1:7447"}, stdin, stdout, stderr)
		if err == nil {
			t.Fatal("expected error for missing --state-dir, got nil")
		}
		if !strings.Contains(err.Error(), "--state-dir") {
			t.Errorf("expected error to mention '--state-dir', got %q", err.Error())
		}
	})

	t.Run("enroll success end-to-end via CLI", func(t *testing.T) {
		const mockAgentID = "018f0000-0000-7000-8000-000000000001"
		token := enrollment.TokenPrefix + strings.Repeat("E", 43)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"agent_id": mockAgentID})
		}))
		defer server.Close()

		tempDir := t.TempDir()
		stateDir := filepath.Join(tempDir, "state")
		stdin := strings.NewReader(token + "\n")
		outBuf := &bytes.Buffer{}
		errBuf := &bytes.Buffer{}

		err := run([]string{"enroll", "--controller", server.URL, "--state-dir", stateDir}, stdin, outBuf, errBuf)
		if err != nil {
			t.Fatalf("enroll command failed: %v", err)
		}

		outStr := outBuf.String()
		if !strings.Contains(outStr, mockAgentID) {
			t.Fatalf("expected stdout to contain agent_id %q, got %q", mockAgentID, outStr)
		}
		if !strings.Contains(outStr, "Agent enrolled successfully") {
			t.Fatalf("expected stdout to contain success message, got %q", outStr)
		}
		// Confirm token is not printed
		if strings.Contains(outStr, token) {
			t.Fatal("stdout printed enrollment token")
		}
	})

	t.Run("enroll positional arguments rejected without leaking secret", func(t *testing.T) {
		syntheticSecret := enrollment.TokenPrefix + "synthetic_argv_secret_token_12345"
		serverCalled := false
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serverCalled = true
			w.WriteHeader(http.StatusCreated)
		}))
		defer server.Close()

		tempDir := t.TempDir()
		stateDir := filepath.Join(tempDir, "state")
		outBuf := &bytes.Buffer{}
		errBuf := &bytes.Buffer{}
		stdin := strings.NewReader("")

		err := run([]string{"enroll", "--controller", server.URL, "--state-dir", stateDir, syntheticSecret}, stdin, outBuf, errBuf)
		if err == nil {
			t.Fatal("expected error on positional argument, got nil")
		}
		if serverCalled {
			t.Fatal("enrollment server was called despite unexpected positional arguments")
		}
		if strings.Contains(err.Error(), syntheticSecret) {
			t.Fatal("error message echoed secret positional argument")
		}
		if strings.Contains(outBuf.String(), syntheticSecret) {
			t.Fatal("stdout echoed secret positional argument")
		}
		if strings.Contains(errBuf.String(), syntheticSecret) {
			t.Fatal("stderr echoed secret positional argument")
		}
	})

	t.Run("transport-check missing state-dir flag returns error", func(t *testing.T) {
		err := run([]string{"transport-check"}, stdin, stdout, stderr)
		if err == nil {
			t.Fatal("expected error for missing --state-dir, got nil")
		}
		if !strings.Contains(err.Error(), "--state-dir") {
			t.Errorf("expected error to mention '--state-dir', got %q", err.Error())
		}
	})

	t.Run("transport-check positional arguments rejected", func(t *testing.T) {
		err := run([]string{"transport-check", "--state-dir", "/tmp/foo", "unexpected"}, stdin, stdout, stderr)
		if err == nil {
			t.Fatal("expected error for positional arguments, got nil")
		}
		if !strings.Contains(err.Error(), "unexpected positional arguments") {
			t.Errorf("expected error to mention unexpected positional arguments, got %q", err.Error())
		}
	})

	t.Run("transport-check success end-to-end via CLI", func(t *testing.T) {
		const mockAgentID = "018f0000-0000-7000-8000-000000000003"
		caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
		caTemplate := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "Test CA"},
			NotBefore:             time.Now().Add(-1 * time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
		}
		caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caPriv)
		caCert, _ := x509.ParseCertificate(caDER)
		caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

		srvPub, srvPriv, _ := ed25519.GenerateKey(rand.Reader)
		srvTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "127.0.0.1"},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
			NotBefore:    time.Now().Add(-1 * time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		srvDER, _ := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, srvPub, caPriv)
		srvTLSCert := tls.Certificate{
			Certificate: [][]byte{srvDER},
			PrivateKey:  srvPriv,
		}

		serverMux := http.NewServeMux()
		serverMux.HandleFunc("/api/v1/agent/self", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(map[string]string{"agent_id": mockAgentID})
		})

		ts := httptest.NewUnstartedServer(serverMux)
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
			t.Fatalf("failed to ensure state dir: %v", err)
		}
		pub, _, err := agent.LoadOrGenerateKey(stateDir, rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}
		pubStr := agent.FormatPublicKeyBase64RawURL(pub)

		meta := &agent.IdentityMetadata{
			Version:       1,
			AgentID:       mockAgentID,
			ControllerURL: ts.URL,
			PublicKey:     pubStr,
		}
		if err := agent.WriteIdentityMetadata(stateDir, meta); err != nil {
			t.Fatalf("failed to write identity metadata: %v", err)
		}

		caFilePath := filepath.Join(tempDir, "ca.pem")
		if err := os.WriteFile(caFilePath, caPEM, 0644); err != nil {
			t.Fatalf("failed to write ca file: %v", err)
		}
		if err := agent.ValidateAndPersistCAFile(stateDir, caFilePath); err != nil {
			t.Fatalf("failed to persist CA: %v", err)
		}

		outBuf := &bytes.Buffer{}
		errBuf := &bytes.Buffer{}
		err = run([]string{"transport-check", "--state-dir", stateDir}, stdin, outBuf, errBuf)
		if err != nil {
			t.Fatalf("transport-check failed: %v", err)
		}

		wantOutput := "Secure transport verified: " + mockAgentID + "\n"
		if outBuf.String() != wantOutput {
			t.Fatalf("expected stdout %q, got %q", wantOutput, outBuf.String())
		}
	})

	t.Run("daemon mode cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		outBuf := &bytes.Buffer{}
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))

		done := make(chan error, 1)
		go func() {
			done <- agent.Run(ctx, logger)
		}()

		// Cancel context shortly
		cancel()

		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("expected clean exit on cancellation, got: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("agent daemon did not exit within timeout")
		}
		_ = outBuf
	})
}
