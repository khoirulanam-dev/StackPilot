package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// helperWriteTestTLSCertAndKey writes a valid self-signed TLS cert and private key to disk.
func helperWriteTestTLSCertAndKey(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey failed: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(10),
		Subject: pkix.Name{
			CommonName: "127.0.0.1",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate failed: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey failed: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	certFile = filepath.Join(dir, "server.crt")
	keyFile = filepath.Join(dir, "server.key")
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	return certFile, keyFile
}

// ============================================================================
// Section 10: Server Lifecycle Tests
// ============================================================================

func TestRun_Lifecycle_RemoteDisabled(t *testing.T) {
	// Find available dynamic port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cfg := Config{
		ListenAddress: addr,
		DatabaseURL:   "postgres://user:pass@127.0.0.1:5432/testdb",
		LogLevel:      slog.LevelInfo,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := &fakeAuthBackend{}

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- Run(ctx, cfg, backend, logger)
	}()

	// Verify server responds on local listener
	client := &http.Client{Timeout: 2 * time.Second}
	var connected bool
	for range 50 {
		resp, err := client.Get("http://" + addr + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				connected = true
				break
			}
		}
		// Yield execution briefly without sleep using channel/select
		select {
		case <-runErrCh:
			break
		default:
		}
	}

	if !connected {
		t.Fatal("local listener failed to respond on /healthz")
	}

	// Cancel context and ensure clean shutdown
	cancel()
	select {
	case err := <-runErrCh:
		if err != nil {
			t.Fatalf("expected clean shutdown, got error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for Run to stop after context cancellation")
	}
}

func TestRun_Lifecycle_InvalidTLSCertKeyPair(t *testing.T) {
	tempDir := t.TempDir()
	cfg := Config{
		ListenAddress:      "127.0.0.1:7447",
		AgentListenAddress: "127.0.0.1:7448",
		AgentTLSCertFile:   filepath.Join(tempDir, "nonexistent.crt"),
		AgentTLSKeyFile:    filepath.Join(tempDir, "nonexistent.key"),
		DatabaseURL:        "postgres://user:pass@127.0.0.1:5432/testdb",
		LogLevel:           slog.LevelInfo,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := &fakeAuthBackend{}

	err := Run(context.Background(), cfg, backend, logger)
	if err == nil {
		t.Fatal("expected Run to fail before serving remote traffic with invalid TLS files, got nil")
	}
	if !strings.Contains(err.Error(), "failed to load agent TLS certificate") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRun_Lifecycle_OccupiedLocalPort(t *testing.T) {
	// Occupy local port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	cfg := Config{
		ListenAddress: ln.Addr().String(),
		DatabaseURL:   "postgres://user:pass@127.0.0.1:5432/testdb",
		LogLevel:      slog.LevelInfo,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := &fakeAuthBackend{}

	err = Run(context.Background(), cfg, backend, logger)
	if err == nil {
		t.Fatal("expected Run to fail cleanly when local port is occupied, got nil")
	}
	if !strings.Contains(err.Error(), "failed to listen on") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRun_Lifecycle_OccupiedRemotePort(t *testing.T) {
	tempDir := t.TempDir()
	certFile, keyFile := helperWriteTestTLSCertAndKey(t, tempDir)

	// Occupy remote port
	lnRemote, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on remote port: %v", err)
	}
	defer lnRemote.Close()

	// Find free local port
	lnLocal, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on local port: %v", err)
	}
	localAddr := lnLocal.Addr().String()
	_ = lnLocal.Close()

	cfg := Config{
		ListenAddress:      localAddr,
		AgentListenAddress: lnRemote.Addr().String(),
		AgentTLSCertFile:   certFile,
		AgentTLSKeyFile:    keyFile,
		DatabaseURL:        "postgres://user:pass@127.0.0.1:5432/testdb",
		LogLevel:           slog.LevelInfo,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := &fakeAuthBackend{}

	err = Run(context.Background(), cfg, backend, logger)
	if err == nil {
		t.Fatal("expected Run to fail cleanly when remote port is occupied, got nil")
	}
	if !strings.Contains(err.Error(), "failed to listen on agent address") {
		t.Errorf("unexpected error message: %v", err)
	}

	// Verify local listener was closed and localAddr is not leaked/occupied
	reboundLn, reErr := net.Listen("tcp", localAddr)
	if reErr != nil {
		t.Fatalf("local port is still occupied after remote startup failure: %v", reErr)
	}
	_ = reboundLn.Close()
}

func TestServeDual_Lifecycle_ContextCancellation(t *testing.T) {
	localLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on local: %v", err)
	}
	remoteLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on remote: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := &fakeAuthBackend{}

	errCh := make(chan error, 1)
	go func() {
		errCh <- serveDual(ctx, localLn, remoteLn, backend, backend, backend, logger)
	}()

	// Cancel context to stop both servers
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("serveDual returned error on context cancellation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for serveDual to stop on context cancellation")
	}
}

func TestServeDual_Lifecycle_UnexpectedFailureOfOneServer(t *testing.T) {
	localLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on local: %v", err)
	}
	remoteLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on remote: %v", err)
	}

	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := &fakeAuthBackend{}

	errCh := make(chan error, 1)
	go func() {
		errCh <- serveDual(ctx, localLn, remoteLn, backend, backend, backend, logger)
	}()

	// Simulate unexpected failure by closing remote listener
	_ = remoteLn.Close()

	select {
	case err := <-errCh:
		// Expect an error indicating listener was closed or network error
		if err == nil {
			t.Fatal("expected serveDual to return error when listener failed unexpectedly, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for serveDual to shut down other server after failure")
	}

	// Verify local listener was closed as part of shutdown
	reboundLn, err := net.Listen("tcp", localLn.Addr().String())
	if err != nil {
		t.Fatalf("local listener port was not released: %v", err)
	}
	_ = reboundLn.Close()
}

// ============================================================================
// Section 11: TLS Config Regression Tests
// ============================================================================

func TestRemoteTLSConfig_Regression(t *testing.T) {
	tempDir := t.TempDir()
	certFile, keyFile := helperWriteTestTLSCertAndKey(t, tempDir)

	tlsCfg, err := buildRemoteTLSConfig(certFile, keyFile)
	if err != nil {
		t.Fatalf("buildRemoteTLSConfig failed: %v", err)
	}

	// 1. MinVersion == tls.VersionTLS13
	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected MinVersion tls.VersionTLS13 (0x%04x), got 0x%04x", tls.VersionTLS13, tlsCfg.MinVersion)
	}

	// 2. ClientAuth == tls.RequestClientCert
	if tlsCfg.ClientAuth != tls.RequestClientCert {
		t.Errorf("expected ClientAuth tls.RequestClientCert (%d), got %d", tls.RequestClientCert, tlsCfg.ClientAuth)
	}

	// 3. Existing local listener validation must STILL reject 0.0.0.0:7447
	err = validateListenAddress("0.0.0.0:7447")
	if err == nil {
		t.Fatal("validateListenAddress must reject 0.0.0.0:7447, got nil")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Errorf("expected error to mention loopback, got: %v", err)
	}
}
