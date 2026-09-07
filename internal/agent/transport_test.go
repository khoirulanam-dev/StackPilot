package agent

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
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"stackpilot/internal/enrollment"
)

// generateTestCA creates a test CA certificate and private key in memory.
func generateTestCA(t *testing.T) (caCert *x509.Certificate, caPriv ed25519.PrivateKey, caPEM []byte) {
	t.Helper()

	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "StackPilot Test CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caPriv)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}

	caCert, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	caPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caDER,
	})

	return caCert, caPriv, caPEM
}

// generateTestServerTLSCert creates a server certificate signed by the test CA for 127.0.0.1.
func generateTestServerTLSCert(t *testing.T, caCert *x509.Certificate, caPriv ed25519.PrivateKey, ip net.IP, host string) tls.Certificate {
	t.Helper()

	srvPub, srvPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate server key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip != nil {
		template.IPAddresses = []net.IP{ip}
	}
	if host != "" {
		template.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, srvPub, caPriv)
	if err != nil {
		t.Fatalf("failed to sign server cert: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  srvPriv,
	}
}

func TestBuildEphemeralClientCert(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	tlsCert, err := BuildEphemeralClientCert(priv)
	if err != nil {
		t.Fatalf("BuildEphemeralClientCert() failed: %v", err)
	}

	if len(tlsCert.Certificate) != 1 {
		t.Fatalf("expected 1 certificate DER, got %d", len(tlsCert.Certificate))
	}

	x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse generated certificate: %v", err)
	}

	// Verify public key matches
	certPub, ok := x509Cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("expected ed25519.PublicKey, got %T", x509Cert.PublicKey)
	}
	if !bytes.Equal(certPub, pub) {
		t.Fatal("certificate public key does not match agent public key")
	}

	// Verify self-signature
	if err := x509Cert.CheckSignature(x509Cert.SignatureAlgorithm, x509Cert.RawTBSCertificate, x509Cert.Signature); err != nil {
		t.Fatalf("certificate signature verification failed: %v", err)
	}

	// Verify validity bounds
	now := time.Now()
	if now.Before(x509Cert.NotBefore) {
		t.Errorf("NotBefore %v is in future", x509Cert.NotBefore)
	}
	if now.After(x509Cert.NotAfter) {
		t.Errorf("NotAfter %v is expired", x509Cert.NotAfter)
	}

	// Verify usages
	if x509Cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("expected KeyUsageDigitalSignature, got %v", x509Cert.KeyUsage)
	}
	if len(x509Cert.ExtKeyUsage) != 1 || x509Cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("expected [ExtKeyUsageClientAuth], got %v", x509Cert.ExtKeyUsage)
	}
	if x509Cert.IsCA {
		t.Error("expected IsCA = false")
	}
}

func TestBuildEphemeralClientCert_InvalidKey(t *testing.T) {
	_, err := BuildEphemeralClientCert(ed25519.PrivateKey([]byte("too-short")))
	if err == nil {
		t.Fatal("expected error for invalid key, got nil")
	}
}

func TestBuildEphemeralClientCert_DeterministicPositiveSerialWithZeroEntropy(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	tlsCert, err := buildEphemeralClientCertWithSource(priv, &zeroEntropyReader{}, time.Now)
	if err != nil {
		t.Fatalf("buildEphemeralClientCertWithSource failed: %v", err)
	}

	x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	if x509Cert.SerialNumber.Sign() <= 0 {
		t.Fatalf("expected positive serial number (Sign() > 0), got Sign() = %d, SerialNumber = %s",
			x509Cert.SerialNumber.Sign(), x509Cert.SerialNumber.String())
	}
}

type zeroEntropyReader struct{}

func (z *zeroEntropyReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func TestValidateAndPersistCAFile(t *testing.T) {
	_, _, caPEM := generateTestCA(t)

	tempDir := t.TempDir()
	stateDir := filepath.Join(tempDir, "state")
	caFile := filepath.Join(tempDir, "test-ca.pem")

	if err := os.WriteFile(caFile, caPEM, 0644); err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}

	// 1. Initial persistence succeeds with mode 0600
	if err := ValidateAndPersistCAFile(stateDir, caFile); err != nil {
		t.Fatalf("ValidateAndPersistCAFile() failed: %v", err)
	}

	destPath := filepath.Join(stateDir, ControllerCAPEMFileName)
	fi, err := os.Lstat(destPath)
	if err != nil {
		t.Fatalf("failed to stat persisted CA file: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("expected mode 0600, got %04o", fi.Mode().Perm())
	}

	// 2. Retry with same contents succeeds
	if err := ValidateAndPersistCAFile(stateDir, caFile); err != nil {
		t.Fatalf("retry with matching CA file failed: %v", err)
	}

	// 3. Retry with different CA contents fails closed
	_, _, otherPEM := generateTestCA(t)
	otherFile := filepath.Join(tempDir, "other-ca.pem")
	if err := os.WriteFile(otherFile, otherPEM, 0644); err != nil {
		t.Fatalf("failed to write other CA file: %v", err)
	}
	if err := ValidateAndPersistCAFile(stateDir, otherFile); err == nil {
		t.Fatal("expected error when existing CA contents differ, got nil")
	}

	// 4. Insecure permissions on existing CA file fails closed
	if err := os.Chmod(destPath, 0644); err != nil {
		t.Fatalf("failed to chmod: %v", err)
	}
	if err := ValidateAndPersistCAFile(stateDir, caFile); err == nil {
		t.Fatal("expected error when existing CA mode is 0644, got nil")
	}

	// 5. Symlink rejected
	symlinkStateDir := filepath.Join(tempDir, "state-symlink")
	_ = EnsureStateDir(symlinkStateDir)
	_ = os.Symlink(caFile, filepath.Join(symlinkStateDir, ControllerCAPEMFileName))
	if err := ValidateAndPersistCAFile(symlinkStateDir, caFile); err == nil {
		t.Fatal("expected error when existing CA file is a symlink, got nil")
	}

	// 6. Non-regular file (directory) rejected
	dirStateDir := filepath.Join(tempDir, "state-dir")
	_ = EnsureStateDir(dirStateDir)
	_ = os.Mkdir(filepath.Join(dirStateDir, ControllerCAPEMFileName), 0700)
	if err := ValidateAndPersistCAFile(dirStateDir, caFile); err == nil {
		t.Fatal("expected error when existing CA file is a directory, got nil")
	}
}

func TestValidateAndPersistCAFile_InvalidInput(t *testing.T) {
	tempDir := t.TempDir()
	stateDir := filepath.Join(tempDir, "state")

	// Empty file
	emptyFile := filepath.Join(tempDir, "empty.pem")
	if err := os.WriteFile(emptyFile, []byte("   \n"), 0644); err != nil {
		t.Fatalf("failed to write empty file: %v", err)
	}
	if err := ValidateAndPersistCAFile(stateDir, emptyFile); err == nil {
		t.Fatal("expected error for empty CA file, got nil")
	}

	// Non-certificate PEM (e.g. PUBLIC KEY)
	nonCertFile := filepath.Join(tempDir, "noncert.pem")
	nonCertPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("bogus")})
	if err := os.WriteFile(nonCertFile, nonCertPEM, 0644); err != nil {
		t.Fatalf("failed to write noncert file: %v", err)
	}
	if err := ValidateAndPersistCAFile(stateDir, nonCertFile); err == nil {
		t.Fatal("expected error for non-certificate PEM, got nil")
	}

	// Oversized file (> 1 MiB)
	oversizedFile := filepath.Join(tempDir, "oversized.pem")
	oversizedData := make([]byte, MaxCAPEMBytes+10)
	if err := os.WriteFile(oversizedFile, oversizedData, 0644); err != nil {
		t.Fatalf("failed to write oversized file: %v", err)
	}
	if err := ValidateAndPersistCAFile(stateDir, oversizedFile); err == nil {
		t.Fatal("expected error for oversized CA file, got nil")
	}

	// Section 2: CA containing valid CERTIFICATE + synthetic PRIVATE KEY block -> rejected, controller-ca.pem NOT created
	_, _, validCAPEM := generateTestCA(t)
	syntheticKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte("synthetic-private-key-payload-not-real"),
	})
	certAndKeyPEM := append(bytes.Clone(validCAPEM), syntheticKeyPEM...)
	certAndKeyFile := filepath.Join(tempDir, "cert-and-key.pem")
	if err := os.WriteFile(certAndKeyFile, certAndKeyPEM, 0644); err != nil {
		t.Fatalf("failed to write cert-and-key file: %v", err)
	}
	stateDirCK := filepath.Join(tempDir, "state-ck")
	if err := ValidateAndPersistCAFile(stateDirCK, certAndKeyFile); err == nil {
		t.Fatal("expected error when CA file contains PRIVATE KEY block, got nil")
	}
	if _, err := os.Stat(filepath.Join(stateDirCK, ControllerCAPEMFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("controller-ca.pem must NOT be created when PRIVATE KEY block is present")
	}

	// Valid certificate + trailing non-whitespace garbage -> rejected
	trailingGarbage := append(bytes.Clone(validCAPEM), []byte("GARBAGE_TRAILING_DATA")...)
	trailingFile := filepath.Join(tempDir, "trailing.pem")
	if err := os.WriteFile(trailingFile, trailingGarbage, 0644); err != nil {
		t.Fatalf("failed to write trailing file: %v", err)
	}
	stateDirTrailing := filepath.Join(tempDir, "state-trailing")
	if err := ValidateAndPersistCAFile(stateDirTrailing, trailingFile); err == nil {
		t.Fatal("expected error for CA file with trailing non-whitespace garbage, got nil")
	}
	if _, err := os.Stat(filepath.Join(stateDirTrailing, ControllerCAPEMFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("controller-ca.pem must NOT be created when trailing garbage is present")
	}

	// Certificate block with invalid DER -> rejected
	invalidDERPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("not-valid-x509-der-data"),
	})
	invalidDERFile := filepath.Join(tempDir, "invalid-der.pem")
	if err := os.WriteFile(invalidDERFile, invalidDERPEM, 0644); err != nil {
		t.Fatalf("failed to write invalid-der file: %v", err)
	}
	stateDirInvalidDER := filepath.Join(tempDir, "state-invalid-der")
	if err := ValidateAndPersistCAFile(stateDirInvalidDER, invalidDERFile); err == nil {
		t.Fatal("expected error for certificate block with invalid DER, got nil")
	}
	if _, err := os.Stat(filepath.Join(stateDirInvalidDER, ControllerCAPEMFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("controller-ca.pem must NOT be created when certificate DER is invalid")
	}

	// Multiple valid CERTIFICATE blocks -> accepted
	_, _, ca1PEM := generateTestCA(t)
	_, _, ca2PEM := generateTestCA(t)
	multiPEM := append(bytes.Clone(ca1PEM), ca2PEM...)
	multiFile := filepath.Join(tempDir, "multi-ca.pem")
	if err := os.WriteFile(multiFile, multiPEM, 0644); err != nil {
		t.Fatalf("failed to write multi-ca file: %v", err)
	}
	stateDirMulti := filepath.Join(tempDir, "state-multi")
	if err := ValidateAndPersistCAFile(stateDirMulti, multiFile); err != nil {
		t.Fatalf("expected multiple valid CERTIFICATE blocks to be accepted, got: %v", err)
	}
	multiPool, err := LoadControllerTrustRoots(stateDirMulti)
	if err != nil {
		t.Fatalf("LoadControllerTrustRoots failed on multi-CA file: %v", err)
	}
	if multiPool == nil {
		t.Fatal("expected non-nil pool for multi-CA file")
	}

	// Section 2 A: Leading garbage + valid CERTIFICATE -> reject, controller-ca.pem NOT created
	leadingGarbagePEM := append([]byte("GARBAGE_BEFORE_CERTIFICATE\n"), validCAPEM...)
	leadingGarbageFile := filepath.Join(tempDir, "leading-garbage.pem")
	if err := os.WriteFile(leadingGarbageFile, leadingGarbagePEM, 0644); err != nil {
		t.Fatalf("failed to write leading garbage file: %v", err)
	}
	stateDirLeading := filepath.Join(tempDir, "state-leading")
	if err := ValidateAndPersistCAFile(stateDirLeading, leadingGarbageFile); err == nil {
		t.Fatal("expected error for CA file with leading garbage, got nil")
	}
	if _, err := os.Stat(filepath.Join(stateDirLeading, ControllerCAPEMFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("controller-ca.pem must NOT be created when leading garbage is present")
	}

	// Section 2 B: Valid CERTIFICATE + inter-block garbage + valid CERTIFICATE -> reject, controller-ca.pem NOT created
	interBlockGarbagePEM := append(bytes.Clone(ca1PEM), []byte("\nINTER_BLOCK_GARBAGE\n")...)
	interBlockGarbagePEM = append(interBlockGarbagePEM, ca2PEM...)
	interBlockGarbageFile := filepath.Join(tempDir, "inter-block-garbage.pem")
	if err := os.WriteFile(interBlockGarbageFile, interBlockGarbagePEM, 0644); err != nil {
		t.Fatalf("failed to write inter-block garbage file: %v", err)
	}
	stateDirInter := filepath.Join(tempDir, "state-inter")
	if err := ValidateAndPersistCAFile(stateDirInter, interBlockGarbageFile); err == nil {
		t.Fatal("expected error for CA file with inter-block garbage, got nil")
	}
	if _, err := os.Stat(filepath.Join(stateDirInter, ControllerCAPEMFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("controller-ca.pem must NOT be created when inter-block garbage is present")
	}

	// Section 2 C: Leading whitespace + valid CERTIFICATE + whitespace + valid CERTIFICATE + trailing whitespace -> accept
	whitespaceSurroundedPEM := []byte("  \t\r\n  ")
	whitespaceSurroundedPEM = append(whitespaceSurroundedPEM, ca1PEM...)
	whitespaceSurroundedPEM = append(whitespaceSurroundedPEM, []byte("\n\r\n \t \n")...)
	whitespaceSurroundedPEM = append(whitespaceSurroundedPEM, ca2PEM...)
	whitespaceSurroundedPEM = append(whitespaceSurroundedPEM, []byte("  \r\n\t  \n")...)
	whitespaceFile := filepath.Join(tempDir, "whitespace-surrounded.pem")
	if err := os.WriteFile(whitespaceFile, whitespaceSurroundedPEM, 0644); err != nil {
		t.Fatalf("failed to write whitespace surrounded file: %v", err)
	}
	stateDirWS := filepath.Join(tempDir, "state-ws")
	if err := ValidateAndPersistCAFile(stateDirWS, whitespaceFile); err != nil {
		t.Fatalf("expected whitespace surrounded multi-CA to be accepted, got: %v", err)
	}
	wsPool, err := LoadControllerTrustRoots(stateDirWS)
	if err != nil {
		t.Fatalf("LoadControllerTrustRoots failed on whitespace surrounded multi-CA: %v", err)
	}
	if wsPool == nil {
		t.Fatal("expected non-nil pool for whitespace surrounded multi-CA")
	}

	// Section 3: Source CA regular file validation
	// Directory rejected
	dirCA := filepath.Join(tempDir, "dir-ca")
	if err := os.Mkdir(dirCA, 0755); err != nil {
		t.Fatalf("failed to mkdir: %v", err)
	}
	stateDirDir := filepath.Join(tempDir, "state-dir-source")
	if err := ValidateAndPersistCAFile(stateDirDir, dirCA); err == nil {
		t.Fatal("expected error when source CA is a directory, got nil")
	}

	// Symlink pointing to regular file accepted
	symlinkToCA := filepath.Join(tempDir, "symlink-to-ca.pem")
	if err := os.Symlink(multiFile, symlinkToCA); err != nil {
		t.Fatalf("failed to symlink: %v", err)
	}
	stateDirSymSource := filepath.Join(tempDir, "state-sym-source")
	if err := ValidateAndPersistCAFile(stateDirSymSource, symlinkToCA); err != nil {
		t.Fatalf("expected symlink pointing to regular file to be accepted, got: %v", err)
	}

	// FIFO / named pipe rejected where supported
	fifoPath := filepath.Join(tempDir, "test.fifo")
	if err := syscall.Mkfifo(fifoPath, 0600); err == nil {
		stateDirFIFO := filepath.Join(tempDir, "state-fifo")
		if err := ValidateAndPersistCAFile(stateDirFIFO, fifoPath); err == nil {
			t.Fatal("expected error when source CA is a FIFO, got nil")
		}
	}
}

func TestLoadControllerTrustRoots(t *testing.T) {
	tempDir := t.TempDir()
	stateDir := filepath.Join(tempDir, "state")
	if err := EnsureStateDir(stateDir); err != nil {
		t.Fatalf("EnsureStateDir failed: %v", err)
	}

	// 1. Absent file returns nil, nil
	pool, err := LoadControllerTrustRoots(stateDir)
	if err != nil {
		t.Fatalf("unexpected error for absent file: %v", err)
	}
	if pool != nil {
		t.Error("expected nil pool for absent controller-ca.pem")
	}

	// 2. Valid file returns pool that validates cert issued by that CA
	caCert, caPriv, caPEM := generateTestCA(t)
	caFile := filepath.Join(tempDir, "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0644); err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}
	if err := ValidateAndPersistCAFile(stateDir, caFile); err != nil {
		t.Fatalf("ValidateAndPersistCAFile failed: %v", err)
	}

	pool, err = LoadControllerTrustRoots(stateDir)
	if err != nil {
		t.Fatalf("LoadControllerTrustRoots failed: %v", err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool for valid controller-ca.pem")
	}

	leafCert := generateTestServerTLSCert(t, caCert, caPriv, net.ParseIP("127.0.0.1"), "127.0.0.1")
	parsedLeaf, err := x509.ParseCertificate(leafCert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse leaf cert: %v", err)
	}
	if _, err := parsedLeaf.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Fatalf("leaf cert verification against loaded pool failed: %v", err)
	}
}

func TestLoadControllerTrustRoots_Security(t *testing.T) {
	tempDir := t.TempDir()
	_, _, caPEM := generateTestCA(t)
	caFile := filepath.Join(tempDir, "real-ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0644); err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}

	// 1. Symlink rejected
	symDir := filepath.Join(tempDir, "sym-state")
	_ = EnsureStateDir(symDir)
	_ = os.Symlink(caFile, filepath.Join(symDir, ControllerCAPEMFileName))
	if _, err := LoadControllerTrustRoots(symDir); err == nil {
		t.Fatal("expected error for symlink, got nil")
	}

	// 2. Non-regular file (directory) rejected
	dirState := filepath.Join(tempDir, "dir-state")
	_ = EnsureStateDir(dirState)
	_ = os.Mkdir(filepath.Join(dirState, ControllerCAPEMFileName), 0700)
	if _, err := LoadControllerTrustRoots(dirState); err == nil {
		t.Fatal("expected error for directory, got nil")
	}

	// 3. Mode != 0600 rejected
	modeState := filepath.Join(tempDir, "mode-state")
	_ = EnsureStateDir(modeState)
	caPath := filepath.Join(modeState, ControllerCAPEMFileName)
	_ = os.WriteFile(caPath, caPEM, 0644)
	if _, err := LoadControllerTrustRoots(modeState); err == nil {
		t.Fatal("expected error for mode 0644, got nil")
	}
}

func TestTransportCheck_SuccessAndFailures(t *testing.T) {
	caCert, caPriv, caPEM := generateTestCA(t)
	srvCert := generateTestServerTLSCert(t, caCert, caPriv, net.ParseIP("127.0.0.1"), "127.0.0.1")

	const testAgentID = "018f0000-0000-7000-8000-000000000001"

	// Mock server that requires TLS and client cert
	var receivedKey [32]byte
	var serverCallCount int

	serverMux := http.NewServeMux()
	serverMux.HandleFunc(SelfEndpointPath, func(w http.ResponseWriter, r *http.Request) {
		serverCallCount++
		if r.TLS == nil {
			http.Error(w, "tls required", http.StatusBadRequest)
			return
		}
		if len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "missing client cert", http.StatusUnauthorized)
			return
		}
		clientPub, ok := r.TLS.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
		if !ok || len(clientPub) != 32 {
			http.Error(w, "invalid key type", http.StatusUnauthorized)
			return
		}
		copy(receivedKey[:], clientPub)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"agent_id": testAgentID,
		})
	})

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{srvCert},
		ClientAuth:   tls.RequestClientCert,
	}

	ts := httptest.NewUnstartedServer(serverMux)
	ts.TLS = tlsConfig
	ts.StartTLS()
	defer ts.Close()

	tempDir := t.TempDir()
	stateDir := filepath.Join(tempDir, "state")
	if err := EnsureStateDir(stateDir); err != nil {
		t.Fatalf("EnsureStateDir failed: %v", err)
	}

	// 1. Generate identity.key
	pub, _, err := LoadOrGenerateKey(stateDir, rand.Reader)
	if err != nil {
		t.Fatalf("LoadOrGenerateKey failed: %v", err)
	}
	pubStr := FormatPublicKeyBase64RawURL(pub)

	// 2. Persist identity.json pointing to HTTPS server
	meta := &IdentityMetadata{
		Version:       1,
		AgentID:       testAgentID,
		ControllerURL: ts.URL,
		PublicKey:     pubStr,
	}
	if err := WriteIdentityMetadata(stateDir, meta); err != nil {
		t.Fatalf("WriteIdentityMetadata failed: %v", err)
	}

	// 3. Persist CA certificate
	caFilePath := filepath.Join(tempDir, "ca.pem")
	if err := os.WriteFile(caFilePath, caPEM, 0644); err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}
	if err := ValidateAndPersistCAFile(stateDir, caFilePath); err != nil {
		t.Fatalf("ValidateAndPersistCAFile failed: %v", err)
	}

	// 4. Run TransportCheck: must succeed
	agentID, err := TransportCheck(context.Background(), stateDir)
	if err != nil {
		t.Fatalf("TransportCheck failed: %v", err)
	}
	if agentID != testAgentID {
		t.Fatalf("expected agent ID %q, got %q", testAgentID, agentID)
	}
	if !bytes.Equal(receivedKey[:], pub) {
		t.Fatal("server received different public key than agent identity")
	}

	// 5. Test failure when controller URL is HTTP loopback
	httpMeta := &IdentityMetadata{
		Version:       1,
		AgentID:       testAgentID,
		ControllerURL: "http://127.0.0.1:7447",
		PublicKey:     pubStr,
	}
	httpStateDir := filepath.Join(tempDir, "http-state")
	if err := EnsureStateDir(httpStateDir); err != nil {
		t.Fatalf("EnsureStateDir failed: %v", err)
	}
	keyData, _ := os.ReadFile(filepath.Join(stateDir, IdentityKeyFileName))
	if err := os.WriteFile(filepath.Join(httpStateDir, IdentityKeyFileName), keyData, 0600); err != nil {
		t.Fatalf("failed to copy key: %v", err)
	}
	if err := WriteIdentityMetadata(httpStateDir, httpMeta); err != nil {
		t.Fatalf("WriteIdentityMetadata failed: %v", err)
	}

	_, err = TransportCheck(context.Background(), httpStateDir)
	if err == nil {
		t.Fatal("expected error when controller URL is HTTP, got nil")
	}
	if !strings.Contains(err.Error(), "requires HTTPS") {
		t.Errorf("expected error to mention 'requires HTTPS', got: %v", err)
	}
}

func TestEnroll_HTTPS_WithCustomCA(t *testing.T) {
	caCert, caPriv, caPEM := generateTestCA(t)
	srvCert := generateTestServerTLSCert(t, caCert, caPriv, net.ParseIP("127.0.0.1"), "127.0.0.1")

	const testAgentID = "018f0000-0000-7000-8000-000000000002"
	token := enrollment.TokenPrefix + strings.Repeat("T", 43)

	serverMux := http.NewServeMux()
	serverMux.HandleFunc(EnrollmentEndpointPath, func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "tls required", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"agent_id": testAgentID,
		})
	})

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{srvCert},
		ClientAuth:   tls.RequestClientCert,
	}

	ts := httptest.NewUnstartedServer(serverMux)
	ts.TLS = tlsConfig
	ts.StartTLS()
	defer ts.Close()

	tempDir := t.TempDir()
	stateDir := filepath.Join(tempDir, "state")
	caFilePath := filepath.Join(tempDir, "ca.pem")
	if err := os.WriteFile(caFilePath, caPEM, 0644); err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}

	opts := EnrollOptions{
		ControllerURL: ts.URL,
		StateDir:      stateDir,
		CAFile:        caFilePath,
		TokenReader:   strings.NewReader(token + "\n"),
	}

	agentID, err := Enroll(context.Background(), opts)
	if err != nil {
		t.Fatalf("Enroll over HTTPS with CA failed: %v", err)
	}
	if agentID != testAgentID {
		t.Fatalf("expected agent ID %q, got %q", testAgentID, agentID)
	}

	// Verify controller-ca.pem was persisted with mode 0600
	caDest := filepath.Join(stateDir, ControllerCAPEMFileName)
	fi, err := os.Lstat(caDest)
	if err != nil {
		t.Fatalf("failed to stat persisted CA file: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("expected persisted CA mode 0600, got %04o", fi.Mode().Perm())
	}

	// Verify identity.json contains HTTPS controller URL
	meta, err := LoadIdentityMetadata(stateDir)
	if err != nil {
		t.Fatalf("LoadIdentityMetadata failed: %v", err)
	}
	if meta.ControllerURL != ts.URL {
		t.Errorf("expected controller_url %q, got %q", ts.URL, meta.ControllerURL)
	}
}

func TestEnroll_HTTPS_RejectsUntrustedServer(t *testing.T) {
	// Generate server cert with untrusted CA
	otherCACert, otherCAPriv, _ := generateTestCA(t)
	srvCert := generateTestServerTLSCert(t, otherCACert, otherCAPriv, net.ParseIP("127.0.0.1"), "127.0.0.1")

	serverMux := http.NewServeMux()
	serverMux.HandleFunc(EnrollmentEndpointPath, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	ts := httptest.NewUnstartedServer(serverMux)
	ts.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{srvCert},
	}
	ts.StartTLS()
	defer ts.Close()

	tempDir := t.TempDir()
	stateDir := filepath.Join(tempDir, "state")
	// Trust a DIFFERENT CA
	_, _, myCAPEM := generateTestCA(t)
	myCAFile := filepath.Join(tempDir, "my-ca.pem")
	if err := os.WriteFile(myCAFile, myCAPEM, 0644); err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}

	token := enrollment.TokenPrefix + strings.Repeat("T", 43)
	opts := EnrollOptions{
		ControllerURL: ts.URL,
		StateDir:      stateDir,
		CAFile:        myCAFile,
		TokenReader:   strings.NewReader(token + "\n"),
	}

	// Must fail because server cert is signed by other CA, not my CA
	_, err := Enroll(context.Background(), opts)
	if err == nil {
		t.Fatal("expected enrollment to fail against untrusted server cert, got nil")
	}
}

func TestTransportCheck_RejectsUntrustedServerCA(t *testing.T) {
	// Server cert signed by server CA
	srvCACert, srvCAPriv, _ := generateTestCA(t)
	srvCert := generateTestServerTLSCert(t, srvCACert, srvCAPriv, net.ParseIP("127.0.0.1"), "127.0.0.1")

	serverMux := http.NewServeMux()
	serverMux.HandleFunc(SelfEndpointPath, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	ts := httptest.NewUnstartedServer(serverMux)
	ts.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{srvCert},
		ClientAuth:   tls.RequestClientCert,
	}
	ts.StartTLS()
	defer ts.Close()

	tempDir := t.TempDir()
	stateDir := filepath.Join(tempDir, "state")
	if err := EnsureStateDir(stateDir); err != nil {
		t.Fatalf("EnsureStateDir failed: %v", err)
	}

	pub, _, err := LoadOrGenerateKey(stateDir, rand.Reader)
	if err != nil {
		t.Fatalf("LoadOrGenerateKey failed: %v", err)
	}
	meta := &IdentityMetadata{
		Version:       1,
		AgentID:       "018f0000-0000-7000-8000-000000000001",
		ControllerURL: ts.URL,
		PublicKey:     FormatPublicKeyBase64RawURL(pub),
	}
	if err := WriteIdentityMetadata(stateDir, meta); err != nil {
		t.Fatalf("WriteIdentityMetadata failed: %v", err)
	}

	// Persist a DIFFERENT CA to stateDir
	_, _, clientCAPEM := generateTestCA(t)
	caFilePath := filepath.Join(tempDir, "client-ca.pem")
	if err := os.WriteFile(caFilePath, clientCAPEM, 0644); err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}
	if err := ValidateAndPersistCAFile(stateDir, caFilePath); err != nil {
		t.Fatalf("ValidateAndPersistCAFile failed: %v", err)
	}

	// TransportCheck MUST fail due to certificate verification failure
	_, err = TransportCheck(context.Background(), stateDir)
	if err == nil {
		t.Fatal("expected TransportCheck to fail against untrusted server CA, got nil")
	}
}

func TestTransportCheck_RejectsHostnameMismatch(t *testing.T) {
	// Server cert signed by same CA, but valid ONLY for different.example.com (no 127.0.0.1 SAN)
	caCert, caPriv, caPEM := generateTestCA(t)
	srvCert := generateTestServerTLSCert(t, caCert, caPriv, nil, "different.example.com")

	serverMux := http.NewServeMux()
	serverMux.HandleFunc(SelfEndpointPath, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	ts := httptest.NewUnstartedServer(serverMux)
	ts.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{srvCert},
		ClientAuth:   tls.RequestClientCert,
	}
	ts.StartTLS()
	defer ts.Close()

	tempDir := t.TempDir()
	stateDir := filepath.Join(tempDir, "state")
	if err := EnsureStateDir(stateDir); err != nil {
		t.Fatalf("EnsureStateDir failed: %v", err)
	}

	pub, _, err := LoadOrGenerateKey(stateDir, rand.Reader)
	if err != nil {
		t.Fatalf("LoadOrGenerateKey failed: %v", err)
	}
	meta := &IdentityMetadata{
		Version:       1,
		AgentID:       "018f0000-0000-7000-8000-000000000001",
		ControllerURL: ts.URL, // points to 127.0.0.1:<port>
		PublicKey:     FormatPublicKeyBase64RawURL(pub),
	}
	if err := WriteIdentityMetadata(stateDir, meta); err != nil {
		t.Fatalf("WriteIdentityMetadata failed: %v", err)
	}

	// Persist the CA that signed the cert
	caFilePath := filepath.Join(tempDir, "ca.pem")
	if err := os.WriteFile(caFilePath, caPEM, 0644); err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}
	if err := ValidateAndPersistCAFile(stateDir, caFilePath); err != nil {
		t.Fatalf("ValidateAndPersistCAFile failed: %v", err)
	}

	// TransportCheck MUST fail due to hostname mismatch (connecting to 127.0.0.1 with cert for different.example.com)
	_, err = TransportCheck(context.Background(), stateDir)
	if err == nil {
		t.Fatal("expected TransportCheck to fail due to hostname/IP mismatch, got nil")
	}
}
