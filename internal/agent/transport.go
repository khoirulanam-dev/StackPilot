package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	ControllerCAPEMFileName = "controller-ca.pem"
	MaxCAPEMBytes           = 1024 * 1024 // 1 MiB
	SelfEndpointPath        = "/api/v1/agent/self"
)

const pemBeginCertificate = "-----BEGIN CERTIFICATE-----"

// validateAndParseCAPEM parses and strictly validates CA certificate PEM data.
// It requires at least one block, every block must have Type == "CERTIFICATE",
// verifies that each block is immediately preceded by "-----BEGIN CERTIFICATE-----"
// without intervening non-whitespace garbage, parses every certificate block,
// rejects malformed DER, and never prints PEM contents.
func validateAndParseCAPEM(caBytes []byte) ([]*x509.Certificate, error) {
	if len(bytes.TrimSpace(caBytes)) == 0 {
		return nil, errors.New("CA file is empty")
	}

	var certs []*x509.Certificate
	rest := caBytes

	for {
		// 1. Trim ONLY leading whitespace from the current rest
		rest = bytes.TrimLeft(rest, " \t\r\n")
		// 2. If empty: finish
		if len(rest) == 0 {
			break
		}

		// 3. Require the next bytes to begin immediately with "-----BEGIN CERTIFICATE-----"
		if !bytes.HasPrefix(rest, []byte(pemBeginCertificate)) {
			return nil, errors.New("CA file contains non-CERTIFICATE block or invalid inter-block data")
		}

		// 4. Call pem.Decode
		var block *pem.Block
		block, rest = pem.Decode(rest)
		// 5. Require block != nil
		if block == nil {
			return nil, errors.New("failed to decode certificate PEM block")
		}

		// 6. Require block.Type == "CERTIFICATE"
		if block.Type != "CERTIFICATE" {
			return nil, errors.New("CA file contains non-CERTIFICATE block")
		}

		// 7. Parse block.Bytes with x509.ParseCertificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("CA file contains malformed certificate block")
		}
		certs = append(certs, cert)
		// 8. Continue with returned rest
	}

	if len(certs) == 0 {
		return nil, errors.New("CA file contains no valid certificates")
	}

	return certs, nil
}

// BuildEphemeralClientCert constructs a short-lived in-memory self-signed X.509 client certificate
// containing the Agent's existing Ed25519 public key, signed by the existing private key.
// It is never persisted to disk.
func BuildEphemeralClientCert(priv ed25519.PrivateKey) (tls.Certificate, error) {
	return buildEphemeralClientCertWithSource(priv, rand.Reader, time.Now)
}

func buildEphemeralClientCertWithSource(priv ed25519.PrivateKey, r io.Reader, nowFunc func() time.Time) (tls.Certificate, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return tls.Certificate{}, ErrInvalidPrivateKey
	}

	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return tls.Certificate{}, ErrInvalidPrivateKey
	}

	// Bounded random integer range transformed safely to strictly positive value
	serialLimit := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
	serial, err := rand.Int(r, serialLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate certificate serial number: %w", err)
	}
	serial.Add(serial, big.NewInt(1))
	if serial.Sign() <= 0 {
		serial.SetInt64(1)
	}

	now := nowFunc()
	template := x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derBytes, err := x509.CreateCertificate(r, &template, &template, pub, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create client certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

// ValidateAndPersistCAFile validates an external CA certificate PEM file and atomically copies it
// into the state directory as controller-ca.pem with mode 0600.
// If controller-ca.pem already exists, it verifies mode 0600, not symlink, valid PEM, and matching contents.
func ValidateAndPersistCAFile(stateDir, caFilePath string) error {
	if err := EnsureStateDir(stateDir); err != nil {
		return err
	}

	f, err := os.OpenFile(caFilePath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("failed to open CA file: %w", err)
	}
	defer f.Close()

	sourceFi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat source CA file: %w", err)
	}
	if !sourceFi.Mode().IsRegular() {
		return errors.New("source CA file must be a regular file")
	}

	limited := io.LimitReader(f, MaxCAPEMBytes+1)
	caBytes, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("failed to read CA file: %w", err)
	}
	if len(caBytes) > MaxCAPEMBytes {
		return errors.New("CA file exceeds maximum allowed size of 1 MiB")
	}

	if _, err := validateAndParseCAPEM(caBytes); err != nil {
		return err
	}

	caDestPath := filepath.Join(stateDir, ControllerCAPEMFileName)
	fi, err := os.Lstat(caDestPath)
	if err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: existing controller CA file cannot be a symlink", ErrInsecurePermissions)
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("%w: existing controller CA file must be a regular file", ErrInsecurePermissions)
		}
		if fi.Mode().Perm() != 0600 {
			return fmt.Errorf("%w: existing controller CA file mode must be 0600, got %04o", ErrInsecurePermissions, fi.Mode().Perm())
		}
		existingBytes, readErr := os.ReadFile(caDestPath)
		if readErr != nil {
			return fmt.Errorf("failed to read existing controller CA file: %w", readErr)
		}
		if !bytes.Equal(existingBytes, caBytes) {
			return errors.New("existing controller CA file contents differ from requested CA file")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to inspect existing controller CA file: %w", err)
	}

	// Write atomically via temp file in stateDir
	tempFile, err := os.CreateTemp(stateDir, "ca-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp CA file: %w", err)
	}
	tempPath := tempFile.Name()
	defer func() {
		_ = os.Remove(tempPath)
	}()

	if err := tempFile.Chmod(0600); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("failed to set CA file permissions: %w", err)
	}
	if _, err := tempFile.Write(caBytes); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("failed to write CA file: %w", err)
	}
	if err := tempFile.Sync(); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("failed to sync CA file: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp CA file: %w", err)
	}

	if err := os.Rename(tempPath, caDestPath); err != nil {
		return fmt.Errorf("failed to atomically rename CA file: %w", err)
	}

	return nil
}

// LoadControllerTrustRoots loads controller CA trust roots from controller-ca.pem if present.
// If the file does not exist, it returns nil, nil (indicating system root pool should be used).
func LoadControllerTrustRoots(stateDir string) (*x509.CertPool, error) {
	caPath := filepath.Join(stateDir, ControllerCAPEMFileName)
	fi, err := os.Lstat(caPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to stat controller CA file: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: controller CA file cannot be a symlink", ErrInsecurePermissions)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: controller CA file must be a regular file", ErrInsecurePermissions)
	}
	if fi.Mode().Perm() != 0600 {
		return nil, fmt.Errorf("%w: controller CA file mode must be 0600, got %04o", ErrInsecurePermissions, fi.Mode().Perm())
	}

	f, err := os.Open(caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open controller CA file: %w", err)
	}
	defer f.Close()

	limited := io.LimitReader(f, MaxCAPEMBytes+1)
	caBytes, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("failed to read controller CA file: %w", err)
	}
	if len(caBytes) > MaxCAPEMBytes {
		return nil, errors.New("controller CA file exceeds maximum allowed size of 1 MiB")
	}

	certs, err := validateAndParseCAPEM(caBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid controller CA file: %w", err)
	}

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	for _, cert := range certs {
		pool.AddCert(cert)
	}

	return pool, nil
}

// BuildAgentHTTPClient constructs a hardened HTTP client with TLS 1.3 minimum and redirect rejection.
func BuildAgentHTTPClient(rootCAs *x509.CertPool, clientCert *tls.Certificate) *http.Client {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    rootCAs,
	}
	if clientCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*clientCert}
	}

	transport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		ForceAttemptHTTP2:     true,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &http.Client{
		Timeout:   HTTPClientTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errors.New("http redirects are not permitted")
		},
	}
}

// TransportCheck verifies secure transport connectivity to the controller using enrolled identity credentials.
func TransportCheck(ctx context.Context, stateDir string) (string, error) {
	if stateDir == "" {
		return "", errors.New("state directory is required")
	}

	meta, err := LoadIdentityMetadata(stateDir)
	if err != nil {
		return "", fmt.Errorf("failed to load agent identity: %w", err)
	}

	ctrlURL, err := ValidateControllerURL(meta.ControllerURL)
	if err != nil {
		return "", fmt.Errorf("invalid controller URL in identity: %w", err)
	}

	if ctrlURL.Scheme != "https" {
		return "", errors.New("transport check requires HTTPS controller URL; found HTTP loopback identity")
	}

	rootCAs, err := LoadControllerTrustRoots(stateDir)
	if err != nil {
		return "", fmt.Errorf("failed to load controller trust roots: %w", err)
	}

	privKey, err := loadExistingPrivateKey(stateDir)
	if err != nil {
		return "", fmt.Errorf("failed to load agent private key: %w", err)
	}

	clientCert, err := BuildEphemeralClientCert(privKey)
	if err != nil {
		return "", fmt.Errorf("failed to create ephemeral client certificate: %w", err)
	}

	client := BuildAgentHTTPClient(rootCAs, &clientCert)

	targetURL := ctrlURL.ResolveReference(&url.URL{Path: SelfEndpointPath}).String()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return "", errors.New("failed to construct transport check request")
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("transport check connection failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, MaxHTTPResponseBody+1))
	if err != nil {
		return "", errors.New("failed to read transport check response")
	}
	if len(bodyBytes) > MaxHTTPResponseBody {
		return "", errors.New("controller response exceeds maximum allowed size")
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return "", errors.New("agent authentication rejected by controller")
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("controller returned unexpected status: %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		return "", errors.New("controller returned missing Content-Type in response")
	}
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil {
		return "", errors.New("controller returned malformed Content-Type in response")
	}
	if mediaType != "application/json" {
		return "", errors.New("controller returned invalid Content-Type in response")
	}
	if charset, ok := params["charset"]; ok && strings.ToLower(charset) != "utf-8" {
		return "", errors.New("controller returned unsupported charset in response")
	}

	var respData struct {
		AgentID string `json:"agent_id"`
	}

	dec := json.NewDecoder(bytes.NewReader(bodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&respData); err != nil {
		return "", errors.New("controller returned malformed JSON in response")
	}
	if dec.More() {
		return "", errors.New("controller returned trailing data in response")
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", errors.New("controller returned additional JSON documents in response")
	}

	if respData.AgentID == "" {
		return "", errors.New("controller returned empty agent_id in response")
	}

	if err := ValidateUUIDv7(respData.AgentID); err != nil {
		return "", errors.New("controller returned invalid agent_id format in response")
	}

	if respData.AgentID != meta.AgentID {
		return "", errors.New("controller returned unexpected agent ID")
	}

	return respData.AgentID, nil
}
