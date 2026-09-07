package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	IdentityKeyFileName  = "identity.key"
	IdentityJSONFileName = "identity.json"
	PEMBlockType         = "PRIVATE KEY"
)

var (
	ErrAlreadyEnrolled     = errors.New("agent is already enrolled")
	ErrInvalidPrivateKey   = errors.New("invalid agent private key")
	ErrInsecurePermissions = errors.New("insecure file permissions")
)

// IdentityMetadata contains non-secret Agent registration metadata.
type IdentityMetadata struct {
	Version       int    `json:"version"`
	AgentID       string `json:"agent_id"`
	ControllerURL string `json:"controller_url"`
	PublicKey     string `json:"public_key"`
}

// ValidateUUIDv7 verifies that s matches the canonical RFC UUIDv7 format without adding dependencies.
func ValidateUUIDv7(s string) error {
	if len(s) != 36 {
		return errors.New("invalid UUID length")
	}
	for i := 0; i < 36; i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return errors.New("invalid UUID format: missing hyphen")
			}
		case 14:
			if c != '7' {
				return errors.New("invalid UUID version: expected version 7")
			}
		case 19:
			if !((c >= '8' && c <= '9') || (c >= 'a' && c <= 'b') || (c >= 'A' && c <= 'B')) {
				return errors.New("invalid UUID variant: expected RFC variant")
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return errors.New("invalid UUID character")
			}
		}
	}
	return nil
}

// GenerateKey generates an Ed25519 keypair using the provided entropy source.
func GenerateKey(r io.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if r == nil {
		r = rand.Reader
	}
	pub, priv, err := ed25519.GenerateKey(r)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ed25519 key: %w", err)
	}
	return pub, priv, nil
}

// EncodePrivateKeyPKCS8PEM encodes an Ed25519 private key into PKCS#8 PEM format.
func EncodePrivateKeyPKCS8PEM(priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, ErrInvalidPrivateKey
	}
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal pkcs8 private key: %w", err)
	}
	block := &pem.Block{
		Type:  PEMBlockType,
		Bytes: pkcs8Bytes,
	}
	return pem.EncodeToMemory(block), nil
}

// ParsePrivateKeyPKCS8PEM decodes and parses an Ed25519 private key from PKCS#8 PEM format.
func ParsePrivateKeyPKCS8PEM(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != PEMBlockType {
		return nil, ErrInvalidPrivateKey
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, ErrInvalidPrivateKey
	}
	privKey, ok := parsedKey.(ed25519.PrivateKey)
	if !ok || len(privKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidPrivateKey
	}
	return privKey, nil
}

func validateExistingStateDir(stateDir string) error {
	info, err := os.Lstat(stateDir)
	if err != nil {
		return fmt.Errorf("failed to stat state directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: state directory cannot be a symlink", ErrInsecurePermissions)
	}
	if !info.IsDir() {
		return fmt.Errorf("state directory path is not a directory")
	}
	if info.Mode().Perm() != 0700 {
		return fmt.Errorf("%w: state directory mode must be 0700, got %04o", ErrInsecurePermissions, info.Mode().Perm())
	}
	return nil
}

// EnsureStateDir creates or validates the state directory with exact mode 0700.
func EnsureStateDir(stateDir string) error {
	_, err := os.Lstat(stateDir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(stateDir, 0700); err != nil {
			return err
		}
		return validateExistingStateDir(stateDir)
	}
	if err != nil {
		return fmt.Errorf("failed to stat state directory: %w", err)
	}
	return validateExistingStateDir(stateDir)
}

func loadExistingPrivateKey(stateDir string) (ed25519.PrivateKey, error) {
	keyPath := filepath.Join(stateDir, IdentityKeyFileName)
	fi, err := os.Lstat(keyPath)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: identity key cannot be a symlink", ErrInsecurePermissions)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: identity key must be a regular file", ErrInsecurePermissions)
	}
	if fi.Mode().Perm() != 0600 {
		return nil, fmt.Errorf("%w: identity key mode must be 0600, got %04o", ErrInsecurePermissions, fi.Mode().Perm())
	}

	data, readErr := os.ReadFile(keyPath)
	if readErr != nil {
		return nil, fmt.Errorf("failed to read identity key: %w", readErr)
	}

	priv, parseErr := ParsePrivateKeyPKCS8PEM(data)
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse existing identity key: %w", parseErr)
	}
	return priv, nil
}

// LoadOrGenerateKey loads an existing valid identity.key, or generates and persists a new one.
func LoadOrGenerateKey(stateDir string, r io.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if err := EnsureStateDir(stateDir); err != nil {
		return nil, nil, err
	}

	priv, err := loadExistingPrivateKey(stateDir)
	if err == nil {
		pub := priv.Public().(ed25519.PublicKey)
		return pub, priv, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}

	// Key does not exist: generate and persist
	pub, priv, err := GenerateKey(r)
	if err != nil {
		return nil, nil, err
	}

	pemBytes, err := EncodePrivateKeyPKCS8PEM(priv)
	if err != nil {
		return nil, nil, err
	}

	keyPath := filepath.Join(stateDir, IdentityKeyFileName)
	f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create identity key file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(pemBytes); err != nil {
		return nil, nil, fmt.Errorf("failed to write identity key file: %w", err)
	}
	if err := f.Sync(); err != nil {
		return nil, nil, fmt.Errorf("failed to sync identity key file: %w", err)
	}

	return pub, priv, nil
}

// LoadIdentityMetadata loads, validates permissions, and parses identity.json from the state directory.
// It requires the state directory to be secure and identity.key to exist, be valid, and match.
func LoadIdentityMetadata(stateDir string) (*IdentityMetadata, error) {
	if err := validateExistingStateDir(stateDir); err != nil {
		return nil, err
	}

	metaPath := filepath.Join(stateDir, IdentityJSONFileName)
	fi, err := os.Lstat(metaPath)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: identity metadata cannot be a symlink", ErrInsecurePermissions)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: identity metadata must be a regular file", ErrInsecurePermissions)
	}
	if fi.Mode().Perm() != 0600 {
		return nil, fmt.Errorf("%w: identity metadata mode must be 0600, got %04o", ErrInsecurePermissions, fi.Mode().Perm())
	}

	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}

	var meta IdentityMetadata
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&meta); err != nil {
		return nil, fmt.Errorf("failed to parse identity metadata: %w", err)
	}
	if dec.More() {
		return nil, errors.New("identity metadata contains trailing data")
	}

	// Validate metadata fields
	if meta.Version != 1 {
		return nil, errors.New("unsupported identity metadata version")
	}
	if err := ValidateUUIDv7(meta.AgentID); err != nil {
		return nil, fmt.Errorf("invalid agent_id in identity metadata: %w", err)
	}
	if _, err := ValidateControllerURL(meta.ControllerURL); err != nil {
		return nil, fmt.Errorf("invalid controller_url in identity metadata: %w", err)
	}
	pubBytes, err := base64.RawURLEncoding.DecodeString(meta.PublicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return nil, errors.New("invalid public_key in identity metadata")
	}

	// Consistency check: MUST require usable, secure identity.key to exist and match
	priv, err := loadExistingPrivateKey(stateDir)
	if err != nil {
		return nil, fmt.Errorf("identity metadata requires valid identity.key: %w", err)
	}
	derivedPub := priv.Public().(ed25519.PublicKey)
	if !bytes.Equal(derivedPub, pubBytes) {
		return nil, errors.New("agent identity consistency error: public key mismatch")
	}

	return &meta, nil
}

// WriteIdentityMetadata atomically writes identity.json using a temp file in stateDir.
func WriteIdentityMetadata(stateDir string, meta *IdentityMetadata) error {
	if err := EnsureStateDir(stateDir); err != nil {
		return err
	}

	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal identity metadata: %w", err)
	}

	tempFile, err := os.CreateTemp(stateDir, "identity-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp metadata file: %w", err)
	}
	tempPath := tempFile.Name()
	defer func() {
		_ = os.Remove(tempPath)
	}()

	if err := tempFile.Chmod(0600); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("failed to set metadata file permissions: %w", err)
	}

	if _, err := tempFile.Write(data); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("failed to write identity metadata: %w", err)
	}
	if err := tempFile.Sync(); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("failed to sync identity metadata: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp metadata file: %w", err)
	}

	targetPath := filepath.Join(stateDir, IdentityJSONFileName)
	if err := os.Rename(tempPath, targetPath); err != nil {
		return fmt.Errorf("failed to atomically rename metadata file: %w", err)
	}

	return nil
}

// FormatPublicKeyBase64RawURL formats a 32-byte Ed25519 public key in Base64 RawURL encoding.
func FormatPublicKeyBase64RawURL(pub ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(pub)
}
