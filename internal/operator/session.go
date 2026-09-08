package operator

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	SessionTokenPrefix           = "sp_session_"
	SessionEntropyBytes          = 32
	SessionTokenRandomLength     = 43
	SessionTokenTotalLength      = len(SessionTokenPrefix) + SessionTokenRandomLength
	SessionLifetime              = 12 * time.Hour
	MaxActiveSessionsPerOperator = 8
)

// Principal represents the authenticated caller identity for authorization.
type Principal struct {
	OperatorID string
	Username   string
	Role       Role
	SessionID  string
	ExpiresAt  time.Time
}

// GenerateSessionToken creates a cryptographically random session token with 32 bytes of entropy.
func GenerateSessionToken() (string, error) {
	b := make([]byte, SessionEntropyBytes)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("failed to generate session entropy: %w", err)
	}
	return SessionTokenPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// ValidateSessionToken validates that the token strictly matches the sp_session_ prefix and 32-byte base64url encoding.
func ValidateSessionToken(token string) error {
	if !strings.HasPrefix(token, SessionTokenPrefix) {
		return errors.New("invalid session token prefix")
	}
	if len(token) != SessionTokenTotalLength {
		return errors.New("invalid session token length")
	}
	if strings.Contains(token, "=") {
		return errors.New("session token must not have padding")
	}
	raw := token[len(SessionTokenPrefix):]
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(decoded) != SessionEntropyBytes {
		return errors.New("invalid session token entropy encoding")
	}
	return nil
}

// HashSessionToken computes the SHA-256 digest of the full plaintext session token for database lookup.
func HashSessionToken(token string) [32]byte {
	return sha256.Sum256([]byte(token))
}
