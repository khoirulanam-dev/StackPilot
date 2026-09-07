package enrollment

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	TokenPrefix       = "sp_enroll_"
	TokenEntropyBytes = 32
	TokenLifetime     = 15 * time.Minute
)

// TokenRecord represents safe metadata returned after persisting an enrollment token.
type TokenRecord struct {
	ID        string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// TokenPersister defines the contract for persisting an enrollment token record.
type TokenPersister interface {
	CreateEnrollmentToken(ctx context.Context, tokenHash [32]byte, expiresAt time.Time) (*TokenRecord, error)
}

// generatePlaintextToken generates a cryptographically random token string using the provided reader.
func generatePlaintextToken(r io.Reader) (string, error) {
	b := make([]byte, TokenEntropyBytes)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", fmt.Errorf("failed to read random entropy: %w", err)
	}
	return TokenPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken computes the SHA-256 digest of the entire plaintext enrollment token.
func HashToken(plaintext string) [32]byte {
	return sha256.Sum256([]byte(plaintext))
}

// IssueToken coordinates token generation, SHA-256 hashing, 15-minute expiration calculation,
// and database persistence. On success, it returns the plaintext token.
func IssueToken(ctx context.Context, persister TokenPersister) (string, error) {
	return issueTokenWithReader(ctx, persister, rand.Reader, time.Now)
}

func issueTokenWithReader(ctx context.Context, persister TokenPersister, r io.Reader, nowFunc func() time.Time) (string, error) {
	plaintext, err := generatePlaintextToken(r)
	if err != nil {
		return "", fmt.Errorf("failed to generate enrollment token: %w", err)
	}

	tokenHash := HashToken(plaintext)
	expiresAt := nowFunc().Add(TokenLifetime)

	if _, err := persister.CreateEnrollmentToken(ctx, tokenHash, expiresAt); err != nil {
		return "", errors.New("failed to persist enrollment token")
	}

	return plaintext, nil
}
