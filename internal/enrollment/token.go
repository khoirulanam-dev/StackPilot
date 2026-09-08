package enrollment

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"stackpilot/internal/protocol"
)

const (
	TokenPrefix       = "sp_enroll_"
	TokenEntropyBytes = 32
	TokenTotalLength  = len(TokenPrefix) + 43 // 53 characters
	TokenLifetime     = 15 * time.Minute
)

var (
	// ErrEnrollmentRejected is returned when a token is invalid, expired, or already consumed by a different key.
	ErrEnrollmentRejected = errors.New("enrollment rejected")
	// ErrIdentityConflict is returned when an Agent public key is already registered with another identity.
	ErrIdentityConflict = errors.New("agent identity conflict")
	// ErrEnrollmentInternal is returned on unexpected internal persistence failure.
	ErrEnrollmentInternal = errors.New("internal enrollment error")
	// ErrAgentNotFound is returned when an Agent public key is not registered.
	ErrAgentNotFound = errors.New("agent not found")
)

// AgentRecord represents safe domain metadata for an enrolled Agent.
type AgentRecord struct {
	ID              string
	PublicKey       [32]byte
	CreatedAt       time.Time
	LastSeenAt      *time.Time
	ProtocolVersion *int
}

// AgentRegistrar defines the contract for atomic token consumption and Agent registration.
type AgentRegistrar interface {
	RegisterAgent(ctx context.Context, tokenHash [32]byte, publicKey [32]byte) (*AgentRecord, bool, error)
}

// AgentFinder defines the contract for looking up an Agent by public key.
type AgentFinder interface {
	FindAgentByPublicKey(ctx context.Context, publicKey [32]byte) (*AgentRecord, error)
}

// AgentHeartbeatRecorder defines the contract for recording an Agent heartbeat.
type AgentHeartbeatRecorder interface {
	RecordAgentHeartbeat(ctx context.Context, publicKey [32]byte, protocolVersion int) (*AgentRecord, bool, error)
}

// AgentInventoryRecorder defines the contract for recording Agent inventory.
type AgentInventoryRecorder interface {
	RecordAgentInventory(ctx context.Context, publicKey [32]byte, req *protocol.InventoryRequest) error
}

// AgentTelemetryRecorder defines the contract for recording Agent telemetry.
type AgentTelemetryRecorder interface {
	RecordAgentTelemetry(ctx context.Context, publicKey [32]byte, req *protocol.TelemetryRequest) error
}

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

// ValidateToken validates that the token string matches the exact enrollment token specification.
// It never includes the token contents in error messages.
func ValidateToken(token string) error {
	if len(token) != TokenTotalLength {
		return errors.New("invalid enrollment token length")
	}
	if !strings.HasPrefix(token, TokenPrefix) {
		return errors.New("invalid enrollment token prefix")
	}
	randomPart := strings.TrimPrefix(token, TokenPrefix)
	if strings.Contains(randomPart, "=") {
		return errors.New("invalid enrollment token padding")
	}
	raw, err := base64.RawURLEncoding.DecodeString(randomPart)
	if err != nil {
		return errors.New("invalid enrollment token encoding")
	}
	if len(raw) != TokenEntropyBytes {
		return errors.New("invalid enrollment token entropy length")
	}
	return nil
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
