package enrollment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

type mockPersister struct {
	createFunc func(ctx context.Context, tokenHash [32]byte, expiresAt time.Time) (*TokenRecord, error)
}

func (m *mockPersister) CreateEnrollmentToken(ctx context.Context, tokenHash [32]byte, expiresAt time.Time) (*TokenRecord, error) {
	if m.createFunc != nil {
		return m.createFunc(ctx, tokenHash, expiresAt)
	}
	return &TokenRecord{
		ID:        "mock-uuid",
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}, nil
}

func TestGeneratePlaintextToken_Deterministic(t *testing.T) {
	// 32 deterministic bytes
	rawEntropy := bytes.Repeat([]byte{0x42}, 32)
	reader := bytes.NewReader(rawEntropy)

	token, err := generatePlaintextToken(reader)
	if err != nil {
		t.Fatalf("generatePlaintextToken failed: %v", err)
	}

	// 1. Prefix exactly sp_enroll_
	if !strings.HasPrefix(token, TokenPrefix) {
		t.Fatalf("expected token prefix %q, got %q", TokenPrefix, token)
	}

	// 2. Random portion uses RawURLEncoding (no padding)
	randomPart := strings.TrimPrefix(token, TokenPrefix)
	if strings.Contains(randomPart, "=") {
		t.Errorf("token contains padding character '=': %s", token)
	}

	expectedRandom := base64.RawURLEncoding.EncodeToString(rawEntropy)
	if randomPart != expectedRandom {
		t.Errorf("expected random part %q, got %q", expectedRandom, randomPart)
	}

	expectedToken := TokenPrefix + expectedRandom
	if token != expectedToken {
		t.Errorf("expected full token %q, got %q", expectedToken, token)
	}

	// 3. Hash is SHA-256 of FULL token
	tokenHash := HashToken(token)
	expectedHash := sha256.Sum256([]byte(expectedToken))
	if tokenHash != expectedHash {
		t.Errorf("HashToken mismatch: expected %x, got %x", expectedHash, tokenHash)
	}

	// 4. Hash length is exactly 32 bytes
	if len(tokenHash) != 32 {
		t.Errorf("expected hash length 32, got %d", len(tokenHash))
	}
}

func TestGeneratePlaintextToken_ShortReader(t *testing.T) {
	shortEntropy := []byte{0x01, 0x02, 0x03}
	reader := bytes.NewReader(shortEntropy)

	_, err := generatePlaintextToken(reader)
	if err == nil {
		t.Fatal("expected error on insufficient entropy, got nil")
	}
}

func TestIssueToken_Success(t *testing.T) {
	fixedNow := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	var capturedHash [32]byte
	var capturedExpiry time.Time

	persister := &mockPersister{
		createFunc: func(ctx context.Context, tokenHash [32]byte, expiresAt time.Time) (*TokenRecord, error) {
			capturedHash = tokenHash
			capturedExpiry = expiresAt
			return &TokenRecord{
				ID:        "018f-mock-uuid",
				CreatedAt: fixedNow,
				ExpiresAt: expiresAt,
			}, nil
		},
	}

	rawEntropy := bytes.Repeat([]byte{0x07}, 32)
	token, err := issueTokenWithReader(context.Background(), persister, bytes.NewReader(rawEntropy), func() time.Time {
		return fixedNow
	})
	if err != nil {
		t.Fatalf("issueTokenWithReader returned unexpected error: %v", err)
	}

	if !strings.HasPrefix(token, TokenPrefix) {
		t.Fatal("token missing expected prefix")
	}

	// Expiry must be exactly fixedNow + 15 minutes
	expectedExpiry := fixedNow.Add(15 * time.Minute)
	if !capturedExpiry.Equal(expectedExpiry) {
		t.Errorf("expected expiry %v, got %v", expectedExpiry, capturedExpiry)
	}

	// Hash must match the generated plaintext token
	expectedHash := sha256.Sum256([]byte(token))
	if capturedHash != expectedHash {
		t.Error("captured hash does not match expected hash")
	}
}

func TestIssueToken_PersistenceFailureDoesNotReturnPlaintext(t *testing.T) {
	const syntheticSecret = "stackpilot-super-secret-enrollment-value"
	const mockErrorPrefix = "database insert failed for"
	persister := &mockPersister{
		createFunc: func(ctx context.Context, tokenHash [32]byte, expiresAt time.Time) (*TokenRecord, error) {
			return nil, fmt.Errorf("%s %s", mockErrorPrefix, syntheticSecret)
		},
	}

	token, err := IssueToken(context.Background(), persister)
	if err == nil {
		t.Fatal("expected error on persistence failure, got nil")
	}

	// 1. Returned token is empty
	if token != "" {
		t.Fatal("plaintext token was returned on persistence failure")
	}

	// 2. err.Error() does NOT contain syntheticSecret
	if strings.Contains(err.Error(), syntheticSecret) {
		t.Fatal("persistence failure error leaked synthetic secret")
	}

	// 3. err.Error() does NOT contain underlying mock text
	if strings.Contains(err.Error(), mockErrorPrefix) {
		t.Fatal("persistence failure error leaked underlying persistence error text")
	}

	// 4. err.Error() provides stable safe context
	if !strings.Contains(err.Error(), "failed to persist enrollment token") {
		t.Errorf("error %q does not contain expected context 'failed to persist enrollment token'", err.Error())
	}
}

func TestIssueToken_ProductionEntropy(t *testing.T) {
	persister := &mockPersister{}

	token, err := IssueToken(context.Background(), persister)
	if err != nil {
		t.Fatalf("IssueToken failed: %v", err)
	}

	if !strings.HasPrefix(token, TokenPrefix) {
		t.Fatal("token missing expected prefix")
	}

	randomPart := strings.TrimPrefix(token, TokenPrefix)
	// 32 bytes in base64url without padding is 43 characters
	if len(randomPart) != 43 {
		t.Errorf("expected random part length 43, got %d", len(randomPart))
	}
	if strings.Contains(randomPart, "=") {
		t.Error("token contains padding character '='")
	}
}
