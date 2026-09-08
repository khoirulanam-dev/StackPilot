package operator

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	Argon2MemoryKiB   = 32 * 1024 // 32 MiB
	Argon2Iterations  = 3
	Argon2Parallelism = 1
	Argon2SaltLength  = 16
	Argon2KeyLength   = 32
	Argon2Version     = 19

	MinPasswordBytes = 12
	MaxPasswordBytes = 128
)

var (
	dummySalt = []byte{0x73, 0x74, 0x61, 0x63, 0x6b, 0x70, 0x69, 0x6c, 0x6f, 0x74, 0x5f, 0x64, 0x75, 0x6d, 0x6d, 0x79}
	dummyKey  = make([]byte, Argon2KeyLength)
)

// ValidatePassword validates length, UTF-8 validity, and absence of control characters without trimming.
func ValidatePassword(pw string) error {
	if len(pw) < MinPasswordBytes {
		return errors.New("password must be at least 12 bytes")
	}
	if len(pw) > MaxPasswordBytes {
		return errors.New("password must be at most 128 bytes")
	}
	if !utf8.ValidString(pw) {
		return errors.New("password must be valid UTF-8")
	}
	for _, r := range pw {
		if unicode.IsControl(r) {
			return errors.New("password must not contain control characters or NUL")
		}
	}
	return nil
}

// HashPassword generates a random salt and derives an Argon2id PHC-formatted hash.
func HashPassword(pw string) (string, error) {
	if err := ValidatePassword(pw); err != nil {
		return "", err
	}

	salt := make([]byte, Argon2SaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("failed to generate random salt: %w", err)
	}

	key := argon2.IDKey([]byte(pw), salt, Argon2Iterations, Argon2MemoryKiB, Argon2Parallelism, Argon2KeyLength)

	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		Argon2Version,
		Argon2MemoryKiB,
		Argon2Iterations,
		Argon2Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)

	return encoded, nil
}

// VerifyPassword strictly verifies a password against a stored PHC hash, rejecting unsupported parameters before allocation.
func VerifyPassword(encodedHash, pw string) error {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return errors.New("invalid password hash format")
	}
	if parts[2] != "v=19" {
		return errors.New("unsupported argon2 version")
	}
	if parts[3] != "m=32768,t=3,p=1" {
		return errors.New("unsupported argon2 parameters")
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) != Argon2SaltLength {
		return errors.New("invalid salt in password hash")
	}

	expectedKey, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(expectedKey) != Argon2KeyLength {
		return errors.New("invalid key in password hash")
	}

	derivedKey := argon2.IDKey([]byte(pw), salt, Argon2Iterations, Argon2MemoryKiB, Argon2Parallelism, Argon2KeyLength)
	if subtle.ConstantTimeCompare(derivedKey, expectedKey) != 1 {
		return errors.New("invalid password")
	}

	return nil
}

// DummyPasswordDerivation performs a dummy Argon2id derivation to ensure uniform timing for unknown usernames.
func DummyPasswordDerivation(pw string) {
	derived := argon2.IDKey([]byte(pw), dummySalt, Argon2Iterations, Argon2MemoryKiB, Argon2Parallelism, Argon2KeyLength)
	_ = subtle.ConstantTimeCompare(derived, dummyKey)
}

// ConcurrencyLimiter bounds the number of concurrent password hash operations to prevent resource exhaustion.
type ConcurrencyLimiter struct {
	sem chan struct{}
}

// NewConcurrencyLimiter creates a concurrency limiter with the specified bound.
func NewConcurrencyLimiter(limit int) *ConcurrencyLimiter {
	return &ConcurrencyLimiter{
		sem: make(chan struct{}, limit),
	}
}

// TryAcquire attempts to acquire a concurrency slot non-blocking, returning a release callback and true if acquired.
func (c *ConcurrencyLimiter) TryAcquire() (func(), bool) {
	select {
	case c.sem <- struct{}{}:
		return func() { <-c.sem }, true
	default:
		return nil, false
	}
}
