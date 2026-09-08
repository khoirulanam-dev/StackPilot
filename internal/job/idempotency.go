package job

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

var (
	ErrInvalidIdempotencyKey = errors.New("invalid idempotency key")
)

// ValidateIdempotencyKey validates that the operator-supplied key meets length (16..128 bytes)
// and ASCII character set constraints: A-Z, a-z, 0-9, ., _, :, - (no spaces, no control characters).
func ValidateIdempotencyKey(key string) error {
	n := len(key)
	if n < 16 || n > 128 {
		return fmt.Errorf("%w: length must be between 16 and 128 bytes, got %d", ErrInvalidIdempotencyKey, n)
	}
	for i := 0; i < n; i++ {
		b := key[i]
		isUpper := b >= 'A' && b <= 'Z'
		isLower := b >= 'a' && b <= 'z'
		isDigit := b >= '0' && b <= '9'
		isSpecial := b == '.' || b == '_' || b == ':' || b == '-'
		if !isUpper && !isLower && !isDigit && !isSpecial {
			return fmt.Errorf("%w: contains invalid character byte %02x", ErrInvalidIdempotencyKey, b)
		}
	}
	return nil
}

// HashIdempotencyKey computes the SHA-256 hash of the Idempotency-Key.
// The plaintext key is never stored or logged; only this 32-byte digest is persisted.
func HashIdempotencyKey(key string) [32]byte {
	return sha256.Sum256([]byte(key))
}
