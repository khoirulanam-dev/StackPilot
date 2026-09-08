package job

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

func TestIdempotency_Validation(t *testing.T) {
	t.Run("valid_min_boundary_16_bytes", func(t *testing.T) {
		minKey := "1234567890abcdef"
		if err := ValidateIdempotencyKey(minKey); err != nil {
			t.Errorf("expected 16-byte key to be valid: %v", err)
		}
	})

	t.Run("valid_max_boundary_128_bytes", func(t *testing.T) {
		maxKey := strings.Repeat("a", 128)
		if err := ValidateIdempotencyKey(maxKey); err != nil {
			t.Errorf("expected 128-byte key to be valid: %v", err)
		}
	})

	t.Run("valid_character_set", func(t *testing.T) {
		allowedKey := "Abc-123_test.0:key"
		if err := ValidateIdempotencyKey(allowedKey); err != nil {
			t.Errorf("expected allowed characters key to be valid: %v", err)
		}
	})

	t.Run("reject_too_short_15_bytes", func(t *testing.T) {
		tooShort := "1234567890abcde"
		if err := ValidateIdempotencyKey(tooShort); !errors.Is(err, ErrInvalidIdempotencyKey) {
			t.Errorf("expected ErrInvalidIdempotencyKey for 15-byte key, got: %v", err)
		}
	})

	t.Run("reject_too_long_129_bytes", func(t *testing.T) {
		tooLong := strings.Repeat("a", 129)
		if err := ValidateIdempotencyKey(tooLong); !errors.Is(err, ErrInvalidIdempotencyKey) {
			t.Errorf("expected ErrInvalidIdempotencyKey for 129-byte key, got: %v", err)
		}
	})

	t.Run("reject_invalid_characters", func(t *testing.T) {
		invalidKeys := []string{
			"valid_key_with space",
			"valid_key_with\tTab",
			"valid_key_with\nNewline",
			"valid_key_with\x00Nul",
			"valid_key_with\x1fCtrl",
			"valid_key_with\x7fDel",
			"valid_key_with_ä_umlaut",
			"valid_key_with_@_at",
			"valid_key_with_#_hash",
			"valid_key_with_!_bang",
		}

		for _, k := range invalidKeys {
			if err := ValidateIdempotencyKey(k); !errors.Is(err, ErrInvalidIdempotencyKey) {
				t.Errorf("expected ErrInvalidIdempotencyKey for %q, got: %v", k, err)
			}
		}
	})
}

func TestIdempotency_Hashing(t *testing.T) {
	key1 := "valid-idempotency-key-001"
	key2 := "valid-idempotency-key-002"

	h1 := HashIdempotencyKey(key1)
	h2 := HashIdempotencyKey(key2)

	if len(h1) != 32 {
		t.Errorf("expected 32 bytes hash, got %d", len(h1))
	}

	h1Again := HashIdempotencyKey(key1)
	if !bytes.Equal(h1[:], h1Again[:]) {
		t.Error("HashIdempotencyKey is not deterministic")
	}

	expectedSum := sha256.Sum256([]byte(key1))
	if !bytes.Equal(h1[:], expectedSum[:]) {
		t.Error("hash does not match sha256.Sum256")
	}

	if bytes.Equal(h1[:], h2[:]) {
		t.Error("different keys must produce different hashes")
	}
}
