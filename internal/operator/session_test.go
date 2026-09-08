package operator

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestSessionToken_GenerationAndValidation(t *testing.T) {
	tok1, err := GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken failed: %v", err)
	}

	if !strings.HasPrefix(tok1, SessionTokenPrefix) {
		t.Fatalf("expected prefix %q, got %q", SessionTokenPrefix, tok1)
	}

	if len(tok1) != SessionTokenTotalLength {
		t.Fatalf("expected length %d, got %d", SessionTokenTotalLength, len(tok1))
	}

	if strings.Contains(tok1, "=") {
		t.Fatal("session token must not contain padding '='")
	}

	rawPart := strings.TrimPrefix(tok1, SessionTokenPrefix)
	decoded, err := base64.RawURLEncoding.DecodeString(rawPart)
	if err != nil {
		t.Fatalf("failed to decode raw base64url portion: %v", err)
	}
	if len(decoded) != SessionEntropyBytes {
		t.Fatalf("expected %d entropy bytes, got %d", SessionEntropyBytes, len(decoded))
	}

	tok2, err := GenerateSessionToken()
	if err != nil {
		t.Fatalf("second GenerateSessionToken failed: %v", err)
	}
	if tok1 == tok2 {
		t.Fatal("two successive session tokens are identical")
	}

	if err := ValidateSessionToken(tok1); err != nil {
		t.Errorf("ValidateSessionToken failed for valid token: %v", err)
	}

	h1 := HashSessionToken(tok1)
	h2 := HashSessionToken(tok1)
	if h1 != h2 {
		t.Fatal("HashSessionToken is non-deterministic")
	}
	expectedHash := sha256.Sum256([]byte(tok1))
	if h1 != expectedHash {
		t.Fatal("HashSessionToken did not compute standard SHA-256")
	}
}

func TestSessionToken_Rejection(t *testing.T) {
	validToken, err := GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken failed: %v", err)
	}

	t.Run("rejects token with wrong prefix", func(t *testing.T) {
		wrongPrefix := "sp_wrong_" + validToken[len(SessionTokenPrefix):]
		if err := ValidateSessionToken(wrongPrefix); err == nil {
			t.Fatal("expected token with wrong prefix to be rejected")
		}
	})

	t.Run("rejects truncated token", func(t *testing.T) {
		tooShort := validToken[:len(validToken)-1]
		if err := ValidateSessionToken(tooShort); err == nil {
			t.Fatal("expected truncated token to be rejected")
		}
	})

	t.Run("rejects oversized token", func(t *testing.T) {
		tooLong := validToken + "a"
		if err := ValidateSessionToken(tooLong); err == nil {
			t.Fatal("expected oversized token to be rejected")
		}
	})

	t.Run("rejects token with base64 padding", func(t *testing.T) {
		withPadding := validToken[:len(validToken)-1] + "="
		if err := ValidateSessionToken(withPadding); err == nil {
			t.Fatal("expected padded token to be rejected")
		}
	})

	t.Run("rejects non-base64url characters", func(t *testing.T) {
		invalidChar := validToken[:len(validToken)-1] + "!"
		if err := ValidateSessionToken(invalidChar); err == nil {
			t.Fatal("expected token with invalid character to be rejected")
		}
	})

	t.Run("rejects standard base64 characters", func(t *testing.T) {
		withPlus := validToken[:len(validToken)-1] + "+"
		if err := ValidateSessionToken(withPlus); err == nil {
			t.Fatal("expected token with '+' to be rejected")
		}
	})
}
