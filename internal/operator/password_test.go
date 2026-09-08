package operator

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestPassword_Validation(t *testing.T) {
	t.Run("minimum boundary 12 bytes allowed", func(t *testing.T) {
		if err := ValidatePassword("123456789012"); err != nil {
			t.Fatalf("expected 12-byte password to be valid, got: %v", err)
		}
	})

	t.Run("maximum boundary 128 bytes allowed", func(t *testing.T) {
		if err := ValidatePassword(strings.Repeat("a", 128)); err != nil {
			t.Fatalf("expected 128-byte password to be valid, got: %v", err)
		}
	})

	t.Run("less than 12 bytes rejected", func(t *testing.T) {
		if err := ValidatePassword("12345678901"); err == nil {
			t.Fatal("expected 11-byte password to be rejected")
		}
	})

	t.Run("more than 128 bytes rejected", func(t *testing.T) {
		if err := ValidatePassword(strings.Repeat("a", 129)); err == nil {
			t.Fatal("expected 129-byte password to be rejected")
		}
	})

	t.Run("ASCII BEL rejected", func(t *testing.T) {
		if err := ValidatePassword("ValidPassword\x07123"); err == nil {
			t.Fatal("expected ASCII BEL in password to be rejected")
		}
	})

	t.Run("NUL byte rejected", func(t *testing.T) {
		if err := ValidatePassword("ValidPassword\x00123"); err == nil {
			t.Fatal("expected NUL character in password to be rejected")
		}
	})

	t.Run("DEL byte rejected", func(t *testing.T) {
		if err := ValidatePassword("ValidPassword\x7f123"); err == nil {
			t.Fatal("expected DEL character in password to be rejected")
		}
	})

	t.Run("Unicode control U+0085 rejected", func(t *testing.T) {
		if err := ValidatePassword("ValidPassword\u0085123"); err == nil {
			t.Fatal("expected Unicode control U+0085 to be rejected")
		}
	})

	t.Run("normal Unicode non-control character allowed", func(t *testing.T) {
		if err := ValidatePassword("ValidPass世界🔐123"); err != nil {
			t.Fatalf("expected normal Unicode non-control characters to be valid, got: %v", err)
		}
	})

	t.Run("invalid UTF-8 sequence rejected", func(t *testing.T) {
		if err := ValidatePassword("ValidPassword\xff\xfe123"); err == nil {
			t.Fatal("expected invalid UTF-8 in password to be rejected")
		}
	})

	t.Run("spaces preserved without trimming", func(t *testing.T) {
		spacedPw := "  valid password with spaces  "
		if err := ValidatePassword(spacedPw); err != nil {
			t.Fatalf("expected password with preserved spaces to be valid, got: %v", err)
		}
	})
}

func TestPassword_HashAndVerify(t *testing.T) {
	pw := "A-Very-Strong-Password-123!"

	hash1, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if !strings.HasPrefix(hash1, "$argon2id$v=19$m=32768,t=3,p=1$") {
		t.Fatalf("unexpected PHC header in hash: %q", hash1)
	}

	hash2, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("second HashPassword failed: %v", err)
	}
	if hash1 == hash2 {
		t.Fatal("successive hashes produced identical salt/output")
	}

	if err := VerifyPassword(hash1, pw); err != nil {
		t.Fatalf("VerifyPassword failed with valid password: %v", err)
	}

	if err := VerifyPassword(hash1, "Wrong-Password-456!"); err == nil {
		t.Fatal("VerifyPassword succeeded with incorrect password")
	}

	parts := strings.Split(hash1, "$")
	if len(parts) != 6 {
		t.Fatalf("expected 6 PHC parts, got %d", len(parts))
	}
	if parts[1] != "argon2id" {
		t.Errorf("expected argon2id, got %q", parts[1])
	}
	if parts[2] != "v=19" {
		t.Errorf("expected v=19, got %q", parts[2])
	}
	if parts[3] != "m=32768,t=3,p=1" {
		t.Errorf("expected m=32768,t=3,p=1, got %q", parts[3])
	}

	saltBytes, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(saltBytes) != 16 {
		t.Errorf("expected 16-byte salt, got len %d (err: %v)", len(saltBytes), err)
	}

	keyBytes, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(keyBytes) != 32 {
		t.Errorf("expected 32-byte key, got len %d (err: %v)", len(keyBytes), err)
	}
}

func TestPassword_PHCParserSafety(t *testing.T) {
	pw := "A-Very-Strong-Password-123!"
	validHash, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	parts := strings.Split(validHash, "$")
	salt := parts[4]
	key := parts[5]

	t.Run("rejects malformed PHC string", func(t *testing.T) {
		if err := VerifyPassword("not-a-valid-phc-hash", pw); err == nil {
			t.Fatal("expected malformed PHC to be rejected")
		}
	})

	t.Run("rejects unsupported algorithm", func(t *testing.T) {
		wrongAlgo := fmt.Sprintf("$argon2i$v=19$m=32768,t=3,p=1$%s$%s", salt, key)
		if err := VerifyPassword(wrongAlgo, pw); err == nil {
			t.Fatal("expected wrong algorithm to be rejected")
		}
	})

	t.Run("rejects unsupported version", func(t *testing.T) {
		wrongVer := fmt.Sprintf("$argon2id$v=18$m=32768,t=3,p=1$%s$%s", salt, key)
		if err := VerifyPassword(wrongVer, pw); err == nil {
			t.Fatal("expected wrong version to be rejected")
		}
	})

	// Security invariant: Rejects hostile parameters before memory allocation to prevent resource exhaustion.
	t.Run("rejects hostile memory parameter before allocation", func(t *testing.T) {
		hostileMem := fmt.Sprintf("$argon2id$v=19$m=10485760,t=3,p=1$%s$%s", salt, key)
		if err := VerifyPassword(hostileMem, pw); err == nil {
			t.Fatal("expected hostile memory parameter to be rejected")
		}
	})

	t.Run("rejects hostile iterations parameter", func(t *testing.T) {
		hostileIter := fmt.Sprintf("$argon2id$v=19$m=32768,t=100,p=1$%s$%s", salt, key)
		if err := VerifyPassword(hostileIter, pw); err == nil {
			t.Fatal("expected hostile iterations to be rejected")
		}
	})

	t.Run("rejects hostile parallelism parameter", func(t *testing.T) {
		hostileParallel := fmt.Sprintf("$argon2id$v=19$m=32768,t=3,p=8$%s$%s", salt, key)
		if err := VerifyPassword(hostileParallel, pw); err == nil {
			t.Fatal("expected hostile parallelism to be rejected")
		}
	})

	t.Run("rejects extra PHC fields", func(t *testing.T) {
		if err := VerifyPassword(validHash+"$extra", pw); err == nil {
			t.Fatal("expected extra PHC fields to be rejected")
		}
	})

	t.Run("rejects truncated salt", func(t *testing.T) {
		truncatedSalt := fmt.Sprintf("$argon2id$v=19$m=32768,t=3,p=1$%s$%s", salt[:5], key)
		if err := VerifyPassword(truncatedSalt, pw); err == nil {
			t.Fatal("expected truncated salt to be rejected")
		}
	})

	t.Run("rejects truncated key", func(t *testing.T) {
		truncatedKey := fmt.Sprintf("$argon2id$v=19$m=32768,t=3,p=1$%s$%s", salt, key[:5])
		if err := VerifyPassword(truncatedKey, pw); err == nil {
			t.Fatal("expected truncated key to be rejected")
		}
	})
}

func TestPassword_DummyDerivation(t *testing.T) {
	// Security invariant: uniform execution path for unknown usernames to mitigate timing side-channels.
	DummyPasswordDerivation("some-test-password-123!")
}

func TestPassword_ConcurrencyLimiter(t *testing.T) {
	limiter := NewConcurrencyLimiter(2)

	release1, ok1 := limiter.TryAcquire()
	if !ok1 || release1 == nil {
		t.Fatal("first acquire must succeed")
	}

	release2, ok2 := limiter.TryAcquire()
	if !ok2 || release2 == nil {
		t.Fatal("second acquire must succeed")
	}

	_, ok3 := limiter.TryAcquire()
	if ok3 {
		t.Fatal("third acquire must fail when limit of 2 is saturated")
	}

	release1()

	release4, ok4 := limiter.TryAcquire()
	if !ok4 || release4 == nil {
		t.Fatal("acquire after release must succeed")
	}

	release2()
	release4()
}
