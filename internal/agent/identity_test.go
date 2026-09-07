package agent

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEd25519Key_DeterministicGenerationAndRoundTrip(t *testing.T) {
	entropy := bytes.Repeat([]byte{0x42}, 32)
	pub, priv, err := GenerateKey(bytes.NewReader(entropy))
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("expected public key size %d, got %d", ed25519.PublicKeySize, len(pub))
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("expected private key size %d, got %d", ed25519.PrivateKeySize, len(priv))
	}

	// Verify public key is derived from private key
	derivedPub := priv.Public().(ed25519.PublicKey)
	if !bytes.Equal(pub, derivedPub) {
		t.Fatal("derived public key does not match generated public key")
	}

	// PEM PKCS#8 Round-trip
	pemBytes, err := EncodePrivateKeyPKCS8PEM(priv)
	if err != nil {
		t.Fatalf("EncodePrivateKeyPKCS8PEM failed: %v", err)
	}

	if !strings.HasPrefix(string(pemBytes), "-----BEGIN PRIVATE KEY-----") {
		t.Fatal("encoded PEM missing expected header")
	}

	parsedPriv, err := ParsePrivateKeyPKCS8PEM(pemBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPKCS8PEM failed: %v", err)
	}

	if !bytes.Equal(priv, parsedPriv) {
		t.Fatal("parsed private key does not match original private key")
	}
}

func TestParsePrivateKeyPKCS8PEM_Malformed(t *testing.T) {
	// Not PEM
	_, err := ParsePrivateKeyPKCS8PEM([]byte("garbage not pem"))
	if err == nil {
		t.Fatal("expected error on garbage PEM, got nil")
	}

	// PEM with wrong block type
	wrongBlock := "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"
	_, err = ParsePrivateKeyPKCS8PEM([]byte(wrongBlock))
	if err == nil {
		t.Fatal("expected error on wrong block type, got nil")
	}
}

func TestIdentityStorage_Lifecycle(t *testing.T) {
	tempDir := t.TempDir()
	stateDir := filepath.Join(tempDir, "agent-state")

	entropy := bytes.Repeat([]byte{0x24}, 32)

	// 1. Initial generation
	pub1, priv1, err := LoadOrGenerateKey(stateDir, bytes.NewReader(entropy))
	if err != nil {
		t.Fatalf("LoadOrGenerateKey failed: %v", err)
	}

	stateDirFi, err := os.Lstat(stateDir)
	if err != nil {
		t.Fatalf("failed to stat state dir: %v", err)
	}
	if stateDirFi.Mode().Perm() != 0700 {
		t.Fatalf("expected state directory permission 0700, got %04o", stateDirFi.Mode().Perm())
	}

	keyPath := filepath.Join(stateDir, IdentityKeyFileName)
	keyFi, err := os.Lstat(keyPath)
	if err != nil {
		t.Fatalf("failed to stat identity.key: %v", err)
	}
	if keyFi.Mode().Perm() != 0600 {
		t.Fatalf("expected identity.key mode 0600, got %04o", keyFi.Mode().Perm())
	}

	// 2. Second load: must reuse existing key, not overwrite
	entropy2 := bytes.Repeat([]byte{0x99}, 32)
	pub2, priv2, err := LoadOrGenerateKey(stateDir, bytes.NewReader(entropy2))
	if err != nil {
		t.Fatalf("second LoadOrGenerateKey failed: %v", err)
	}

	if !bytes.Equal(pub1, pub2) {
		t.Fatal("second load returned different public key, existing key was not reused")
	}
	if !bytes.Equal(priv1, priv2) {
		t.Fatal("second load returned different private key, existing key was overwritten")
	}

	// 3. Identity metadata atomic write
	const validUUIDv7 = "018f0000-0000-7000-8000-000000000001"
	meta := &IdentityMetadata{
		Version:       1,
		AgentID:       validUUIDv7,
		ControllerURL: "http://127.0.0.1:7447",
		PublicKey:     FormatPublicKeyBase64RawURL(pub1),
	}

	if err := WriteIdentityMetadata(stateDir, meta); err != nil {
		t.Fatalf("WriteIdentityMetadata failed: %v", err)
	}

	jsonPath := filepath.Join(stateDir, IdentityJSONFileName)
	jsonFi, err := os.Lstat(jsonPath)
	if err != nil {
		t.Fatalf("failed to stat identity.json: %v", err)
	}
	if jsonFi.Mode().Perm() != 0600 {
		t.Fatalf("expected identity.json mode 0600, got %04o", jsonFi.Mode().Perm())
	}

	loadedMeta, err := LoadIdentityMetadata(stateDir)
	if err != nil {
		t.Fatalf("LoadIdentityMetadata failed: %v", err)
	}

	if loadedMeta.AgentID != meta.AgentID {
		t.Fatalf("expected agent_id %q, got %q", meta.AgentID, loadedMeta.AgentID)
	}
	if loadedMeta.ControllerURL != meta.ControllerURL {
		t.Fatalf("expected controller_url %q, got %q", meta.ControllerURL, loadedMeta.ControllerURL)
	}
	if loadedMeta.PublicKey != meta.PublicKey {
		t.Fatal("public key in loaded metadata did not match original")
	}

	// Verify enrollment token never appears in state files
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("failed to read identity.json: %v", err)
	}
	if strings.Contains(string(jsonData), "sp_enroll_") || strings.Contains(string(jsonData), "token_hash") {
		t.Fatal("identity.json contains prohibited token reference")
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("failed to read identity.key: %v", err)
	}
	if strings.Contains(string(keyData), "sp_enroll_") {
		t.Fatal("identity.key contains prohibited token reference")
	}
}

func TestEnsureStateDir_Security(t *testing.T) {
	t.Run("rejects insecure 0755 permissions", func(t *testing.T) {
		tempDir := t.TempDir()
		stateDir := filepath.Join(tempDir, "insecure-dir")
		if err := os.Mkdir(stateDir, 0755); err != nil {
			t.Fatalf("failed to create dir: %v", err)
		}
		if err := EnsureStateDir(stateDir); err == nil {
			t.Fatal("expected EnsureStateDir to reject 0755 directory, got nil")
		}
	})

	t.Run("rejects insecure 0777 permissions", func(t *testing.T) {
		tempDir := t.TempDir()
		stateDir := filepath.Join(tempDir, "insecure-dir")
		if err := os.Mkdir(stateDir, 0777); err != nil {
			t.Fatalf("failed to create dir: %v", err)
		}
		if err := EnsureStateDir(stateDir); err == nil {
			t.Fatal("expected EnsureStateDir to reject 0777 directory, got nil")
		}
	})

	t.Run("rejects symlinked state directory", func(t *testing.T) {
		tempDir := t.TempDir()
		realDir := filepath.Join(tempDir, "real-dir")
		if err := os.Mkdir(realDir, 0700); err != nil {
			t.Fatalf("failed to create real dir: %v", err)
		}
		symlinkDir := filepath.Join(tempDir, "symlink-dir")
		if err := os.Symlink(realDir, symlinkDir); err != nil {
			t.Skipf("symlinks not supported on this filesystem: %v", err)
		}
		if err := EnsureStateDir(symlinkDir); err == nil {
			t.Fatal("expected EnsureStateDir to reject symlink directory, got nil")
		}
	})
}

func TestLoadOrGenerateKey_Security(t *testing.T) {
	t.Run("rejects existing key with 0644 permissions", func(t *testing.T) {
		tempDir := t.TempDir()
		stateDir := filepath.Join(tempDir, "state")
		if err := os.Mkdir(stateDir, 0700); err != nil {
			t.Fatalf("failed to create state dir: %v", err)
		}

		keyPath := filepath.Join(stateDir, IdentityKeyFileName)
		_, priv, err := GenerateKey(nil)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}
		pemBytes, err := EncodePrivateKeyPKCS8PEM(priv)
		if err != nil {
			t.Fatalf("failed to encode key: %v", err)
		}
		if err := os.WriteFile(keyPath, pemBytes, 0644); err != nil {
			t.Fatalf("failed to write key: %v", err)
		}

		_, _, err = LoadOrGenerateKey(stateDir, nil)
		if err == nil {
			t.Fatal("expected LoadOrGenerateKey to reject 0644 key file, got nil")
		}
	})

	t.Run("rejects existing key that is a symlink", func(t *testing.T) {
		tempDir := t.TempDir()
		stateDir := filepath.Join(tempDir, "state")
		if err := os.Mkdir(stateDir, 0700); err != nil {
			t.Fatalf("failed to create state dir: %v", err)
		}

		realKeyPath := filepath.Join(tempDir, "real.key")
		_, priv, err := GenerateKey(nil)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}
		pemBytes, err := EncodePrivateKeyPKCS8PEM(priv)
		if err != nil {
			t.Fatalf("failed to encode key: %v", err)
		}
		if err := os.WriteFile(realKeyPath, pemBytes, 0600); err != nil {
			t.Fatalf("failed to write key: %v", err)
		}

		symlinkKeyPath := filepath.Join(stateDir, IdentityKeyFileName)
		if err := os.Symlink(realKeyPath, symlinkKeyPath); err != nil {
			t.Skipf("symlinks not supported: %v", err)
		}

		_, _, err = LoadOrGenerateKey(stateDir, nil)
		if err == nil {
			t.Fatal("expected LoadOrGenerateKey to reject symlink key, got nil")
		}
	})
}

func TestLoadIdentityMetadata_Security(t *testing.T) {
	const validUUID = "018f0000-0000-7000-8000-000000000001"

	t.Run("valid metadata and valid matching key succeeds", func(t *testing.T) {
		tempDir := t.TempDir()
		stateDir := filepath.Join(tempDir, "state")
		pub, _, err := LoadOrGenerateKey(stateDir, nil)
		if err != nil {
			t.Fatalf("LoadOrGenerateKey failed: %v", err)
		}

		meta := &IdentityMetadata{
			Version:       1,
			AgentID:       validUUID,
			ControllerURL: "http://127.0.0.1:7447",
			PublicKey:     FormatPublicKeyBase64RawURL(pub),
		}
		if err := WriteIdentityMetadata(stateDir, meta); err != nil {
			t.Fatalf("WriteIdentityMetadata failed: %v", err)
		}

		loaded, err := LoadIdentityMetadata(stateDir)
		if err != nil {
			t.Fatalf("expected LoadIdentityMetadata to succeed, got %v", err)
		}
		if loaded.AgentID != validUUID {
			t.Fatalf("expected agent_id %s, got %s", validUUID, loaded.AgentID)
		}
	})

	t.Run("valid metadata with missing key fails", func(t *testing.T) {
		tempDir := t.TempDir()
		stateDir := filepath.Join(tempDir, "state")
		if err := os.Mkdir(stateDir, 0700); err != nil {
			t.Fatalf("failed to create dir: %v", err)
		}

		pub, _, err := GenerateKey(nil)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		meta := &IdentityMetadata{
			Version:       1,
			AgentID:       validUUID,
			ControllerURL: "http://127.0.0.1:7447",
			PublicKey:     FormatPublicKeyBase64RawURL(pub),
		}
		if err := WriteIdentityMetadata(stateDir, meta); err != nil {
			t.Fatalf("WriteIdentityMetadata failed: %v", err)
		}

		// Ensure identity.key does not exist
		keyPath := filepath.Join(stateDir, IdentityKeyFileName)
		_ = os.Remove(keyPath)

		_, err = LoadIdentityMetadata(stateDir)
		if err == nil {
			t.Fatal("expected LoadIdentityMetadata to fail when identity.key is missing, got nil")
		}
	})

	t.Run("valid metadata with malformed key fails", func(t *testing.T) {
		tempDir := t.TempDir()
		stateDir := filepath.Join(tempDir, "state")
		if err := os.Mkdir(stateDir, 0700); err != nil {
			t.Fatalf("failed to create dir: %v", err)
		}

		pub, _, err := GenerateKey(nil)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		meta := &IdentityMetadata{
			Version:       1,
			AgentID:       validUUID,
			ControllerURL: "http://127.0.0.1:7447",
			PublicKey:     FormatPublicKeyBase64RawURL(pub),
		}
		if err := WriteIdentityMetadata(stateDir, meta); err != nil {
			t.Fatalf("WriteIdentityMetadata failed: %v", err)
		}

		keyPath := filepath.Join(stateDir, IdentityKeyFileName)
		if err := os.WriteFile(keyPath, []byte("garbage not pkcs8"), 0600); err != nil {
			t.Fatalf("failed to write key: %v", err)
		}

		_, err = LoadIdentityMetadata(stateDir)
		if err == nil {
			t.Fatal("expected LoadIdentityMetadata to fail when identity.key is malformed, got nil")
		}
	})

	t.Run("valid metadata with insecure key mode fails", func(t *testing.T) {
		tempDir := t.TempDir()
		stateDir := filepath.Join(tempDir, "state")
		pub, priv, err := GenerateKey(nil)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
		pemBytes, err := EncodePrivateKeyPKCS8PEM(priv)
		if err != nil {
			t.Fatalf("EncodePrivateKeyPKCS8PEM failed: %v", err)
		}

		meta := &IdentityMetadata{
			Version:       1,
			AgentID:       validUUID,
			ControllerURL: "http://127.0.0.1:7447",
			PublicKey:     FormatPublicKeyBase64RawURL(pub),
		}
		if err := WriteIdentityMetadata(stateDir, meta); err != nil {
			t.Fatalf("WriteIdentityMetadata failed: %v", err)
		}

		keyPath := filepath.Join(stateDir, IdentityKeyFileName)
		if err := os.WriteFile(keyPath, pemBytes, 0644); err != nil {
			t.Fatalf("failed to write key: %v", err)
		}

		_, err = LoadIdentityMetadata(stateDir)
		if err == nil {
			t.Fatal("expected LoadIdentityMetadata to fail when identity.key has 0644 mode, got nil")
		}
	})

	t.Run("valid metadata with insecure state dir mode fails", func(t *testing.T) {
		tempDir := t.TempDir()
		stateDir := filepath.Join(tempDir, "state")
		pub, _, err := LoadOrGenerateKey(stateDir, nil)
		if err != nil {
			t.Fatalf("LoadOrGenerateKey failed: %v", err)
		}

		meta := &IdentityMetadata{
			Version:       1,
			AgentID:       validUUID,
			ControllerURL: "http://127.0.0.1:7447",
			PublicKey:     FormatPublicKeyBase64RawURL(pub),
		}
		if err := WriteIdentityMetadata(stateDir, meta); err != nil {
			t.Fatalf("WriteIdentityMetadata failed: %v", err)
		}

		// Change stateDir permissions to 0755
		if err := os.Chmod(stateDir, 0755); err != nil {
			t.Fatalf("failed to chmod stateDir: %v", err)
		}

		_, err = LoadIdentityMetadata(stateDir)
		if err == nil {
			t.Fatal("expected LoadIdentityMetadata to fail on insecure state dir, got nil")
		}
	})

	t.Run("valid metadata with key/public-key mismatch fails", func(t *testing.T) {
		tempDir := t.TempDir()
		stateDir := filepath.Join(tempDir, "state")
		pub1, _, err := LoadOrGenerateKey(stateDir, nil)
		if err != nil {
			t.Fatalf("LoadOrGenerateKey failed: %v", err)
		}

		pub2, _, err := GenerateKey(nil)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		_ = pub1
		meta := &IdentityMetadata{
			Version:       1,
			AgentID:       validUUID,
			ControllerURL: "http://127.0.0.1:7447",
			PublicKey:     FormatPublicKeyBase64RawURL(pub2), // mismatching public key!
		}
		if err := WriteIdentityMetadata(stateDir, meta); err != nil {
			t.Fatalf("WriteIdentityMetadata failed: %v", err)
		}

		_, err = LoadIdentityMetadata(stateDir)
		if err == nil {
			t.Fatal("expected consistency error on public key mismatch, got nil")
		}
		if !strings.Contains(err.Error(), "mismatch") {
			t.Fatalf("expected mismatch error, got: %v", err)
		}
	})

	t.Run("rejects insecure 0644 metadata permissions", func(t *testing.T) {
		tempDir := t.TempDir()
		stateDir := filepath.Join(tempDir, "state")
		_, _, err := LoadOrGenerateKey(stateDir, nil)
		if err != nil {
			t.Fatalf("LoadOrGenerateKey failed: %v", err)
		}
		metaPath := filepath.Join(stateDir, IdentityJSONFileName)
		if err := os.WriteFile(metaPath, []byte(`{"version":1}`), 0644); err != nil {
			t.Fatalf("failed to write meta: %v", err)
		}
		_, err = LoadIdentityMetadata(stateDir)
		if err == nil {
			t.Fatal("expected error on 0644 metadata, got nil")
		}
	})

	t.Run("rejects symlinked identity.json", func(t *testing.T) {
		tempDir := t.TempDir()
		stateDir := filepath.Join(tempDir, "state")
		_, _, err := LoadOrGenerateKey(stateDir, nil)
		if err != nil {
			t.Fatalf("LoadOrGenerateKey failed: %v", err)
		}
		realMetaPath := filepath.Join(tempDir, "real.json")
		if err := os.WriteFile(realMetaPath, []byte(`{"version":1}`), 0600); err != nil {
			t.Fatalf("failed to write meta: %v", err)
		}
		symlinkMetaPath := filepath.Join(stateDir, IdentityJSONFileName)
		if err := os.Symlink(realMetaPath, symlinkMetaPath); err != nil {
			t.Skipf("symlinks not supported: %v", err)
		}
		_, err = LoadIdentityMetadata(stateDir)
		if err == nil {
			t.Fatal("expected error on symlink identity.json, got nil")
		}
	})

	t.Run("rejects malformed json", func(t *testing.T) {
		tempDir := t.TempDir()
		stateDir := filepath.Join(tempDir, "state")
		_, _, err := LoadOrGenerateKey(stateDir, nil)
		if err != nil {
			t.Fatalf("LoadOrGenerateKey failed: %v", err)
		}
		metaPath := filepath.Join(stateDir, IdentityJSONFileName)
		if err := os.WriteFile(metaPath, []byte(`{not valid json}`), 0600); err != nil {
			t.Fatalf("failed to write meta: %v", err)
		}
		_, err = LoadIdentityMetadata(stateDir)
		if err == nil {
			t.Fatal("expected error on malformed json, got nil")
		}
	})

	t.Run("rejects trailing json data", func(t *testing.T) {
		tempDir := t.TempDir()
		stateDir := filepath.Join(tempDir, "state")
		_, _, err := LoadOrGenerateKey(stateDir, nil)
		if err != nil {
			t.Fatalf("LoadOrGenerateKey failed: %v", err)
		}
		metaPath := filepath.Join(stateDir, IdentityJSONFileName)
		content := `{"version":1,"agent_id":"` + validUUID + `","controller_url":"http://127.0.0.1:7447","public_key":"` + strings.Repeat("A", 43) + `"} extra`
		if err := os.WriteFile(metaPath, []byte(content), 0600); err != nil {
			t.Fatalf("failed to write meta: %v", err)
		}
		_, err = LoadIdentityMetadata(stateDir)
		if err == nil {
			t.Fatal("expected error on trailing json data, got nil")
		}
	})

	t.Run("rejects invalid UUIDv7 agent_id", func(t *testing.T) {
		tempDir := t.TempDir()
		stateDir := filepath.Join(tempDir, "state")
		_, _, err := LoadOrGenerateKey(stateDir, nil)
		if err != nil {
			t.Fatalf("LoadOrGenerateKey failed: %v", err)
		}
		metaPath := filepath.Join(stateDir, IdentityJSONFileName)
		// invalid version (version 4 instead of 7)
		content := `{"version":1,"agent_id":"018f0000-0000-4000-8000-000000000001","controller_url":"http://127.0.0.1:7447","public_key":"` + strings.Repeat("A", 43) + `"}`
		if err := os.WriteFile(metaPath, []byte(content), 0600); err != nil {
			t.Fatalf("failed to write meta: %v", err)
		}
		_, err = LoadIdentityMetadata(stateDir)
		if err == nil {
			t.Fatal("expected error on non-v7 UUID, got nil")
		}
	})

	t.Run("rejects non-loopback controller url", func(t *testing.T) {
		tempDir := t.TempDir()
		stateDir := filepath.Join(tempDir, "state")
		_, _, err := LoadOrGenerateKey(stateDir, nil)
		if err != nil {
			t.Fatalf("LoadOrGenerateKey failed: %v", err)
		}
		metaPath := filepath.Join(stateDir, IdentityJSONFileName)
		content := `{"version":1,"agent_id":"` + validUUID + `","controller_url":"http://192.168.1.1:7447","public_key":"` + strings.Repeat("A", 43) + `"}`
		if err := os.WriteFile(metaPath, []byte(content), 0600); err != nil {
			t.Fatalf("failed to write meta: %v", err)
		}
		_, err = LoadIdentityMetadata(stateDir)
		if err == nil {
			t.Fatal("expected error on non-loopback controller URL, got nil")
		}
	})
}

func TestValidateUUIDv7(t *testing.T) {
	valid := "018f0000-0000-7000-8000-000000000001"
	if err := ValidateUUIDv7(valid); err != nil {
		t.Fatalf("expected %s to be valid UUIDv7: %v", valid, err)
	}

	invalidCases := []struct {
		name string
		uuid string
	}{
		{"wrong length", "018f0000-0000-7000-8000-00000000000"},
		{"missing hyphen", "018f00000000-7000-8000-000000000001"},
		{"wrong version 4", "018f0000-0000-4000-8000-000000000001"},
		{"wrong variant", "018f0000-0000-7000-0000-000000000001"},
		{"non-hex chars", "018f0000-0000-7000-8000-00000000000z"},
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateUUIDv7(tc.uuid); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.uuid)
			}
		})
	}
}
