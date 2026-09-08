//go:build linux

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validZeroStatusContent = `
Name:	stackpilot-agent
State:	S (sleeping)
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000
`

func TestAgentEUIDValidation(t *testing.T) {
	if err := validateAgentEUID(0); err == nil {
		t.Fatal("expected root EUID 0 to be rejected")
	}
	if err := validateAgentEUID(1000); err != nil {
		t.Fatalf("expected non-root UID 1000 to be accepted, got: %v", err)
	}
	if err := validateAgentEUID(1001); err != nil {
		t.Fatalf("expected non-root UID 1001 to be accepted, got: %v", err)
	}
}

func TestParseCapabilities(t *testing.T) {
	t.Run("all zero capabilities accepted with non-zero CapBnd", func(t *testing.T) {
		caps, err := parseCapabilities(validZeroStatusContent)
		if err != nil {
			t.Fatalf("expected valid zero caps to pass, got: %v", err)
		}
		if caps.Inh != 0 || caps.Prm != 0 || caps.Eff != 0 || caps.Amb != 0 {
			t.Errorf("expected 0 for Inh/Prm/Eff/Amb, got %+v", caps)
		}
		if caps.Bnd == 0 {
			t.Error("expected non-zero CapBnd to be parsed")
		}
	})

	t.Run("all zero with zero CapBnd accepted", func(t *testing.T) {
		content := `
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000000000000000
CapAmb:	0000000000000000
`
		if _, err := parseCapabilities(content); err != nil {
			t.Fatalf("expected zero caps to pass, got: %v", err)
		}
	})

	t.Run("non-zero CapInh rejected", func(t *testing.T) {
		content := strings.Replace(validZeroStatusContent, "CapInh:\t0000000000000000", "CapInh:\t0000000000000001", 1)
		if _, err := parseCapabilities(content); err == nil {
			t.Fatal("expected error for non-zero CapInh")
		}
	})

	t.Run("non-zero CapPrm rejected", func(t *testing.T) {
		content := strings.Replace(validZeroStatusContent, "CapPrm:\t0000000000000000", "CapPrm:\t0000000000000020", 1)
		if _, err := parseCapabilities(content); err == nil {
			t.Fatal("expected error for non-zero CapPrm")
		}
	})

	t.Run("non-zero CapEff rejected", func(t *testing.T) {
		content := strings.Replace(validZeroStatusContent, "CapEff:\t0000000000000000", "CapEff:\t0000000000000004", 1)
		if _, err := parseCapabilities(content); err == nil {
			t.Fatal("expected error for non-zero CapEff")
		}
	})

	t.Run("non-zero CapAmb rejected", func(t *testing.T) {
		content := strings.Replace(validZeroStatusContent, "CapAmb:\t0000000000000000", "CapAmb:\t0000000000000002", 1)
		if _, err := parseCapabilities(content); err == nil {
			t.Fatal("expected error for non-zero CapAmb")
		}
	})

	t.Run("missing CapEff rejected", func(t *testing.T) {
		content := `
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000
`
		if _, err := parseCapabilities(content); err == nil {
			t.Fatal("expected error for missing CapEff field")
		}
	})

	t.Run("malformed CapPrm rejected", func(t *testing.T) {
		content := strings.Replace(validZeroStatusContent, "CapPrm:\t0000000000000000", "CapPrm:\tNOT_HEX_CHARS", 1)
		if _, err := parseCapabilities(content); err == nil {
			t.Fatal("expected error for malformed CapPrm field")
		}
	})
}

func TestCheckAllThreadsCapabilities(t *testing.T) {
	t.Run("multi-thread all zero passes", func(t *testing.T) {
		taskDir := t.TempDir()
		for _, tid := range []string{"1001", "1002", "1003"} {
			threadDir := filepath.Join(taskDir, tid)
			if err := os.Mkdir(threadDir, 0755); err != nil {
				t.Fatalf("failed to create thread dir: %v", err)
			}
			if err := os.WriteFile(filepath.Join(threadDir, "status"), []byte(validZeroStatusContent), 0644); err != nil {
				t.Fatalf("failed to write thread status: %v", err)
			}
		}

		if err := checkAllThreadsCapabilities(taskDir); err != nil {
			t.Fatalf("expected success for multi-thread all zero, got: %v", err)
		}
	})

	t.Run("one thread with non-zero capability fails closed", func(t *testing.T) {
		taskDir := t.TempDir()
		// Thread 1: ok
		dir1 := filepath.Join(taskDir, "2001")
		_ = os.Mkdir(dir1, 0755)
		_ = os.WriteFile(filepath.Join(dir1, "status"), []byte(validZeroStatusContent), 0644)

		// Thread 2: non-zero effective capability
		badStatus := strings.Replace(validZeroStatusContent, "CapEff:\t0000000000000000", "CapEff:\t0000000000000002", 1)
		dir2 := filepath.Join(taskDir, "2002")
		_ = os.Mkdir(dir2, 0755)
		_ = os.WriteFile(filepath.Join(dir2, "status"), []byte(badStatus), 0644)

		err := checkAllThreadsCapabilities(taskDir)
		if err == nil {
			t.Fatal("expected failure when any thread retains capabilities")
		}
		if !strings.Contains(err.Error(), "capability check failed on thread 2002") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("vanished thread is skipped safely", func(t *testing.T) {
		taskDir := t.TempDir()
		// Thread 1: valid
		dir1 := filepath.Join(taskDir, "3001")
		_ = os.Mkdir(dir1, 0755)
		_ = os.WriteFile(filepath.Join(dir1, "status"), []byte(validZeroStatusContent), 0644)

		// Thread 2: directory exists but status file is missing (simulating race where thread vanished)
		dir2 := filepath.Join(taskDir, "3002")
		_ = os.Mkdir(dir2, 0755)

		if err := checkAllThreadsCapabilities(taskDir); err != nil {
			t.Fatalf("expected vanished thread to be ignored, got: %v", err)
		}
	})

	t.Run("empty task directory fails closed", func(t *testing.T) {
		taskDir := t.TempDir()
		if err := checkAllThreadsCapabilities(taskDir); err == nil {
			t.Fatal("expected failure on empty task directory")
		}
	})

	t.Run("nonexistent task directory fails closed", func(t *testing.T) {
		if err := checkAllThreadsCapabilities("/nonexistent/task/path"); err == nil {
			t.Fatal("expected failure on nonexistent task directory")
		}
	})
}
