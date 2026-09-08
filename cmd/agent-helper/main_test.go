package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"stackpilot/internal/privilege"
)

func TestHelperCLI_Flags(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	tmpDir := t.TempDir()

	cases := []struct {
		name       string
		args       []string
		wantErr    string
		wantUID    uint32
		wantGID    uint32
		wantDir    string
		shouldPass bool
	}{
		{
			name:    "missing runtime-dir",
			args:    []string{"--allowed-uid", "1000", "--allowed-gid", "1000"},
			wantErr: "missing required flag --runtime-dir",
		},
		{
			name:    "missing allowed-uid",
			args:    []string{"--runtime-dir", tmpDir, "--allowed-gid", "1000"},
			wantErr: "missing required flag --allowed-uid",
		},
		{
			name:    "missing allowed-gid",
			args:    []string{"--runtime-dir", tmpDir, "--allowed-uid", "1000"},
			wantErr: "missing required flag --allowed-gid",
		},
		{
			name:    "allowed-uid 0 rejected",
			args:    []string{"--runtime-dir", tmpDir, "--allowed-uid", "0", "--allowed-gid", "1000"},
			wantErr: "allowed UID must be non-root",
		},
		{
			name:    "invalid numeric allowed-uid",
			args:    []string{"--runtime-dir", tmpDir, "--allowed-uid", "admin", "--allowed-gid", "1000"},
			wantErr: "invalid numeric --allowed-uid",
		},
		{
			name:    "invalid numeric allowed-gid",
			args:    []string{"--runtime-dir", tmpDir, "--allowed-uid", "1000", "--allowed-gid", "wheel"},
			wantErr: "invalid numeric --allowed-gid",
		},
		{
			name:    "relative runtime-dir rejected",
			args:    []string{"--runtime-dir", "rel/dir", "--allowed-uid", "1000", "--allowed-gid", "1000"},
			wantErr: "must be an absolute path",
		},
		{
			name:    "positional arguments rejected",
			args:    []string{"--runtime-dir", tmpDir, "--allowed-uid", "1000", "--allowed-gid", "1000", "unexpected"},
			wantErr: "unexpected positional arguments",
		},
		{
			name:       "valid arguments",
			args:       []string{"--runtime-dir", tmpDir, "--allowed-uid", "1005", "--allowed-gid", "1006"},
			wantUID:    1005,
			wantGID:    1006,
			wantDir:    tmpDir,
			shouldPass: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var recordedCfg privilege.ServerConfig
			var runnerCalled bool

			mockRunner := func(ctx context.Context, cfg privilege.ServerConfig) error {
				runnerCalled = true
				recordedCfg = cfg
				return nil
			}

			err := runWithRunner(tc.args, stdout, stderr, mockRunner)
			if tc.shouldPass {
				if err != nil {
					t.Fatalf("expected success, got error: %v", err)
				}
				if !runnerCalled {
					t.Fatal("expected runner to be called")
				}
				if recordedCfg.AllowedUID != tc.wantUID {
					t.Errorf("expected UID %d, got %d", tc.wantUID, recordedCfg.AllowedUID)
				}
				if recordedCfg.AllowedGID != tc.wantGID {
					t.Errorf("expected GID %d, got %d", tc.wantGID, recordedCfg.AllowedGID)
				}
				if recordedCfg.RuntimeDir != tc.wantDir {
					t.Errorf("expected RuntimeDir %q, got %q", tc.wantDir, recordedCfg.RuntimeDir)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
				}
			}
		})
	}
}

func TestHelperCLI_NonCanonicalPath(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	tmpDir := t.TempDir()
	nonCanonical := tmpDir + "/sub/../sub"

	err := runWithRunner([]string{
		"--runtime-dir", nonCanonical,
		"--allowed-uid", "1000",
		"--allowed-gid", "1000",
	}, stdout, stderr, func(ctx context.Context, cfg privilege.ServerConfig) error {
		return nil
	})

	if err == nil {
		t.Fatal("expected error for non-canonical runtime-dir")
	}
	if !strings.Contains(err.Error(), "must be a canonical clean path") {
		t.Errorf("expected clean path error, got: %v", err)
	}
}
