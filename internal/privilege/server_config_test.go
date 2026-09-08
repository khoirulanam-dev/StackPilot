package privilege

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServerConfig_Validation(t *testing.T) {
	tmpDir := t.TempDir()

	cases := []struct {
		name    string
		cfg     ServerConfig
		wantErr string
	}{
		{
			name: "missing runtime directory",
			cfg: ServerConfig{
				RuntimeDir: "",
				AllowedUID: 1000,
				AllowedGID: 1000,
			},
			wantErr: "runtime directory is required",
		},
		{
			name: "relative runtime directory",
			cfg: ServerConfig{
				RuntimeDir: "relative/path",
				AllowedUID: 1000,
				AllowedGID: 1000,
			},
			wantErr: "must be an absolute path",
		},
		{
			name: "non-canonical runtime directory",
			cfg: ServerConfig{
				RuntimeDir: tmpDir + "/sub/../sub",
				AllowedUID: 1000,
				AllowedGID: 1000,
			},
			wantErr: "must be a canonical clean path",
		},
		{
			name: "path containing NUL byte",
			cfg: ServerConfig{
				RuntimeDir: tmpDir + "\x00bad",
				AllowedUID: 1000,
				AllowedGID: 1000,
			},
			wantErr: "cannot contain NUL bytes",
		},
		{
			name: "allowed UID 0 rejected",
			cfg: ServerConfig{
				RuntimeDir: tmpDir,
				AllowedUID: 0,
				AllowedGID: 1000,
			},
			wantErr: "allowed UID must be non-root",
		},
		{
			name: "socket path exceeding safe length",
			cfg: ServerConfig{
				RuntimeDir: "/" + strings.Repeat("a", MaxSocketPathLen),
				AllowedUID: 1000,
				AllowedGID: 1000,
			},
			wantErr: "socket path exceeds maximum safe Unix domain path length",
		},
		{
			name: "valid configuration",
			cfg: ServerConfig{
				RuntimeDir: tmpDir,
				AllowedUID: 1001,
				AllowedGID: 1001,
			},
			wantErr: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateServerConfig(tc.cfg)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid config, got error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestServer_SymlinkRejection(t *testing.T) {
	baseDir := t.TempDir()
	realDir := filepath.Join(baseDir, "real_dir")
	if err := os.Mkdir(realDir, 0750); err != nil {
		t.Fatalf("failed to create real dir: %v", err)
	}

	symlinkDir := filepath.Join(baseDir, "symlink_dir")
	if err := os.Symlink(realDir, symlinkDir); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	cfg := ServerConfig{
		RuntimeDir: symlinkDir,
		AllowedUID: 1000,
		AllowedGID: 1000,
	}

	deps := defaultServerDeps()
	deps.getEUIDFn = func() int { return 0 }
	deps.chownFn = func(string, int, int) error { return nil }
	deps.chmodFn = func(string, os.FileMode) error { return nil }
	deps.hardenFn = func() error { return nil }

	srv, err := newServerWithDeps(cfg, deps)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	err = srv.Serve(t.Context())
	if err == nil {
		t.Fatal("expected Serve to fail on symlink runtime directory")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error %q does not contain 'symlink'", err.Error())
	}
}

func TestServer_ExistingSocketRejection(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, SocketFileName)

	if err := os.WriteFile(sockPath, []byte("existing"), 0600); err != nil {
		t.Fatalf("failed to create existing socket file: %v", err)
	}

	cfg := ServerConfig{
		RuntimeDir: tmpDir,
		AllowedUID: 1000,
		AllowedGID: 1000,
	}

	deps := testServerDeps(1000, 1000)

	srv, err := newServerWithDeps(cfg, deps)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	err = srv.Serve(t.Context())
	if err == nil {
		t.Fatal("expected Serve to fail when socket already exists")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error %q does not contain 'already exists'", err.Error())
	}

	if _, err := os.Stat(sockPath); err != nil {
		t.Errorf("existing socket file was unlinked or modified: %v", err)
	}
}

func TestServer_NonRootEUIDRejection(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := ServerConfig{
		RuntimeDir: tmpDir,
		AllowedUID: 1000,
		AllowedGID: 1000,
	}

	deps := defaultServerDeps()
	deps.getEUIDFn = func() int { return 1000 }
	deps.chownFn = func(string, int, int) error { return nil }
	deps.chmodFn = func(string, os.FileMode) error { return nil }
	deps.hardenFn = func() error { return nil }

	srv, err := newServerWithDeps(cfg, deps)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	err = srv.Serve(t.Context())
	if err == nil {
		t.Fatal("expected Serve to fail when running as non-root")
	}
	if !strings.Contains(err.Error(), "must be run as root") {
		t.Errorf("error %q does not contain 'must be run as root'", err.Error())
	}
}

func TestServer_EUIDSampledAtServeStart(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := ServerConfig{
		RuntimeDir: tmpDir,
		AllowedUID: 1000,
		AllowedGID: 1000,
	}

	currentEUID := 0
	deps := defaultServerDeps()
	deps.getEUIDFn = func() int { return currentEUID }
	deps.chownFn = func(string, int, int) error { return nil }
	deps.chmodFn = func(string, os.FileMode) error { return nil }
	deps.hardenFn = func() error { return nil }

	srv, err := newServerWithDeps(cfg, deps)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Change EUID to non-root after construction but before Serve starts
	currentEUID = 1000

	err = srv.Serve(t.Context())
	if err == nil {
		t.Fatal("expected Serve to fail when EUID becomes non-root before Serve begins")
	}
	if !strings.Contains(err.Error(), "must be run as root") {
		t.Errorf("error %q does not contain 'must be run as root'", err.Error())
	}
}

func TestServer_SetDeadline_FailClosed(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := ServerConfig{
		RuntimeDir: tmpDir,
		AllowedUID: 1000,
		AllowedGID: 1000,
	}

	peerCredQueried := false
	deps := defaultServerDeps()
	deps.getEUIDFn = func() int { return 0 }
	deps.setDeadlineFn = func(c *net.UnixConn, tm time.Time) error {
		return errors.New("simulated setDeadline error")
	}
	deps.peerCredReader = func(conn *net.UnixConn) (uint32, error) {
		peerCredQueried = true
		return 1000, nil
	}

	srv, err := newServerWithDeps(cfg, deps)
	if err != nil {
		t.Fatalf("newServerWithDeps failed: %v", err)
	}

	mockConn := newMockUnixConn()
	reqData, _ := EncodeRequest(Request{
		Version:   ProtocolVersion,
		RequestID: "00000000-0000-4000-8000-000000000001",
		Operation: OpBoundaryPing,
	})
	mockConn.readBuf = reqData

	// Handle connection with failing SetDeadline
	srv.handleConn(t.Context(), (*net.UnixConn)(nil))

	if peerCredQueried {
		t.Fatal("expected handler to fail closed before reading peer credentials upon SetDeadline error")
	}
	if len(mockConn.writeBuf) > 0 {
		t.Fatal("expected no response to be written when SetDeadline fails")
	}
}

func TestServer_ModeValidation(t *testing.T) {
	tmpDir := t.TempDir()
	badModeDir := filepath.Join(tmpDir, "bad_mode")
	if err := os.Mkdir(badModeDir, 0777); err != nil {
		t.Fatalf("Mkdir failed: %v", err)
	}
	if err := os.Chmod(badModeDir, 0777); err != nil {
		t.Fatalf("Chmod failed: %v", err)
	}

	cfg := ServerConfig{
		RuntimeDir: badModeDir,
		AllowedUID: 1000,
		AllowedGID: 1000,
	}

	deps := defaultServerDeps()
	deps.getEUIDFn = func() int { return 0 }
	deps.chownFn = func(string, int, int) error { return nil }
	deps.hardenFn = func() error { return nil }

	srv, err := newServerWithDeps(cfg, deps)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	err = srv.Serve(t.Context())
	if err == nil {
		t.Fatal("expected Serve to fail when runtime directory permissions are not 0750")
	}
	if !strings.Contains(err.Error(), "must be exactly 0750") {
		t.Errorf("error %q does not contain 'must be exactly 0750'", err.Error())
	}
}

func TestServer_AcceptError_FailClosed(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := ServerConfig{
		RuntimeDir: tmpDir,
		AllowedUID: 1000,
		AllowedGID: 1000,
	}

	deps := defaultServerDeps()
	deps.getEUIDFn = func() int { return 0 }
	deps.chownFn = func(string, int, int) error { return nil }
	deps.chmodFn = func(string, os.FileMode) error { return nil }
	deps.hardenFn = func() error { return nil }

	listened := false
	acceptErr := errors.New("simulated fatal accept network error")
	mockL := &mockFailingListener{err: acceptErr}
	deps.listenUnixFn = func(network, address string) (net.Listener, error) {
		listened = true
		return mockL, nil
	}
	deps.lstatFn = func(name string) (os.FileInfo, error) {
		if name == cfg.RuntimeDir {
			return &mockFileInfo{isDir: true, mode: 0750, uid: 0, gid: 1000, ino: 10, dev: 1}, nil
		}
		if name == filepath.Join(cfg.RuntimeDir, SocketFileName) {
			if listened {
				return &mockFileInfo{isSocket: true, mode: 0660 | os.ModeSocket, uid: 0, gid: 1000, ino: 20, dev: 1}, nil
			}
			return nil, os.ErrNotExist
		}
		return nil, os.ErrNotExist
	}
	deps.sameFileFn = func(fi1, fi2 os.FileInfo) bool {
		return true
	}
	unlinked := false
	deps.removeFn = func(name string) error {
		unlinked = true
		return nil
	}

	srv, err := newServerWithDeps(cfg, deps)
	if err != nil {
		t.Fatalf("newServerWithDeps failed: %v", err)
	}

	err = srv.Serve(t.Context())
	if err == nil {
		t.Fatal("expected Serve to return error on unexpected Accept failure")
	}
	if !strings.Contains(err.Error(), "accept error") {
		t.Errorf("unexpected error: %v", err)
	}
	if !unlinked {
		t.Error("expected socket cleanup to run after accept error")
	}
}

type mockFailingListener struct {
	err error
}

func (m *mockFailingListener) Accept() (net.Conn, error) {
	return nil, m.err
}

func (m *mockFailingListener) Close() error {
	return nil
}

func (m *mockFailingListener) Addr() net.Addr {
	return &net.UnixAddr{Name: "mock.sock", Net: "unixpacket"}
}
