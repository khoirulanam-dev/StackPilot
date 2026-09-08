package privilege

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestSocketLifecycle_UnlinkOnCloseDisabled(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, SocketFileName)

	deps := defaultServerDeps()
	listener, err := deps.listenUnixFn("unixpacket", sockPath)
	if err != nil {
		t.Fatalf("listenUnixFn failed: %v", err)
	}

	if _, err := os.Stat(sockPath); err != nil {
		t.Fatalf("socket file should exist after listen: %v", err)
	}

	if err := listener.Close(); err != nil {
		t.Fatalf("failed to close listener: %v", err)
	}

	if _, err := os.Stat(sockPath); err != nil {
		t.Errorf("socket file was deleted by listener close (SetUnlinkOnClose(false) was bypassed): %v", err)
	}
}

// Scenario A: Normal shutdown removes created socket and Serve returns nil
func TestSocketLifecycle_NormalShutdownRemovesSocket(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, SocketFileName)

	cfg := ServerConfig{
		RuntimeDir: tmpDir,
		AllowedUID: 1000,
		AllowedGID: 1000,
	}

	readyCh := make(chan struct{})
	deps := testServerDeps(1000, 1000)
	deps.onReady = func() {
		close(readyCh)
	}

	srv, err := newServerWithDeps(cfg, deps)
	if err != nil {
		t.Fatalf("newServerWithDeps failed: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- srv.Serve(ctx)
	}()

	<-readyCh

	cancel()
	if err := <-serverErrCh; err != nil {
		t.Fatalf("Serve failed: %v", err)
	}

	if _, err := os.Lstat(sockPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected socket %s to be unlinked on shutdown, err: %v", sockPath, err)
	}
}

// Scenario B: Replacement socket/object is not removed and Serve returns cleanup-integrity error
func TestSocketLifecycle_ReplacementSocketNotRemoved(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := ServerConfig{
		RuntimeDir: tmpDir,
		AllowedUID: 1000,
		AllowedGID: 1000,
	}

	removed := false
	sameFileCheckDone := false

	readyCh := make(chan struct{})
	deps := testServerDeps(1000, 1000)
	deps.onReady = func() {
		close(readyCh)
	}
	deps.removeFn = func(name string) error {
		removed = true
		return nil
	}
	deps.sameFileFn = func(fi1, fi2 os.FileInfo) bool {
		sameFileCheckDone = true
		return false
	}

	srv, err := newServerWithDeps(cfg, deps)
	if err != nil {
		t.Fatalf("newServerWithDeps failed: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- srv.Serve(ctx)
	}()

	<-readyCh

	cancel()
	err = <-serverErrCh

	if !sameFileCheckDone {
		t.Fatal("expected sameFileFn to be called during socket cleanup")
	}
	if removed {
		t.Fatal("replacement socket was erroneously unlinked during cleanup")
	}
	if err == nil || !strings.Contains(err.Error(), "socket file changed or was replaced before cleanup") {
		t.Fatalf("expected cleanup-integrity error for replacement socket, got: %v", err)
	}
}

// Scenario C: Runtime directory wrong owner before cleanup fails closed and returns cleanup error
func TestSocketLifecycle_RuntimeDirWrongOwnerBeforeCleanup(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := ServerConfig{
		RuntimeDir: tmpDir,
		AllowedUID: 1000,
		AllowedGID: 1000,
	}

	removed := false
	var inCleanup atomic.Bool
	readyCh := make(chan struct{})
	deps := testServerDeps(1000, 1000)
	deps.onReady = func() {
		close(readyCh)
	}
	deps.removeFn = func(name string) error {
		removed = true
		return nil
	}
	origLstat := deps.lstatFn
	deps.lstatFn = func(name string) (os.FileInfo, error) {
		if inCleanup.Load() && name == cfg.RuntimeDir {
			return &mockFileInfo{
				name:  filepath.Base(cfg.RuntimeDir),
				isDir: true,
				mode:  0750,
				uid:   1000, // Non-root owner during cleanup
				gid:   1000,
			}, nil
		}
		return origLstat(name)
	}

	srv, err := newServerWithDeps(cfg, deps)
	if err != nil {
		t.Fatalf("newServerWithDeps failed: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- srv.Serve(ctx)
	}()

	<-readyCh

	inCleanup.Store(true)
	cancel()
	err = <-serverErrCh

	if removed {
		t.Fatal("socket was unlinked despite invalid runtime directory ownership")
	}
	if err == nil || !strings.Contains(err.Error(), "runtime directory invariant changed before cleanup") {
		t.Fatalf("expected cleanup error, got: %v", err)
	}
}

// Scenario D: Runtime directory wrong GID before cleanup fails closed
func TestSocketLifecycle_RuntimeDirWrongGIDBeforeCleanup(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := ServerConfig{
		RuntimeDir: tmpDir,
		AllowedUID: 1000,
		AllowedGID: 1000,
	}

	removed := false
	var inCleanup atomic.Bool
	readyCh := make(chan struct{})
	deps := testServerDeps(1000, 1000)
	deps.onReady = func() {
		close(readyCh)
	}
	deps.removeFn = func(name string) error {
		removed = true
		return nil
	}
	origLstat := deps.lstatFn
	deps.lstatFn = func(name string) (os.FileInfo, error) {
		if inCleanup.Load() && name == cfg.RuntimeDir {
			return &mockFileInfo{
				name:  filepath.Base(cfg.RuntimeDir),
				isDir: true,
				mode:  0750,
				uid:   0,
				gid:   9999, // Wrong GID during cleanup
			}, nil
		}
		return origLstat(name)
	}

	srv, err := newServerWithDeps(cfg, deps)
	if err != nil {
		t.Fatalf("newServerWithDeps failed: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- srv.Serve(ctx)
	}()

	<-readyCh

	inCleanup.Store(true)
	cancel()
	err = <-serverErrCh

	if removed {
		t.Fatal("socket was unlinked despite invalid runtime directory group")
	}
	if err == nil || !strings.Contains(err.Error(), "runtime directory invariant changed before cleanup") {
		t.Fatalf("expected cleanup error, got: %v", err)
	}
}

// Scenario E: Runtime directory wrong mode before cleanup fails closed
func TestSocketLifecycle_RuntimeDirWrongModeBeforeCleanup(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := ServerConfig{
		RuntimeDir: tmpDir,
		AllowedUID: 1000,
		AllowedGID: 1000,
	}

	removed := false
	var inCleanup atomic.Bool
	readyCh := make(chan struct{})
	deps := testServerDeps(1000, 1000)
	deps.onReady = func() {
		close(readyCh)
	}
	deps.removeFn = func(name string) error {
		removed = true
		return nil
	}
	origLstat := deps.lstatFn
	deps.lstatFn = func(name string) (os.FileInfo, error) {
		if inCleanup.Load() && name == cfg.RuntimeDir {
			return &mockFileInfo{
				name:  filepath.Base(cfg.RuntimeDir),
				isDir: true,
				mode:  0777, // Wrong mode during cleanup
				uid:   0,
				gid:   1000,
			}, nil
		}
		return origLstat(name)
	}

	srv, err := newServerWithDeps(cfg, deps)
	if err != nil {
		t.Fatalf("newServerWithDeps failed: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- srv.Serve(ctx)
	}()

	<-readyCh

	inCleanup.Store(true)
	cancel()
	err = <-serverErrCh

	if removed {
		t.Fatal("socket was unlinked despite invalid runtime directory mode")
	}
	if err == nil || !strings.Contains(err.Error(), "runtime directory invariant changed before cleanup") {
		t.Fatalf("expected cleanup error, got: %v", err)
	}
}

// Scenario F: Runtime directory replaced by symlink before cleanup fails closed
func TestSocketLifecycle_RuntimeDirReplacedBySymlink(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := ServerConfig{
		RuntimeDir: tmpDir,
		AllowedUID: 1000,
		AllowedGID: 1000,
	}

	removed := false
	var inCleanup atomic.Bool
	readyCh := make(chan struct{})
	deps := testServerDeps(1000, 1000)
	deps.onReady = func() {
		close(readyCh)
	}
	deps.removeFn = func(name string) error {
		removed = true
		return nil
	}
	origLstat := deps.lstatFn
	deps.lstatFn = func(name string) (os.FileInfo, error) {
		if inCleanup.Load() && name == cfg.RuntimeDir {
			return &mockFileInfo{
				name:  filepath.Base(cfg.RuntimeDir),
				isDir: false,
				mode:  os.ModeSymlink | 0750, // Replaced with symlink during cleanup
				uid:   0,
				gid:   1000,
			}, nil
		}
		return origLstat(name)
	}

	srv, err := newServerWithDeps(cfg, deps)
	if err != nil {
		t.Fatalf("newServerWithDeps failed: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- srv.Serve(ctx)
	}()

	<-readyCh

	inCleanup.Store(true)
	cancel()
	err = <-serverErrCh

	if removed {
		t.Fatal("socket was unlinked despite runtime directory being a symlink")
	}
	if err == nil || !strings.Contains(err.Error(), "runtime directory invariant changed before cleanup") {
		t.Fatalf("expected cleanup error, got: %v", err)
	}
}

// Scenario G: removeFn failure returns cleanup error
func TestSocketLifecycle_RemoveFnFailure(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := ServerConfig{
		RuntimeDir: tmpDir,
		AllowedUID: 1000,
		AllowedGID: 1000,
	}

	readyCh := make(chan struct{})
	deps := testServerDeps(1000, 1000)
	deps.onReady = func() {
		close(readyCh)
	}
	deps.removeFn = func(name string) error {
		return errors.New("simulated unlink permission denied")
	}

	srv, err := newServerWithDeps(cfg, deps)
	if err != nil {
		t.Fatalf("newServerWithDeps failed: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- srv.Serve(ctx)
	}()

	<-readyCh

	cancel()
	err = <-serverErrCh

	if err == nil || !strings.Contains(err.Error(), "simulated unlink permission denied") {
		t.Fatalf("expected remove failure error, got: %v", err)
	}
}

// Scenario H: Startup chown/chmod/hardening error after bind attempts cleanup and preserves both errors if cleanup fails
func TestSocketLifecycle_StartupErrorsCleanUpSocket(t *testing.T) {
	cases := []struct {
		name      string
		setupDeps func(*serverDeps)
		wantErr   string
	}{
		{
			name: "chown failure after bind cleans socket",
			setupDeps: func(d *serverDeps) {
				d.chownFn = func(path string, uid, gid int) error {
					if filepath.Base(path) == SocketFileName {
						return errors.New("simulated chown failure")
					}
					return nil
				}
			},
			wantErr: "simulated chown failure",
		},
		{
			name: "chmod failure after bind cleans socket",
			setupDeps: func(d *serverDeps) {
				d.chmodFn = func(path string, mode os.FileMode) error {
					if filepath.Base(path) == SocketFileName {
						return errors.New("simulated chmod failure")
					}
					return nil
				}
			},
			wantErr: "simulated chmod failure",
		},
		{
			name: "hardening failure after bind cleans socket",
			setupDeps: func(d *serverDeps) {
				d.hardenFn = func() error {
					return errors.New("simulated hardening failure")
				}
			},
			wantErr: "simulated hardening failure",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			sockPath := filepath.Join(tmpDir, SocketFileName)

			cfg := ServerConfig{
				RuntimeDir: tmpDir,
				AllowedUID: 1000,
				AllowedGID: 1000,
			}

			deps := testServerDeps(1000, 1000)
			tc.setupDeps(&deps)

			srv, err := newServerWithDeps(cfg, deps)
			if err != nil {
				t.Fatalf("newServerWithDeps failed: %v", err)
			}

			err = srv.Serve(t.Context())
			if err == nil {
				t.Fatal("expected Serve to fail on startup error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
			}

			if _, statErr := os.Lstat(sockPath); !errors.Is(statErr, os.ErrNotExist) {
				t.Errorf("expected socket to be cleaned up after startup error, found: %v", statErr)
			}
		})
	}

	t.Run("startup error and cleanup error are both preserved", func(t *testing.T) {
		tmpDir := t.TempDir()

		cfg := ServerConfig{
			RuntimeDir: tmpDir,
			AllowedUID: 1000,
			AllowedGID: 1000,
		}

		deps := testServerDeps(1000, 1000)
		deps.hardenFn = func() error {
			return errors.New("primary hardening error")
		}
		deps.removeFn = func(string) error {
			return errors.New("secondary cleanup error")
		}

		srv, err := newServerWithDeps(cfg, deps)
		if err != nil {
			t.Fatalf("newServerWithDeps failed: %v", err)
		}

		err = srv.Serve(t.Context())
		if err == nil {
			t.Fatal("expected error on startup failure")
		}
		if !strings.Contains(err.Error(), "primary hardening error") {
			t.Errorf("error %q does not contain primary error", err.Error())
		}
		if !strings.Contains(err.Error(), "secondary cleanup error") {
			t.Errorf("error %q does not contain secondary cleanup error", err.Error())
		}
	})
}

// Scenario I: Unexpected Accept error exits without spinning and performs cleanup
func TestSocketLifecycle_UnexpectedAcceptError_ExitsAndCleansUp(t *testing.T) {
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
	acceptErr := errors.New("fatal simulated accept network failure")
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
	if !strings.Contains(err.Error(), "fatal simulated accept network failure") {
		t.Errorf("unexpected error: %v", err)
	}
	if !unlinked {
		t.Error("expected socket cleanup to run after unexpected accept error")
	}
}
