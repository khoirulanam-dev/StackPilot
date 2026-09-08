package privilege

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestClient_FailClosed(t *testing.T) {
	t.Run("runtime directory invalid - relative", func(t *testing.T) {
		_, err := NewClient(ClientConfig{RuntimeDir: "relative/dir"})
		if err == nil || !strings.Contains(err.Error(), "must be an absolute path") {
			t.Fatalf("expected error about absolute path, got: %v", err)
		}
	})

	t.Run("runtime directory invalid - empty", func(t *testing.T) {
		_, err := NewClient(ClientConfig{RuntimeDir: ""})
		if err == nil || !strings.Contains(err.Error(), "directory is required") {
			t.Fatalf("expected error about required directory, got: %v", err)
		}
	})

	t.Run("runtime directory is symlink", func(t *testing.T) {
		baseDir := t.TempDir()
		realDir := filepath.Join(baseDir, "real")
		_ = os.Mkdir(realDir, 0750)
		symDir := filepath.Join(baseDir, "sym")
		_ = os.Symlink(realDir, symDir)

		client, err := NewClient(ClientConfig{RuntimeDir: symDir})
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		err = client.Ping(t.Context())
		if err == nil {
			t.Fatal("expected Ping to fail on symlink runtime directory")
		}
		if !strings.Contains(err.Error(), "is a symlink") {
			t.Errorf("expected symlink error, got: %v", err)
		}
	})

	t.Run("runtime directory wrong owner", func(t *testing.T) {
		tmpDir := t.TempDir()
		deps := defaultClientDeps()
		deps.lstatFn = func(name string) (os.FileInfo, error) {
			if name == tmpDir {
				return &mockFileInfo{isDir: true, mode: 0750, uid: 1000, gid: 1000}, nil
			}
			return &mockFileInfo{isSocket: true, mode: 0660 | os.ModeSocket, uid: 0, gid: 1000}, nil
		}

		client, err := newClientWithDeps(ClientConfig{RuntimeDir: tmpDir}, deps)
		if err != nil {
			t.Fatalf("newClientWithDeps failed: %v", err)
		}

		err = client.Ping(t.Context())
		if err == nil {
			t.Fatal("expected Ping to fail on wrong runtime directory owner")
		}
		if !strings.Contains(err.Error(), "owner is not root") {
			t.Errorf("expected root owner error, got: %v", err)
		}
	})

	t.Run("runtime directory wrong mode", func(t *testing.T) {
		tmpDir := t.TempDir()
		deps := defaultClientDeps()
		deps.lstatFn = func(name string) (os.FileInfo, error) {
			if name == tmpDir {
				return &mockFileInfo{isDir: true, mode: 0777, uid: 0, gid: 1000}, nil
			}
			return &mockFileInfo{isSocket: true, mode: 0660 | os.ModeSocket, uid: 0, gid: 1000}, nil
		}

		client, err := newClientWithDeps(ClientConfig{RuntimeDir: tmpDir}, deps)
		if err != nil {
			t.Fatalf("newClientWithDeps failed: %v", err)
		}

		err = client.Ping(t.Context())
		if err == nil {
			t.Fatal("expected Ping to fail on wrong runtime directory mode")
		}
		if !strings.Contains(err.Error(), "must be exactly 0750") {
			t.Errorf("expected 0750 mode error, got: %v", err)
		}
	})

	t.Run("socket missing", func(t *testing.T) {
		tmpDir := t.TempDir()
		deps := defaultClientDeps()
		deps.lstatFn = func(name string) (os.FileInfo, error) {
			if name == tmpDir {
				return &mockFileInfo{isDir: true, mode: 0750, uid: 0, gid: 1000}, nil
			}
			return nil, os.ErrNotExist
		}

		client, err := newClientWithDeps(ClientConfig{RuntimeDir: tmpDir}, deps)
		if err != nil {
			t.Fatalf("newClientWithDeps failed: %v", err)
		}

		err = client.Ping(t.Context())
		if err == nil {
			t.Fatal("expected Ping to fail when socket is missing")
		}
		if !strings.Contains(err.Error(), "cannot access") {
			t.Errorf("expected access error, got: %v", err)
		}
	})

	t.Run("socket wrong file type - regular file", func(t *testing.T) {
		tmpDir := t.TempDir()
		deps := defaultClientDeps()
		deps.lstatFn = func(name string) (os.FileInfo, error) {
			if name == tmpDir {
				return &mockFileInfo{isDir: true, mode: 0750, uid: 0, gid: 1000}, nil
			}
			return &mockFileInfo{mode: 0660, isSocket: false, uid: 0, gid: 1000}, nil
		}

		client, err := newClientWithDeps(ClientConfig{RuntimeDir: tmpDir}, deps)
		if err != nil {
			t.Fatalf("newClientWithDeps failed: %v", err)
		}

		err = client.Ping(t.Context())
		if err == nil {
			t.Fatal("expected Ping to fail when path is not a socket")
		}
		if !strings.Contains(err.Error(), "not a Unix domain socket") {
			t.Errorf("expected 'not a Unix domain socket' error, got: %v", err)
		}
	})

	t.Run("socket wrong mode", func(t *testing.T) {
		tmpDir := t.TempDir()
		deps := defaultClientDeps()
		deps.lstatFn = func(name string) (os.FileInfo, error) {
			if name == tmpDir {
				return &mockFileInfo{isDir: true, mode: 0750, uid: 0, gid: 1000}, nil
			}
			return &mockFileInfo{mode: 0666 | os.ModeSocket, isSocket: true, uid: 0, gid: 1000}, nil
		}

		client, err := newClientWithDeps(ClientConfig{RuntimeDir: tmpDir}, deps)
		if err != nil {
			t.Fatalf("newClientWithDeps failed: %v", err)
		}

		err = client.Ping(t.Context())
		if err == nil {
			t.Fatal("expected Ping to fail on wrong socket permissions")
		}
		if !strings.Contains(err.Error(), "must be exactly 0660") {
			t.Errorf("expected mode 0660 error, got: %v", err)
		}
	})

	t.Run("socket wrong owner", func(t *testing.T) {
		tmpDir := t.TempDir()
		deps := defaultClientDeps()
		deps.lstatFn = func(name string) (os.FileInfo, error) {
			if name == tmpDir {
				return &mockFileInfo{isDir: true, mode: 0750, uid: 0, gid: 1000}, nil
			}
			return &mockFileInfo{mode: 0660 | os.ModeSocket, isSocket: true, uid: 1000, gid: 1000}, nil
		}

		client, err := newClientWithDeps(ClientConfig{RuntimeDir: tmpDir}, deps)
		if err != nil {
			t.Fatalf("newClientWithDeps failed: %v", err)
		}

		err = client.Ping(t.Context())
		if err == nil {
			t.Fatal("expected Ping to fail on non-root socket owner")
		}
		if !strings.Contains(err.Error(), "owner is not root") {
			t.Errorf("expected root socket error, got: %v", err)
		}
	})

	t.Run("socket GID mismatch", func(t *testing.T) {
		tmpDir := t.TempDir()
		deps := defaultClientDeps()
		deps.lstatFn = func(name string) (os.FileInfo, error) {
			if name == tmpDir {
				return &mockFileInfo{isDir: true, mode: 0750, uid: 0, gid: 1000}, nil
			}
			return &mockFileInfo{mode: 0660 | os.ModeSocket, isSocket: true, uid: 0, gid: 1001}, nil
		}

		client, err := newClientWithDeps(ClientConfig{RuntimeDir: tmpDir}, deps)
		if err != nil {
			t.Fatalf("newClientWithDeps failed: %v", err)
		}

		err = client.Ping(t.Context())
		if err == nil {
			t.Fatal("expected Ping to fail on socket GID mismatch")
		}
		if !strings.Contains(err.Error(), "helper socket group does not match runtime directory group") {
			t.Errorf("expected GID mismatch error, got: %v", err)
		}
	})

	t.Run("fake non-root helper rejected post-connect", func(t *testing.T) {
		tmpDir := t.TempDir()
		sockPath := filepath.Join(tmpDir, SocketFileName)

		ul, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: sockPath, Net: "unixpacket"})
		if err != nil {
			t.Fatalf("ListenUnix failed: %v", err)
		}
		defer ul.Close()

		acceptedCh := make(chan struct{})
		go func() {
			conn, err := ul.AcceptUnix()
			if err != nil {
				return
			}
			defer conn.Close()
			close(acceptedCh)
		}()

		deps := defaultClientDeps()
		deps.lstatFn = func(name string) (os.FileInfo, error) {
			if name == tmpDir {
				return &mockFileInfo{isDir: true, mode: 0750, uid: 0, gid: 1000}, nil
			}
			return &mockFileInfo{isSocket: true, mode: 0660 | os.ModeSocket, uid: 0, gid: 1000}, nil
		}
		deps.peerCredReader = func(conn *net.UnixConn) (uint32, error) {
			return 1000, nil // fake non-root UID
		}

		client, err := newClientWithDeps(ClientConfig{RuntimeDir: tmpDir}, deps)
		if err != nil {
			t.Fatalf("newClientWithDeps failed: %v", err)
		}

		err = client.Ping(t.Context())
		if err == nil {
			t.Fatal("expected Ping to fail when helper is non-root")
		}
		if !strings.Contains(err.Error(), "not root") {
			t.Errorf("expected 'not root' error, got: %v", err)
		}
		<-acceptedCh
	})

	t.Run("response request_id mismatch", func(t *testing.T) {
		tmpDir := t.TempDir()
		sockPath := filepath.Join(tmpDir, SocketFileName)

		ul, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: sockPath, Net: "unixpacket"})
		if err != nil {
			t.Fatalf("ListenUnix failed: %v", err)
		}
		defer ul.Close()

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := ul.AcceptUnix()
			if err != nil {
				return
			}
			defer conn.Close()
			buf := make([]byte, MaxPacketSize)
			_, _ = conn.Read(buf)

			differentID := uuid.NewString()
			respBytes, _ := EncodeResponse(Response{
				Version:   ProtocolVersion,
				RequestID: differentID,
				Status:    StatusOk,
			})
			_, _ = conn.Write(respBytes)
		}()

		deps := defaultClientDeps()
		deps.lstatFn = func(name string) (os.FileInfo, error) {
			if name == tmpDir {
				return &mockFileInfo{isDir: true, mode: 0750, uid: 0, gid: 1000}, nil
			}
			return &mockFileInfo{isSocket: true, mode: 0660 | os.ModeSocket, uid: 0, gid: 1000}, nil
		}
		deps.peerCredReader = func(conn *net.UnixConn) (uint32, error) {
			return 0, nil // root
		}

		client, err := newClientWithDeps(ClientConfig{RuntimeDir: tmpDir}, deps)
		if err != nil {
			t.Fatalf("newClientWithDeps failed: %v", err)
		}

		err = client.Ping(t.Context())
		if err == nil {
			t.Fatal("expected Ping to fail on request_id mismatch")
		}
		if !strings.Contains(err.Error(), "helper response request_id mismatch") {
			t.Errorf("expected mismatch error, got: %v", err)
		}
		wg.Wait()
	})

	t.Run("context cancellation before call", func(t *testing.T) {
		tmpDir := t.TempDir()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		client, err := NewClient(ClientConfig{RuntimeDir: tmpDir})
		if err != nil {
			t.Fatalf("NewClient failed: %v", err)
		}

		err = client.Ping(ctx)
		if err == nil {
			t.Fatal("expected Ping to fail on canceled context")
		}
	})

	t.Run("mid-flight context cancellation with barrier", func(t *testing.T) {
		tmpDir := t.TempDir()
		sockPath := filepath.Join(tmpDir, SocketFileName)

		ul, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: sockPath, Net: "unixpacket"})
		if err != nil {
			t.Fatalf("ListenUnix failed: %v", err)
		}
		defer ul.Close()

		requestReceivedCh := make(chan struct{})
		serverDoneCh := make(chan struct{})

		go func() {
			defer close(serverDoneCh)
			conn, err := ul.AcceptUnix()
			if err != nil {
				return
			}
			defer conn.Close()

			buf := make([]byte, MaxPacketSize)
			_, _ = conn.Read(buf)

			// Signal barrier that request was received by server
			close(requestReceivedCh)

			// Intentionally withhold response and wait until client disconnects/closes
			_, _ = conn.Read(buf)
		}()

		deps := defaultClientDeps()
		deps.lstatFn = func(name string) (os.FileInfo, error) {
			if name == tmpDir {
				return &mockFileInfo{isDir: true, mode: 0750, uid: 0, gid: 1000}, nil
			}
			return &mockFileInfo{isSocket: true, mode: 0660 | os.ModeSocket, uid: 0, gid: 1000}, nil
		}
		deps.peerCredReader = func(conn *net.UnixConn) (uint32, error) {
			return 0, nil
		}

		client, err := newClientWithDeps(ClientConfig{
			RuntimeDir: tmpDir,
			Timeout:    5 * time.Second,
		}, deps)
		if err != nil {
			t.Fatalf("newClientWithDeps failed: %v", err)
		}

		ctx, cancel := context.WithCancel(t.Context())

		pingErrCh := make(chan error, 1)
		go func() {
			pingErrCh <- client.Ping(ctx)
		}()

		<-requestReceivedCh
		cancel()

		pingErr := <-pingErrCh
		if pingErr == nil {
			t.Fatal("expected Ping to fail upon mid-flight cancellation")
		}
		if !errors.Is(pingErr, context.Canceled) && !strings.Contains(pingErr.Error(), "canceled") && !strings.Contains(pingErr.Error(), "closed") {
			t.Errorf("unexpected error on cancellation: %v", pingErr)
		}

		<-serverDoneCh
	})
}
