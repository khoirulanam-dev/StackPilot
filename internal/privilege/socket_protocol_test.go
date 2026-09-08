package privilege

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSocketProtocol_Scenarios(t *testing.T) {
	const allowedUID uint32 = 1000

	setupServer := func(t *testing.T, timeout time.Duration) (*Server, string, func()) {
		tmpDir := t.TempDir()
		sockPath := filepath.Join(tmpDir, SocketFileName)

		cfg := ServerConfig{
			RuntimeDir: tmpDir,
			AllowedUID: allowedUID,
			AllowedGID: 1000,
			Timeout:    timeout,
		}

		readyCh := make(chan struct{})
		deps := testServerDeps(allowedUID, 1000)
		deps.onReady = func() {
			close(readyCh)
		}

		srv, err := newServerWithDeps(cfg, deps)
		if err != nil {
			t.Fatalf("newServerWithDeps failed: %v", err)
		}

		ctx, cancel := context.WithCancel(t.Context())
		serverDone := make(chan struct{})
		go func() {
			_ = srv.Serve(ctx)
			close(serverDone)
		}()

		<-readyCh

		cleanup := func() {
			cancel()
			<-serverDone
		}

		return srv, sockPath, cleanup
	}

	t.Run("valid boundary.ping returns ok", func(t *testing.T) {
		_, sockPath, cleanup := setupServer(t, 2*time.Second)
		defer cleanup()

		conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: sockPath, Net: "unixpacket"})
		if err != nil {
			t.Fatalf("DialUnix failed: %v", err)
		}
		defer conn.Close()

		reqID := uuid.NewString()
		reqData, err := EncodeRequest(Request{
			Version:   ProtocolVersion,
			RequestID: reqID,
			Operation: OpBoundaryPing,
		})
		if err != nil {
			t.Fatalf("EncodeRequest failed: %v", err)
		}

		if _, err := conn.Write(reqData); err != nil {
			t.Fatalf("Write failed: %v", err)
		}

		buf := make([]byte, MaxPacketSize)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}

		resp, err := DecodeResponse(buf[:n])
		if err != nil {
			t.Fatalf("DecodeResponse failed: %v", err)
		}
		if resp.RequestID != reqID {
			t.Errorf("expected request ID %q, got %q", reqID, resp.RequestID)
		}
		if resp.Status != StatusOk {
			t.Errorf("expected status 'ok', got %q", resp.Status)
		}
	})

	t.Run("wrong operation rejected without response", func(t *testing.T) {
		_, sockPath, cleanup := setupServer(t, 2*time.Second)
		defer cleanup()

		conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: sockPath, Net: "unixpacket"})
		if err != nil {
			t.Fatalf("DialUnix failed: %v", err)
		}
		defer conn.Close()

		req := `{"version":1,"request_id":"` + uuid.NewString() + `","operation":"boundary.reboot"}`
		_, _ = conn.Write([]byte(req))

		buf := make([]byte, MaxPacketSize)
		n, err := conn.Read(buf)
		if err == nil && n > 0 {
			t.Fatalf("expected server to reject and close connection, got response: %s", string(buf[:n]))
		}
	})

	t.Run("oversize packet rejected without response", func(t *testing.T) {
		_, sockPath, cleanup := setupServer(t, 2*time.Second)
		defer cleanup()

		conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: sockPath, Net: "unixpacket"})
		if err != nil {
			t.Fatalf("DialUnix failed: %v", err)
		}
		defer conn.Close()

		oversize := []byte(strings.Repeat("x", MaxPacketSize+50))
		_, _ = conn.Write(oversize)

		buf := make([]byte, MaxPacketSize)
		n, err := conn.Read(buf)
		if err == nil && n > 0 {
			t.Fatalf("expected rejection of oversize packet, got response: %s", string(buf[:n]))
		}
	})

	t.Run("invalid UTF-8 rejected without response", func(t *testing.T) {
		_, sockPath, cleanup := setupServer(t, 2*time.Second)
		defer cleanup()

		conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: sockPath, Net: "unixpacket"})
		if err != nil {
			t.Fatalf("DialUnix failed: %v", err)
		}
		defer conn.Close()

		_, _ = conn.Write([]byte{0xff, 0xfe, 0xfd})

		buf := make([]byte, MaxPacketSize)
		n, err := conn.Read(buf)
		if err == nil && n > 0 {
			t.Fatalf("expected rejection of invalid utf-8, got response: %s", string(buf[:n]))
		}
	})

	t.Run("unknown JSON field rejected without response", func(t *testing.T) {
		_, sockPath, cleanup := setupServer(t, 2*time.Second)
		defer cleanup()

		conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: sockPath, Net: "unixpacket"})
		if err != nil {
			t.Fatalf("DialUnix failed: %v", err)
		}
		defer conn.Close()

		req := `{"version":1,"request_id":"` + uuid.NewString() + `","operation":"boundary.ping","extra":"unauthorized"}`
		_, _ = conn.Write([]byte(req))

		buf := make([]byte, MaxPacketSize)
		n, err := conn.Read(buf)
		if err == nil && n > 0 {
			t.Fatalf("expected rejection of unknown JSON field, got: %s", string(buf[:n]))
		}
	})

	t.Run("trailing JSON rejected without response", func(t *testing.T) {
		_, sockPath, cleanup := setupServer(t, 2*time.Second)
		defer cleanup()

		conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: sockPath, Net: "unixpacket"})
		if err != nil {
			t.Fatalf("DialUnix failed: %v", err)
		}
		defer conn.Close()

		req := `{"version":1,"request_id":"` + uuid.NewString() + `","operation":"boundary.ping"} 123`
		_, _ = conn.Write([]byte(req))

		buf := make([]byte, MaxPacketSize)
		n, err := conn.Read(buf)
		if err == nil && n > 0 {
			t.Fatalf("expected rejection of trailing JSON, got: %s", string(buf[:n]))
		}
	})

	t.Run("client disconnect before request handled cleanly", func(t *testing.T) {
		_, sockPath, cleanup := setupServer(t, 2*time.Second)
		defer cleanup()

		conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: sockPath, Net: "unixpacket"})
		if err != nil {
			t.Fatalf("DialUnix failed: %v", err)
		}
		conn.Close()
	})

	t.Run("handler connection closure on read EOF", func(t *testing.T) {
		_, sockPath, cleanup := setupServer(t, 2*time.Second)
		defer cleanup()

		conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: sockPath, Net: "unixpacket"})
		if err != nil {
			t.Fatalf("DialUnix failed: %v", err)
		}
		_ = conn.CloseWrite()
		buf := make([]byte, MaxPacketSize)
		n, err := conn.Read(buf)
		if err != nil && !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "closed") {
			t.Fatalf("expected EOF or closed connection, got: %v", err)
		}
		if n > 0 {
			t.Fatalf("expected 0 bytes, got %d", n)
		}
		conn.Close()
	})
}
