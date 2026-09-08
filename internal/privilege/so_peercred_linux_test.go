//go:build linux

package privilege

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestRealSOPeercredIntegration(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "peercred_test.sock")

	ul, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: sockPath, Net: "unixpacket"})
	if err != nil {
		t.Fatalf("ListenUnix failed: %v", err)
	}
	defer ul.Close()

	currentUID := uint32(os.Geteuid())

	errCh := make(chan error, 1)
	serverUIDCh := make(chan uint32, 1)

	go func() {
		conn, err := ul.AcceptUnix()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		peerUID, err := DefaultPeerCredReader(conn)
		if err != nil {
			errCh <- err
			return
		}
		serverUIDCh <- peerUID
	}()

	clientConn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: sockPath, Net: "unixpacket"})
	if err != nil {
		t.Fatalf("DialUnix failed: %v", err)
	}
	defer clientConn.Close()

	clientPeerUID, err := DefaultPeerCredReader(clientConn)
	if err != nil {
		t.Fatalf("DefaultPeerCredReader on client failed: %v", err)
	}

	if clientPeerUID != currentUID {
		t.Errorf("client observed peer UID %d, expected current test process UID %d", clientPeerUID, currentUID)
	}

	select {
	case err := <-errCh:
		t.Fatalf("server side failed: %v", err)
	case serverObservedUID := <-serverUIDCh:
		if serverObservedUID != currentUID {
			t.Errorf("server observed peer UID %d, expected current test process UID %d", serverObservedUID, currentUID)
		}
	}
}
