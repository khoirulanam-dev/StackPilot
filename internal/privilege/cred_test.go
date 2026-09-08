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
)

func TestPeerCredAuthorization_ServerSide(t *testing.T) {
	const allowedUID uint32 = 1000

	cases := []struct {
		name       string
		peerUID    uint32
		peerErr    error
		shouldPass bool
	}{
		{
			name:       "exact allowed UID accepted",
			peerUID:    1000,
			shouldPass: true,
		},
		{
			name:       "different non-root UID rejected",
			peerUID:    1001,
			shouldPass: false,
		},
		{
			name:       "root client rejected",
			peerUID:    0,
			shouldPass: false,
		},
		{
			name:       "peer cred error rejected",
			peerErr:    errors.New("kernel credential query failed"),
			shouldPass: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			sockPath := filepath.Join(tmpDir, SocketFileName)

			cfg := ServerConfig{
				RuntimeDir: tmpDir,
				AllowedUID: allowedUID,
				AllowedGID: 1000,
			}

			readyCh := make(chan struct{})
			deps := testServerDeps(allowedUID, 1000)
			deps.onReady = func() {
				close(readyCh)
			}
			deps.peerCredReader = func(conn *net.UnixConn) (uint32, error) {
				return tc.peerUID, tc.peerErr
			}

			srv, err := newServerWithDeps(cfg, deps)
			if err != nil {
				t.Fatalf("NewServer failed: %v", err)
			}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			serverErrCh := make(chan error, 1)
			go func() {
				serverErrCh <- srv.Serve(ctx)
			}()

			<-readyCh

			clientConn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: sockPath, Net: "unixpacket"})
			if err != nil {
				t.Fatalf("DialUnix failed: %v", err)
			}
			defer clientConn.Close()

			reqBytes, err := EncodeRequest(Request{
				Version:   ProtocolVersion,
				RequestID: "00000000-0000-4000-8000-000000000001",
				Operation: OpBoundaryPing,
			})
			if err != nil {
				t.Fatalf("EncodeRequest failed: %v", err)
			}

			_, err = clientConn.Write(reqBytes)
			if err != nil {
				if !tc.shouldPass {
					// Server immediately rejected and closed connection
					cancel()
					<-serverErrCh
					return
				}
				t.Fatalf("Write failed: %v", err)
			}

			buf := make([]byte, MaxPacketSize)
			n, err := clientConn.Read(buf)

			if tc.shouldPass {
				if err != nil {
					t.Fatalf("expected successful response, got error: %v", err)
				}
				resp, err := DecodeResponse(buf[:n])
				if err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp.Status != StatusOk {
					t.Errorf("expected status 'ok', got %q", resp.Status)
				}
			} else {
				if err == nil && n > 0 {
					t.Fatalf("expected server to reject connection, but received response: %s", string(buf[:n]))
				}
			}

			cancel()
			<-serverErrCh
		})
	}
}

func TestPeerCredAuthorization_ClientSide(t *testing.T) {
	cases := []struct {
		name       string
		serverUID  uint32
		serverErr  error
		shouldPass bool
	}{
		{
			name:       "root helper UID 0 accepted",
			serverUID:  0,
			shouldPass: true,
		},
		{
			name:       "non-root server UID 1000 rejected",
			serverUID:  1000,
			shouldPass: false,
		},
		{
			name:       "non-root server UID 1001 rejected",
			serverUID:  1001,
			shouldPass: false,
		},
		{
			name:       "peer cred retrieval error rejected",
			serverErr:  errors.New("credential error"),
			shouldPass: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
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
				n, err := conn.Read(buf)
				if err != nil {
					return
				}

				req, err := DecodeRequest(buf[:n])
				if err != nil {
					return
				}

				respBytes, _ := EncodeResponse(Response{
					Version:   ProtocolVersion,
					RequestID: req.RequestID,
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
				return tc.serverUID, tc.serverErr
			}

			client, err := newClientWithDeps(ClientConfig{RuntimeDir: tmpDir}, deps)
			if err != nil {
				t.Fatalf("newClientWithDeps failed: %v", err)
			}

			err = client.Ping(t.Context())
			if tc.shouldPass {
				if err != nil {
					t.Fatalf("expected ping to succeed, got error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("expected ping to fail when server peer UID is non-root")
				}
				if tc.serverErr != nil && !strings.Contains(err.Error(), tc.serverErr.Error()) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.serverErr.Error())
				}
				if tc.serverErr == nil && !strings.Contains(err.Error(), "not root") {
					t.Errorf("error %q does not contain 'not root'", err.Error())
				}
			}
			wg.Wait()
		})
	}
}

func TestVerifyOwnership_Validation(t *testing.T) {
	tmpDir := t.TempDir()
	fi, err := os.Lstat(tmpDir)
	if err != nil {
		t.Fatalf("Lstat failed: %v", err)
	}

	currentUID := uint32(os.Geteuid())
	currentGID := uint32(os.Getegid())

	if err := verifyOwnership(fi, currentUID, currentGID); err != nil {
		t.Errorf("expected current UID/GID to match, got error: %v", err)
	}

	if err := verifyOwnership(fi, currentUID+99999, currentGID); err == nil {
		t.Error("expected mismatched UID to fail")
	}

	if err := verifyOwnership(fi, currentUID, currentGID+99999); err == nil {
		t.Error("expected mismatched GID to fail")
	}
}
