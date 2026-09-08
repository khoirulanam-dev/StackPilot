package privilege

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Client exposes typed, high-level privileged operations.
// It deliberately avoids exposing generic command or execution APIs.
type Client interface {
	Ping(ctx context.Context) error
}

type clientDeps struct {
	lstatFn        func(name string) (os.FileInfo, error)
	dialer         func(ctx context.Context, network, addr string) (net.Conn, error)
	peerCredReader PeerCredReader
}

func defaultClientDeps() clientDeps {
	var d net.Dialer
	return clientDeps{
		lstatFn:        os.Lstat,
		dialer:         d.DialContext,
		peerCredReader: DefaultPeerCredReader,
	}
}

type client struct {
	runtimeDir string
	socketPath string
	timeout    time.Duration
	deps       clientDeps
}

type ClientConfig struct {
	RuntimeDir string
	Timeout    time.Duration
}

// NewClient creates a new production privilege client targeting the helper socket in runtimeDir.
func NewClient(cfg ClientConfig) (Client, error) {
	return newClientWithDeps(cfg, defaultClientDeps())
}

func newClientWithDeps(cfg ClientConfig, deps clientDeps) (Client, error) {
	if cfg.RuntimeDir == "" {
		return nil, errors.New("runtime directory is required")
	}
	if !filepath.IsAbs(cfg.RuntimeDir) {
		return nil, fmt.Errorf("runtime directory must be an absolute path: %q", cfg.RuntimeDir)
	}
	if filepath.Clean(cfg.RuntimeDir) != cfg.RuntimeDir {
		return nil, fmt.Errorf("runtime directory must be a canonical clean path: %q", cfg.RuntimeDir)
	}
	if strings.ContainsRune(cfg.RuntimeDir, 0) {
		return nil, errors.New("runtime directory path cannot contain NUL bytes")
	}

	sockPath := filepath.Join(cfg.RuntimeDir, SocketFileName)
	if len(sockPath) > MaxSocketPathLen {
		return nil, fmt.Errorf("socket path exceeds maximum safe Unix domain path length (%d > %d)", len(sockPath), MaxSocketPathLen)
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	return &client{
		runtimeDir: cfg.RuntimeDir,
		socketPath: sockPath,
		timeout:    timeout,
		deps:       deps,
	}, nil
}

// Ping verifies the privilege boundary with the root helper daemon.
func (c *client) Ping(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	// Note: SO_PEERCRED UID==0 remains the authoritative helper identity check.
	dirFi, err := c.deps.lstatFn(c.runtimeDir)
	if err != nil {
		return fmt.Errorf("cannot access runtime directory: %w", err)
	}
	if dirFi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("runtime directory %s is a symlink", c.runtimeDir)
	}
	if !dirFi.IsDir() {
		return fmt.Errorf("runtime directory %s is not a directory", c.runtimeDir)
	}
	if dirFi.Mode().Perm() != 0750 {
		return fmt.Errorf("runtime directory %s permissions are %04o (must be exactly 0750)", c.runtimeDir, dirFi.Mode().Perm())
	}
	dirUID, dirGID, err := getFileOwnership(dirFi)
	if err != nil {
		return fmt.Errorf("failed to inspect runtime directory ownership: %w", err)
	}
	if dirUID != 0 {
		return fmt.Errorf("runtime directory %s owner is not root", c.runtimeDir)
	}

	sockFi, err := c.deps.lstatFn(c.socketPath)
	if err != nil {
		return fmt.Errorf("cannot access privilege helper socket: %w", err)
	}
	if sockFi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("helper path %s is not a Unix domain socket", c.socketPath)
	}
	if sockFi.Mode().Perm() != 0660 {
		return fmt.Errorf("helper socket %s permissions are %04o (must be exactly 0660)", c.socketPath, sockFi.Mode().Perm())
	}
	sockUID, sockGID, err := getFileOwnership(sockFi)
	if err != nil {
		return fmt.Errorf("failed to inspect helper socket ownership: %w", err)
	}
	if sockUID != 0 {
		return fmt.Errorf("helper socket %s owner is not root", c.socketPath)
	}
	if sockGID != dirGID {
		return errors.New("helper socket group does not match runtime directory group")
	}

	deadline := time.Now().Add(c.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	dialCtx, cancel := context.WithDeadline(ctx, deadline)
	conn, err := c.deps.dialer(dialCtx, "unixpacket", c.socketPath)
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("failed to connect to privilege helper socket: %w", err)
	}
	defer conn.Close()

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("unexpected connection type %T (expected *net.UnixConn)", conn)
	}

	stop := context.AfterFunc(ctx, func() {
		_ = unixConn.Close()
	})
	defer stop()

	if err := ctx.Err(); err != nil {
		return err
	}

	// SO_PEERCRED is security-authoritative: it guarantees the peer process is UID 0 (root).
	peerUID, err := c.deps.peerCredReader(unixConn)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("failed to verify helper peer credentials: %w", err)
	}
	if peerUID != 0 {
		return errors.New("privilege helper peer is not root; connection rejected")
	}

	reqID := uuid.NewString()
	reqData, err := EncodeRequest(Request{
		Version:   ProtocolVersion,
		RequestID: reqID,
		Operation: OpBoundaryPing,
	})
	if err != nil {
		return fmt.Errorf("failed to encode ping request: %w", err)
	}

	if err := unixConn.SetWriteDeadline(deadline); err != nil {
		return fmt.Errorf("failed to set write deadline: %w", err)
	}
	if _, err := unixConn.Write(reqData); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("failed to send ping request: %w", err)
	}

	if err := unixConn.SetReadDeadline(deadline); err != nil {
		return fmt.Errorf("failed to set read deadline: %w", err)
	}

	respBuf := make([]byte, MaxPacketSize+1)
	n, err := unixConn.Read(respBuf)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("failed to read response from helper: %w", err)
	}
	if n > MaxPacketSize {
		return fmt.Errorf("response packet exceeds maximum size (%d > %d)", n, MaxPacketSize)
	}

	resp, err := DecodeResponse(respBuf[:n])
	if err != nil {
		return fmt.Errorf("failed to parse helper response: %w", err)
	}
	if resp.RequestID != reqID {
		return errors.New("helper response request_id mismatch")
	}

	return nil
}
