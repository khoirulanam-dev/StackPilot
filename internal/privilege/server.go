package privilege

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type ServerConfig struct {
	RuntimeDir string
	AllowedUID uint32
	AllowedGID uint32
	Timeout    time.Duration
	Logger     *slog.Logger
}

type serverDeps struct {
	getEUIDFn      func() int
	lstatFn        func(string) (os.FileInfo, error)
	chownFn        func(string, int, int) error
	chmodFn        func(string, os.FileMode) error
	mkdirFn        func(string, os.FileMode) error
	removeFn       func(string) error
	listenUnixFn   func(network, address string) (net.Listener, error)
	peerCredReader PeerCredReader
	hardenFn       func() error
	setDeadlineFn  func(*net.UnixConn, time.Time) error
	onHandleStart  func()
	onHandleEnd    func()
	onReady        func()
	sameFileFn     func(fi1, fi2 os.FileInfo) bool
}

func defaultServerDeps() serverDeps {
	return serverDeps{
		getEUIDFn: GetEffectiveUID,
		lstatFn:   os.Lstat,
		chownFn:   os.Chown,
		chmodFn:   os.Chmod,
		mkdirFn:   os.Mkdir,
		removeFn:  os.Remove,
		listenUnixFn: func(network, address string) (net.Listener, error) {
			addr := &net.UnixAddr{Name: address, Net: network}
			ul, err := net.ListenUnix(network, addr)
			if err != nil {
				return nil, err
			}
			ul.SetUnlinkOnClose(false)
			return ul, nil
		},
		peerCredReader: DefaultPeerCredReader,
		hardenFn:       HardenProcess,
		setDeadlineFn: func(conn *net.UnixConn, t time.Time) error {
			return conn.SetDeadline(t)
		},
		sameFileFn: SameFile,
	}
}

type Server struct {
	cfg        ServerConfig
	deps       serverDeps
	socketPath string
}

func ValidateServerConfig(cfg ServerConfig) error {
	if cfg.RuntimeDir == "" {
		return errors.New("runtime directory is required")
	}
	if !filepath.IsAbs(cfg.RuntimeDir) {
		return fmt.Errorf("runtime directory must be an absolute path: %q", cfg.RuntimeDir)
	}
	if filepath.Clean(cfg.RuntimeDir) != cfg.RuntimeDir {
		return fmt.Errorf("runtime directory must be a canonical clean path: %q", cfg.RuntimeDir)
	}
	if strings.ContainsRune(cfg.RuntimeDir, 0) {
		return errors.New("runtime directory path cannot contain NUL bytes")
	}
	if cfg.AllowedUID == 0 {
		return errors.New("allowed UID must be non-root (non-zero)")
	}

	sockPath := filepath.Join(cfg.RuntimeDir, SocketFileName)
	if len(sockPath) > MaxSocketPathLen {
		return fmt.Errorf("socket path exceeds maximum safe Unix domain path length (%d > %d)", len(sockPath), MaxSocketPathLen)
	}

	return nil
}

func validateRuntimeDirFi(fi os.FileInfo, allowedGID uint32) error {
	if fi.Mode()&os.ModeSymlink != 0 {
		return errors.New("runtime directory is a symlink (must be regular directory)")
	}
	if !fi.IsDir() {
		return errors.New("runtime directory is not a directory")
	}
	if fi.Mode().Perm() != 0750 {
		return fmt.Errorf("runtime directory permissions are %04o (must be exactly 0750)", fi.Mode().Perm())
	}
	if err := verifyOwnership(fi, 0, allowedGID); err != nil {
		return fmt.Errorf("runtime directory ownership invalid: %w", err)
	}
	return nil
}

func NewServer(cfg ServerConfig) (*Server, error) {
	return newServerWithDeps(cfg, defaultServerDeps())
}

func newServerWithDeps(cfg ServerConfig, deps serverDeps) (*Server, error) {
	if err := ValidateServerConfig(cfg); err != nil {
		return nil, err
	}

	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}

	return &Server{
		cfg:        cfg,
		deps:       deps,
		socketPath: filepath.Join(cfg.RuntimeDir, SocketFileName),
	}, nil
}

func (s *Server) SocketPath() string {
	return s.socketPath
}

func (s *Server) Serve(ctx context.Context) (retErr error) {
	if err := ValidateHelperEUID(s.deps.getEUIDFn()); err != nil {
		return err
	}

	fi, err := s.deps.lstatFn(s.cfg.RuntimeDir)
	if errors.Is(err, os.ErrNotExist) {
		if err := s.deps.mkdirFn(s.cfg.RuntimeDir, 0750); err != nil {
			return fmt.Errorf("failed to create runtime directory %s: %w", s.cfg.RuntimeDir, err)
		}
		if err := s.deps.chownFn(s.cfg.RuntimeDir, 0, int(s.cfg.AllowedGID)); err != nil {
			return fmt.Errorf("failed to set runtime directory ownership: %w", err)
		}
		if err := s.deps.chmodFn(s.cfg.RuntimeDir, 0750); err != nil {
			return fmt.Errorf("failed to set runtime directory permissions: %w", err)
		}
		createdDirFi, err := s.deps.lstatFn(s.cfg.RuntimeDir)
		if err != nil {
			return fmt.Errorf("failed to inspect newly created runtime directory %s: %w", s.cfg.RuntimeDir, err)
		}
		if err := validateRuntimeDirFi(createdDirFi, s.cfg.AllowedGID); err != nil {
			return fmt.Errorf("newly created runtime directory verification failed: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to inspect runtime directory: %w", err)
	} else {
		if err := validateRuntimeDirFi(fi, s.cfg.AllowedGID); err != nil {
			return fmt.Errorf("runtime directory %s invalid: %w", s.cfg.RuntimeDir, err)
		}
	}

	if _, err := s.deps.lstatFn(s.socketPath); err == nil {
		return fmt.Errorf("helper socket %s already exists; refusing to start or unlink existing socket", s.socketPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to inspect socket path %s: %w", s.socketPath, err)
	}

	listener, err := s.deps.listenUnixFn("unixpacket", s.socketPath)
	if err != nil {
		return fmt.Errorf("failed to bind unixpacket listener on %s: %w", s.socketPath, err)
	}

	createdFi, err := s.deps.lstatFn(s.socketPath)
	if err != nil {
		_ = listener.Close()
		return fmt.Errorf("failed to stat created socket instance %s: %w", s.socketPath, err)
	}

	cleanupSocket := func() error {
		dirFi, err := s.deps.lstatFn(s.cfg.RuntimeDir)
		if err != nil {
			return fmt.Errorf("runtime directory cleanup verification failed: %w", err)
		}
		if err := validateRuntimeDirFi(dirFi, s.cfg.AllowedGID); err != nil {
			return fmt.Errorf("runtime directory invariant changed before cleanup: %w", err)
		}

		currFi, err := s.deps.lstatFn(s.socketPath)
		if err != nil {
			return fmt.Errorf("failed to inspect socket path before cleanup: %w", err)
		}
		if currFi.Mode()&os.ModeSocket == 0 {
			return errors.New("socket path before cleanup is not a Unix domain socket")
		}
		// SameFile check prevents unlinking a replacement socket object
		if !s.deps.sameFileFn(createdFi, currFi) {
			return errors.New("socket file changed or was replaced before cleanup; refusing to unlink")
		}

		if err := s.deps.removeFn(s.socketPath); err != nil {
			return fmt.Errorf("failed to remove socket file: %w", err)
		}
		return nil
	}

	var (
		listenerClosed bool
		wg             sync.WaitGroup
	)

	defer func() {
		if !listenerClosed {
			_ = listener.Close()
		}
		wg.Wait()
		if cleanupErr := cleanupSocket(); cleanupErr != nil {
			retErr = errors.Join(retErr, cleanupErr)
		}
	}()

	if err := s.deps.chownFn(s.socketPath, 0, int(s.cfg.AllowedGID)); err != nil {
		return fmt.Errorf("failed to set socket ownership: %w", err)
	}
	if err := s.deps.chmodFn(s.socketPath, 0660); err != nil {
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	sockFi, err := s.deps.lstatFn(s.socketPath)
	if err != nil {
		return fmt.Errorf("failed to verify created socket: %w", err)
	}
	if sockFi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("created path %s is not a Unix domain socket", s.socketPath)
	}
	if sockFi.Mode().Perm() != 0660 {
		return fmt.Errorf("created socket %s permissions are %04o (must be exactly 0660)", s.socketPath, sockFi.Mode().Perm())
	}
	if err := verifyOwnership(sockFi, 0, s.cfg.AllowedGID); err != nil {
		return fmt.Errorf("created socket ownership invalid: %w", err)
	}

	if err := s.deps.hardenFn(); err != nil {
		return fmt.Errorf("failed to harden helper process: %w", err)
	}

	sem := make(chan struct{}, MaxConcurrentConnections)
	shutdownCh := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-shutdownCh:
		}
	}()
	defer close(shutdownCh)

	if s.deps.onReady != nil {
		s.deps.onReady()
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			retErr = fmt.Errorf("accept error: %w", err)
			break
		}

		unixConn, ok := conn.(*net.UnixConn)
		if !ok {
			_ = conn.Close()
			continue
		}

		select {
		case sem <- struct{}{}:
			wg.Add(1)
			go func(c *net.UnixConn) {
				defer func() {
					<-sem
					wg.Done()
					_ = c.Close()
				}()
				s.handleConn(ctx, c)
			}(unixConn)
		default:
			_ = unixConn.Close()
		}
	}

	listenerClosed = true
	_ = listener.Close()
	wg.Wait()
	return retErr
}

func (s *Server) handleConn(ctx context.Context, conn *net.UnixConn) {
	if s.deps.onHandleStart != nil {
		s.deps.onHandleStart()
		if s.deps.onHandleEnd != nil {
			defer s.deps.onHandleEnd()
		}
	}

	deadline := time.Now().Add(s.cfg.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := s.deps.setDeadlineFn(conn, deadline); err != nil {
		return
	}

	// SO_PEERCRED is kernel-authoritative identity verification
	peerUID, err := s.deps.peerCredReader(conn)
	if err != nil || peerUID != s.cfg.AllowedUID {
		return
	}

	buf := make([]byte, MaxPacketSize+1)
	n, err := conn.Read(buf)
	if err != nil || n == 0 || n > MaxPacketSize {
		return
	}

	req, err := DecodeRequest(buf[:n])
	if err != nil {
		return
	}

	if req.Operation != OpBoundaryPing {
		return
	}

	resp := Response{
		Version:   ProtocolVersion,
		RequestID: req.RequestID,
		Status:    StatusOk,
	}

	respBytes, err := EncodeResponse(resp)
	if err != nil {
		return
	}

	_, _ = conn.Write(respBytes)
}
