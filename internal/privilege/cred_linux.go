//go:build linux

package privilege

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// DefaultPeerCredReader queries Linux SO_PEERCRED to obtain the peer process UID.
// Linux SO_PEERCRED is security-authoritative because credentials are provided
// directly by the kernel at connection time and cannot be forged or spoofed in user-space.
func DefaultPeerCredReader(conn *net.UnixConn) (uint32, error) {
	if conn == nil {
		return 0, fmt.Errorf("connection is nil")
	}

	rawConn, err := conn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("failed to obtain raw socket control: %w", err)
	}

	var cred *unix.Ucred
	var credErr error
	err = rawConn.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil {
		return 0, fmt.Errorf("failed to control socket for peer credentials: %w", err)
	}
	if credErr != nil {
		return 0, fmt.Errorf("SO_PEERCRED failed: %w", credErr)
	}
	if cred == nil {
		return 0, fmt.Errorf("SO_PEERCRED returned nil credentials")
	}

	return cred.Uid, nil
}
