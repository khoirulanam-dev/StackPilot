//go:build !linux

package privilege

import (
	"errors"
	"net"
)

func DefaultPeerCredReader(conn *net.UnixConn) (uint32, error) {
	return 0, errors.New("SO_PEERCRED is only supported on Linux")
}
