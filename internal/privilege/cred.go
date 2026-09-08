package privilege

import (
	"net"
)

// PeerCredReader queries the OS kernel for the UID of the peer process connected to conn.
type PeerCredReader func(conn *net.UnixConn) (uint32, error)
