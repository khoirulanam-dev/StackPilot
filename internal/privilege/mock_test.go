package privilege

import (
	"io/fs"
	"net"
	"os"
	"syscall"
	"time"
)

type mockFileInfo struct {
	name     string
	size     int64
	mode     os.FileMode
	modTime  time.Time
	isDir    bool
	isSocket bool
	uid      uint32
	gid      uint32
	ino      uint64
	dev      uint64
}

func (m *mockFileInfo) Name() string       { return m.name }
func (m *mockFileInfo) Size() int64        { return m.size }
func (m *mockFileInfo) Mode() os.FileMode  { return m.mode }
func (m *mockFileInfo) ModTime() time.Time { return m.modTime }
func (m *mockFileInfo) IsDir() bool        { return m.isDir }
func (m *mockFileInfo) Sys() any {
	return &syscall.Stat_t{
		Uid: m.uid,
		Gid: m.gid,
		Ino: m.ino,
		Dev: m.dev,
	}
}

type mockUnixConn struct {
	readBuf    []byte
	writeBuf   []byte
	readErr    error
	writeErr   error
	closeErr   error
	isClosed   bool
	onRead     func()
	onWrite    func([]byte)
	closeCh    chan struct{}
	writeBlock chan struct{}
}

func newMockUnixConn() *mockUnixConn {
	return &mockUnixConn{
		closeCh: make(chan struct{}),
	}
}

func (m *mockUnixConn) Read(b []byte) (n int, err error) {
	if m.onRead != nil {
		m.onRead()
	}
	if m.readErr != nil {
		return 0, m.readErr
	}
	n = copy(b, m.readBuf)
	return n, nil
}

func (m *mockUnixConn) Write(b []byte) (n int, err error) {
	if m.writeBlock != nil {
		<-m.writeBlock
	}
	if m.onWrite != nil {
		m.onWrite(b)
	}
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	m.writeBuf = append(m.writeBuf, b...)
	return len(b), nil
}

func (m *mockUnixConn) Close() error {
	m.isClosed = true
	select {
	case <-m.closeCh:
	default:
		close(m.closeCh)
	}
	return m.closeErr
}

func (m *mockUnixConn) LocalAddr() net.Addr {
	return &net.UnixAddr{Name: "client.sock", Net: "unixpacket"}
}

func (m *mockUnixConn) RemoteAddr() net.Addr {
	return &net.UnixAddr{Name: "helper.sock", Net: "unixpacket"}
}

func (m *mockUnixConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockUnixConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockUnixConn) SetWriteDeadline(t time.Time) error { return nil }

var _ fs.FileInfo = (*mockFileInfo)(nil)

func testServerDeps(allowedUID, allowedGID uint32) serverDeps {
	deps := defaultServerDeps()
	deps.getEUIDFn = func() int { return 0 }
	deps.chownFn = func(string, int, int) error { return nil }
	deps.chmodFn = func(string, os.FileMode) error { return nil }
	deps.hardenFn = func() error { return nil }
	deps.lstatFn = func(name string) (os.FileInfo, error) {
		fi, err := os.Lstat(name)
		if err != nil {
			return nil, err
		}
		var ino, dev uint64
		if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
			ino = sys.Ino
			dev = sys.Dev
		}
		mode := fi.Mode()
		if fi.IsDir() {
			mode = (mode &^ os.ModePerm) | 0750
		} else if mode&os.ModeSocket != 0 {
			mode = (mode &^ os.ModePerm) | 0660 | os.ModeSocket
		}
		return &mockFileInfo{
			name:     fi.Name(),
			size:     fi.Size(),
			mode:     mode,
			isDir:    fi.IsDir(),
			isSocket: mode&os.ModeSocket != 0,
			uid:      0,
			gid:      allowedGID,
			ino:      ino,
			dev:      dev,
		}, nil
	}
	deps.peerCredReader = func(conn *net.UnixConn) (uint32, error) {
		return allowedUID, nil
	}
	return deps
}
