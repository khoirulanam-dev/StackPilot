package privilege

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestServer_BoundedConcurrency(t *testing.T) {
	const allowedUID uint32 = 1000
	const numClients = 16

	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, SocketFileName)

	var activeHandlers int32
	var peakHandlers int32
	startedCh := make(chan struct{}, numClients)
	releaseCh := make(chan struct{})

	cfg := ServerConfig{
		RuntimeDir: tmpDir,
		AllowedUID: allowedUID,
		AllowedGID: 1000,
		Timeout:    30 * time.Second,
	}

	deps := testServerDeps(allowedUID, 1000)
	deps.onHandleStart = func() {
		current := atomic.AddInt32(&activeHandlers, 1)
		for {
			peak := atomic.LoadInt32(&peakHandlers)
			if current <= peak || atomic.CompareAndSwapInt32(&peakHandlers, peak, current) {
				break
			}
		}
		startedCh <- struct{}{}
		<-releaseCh
	}
	deps.onHandleEnd = func() {
		atomic.AddInt32(&activeHandlers, -1)
	}

	readyCh := make(chan struct{})
	deps.onReady = func() {
		close(readyCh)
	}

	srv, err := newServerWithDeps(cfg, deps)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	serverDone := make(chan struct{})
	go func() {
		_ = srv.Serve(ctx)
		close(serverDone)
	}()

	<-readyCh

	var clientWg sync.WaitGroup
	clientWg.Add(numClients)

	reqBytes, err := EncodeRequest(Request{
		Version:   ProtocolVersion,
		RequestID: uuid.NewString(),
		Operation: OpBoundaryPing,
	})
	if err != nil {
		t.Fatalf("EncodeRequest failed: %v", err)
	}

	for i := 0; i < numClients; i++ {
		go func() {
			defer clientWg.Done()
			conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: sockPath, Net: "unixpacket"})
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = conn.Write(reqBytes)
			buf := make([]byte, MaxPacketSize)
			_, _ = conn.Read(buf)
		}()
	}

	for i := 0; i < MaxConcurrentConnections; i++ {
		<-startedCh
	}

	peak := atomic.LoadInt32(&peakHandlers)
	if peak > MaxConcurrentConnections {
		t.Fatalf("peak active handlers was %d, exceeded maximum %d", peak, MaxConcurrentConnections)
	}

	close(releaseCh)
	clientWg.Wait()

	cancel()
	<-serverDone

	finalPeak := atomic.LoadInt32(&peakHandlers)
	if finalPeak > MaxConcurrentConnections {
		t.Errorf("final peak active handlers was %d, expected <= %d", finalPeak, MaxConcurrentConnections)
	}
	if current := atomic.LoadInt32(&activeHandlers); current != 0 {
		t.Errorf("expected 0 active handlers after completion, got %d", current)
	}
}
