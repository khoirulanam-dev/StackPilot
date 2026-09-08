//go:build linux

package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"stackpilot/internal/protocol"
)

func createTempFixture(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "fixture-*")
	if err != nil {
		t.Fatalf("failed to create temp fixture: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("failed to write fixture content: %v", err)
	}
	return f.Name()
}

func TestLinuxCPUCollection(t *testing.T) {
	t.Run("normal /proc/stat", func(t *testing.T) {
		content := "cpu  100 20 30 500 10 5 2 1 0 0\ncpu0 100 20 30 500 10 5 2 1 0 0\n"
		path := createTempFixture(t, content)
		total, idle, err := readProcStatCPU(path)
		if err != nil {
			t.Fatalf("readProcStatCPU failed: %v", err)
		}
		// idleAll = idle(500) + iowait(10) = 510
		// nonIdle = user(100) + nice(20) + system(30) + irq(5) + softirq(2) + steal(1) = 158
		// total = 510 + 158 = 668
		if idle != 510 {
			t.Fatalf("expected idle 510, got %d", idle)
		}
		if total != 668 {
			t.Fatalf("expected total 668, got %d", total)
		}
	})

	t.Run("25% usage calculation", func(t *testing.T) {
		// sample 1: total = 1000, idle = 800 (busy = 200)
		// sample 2: total = 2000, idle = 1550 (busy = 450)
		// totalDelta = 1000, idleDelta = 750, busyDelta = 250 -> 250 * 10000 / 1000 = 2500 basis points
		cfg := defaultLinuxSamplerConfig()
		s1 := "cpu  150 20 30 800 0 0 0 0 0 0\n"
		s2 := "cpu  350 40 60 1550 0 0 0 0 0 0\n"
		p1 := createTempFixture(t, s1)
		cfg.statPath = p1

		sampler := newLinuxSampler(cfg)
		t1 := time.Unix(1000, 0)
		req1, ready1, err1 := sampler.Sample(t1)
		if err1 != nil || ready1 || req1 != nil {
			t.Fatalf("sample 1 expected ready=false, got ready=%v, err=%v", ready1, err1)
		}

		p2 := createTempFixture(t, s2)
		sampler.cfg.statPath = p2
		sampler.cfg.meminfoPath = createTempFixture(t, "MemTotal:       1000000 kB\nMemAvailable:    500000 kB\n")
		sampler.cfg.loadavgPath = createTempFixture(t, "1.00 2.00 3.00 1/100 1234\n")
		sampler.cfg.uptimePath = createTempFixture(t, "1234.56 5678.90\n")
		sampler.cfg.netdevPath = createTempFixture(t, "Inter-|   Receive\n face |bytes\n  eth0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0\n")
		sampler.cfg.statfsFunc = func(path string) (uint64, uint64, uint64, uint64, error) {
			return 1000, 500, 400, 4096, nil
		}

		t2 := t1.Add(30 * time.Second)
		req2, ready2, err2 := sampler.Sample(t2)
		if err2 != nil || !ready2 || req2 == nil {
			t.Fatalf("sample 2 expected ready=true, got ready=%v, err=%v", ready2, err2)
		}
		if req2.CPUUsageBasisPoints != 2500 {
			t.Fatalf("expected 2500 basis points (25.00%%), got %d", req2.CPUUsageBasisPoints)
		}
	})

	t.Run("0% usage calculation", func(t *testing.T) {
		s1 := "cpu  100 0 0 900 0 0 0 0 0 0\n"
		s2 := "cpu  100 0 0 1900 0 0 0 0 0 0\n"
		cfg := defaultLinuxSamplerConfig()
		cfg.statPath = createTempFixture(t, s1)
		sampler := newLinuxSampler(cfg)
		t1 := time.Unix(1000, 0)
		_, _, _ = sampler.Sample(t1)

		sampler.cfg.statPath = createTempFixture(t, s2)
		sampler.cfg.meminfoPath = createTempFixture(t, "MemTotal: 100 kB\nMemAvailable: 50 kB\n")
		sampler.cfg.loadavgPath = createTempFixture(t, "0.00 0.00 0.00 1/1 1\n")
		sampler.cfg.uptimePath = createTempFixture(t, "100.0 0.0\n")
		sampler.cfg.netdevPath = createTempFixture(t, "lo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
		sampler.cfg.statfsFunc = func(path string) (uint64, uint64, uint64, uint64, error) {
			return 100, 50, 50, 1024, nil
		}

		req, ready, err := sampler.Sample(t1.Add(30 * time.Second))
		if err != nil || !ready || req == nil {
			t.Fatalf("expected ready=true, got ready=%v, err=%v", ready, err)
		}
		if req.CPUUsageBasisPoints != 0 {
			t.Fatalf("expected 0 basis points (0.00%%), got %d", req.CPUUsageBasisPoints)
		}
	})

	t.Run("100% usage calculation", func(t *testing.T) {
		s1 := "cpu  100 0 0 900 0 0 0 0 0 0\n"
		s2 := "cpu  1100 0 0 900 0 0 0 0 0 0\n"
		cfg := defaultLinuxSamplerConfig()
		cfg.statPath = createTempFixture(t, s1)
		sampler := newLinuxSampler(cfg)
		t1 := time.Unix(1000, 0)
		_, _, _ = sampler.Sample(t1)

		sampler.cfg.statPath = createTempFixture(t, s2)
		sampler.cfg.meminfoPath = createTempFixture(t, "MemTotal: 100 kB\nMemAvailable: 50 kB\n")
		sampler.cfg.loadavgPath = createTempFixture(t, "1.00 1.00 1.00 1/1 1\n")
		sampler.cfg.uptimePath = createTempFixture(t, "100.0 0.0\n")
		sampler.cfg.netdevPath = createTempFixture(t, "lo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
		sampler.cfg.statfsFunc = func(path string) (uint64, uint64, uint64, uint64, error) {
			return 100, 50, 50, 1024, nil
		}

		req, ready, err := sampler.Sample(t1.Add(30 * time.Second))
		if err != nil || !ready || req == nil {
			t.Fatalf("expected ready=true, got ready=%v, err=%v", ready, err)
		}
		if req.CPUUsageBasisPoints != 10000 {
			t.Fatalf("expected 10000 basis points (100.00%%), got %d", req.CPUUsageBasisPoints)
		}
	})

	t.Run("iowait counted idle", func(t *testing.T) {
		// All delta is in iowait; usage must be 0%
		s1 := "cpu  100 0 0 500 100 0 0 0 0 0\n"
		s2 := "cpu  100 0 0 500 500 0 0 0 0 0\n"
		cfg := defaultLinuxSamplerConfig()
		cfg.statPath = createTempFixture(t, s1)
		sampler := newLinuxSampler(cfg)
		t1 := time.Unix(1000, 0)
		_, _, _ = sampler.Sample(t1)

		sampler.cfg.statPath = createTempFixture(t, s2)
		sampler.cfg.meminfoPath = createTempFixture(t, "MemTotal: 100 kB\nMemAvailable: 50 kB\n")
		sampler.cfg.loadavgPath = createTempFixture(t, "0.00 0.00 0.00 1/1 1\n")
		sampler.cfg.uptimePath = createTempFixture(t, "100.0 0.0\n")
		sampler.cfg.netdevPath = createTempFixture(t, "lo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
		sampler.cfg.statfsFunc = func(path string) (uint64, uint64, uint64, uint64, error) {
			return 100, 50, 50, 1024, nil
		}

		req, ready, err := sampler.Sample(t1.Add(30 * time.Second))
		if err != nil || !ready || req == nil {
			t.Fatalf("expected ready=true, got ready=%v, err=%v", ready, err)
		}
		if req.CPUUsageBasisPoints != 0 {
			t.Fatalf("expected 0 basis points when only iowait increases, got %d", req.CPUUsageBasisPoints)
		}
	})

	t.Run("guest fields not double-counted", func(t *testing.T) {
		// Fields: user(100) nice(0) sys(0) idle(500) iowait(0) irq(0) softirq(0) steal(0) guest(50) guest_nice(20)
		// Total should not include guest(50) and guest_nice(20) a second time.
		content := "cpu  100 0 0 500 0 0 0 0 50 20\n"
		path := createTempFixture(t, content)
		total, idle, err := readProcStatCPU(path)
		if err != nil {
			t.Fatalf("readProcStatCPU failed: %v", err)
		}
		if idle != 500 {
			t.Fatalf("expected idle 500, got %d", idle)
		}
		if total != 600 {
			t.Fatalf("expected total 600 (100+500), got %d", total)
		}
	})

	t.Run("malformed counter", func(t *testing.T) {
		content := "cpu  user 0 0 500 0 0 0 0\n"
		path := createTempFixture(t, content)
		_, _, err := readProcStatCPU(path)
		if err == nil {
			t.Fatal("expected error for malformed counter string, got nil")
		}
	})

	t.Run("valid aggregate line with large trailing content", func(t *testing.T) {
		content := "cpu  100 20 30 500 10 5 2 1 0 0\n" + strings.Repeat("cpu0 100 20 30 500 10 5 2 1 0 0\nintr 0 0 0 0 0\n", 300)
		if len(content) <= 4096 {
			t.Fatalf("fixture size %d is not > 4096", len(content))
		}
		path := createTempFixture(t, content)
		total, idle, err := readProcStatCPU(path)
		if err != nil {
			t.Fatalf("expected success for valid aggregate line with >4KiB trailing data, got: %v", err)
		}
		if idle != 510 || total != 668 {
			t.Fatalf("expected idle=510, total=668; got idle=%d, total=%d", idle, total)
		}
	})

	t.Run("valid aggregate line with 100KiB trailing content", func(t *testing.T) {
		content := "cpu  200 40 60 1000 20 10 4 2 0 0\n" + strings.Repeat("cpu99 1 2 3 4 5 6 7 8 9 10\n", 4000)
		if len(content) < 100*1024 {
			t.Fatalf("fixture size %d is not >= 100 KiB", len(content))
		}
		path := createTempFixture(t, content)
		total, idle, err := readProcStatCPU(path)
		if err != nil {
			t.Fatalf("expected success for valid aggregate line with 100KiB trailing data, got: %v", err)
		}
		if idle != 1020 || total != 1336 {
			t.Fatalf("expected idle=1020, total=1336; got idle=%d, total=%d", idle, total)
		}
	})

	t.Run("aggregate first line exceeding 4096 bytes", func(t *testing.T) {
		content := "cpu  " + strings.Repeat("1 ", 3000) + "\n"
		if len(content) <= 4096 {
			t.Fatalf("first line size %d is not > 4096", len(content))
		}
		path := createTempFixture(t, content)
		_, _, err := readProcStatCPU(path)
		if err == nil {
			t.Fatal("expected error when aggregate first line exceeds 4096 bytes, got nil")
		}
	})

	t.Run("aggregate first line without trailing newline", func(t *testing.T) {
		content := "cpu  100 20 30 500 10 5 2 1 0 0"
		path := createTempFixture(t, content)
		total, idle, err := readProcStatCPU(path)
		if err != nil {
			t.Fatalf("expected success for line without newline, got: %v", err)
		}
		if idle != 510 || total != 668 {
			t.Fatalf("expected idle=510, total=668; got idle=%d, total=%d", idle, total)
		}
	})

	t.Run("missing aggregate first line", func(t *testing.T) {
		for _, content := range []string{
			"",
			"cpu0 100 0 0 500 0 0 0 0\n",
			"intr 0 0 0 0 0\n",
		} {
			path := createTempFixture(t, content)
			_, _, err := readProcStatCPU(path)
			if err == nil {
				t.Fatalf("expected error for content %q, got nil", content)
			}
		}
	})

	t.Run("counter decrease/reset", func(t *testing.T) {
		s1 := "cpu  1000 0 0 5000 0 0 0 0 0 0\n"
		s2 := "cpu  100 0 0 500 0 0 0 0 0 0\n"
		cfg := defaultLinuxSamplerConfig()
		cfg.statPath = createTempFixture(t, s1)
		sampler := newLinuxSampler(cfg)
		t1 := time.Unix(1000, 0)
		_, _, _ = sampler.Sample(t1)

		sampler.cfg.statPath = createTempFixture(t, s2)
		req, ready, err := sampler.Sample(t1.Add(30 * time.Second))
		if err != nil {
			t.Fatalf("expected nil error on counter decrease, got: %v", err)
		}
		if ready || req != nil {
			t.Fatalf("expected ready=false on counter decrease, got ready=%v", ready)
		}
	})

	t.Run("zero total delta", func(t *testing.T) {
		s1 := "cpu  1000 0 0 5000 0 0 0 0 0 0\n"
		cfg := defaultLinuxSamplerConfig()
		cfg.statPath = createTempFixture(t, s1)
		sampler := newLinuxSampler(cfg)
		t1 := time.Unix(1000, 0)
		_, _, _ = sampler.Sample(t1)

		req, ready, err := sampler.Sample(t1.Add(30 * time.Second))
		if err != nil {
			t.Fatalf("expected nil error on zero delta, got: %v", err)
		}
		if ready || req != nil {
			t.Fatalf("expected ready=false on zero delta, got ready=%v", ready)
		}
	})

	t.Run("overflow-safe counter summation and calculation", func(t *testing.T) {
		userVal := uint64(math.MaxUint64 / 4)
		idleVal := uint64(math.MaxUint64 / 4)
		content := fmt.Sprintf("cpu  %d 0 0 %d 0 0 0 0 0 0\n", userVal, idleVal)
		path := createTempFixture(t, content)
		total, idle, err := readProcStatCPU(path)
		if err != nil {
			t.Fatalf("readProcStatCPU failed: %v", err)
		}
		if idle != idleVal {
			t.Fatalf("expected idle %d, got %d", idleVal, idle)
		}
		if total != userVal+idleVal {
			t.Fatalf("expected total %d, got %d", userVal+idleVal, total)
		}
	})
}

func TestLinuxMemoryCollection(t *testing.T) {
	t.Run("MemTotal and MemAvailable normal", func(t *testing.T) {
		content := "MemTotal:       16384000 kB\nMemFree:         1000000 kB\nMemAvailable:    8192000 kB\nBuffers:          500000 kB\n"
		path := createTempFixture(t, content)
		total, used, avail, err := readProcMeminfo(path)
		if err != nil {
			t.Fatalf("readProcMeminfo failed: %v", err)
		}
		expectedTotal := int64(16384000) * 1024
		expectedAvail := int64(8192000) * 1024
		expectedUsed := expectedTotal - expectedAvail
		if total != expectedTotal {
			t.Fatalf("expected total %d, got %d", expectedTotal, total)
		}
		if avail != expectedAvail {
			t.Fatalf("expected avail %d, got %d", expectedAvail, avail)
		}
		if used != expectedUsed {
			t.Fatalf("expected used %d, got %d", expectedUsed, used)
		}
	})

	t.Run("MemAvailable zero allowed", func(t *testing.T) {
		content := "MemTotal:       1000000 kB\nMemAvailable:         0 kB\n"
		path := createTempFixture(t, content)
		total, used, avail, err := readProcMeminfo(path)
		if err != nil {
			t.Fatalf("readProcMeminfo failed: %v", err)
		}
		if avail != 0 {
			t.Fatalf("expected available 0, got %d", avail)
		}
		if used != total {
			t.Fatalf("expected used == total, got used=%d, total=%d", used, total)
		}
	})

	t.Run("missing MemTotal", func(t *testing.T) {
		content := "MemAvailable:    8192000 kB\n"
		path := createTempFixture(t, content)
		_, _, _, err := readProcMeminfo(path)
		if err == nil {
			t.Fatal("expected error for missing MemTotal, got nil")
		}
	})

	t.Run("missing MemAvailable", func(t *testing.T) {
		content := "MemTotal:       16384000 kB\n"
		path := createTempFixture(t, content)
		_, _, _, err := readProcMeminfo(path)
		if err == nil {
			t.Fatal("expected error for missing MemAvailable, got nil")
		}
	})

	t.Run("available > total", func(t *testing.T) {
		content := "MemTotal:       1000 kB\nMemAvailable:   2000 kB\n"
		path := createTempFixture(t, content)
		_, _, _, err := readProcMeminfo(path)
		if err == nil {
			t.Fatal("expected error when available > total, got nil")
		}
	})

	t.Run("MemTotal missing unit", func(t *testing.T) {
		content := "MemTotal: 1000\nMemAvailable: 500 kB\n"
		path := createTempFixture(t, content)
		_, _, _, err := readProcMeminfo(path)
		if err == nil {
			t.Fatal("expected error for MemTotal missing unit, got nil")
		}
	})

	t.Run("MemAvailable missing unit", func(t *testing.T) {
		content := "MemTotal: 1000 kB\nMemAvailable: 500\n"
		path := createTempFixture(t, content)
		_, _, _, err := readProcMeminfo(path)
		if err == nil {
			t.Fatal("expected error for MemAvailable missing unit, got nil")
		}
	})

	t.Run("MemTotal wrong unit", func(t *testing.T) {
		content := "MemTotal: 1000 MB\nMemAvailable: 500 kB\n"
		path := createTempFixture(t, content)
		_, _, _, err := readProcMeminfo(path)
		if err == nil {
			t.Fatal("expected error for MemTotal wrong unit, got nil")
		}
	})

	t.Run("MemAvailable wrong unit", func(t *testing.T) {
		content := "MemTotal: 1000 kB\nMemAvailable: 500 MB\n"
		path := createTempFixture(t, content)
		_, _, _, err := readProcMeminfo(path)
		if err == nil {
			t.Fatal("expected error for MemAvailable wrong unit, got nil")
		}
	})

	t.Run("MemTotal extra token", func(t *testing.T) {
		content := "MemTotal: 1000 kB garbage\nMemAvailable: 500 kB\n"
		path := createTempFixture(t, content)
		_, _, _, err := readProcMeminfo(path)
		if err == nil {
			t.Fatal("expected error for MemTotal extra token, got nil")
		}
	})

	t.Run("MemAvailable extra token", func(t *testing.T) {
		content := "MemTotal: 1000 kB\nMemAvailable: 500 kB garbage\n"
		path := createTempFixture(t, content)
		_, _, _, err := readProcMeminfo(path)
		if err == nil {
			t.Fatal("expected error for MemAvailable extra token, got nil")
		}
	})

	t.Run("MemTotal malformed integer", func(t *testing.T) {
		content := "MemTotal: invalid kB\nMemAvailable: 500 kB\n"
		path := createTempFixture(t, content)
		_, _, _, err := readProcMeminfo(path)
		if err == nil {
			t.Fatal("expected error for MemTotal malformed integer, got nil")
		}
	})

	t.Run("MemAvailable malformed integer", func(t *testing.T) {
		content := "MemTotal: 1000 kB\nMemAvailable: invalid kB\n"
		path := createTempFixture(t, content)
		_, _, _, err := readProcMeminfo(path)
		if err == nil {
			t.Fatal("expected error for MemAvailable malformed integer, got nil")
		}
	})

	t.Run("zero or negative total", func(t *testing.T) {
		for _, invalid := range []string{
			"MemTotal: 0 kB\nMemAvailable: 0 kB\n",
			"MemTotal: -100 kB\nMemAvailable: 0 kB\n",
		} {
			path := createTempFixture(t, invalid)
			_, _, _, err := readProcMeminfo(path)
			if err == nil {
				t.Fatalf("expected error for total in %q, got nil", invalid)
			}
		}
	})

	t.Run("negative available", func(t *testing.T) {
		content := "MemTotal: 1000 kB\nMemAvailable: -1 kB\n"
		path := createTempFixture(t, content)
		_, _, _, err := readProcMeminfo(path)
		if err == nil {
			t.Fatal("expected error for negative MemAvailable, got nil")
		}
	})

	t.Run("integer overflow", func(t *testing.T) {
		content := fmt.Sprintf("MemTotal:       %d kB\nMemAvailable:   1000 kB\n", math.MaxInt64)
		path := createTempFixture(t, content)
		_, _, _, err := readProcMeminfo(path)
		if err == nil {
			t.Fatal("expected error for integer overflow, got nil")
		}
	})

	t.Run("oversized meminfo", func(t *testing.T) {
		content := "MemTotal: 1000 kB\nMemAvailable: 500 kB\n" + strings.Repeat("Key: Value\n", 15000)
		if len(content) <= 128*1024 {
			t.Fatalf("fixture size %d is not > 128 KiB", len(content))
		}
		path := createTempFixture(t, content)
		_, _, _, err := readProcMeminfo(path)
		if err == nil {
			t.Fatal("expected error for oversized meminfo, got nil")
		}
	})
}

func TestLinuxLoadavgAndUptimeCollection(t *testing.T) {
	t.Run("Load normal and fraction precision", func(t *testing.T) {
		path := createTempFixture(t, "0.00 1.25 12.345 1/234 5678\n")
		l1, l5, l15, err := readProcLoadavg(path)
		if err != nil {
			t.Fatalf("readProcLoadavg failed: %v", err)
		}
		if l1 != 0 {
			t.Fatalf("expected l1 == 0, got %d", l1)
		}
		if l5 != 1250 {
			t.Fatalf("expected l5 == 1250, got %d", l5)
		}
		if l15 != 12345 {
			t.Fatalf("expected l15 == 12345, got %d", l15)
		}
	})

	t.Run("Load negative", func(t *testing.T) {
		path := createTempFixture(t, "-0.01 1.25 2.00 1/1 1\n")
		_, _, _, err := readProcLoadavg(path)
		if err == nil {
			t.Fatal("expected error for negative load, got nil")
		}
	})

	t.Run("Load NaN and Inf", func(t *testing.T) {
		for _, invalid := range []string{"NaN 1.0 1.0\n", "1.0 Inf 1.0\n", "1.0 1.0 -Inf\n"} {
			path := createTempFixture(t, invalid)
			_, _, _, err := readProcLoadavg(path)
			if err == nil {
				t.Fatalf("expected error for non-finite load %q, got nil", invalid)
			}
		}
	})

	t.Run("Load malformed", func(t *testing.T) {
		path := createTempFixture(t, "abc 1.0 1.0\n")
		_, _, _, err := readProcLoadavg(path)
		if err == nil {
			t.Fatal("expected error for malformed load, got nil")
		}
	})

	t.Run("Load oversized file", func(t *testing.T) {
		content := "1.00 2.00 3.00 " + strings.Repeat("x", 5000)
		path := createTempFixture(t, content)
		_, _, _, err := readProcLoadavg(path)
		if err == nil {
			t.Fatal("expected error for oversized loadavg, got nil")
		}
	})

	t.Run("Uptime normal fractional to integer floor", func(t *testing.T) {
		path := createTempFixture(t, "350735.47 1400234.12\n")
		uptime, err := readProcUptime(path)
		if err != nil {
			t.Fatalf("readProcUptime failed: %v", err)
		}
		if uptime != 350735 {
			t.Fatalf("expected uptime floor 350735, got %d", uptime)
		}
	})

	t.Run("Uptime zero", func(t *testing.T) {
		path := createTempFixture(t, "0.00 0.00\n")
		uptime, err := readProcUptime(path)
		if err != nil {
			t.Fatalf("readProcUptime failed: %v", err)
		}
		if uptime != 0 {
			t.Fatalf("expected uptime 0, got %d", uptime)
		}
	})

	t.Run("Uptime negative", func(t *testing.T) {
		path := createTempFixture(t, "-10.50 0.00\n")
		_, err := readProcUptime(path)
		if err == nil {
			t.Fatal("expected error for negative uptime, got nil")
		}
	})

	t.Run("Uptime NaN and Inf", func(t *testing.T) {
		for _, invalid := range []string{"NaN 0.0\n", "Inf 0.0\n", "-Inf 0.0\n"} {
			path := createTempFixture(t, invalid)
			_, err := readProcUptime(path)
			if err == nil {
				t.Fatalf("expected error for non-finite uptime %q, got nil", invalid)
			}
		}
	})

	t.Run("Uptime malformed", func(t *testing.T) {
		path := createTempFixture(t, "invalid 0.0\n")
		_, err := readProcUptime(path)
		if err == nil {
			t.Fatal("expected error for malformed uptime, got nil")
		}
	})

	t.Run("Uptime oversized file", func(t *testing.T) {
		content := "100.0 " + strings.Repeat("y", 5000)
		path := createTempFixture(t, content)
		_, err := readProcUptime(path)
		if err == nil {
			t.Fatal("expected error for oversized uptime, got nil")
		}
	})

	t.Run("Load numeric overflow", func(t *testing.T) {
		for _, overflowInput := range []string{
			"1e300 1.00 1.00 1/1 1\n",
			"1e19 1.00 1.00 1/1 1\n",
			"999999999999999999.00 1.00 1.00 1/1 1\n",
		} {
			path := createTempFixture(t, overflowInput)
			_, _, _, err := readProcLoadavg(path)
			if err == nil {
				t.Fatalf("expected error for load overflow %q, got nil", overflowInput)
			}
		}
	})

	t.Run("Uptime numeric overflow", func(t *testing.T) {
		for _, overflowInput := range []string{
			"1e300 0.00\n",
			"1e19 0.00\n",
			"99999999999999999999.00 0.00\n",
		} {
			path := createTempFixture(t, overflowInput)
			_, err := readProcUptime(path)
			if err == nil {
				t.Fatalf("expected error for uptime overflow %q, got nil", overflowInput)
			}
		}
	})
}

func TestLinuxRootFilesystemCollection(t *testing.T) {
	t.Run("normal total, free, available", func(t *testing.T) {
		statfs := func(path string) (uint64, uint64, uint64, uint64, error) {
			return 1000, 400, 300, 4096, nil
		}
		total, used, avail, err := readRootFS(statfs)
		if err != nil {
			t.Fatalf("readRootFS failed: %v", err)
		}
		// total = 1000 * 4096 = 4096000
		// free = 400 * 4096 = 1638400
		// avail = 300 * 4096 = 1228800
		// used = total - free = 2457600
		if total != 4096000 {
			t.Fatalf("expected total 4096000, got %d", total)
		}
		if used != 2457600 {
			t.Fatalf("expected used 2457600, got %d", used)
		}
		if avail != 1228800 {
			t.Fatalf("expected avail 1228800, got %d", avail)
		}
	})

	t.Run("reserved blocks: available < free and used correct", func(t *testing.T) {
		statfs := func(path string) (uint64, uint64, uint64, uint64, error) {
			// free = 200, available = 150 (50 blocks reserved for root)
			return 1000, 200, 150, 4096, nil
		}
		total, used, avail, err := readRootFS(statfs)
		if err != nil {
			t.Fatalf("readRootFS failed: %v", err)
		}
		if total != 4096000 {
			t.Fatalf("expected total 4096000, got %d", total)
		}
		if used != 3276800 { // (1000 - 200) * 4096
			t.Fatalf("expected used 3276800, got %d", used)
		}
		if avail != 614400 { // 150 * 4096
			t.Fatalf("expected avail 614400, got %d", avail)
		}
	})

	t.Run("zero block size", func(t *testing.T) {
		statfs := func(path string) (uint64, uint64, uint64, uint64, error) {
			return 1000, 200, 150, 0, nil
		}
		_, _, _, err := readRootFS(statfs)
		if err == nil {
			t.Fatal("expected error for zero block size, got nil")
		}
	})

	t.Run("free > total invalid", func(t *testing.T) {
		statfs := func(path string) (uint64, uint64, uint64, uint64, error) {
			return 100, 200, 150, 4096, nil
		}
		_, _, _, err := readRootFS(statfs)
		if err == nil {
			t.Fatal("expected error when free > total, got nil")
		}
	})

	t.Run("available > free invalid", func(t *testing.T) {
		statfs := func(path string) (uint64, uint64, uint64, uint64, error) {
			return 1000, 200, 250, 4096, nil
		}
		_, _, _, err := readRootFS(statfs)
		if err == nil {
			t.Fatal("expected error when available > free, got nil")
		}
	})

	t.Run("integer multiplication overflow", func(t *testing.T) {
		statfs := func(path string) (uint64, uint64, uint64, uint64, error) {
			return math.MaxUint64 / 2, 100, 100, 4096, nil
		}
		_, _, _, err := readRootFS(statfs)
		if err == nil {
			t.Fatal("expected error for blocks multiplication overflow, got nil")
		}
	})
}

func TestLinuxNetworkCollection(t *testing.T) {
	t.Run("single interface and lo excluded", func(t *testing.T) {
		content := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1234567       0    0    0    0     0          0         0  1234567       0    0    0    0     0       0          0
  eth0: 1000000       0    0    0    0     0          0         0   500000       0    0    0    0     0       0          0
`
		path := createTempFixture(t, content)
		rx, tx, err := readProcNetDev(path)
		if err != nil {
			t.Fatalf("readProcNetDev failed: %v", err)
		}
		if rx != 1000000 {
			t.Fatalf("expected rx 1000000 (excluding lo), got %d", rx)
		}
		if tx != 500000 {
			t.Fatalf("expected tx 500000 (excluding lo), got %d", tx)
		}
	})

	t.Run("multiple interfaces aggregate", func(t *testing.T) {
		content := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 9999999       0    0    0    0     0          0         0  9999999       0    0    0    0     0       0          0
  eth0: 1000000       0    0    0    0     0          0         0   500000       0    0    0    0     0       0          0
  eth1: 2000000       0    0    0    0     0          0         0   800000       0    0    0    0     0       0          0
  wlan0:  50000       0    0    0    0     0          0         0    20000       0    0    0    0     0       0          0
`
		path := createTempFixture(t, content)
		rx, tx, err := readProcNetDev(path)
		if err != nil {
			t.Fatalf("readProcNetDev failed: %v", err)
		}
		if rx != 3050000 {
			t.Fatalf("expected aggregate rx 3050000, got %d", rx)
		}
		if tx != 1320000 {
			t.Fatalf("expected aggregate tx 1320000, got %d", tx)
		}
	})

	t.Run("zero traffic", func(t *testing.T) {
		content := `Inter-|   Receive
 face |bytes
    lo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
  eth0: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
`
		path := createTempFixture(t, content)
		rx, tx, err := readProcNetDev(path)
		if err != nil {
			t.Fatalf("readProcNetDev failed: %v", err)
		}
		if rx != 0 || tx != 0 {
			t.Fatalf("expected rx=0, tx=0, got rx=%d, tx=%d", rx, tx)
		}
	})

	t.Run("malformed RX and TX", func(t *testing.T) {
		content := `Inter-|   Receive
 face |bytes
  eth0: notanumber 0 0 0 0 0 0 0 500 0 0 0 0 0 0 0
`
		path := createTempFixture(t, content)
		_, _, err := readProcNetDev(path)
		if err == nil {
			t.Fatal("expected error for malformed RX, got nil")
		}
	})

	t.Run("too few fields", func(t *testing.T) {
		content := `Inter-|   Receive
 face |bytes
  eth0: 1000 0 0
`
		path := createTempFixture(t, content)
		_, _, err := readProcNetDev(path)
		if err == nil {
			t.Fatal("expected error for insufficient fields, got nil")
		}
	})

	t.Run("sum overflow and int64 overflow", func(t *testing.T) {
		content := fmt.Sprintf(`Inter-|   Receive
 face |bytes
  eth0: %d 0 0 0 0 0 0 0 %d 0 0 0 0 0 0 0
  eth1: %d 0 0 0 0 0 0 0 %d 0 0 0 0 0 0 0
`, uint64(math.MaxInt64), uint64(math.MaxInt64), uint64(10), uint64(10))
		path := createTempFixture(t, content)
		_, _, err := readProcNetDev(path)
		if err == nil {
			t.Fatal("expected error for byte counter overflow, got nil")
		}
	})

	t.Run("oversized netdev", func(t *testing.T) {
		content := "Inter-| Receive\n face |bytes\n" + strings.Repeat("  ethX: 1 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0\n", 8000)
		if len(content) <= 256*1024 {
			t.Fatalf("fixture size %d is not > 256 KiB", len(content))
		}
		path := createTempFixture(t, content)
		_, _, err := readProcNetDev(path)
		if err == nil {
			t.Fatal("expected error for oversized netdev, got nil")
		}
	})
}

func TestSamplerLifecycleAndBaselineAdvancement(t *testing.T) {
	cfg := linuxSamplerConfig{
		statPath:    createTempFixture(t, "cpu  100 0 0 900 0 0 0 0 0 0\n"),
		meminfoPath: createTempFixture(t, "MemTotal: 1000000 kB\nMemAvailable: 500000 kB\n"),
		loadavgPath: createTempFixture(t, "1.00 2.00 3.00 1/1 1\n"),
		uptimePath:  createTempFixture(t, "100.0 0.0\n"),
		netdevPath:  createTempFixture(t, "  eth0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0\n"),
		statfsFunc: func(path string) (uint64, uint64, uint64, uint64, error) {
			return 1000, 500, 400, 4096, nil
		},
	}
	sampler := newLinuxSampler(cfg)

	t0 := time.Unix(1000, 0)
	req1, ready1, err1 := sampler.Sample(t0)
	if err1 != nil || ready1 || req1 != nil {
		t.Fatalf("sample 1: expected ready=false, err=nil, got ready=%v, err=%v", ready1, err1)
	}

	t1 := t0.Add(30 * time.Second)
	sampler.cfg.statPath = createTempFixture(t, "cpu  350 0 0 1650 0 0 0 0 0 0\n")
	req2, ready2, err2 := sampler.Sample(t1)
	if err2 != nil || !ready2 || req2 == nil {
		t.Fatalf("sample 2: expected ready=true, err=nil, got ready=%v, err=%v", ready2, err2)
	}
	if req2.CPUUsageBasisPoints != 2500 {
		t.Fatalf("expected 2500 basis points, got %d", req2.CPUUsageBasisPoints)
	}
	if req2.SampleWindowMS != 30000 {
		t.Fatalf("expected sample_window_ms == 30000, got %d", req2.SampleWindowMS)
	}

	// Downstream collection error must still advance the CPU baseline.
	t2 := t1.Add(30 * time.Second)
	sampler.cfg.statPath = createTempFixture(t, "cpu  850 0 0 2150 0 0 0 0 0 0\n")
	sampler.cfg.meminfoPath = createTempFixture(t, "invalid meminfo\n")
	req3, ready3, err3 := sampler.Sample(t2)
	if err3 == nil {
		t.Fatal("sample 3: expected error on invalid meminfo, got nil")
	}
	if ready3 || req3 != nil {
		t.Fatalf("sample 3: expected ready=false on error, got ready=%v", ready3)
	}

	// Succeeding sample calculates CPU delta against the previous observation despite its downstream error.
	t3 := t2.Add(30 * time.Second)
	sampler.cfg.statPath = createTempFixture(t, "cpu  1850 0 0 2150 0 0 0 0 0 0\n")
	sampler.cfg.meminfoPath = createTempFixture(t, "MemTotal: 1000000 kB\nMemAvailable: 500000 kB\n")
	req4, ready4, err4 := sampler.Sample(t3)
	if err4 != nil || !ready4 || req4 == nil {
		t.Fatalf("sample 4: expected ready=true, err=nil, got ready=%v, err=%v", ready4, err4)
	}
	if req4.CPUUsageBasisPoints != 10000 {
		t.Fatalf("expected 10000 basis points against advanced baseline, got %d", req4.CPUUsageBasisPoints)
	}
	if req4.SampleWindowMS != 30000 {
		t.Fatalf("expected sample_window_ms == 30000, got %d", req4.SampleWindowMS)
	}

	t5 := t3.Add(301 * time.Second)
	sampler.cfg.statPath = createTempFixture(t, "cpu  2850 0 0 2150 0 0 0 0 0 0\n")
	req5, ready5, err5 := sampler.Sample(t5)
	if err5 != nil {
		t.Fatalf("expected nil error on stale window, got: %v", err5)
	}
	if ready5 || req5 != nil {
		t.Fatalf("expected ready=false on stale window > 5 minutes, got ready=%v", ready5)
	}
}

type sequenceSampler struct {
	mu      sync.Mutex
	calls   int
	samples []struct {
		req   *protocol.TelemetryRequest
		ready bool
		err   error
	}
}

func (s *sequenceSampler) Sample(now time.Time) (*protocol.TelemetryRequest, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := s.calls
	s.calls++
	if idx < len(s.samples) {
		return s.samples[idx].req, s.samples[idx].ready, s.samples[idx].err
	}
	return nil, false, nil
}

func TestPresence_TelemetryIntegration(t *testing.T) {
	t.Run("heartbeat #1 immediate, inventory #1 immediate, telemetry skipped #1 then sent #2 and #3", func(t *testing.T) {
		var (
			mu             sync.Mutex
			hbEndpoints    []string
			invEndpoints   []string
			telemEndpoints []string
			reqClients     []*http.Client
		)

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			switch r.URL.Path {
			case protocol.HeartbeatEndpointPath:
				hbEndpoints = append(hbEndpoints, r.URL.Path)
			case protocol.InventoryEndpointPath:
				invEndpoints = append(invEndpoints, r.URL.Path)
			case protocol.TelemetryEndpointPath:
				telemEndpoints = append(telemEndpoints, r.URL.Path)
			}
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		})

		_, caPEM, ts := setupTestCAAndServer(t, handler)
		defer ts.Close()

		stateDir, _, _ := setupTestEnrolledState(t, ts.URL)
		caFile := filepath.Join(stateDir, "custom-ca.pem")
		_ = os.WriteFile(caFile, caPEM, 0644)
		_ = ValidateAndPersistCAFile(stateDir, caFile)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		callCount := 0
		cfg := defaultPresenceConfig()
		cfg.timerFunc = func(d time.Duration) (<-chan time.Time, func() bool) {
			callCount++
			ch := make(chan time.Time, 1)
			if callCount >= 3 {
				cancel()
			} else {
				ch <- time.Now()
			}
			return ch, func() bool { return true }
		}
		cfg.jitterFunc = func(base time.Duration, pct float64) time.Duration {
			return base
		}

		cfg.collector = func() (*protocol.InventoryRequest, error) {
			return &protocol.InventoryRequest{
				ProtocolVersion:  1,
				Hostname:         "test-host",
				OSID:             "linux",
				OSName:           "Linux",
				OSVersion:        "1.0",
				KernelRelease:    "6.0",
				Architecture:     "amd64",
				CPULogicalCores:  4,
				MemoryTotalBytes: 1024,
			}, nil
		}

		sampleReq := &protocol.TelemetryRequest{
			ProtocolVersion:              1,
			CPUUsageBasisPoints:          1500,
			MemoryTotalBytes:             1000,
			MemoryUsedBytes:              500,
			MemoryAvailableBytes:         500,
			Load1mMilli:                  100,
			Load5mMilli:                  100,
			Load15mMilli:                 100,
			RootFilesystemTotalBytes:     1000,
			RootFilesystemUsedBytes:      500,
			RootFilesystemAvailableBytes: 500,
			NetworkReceiveBytesTotal:     100,
			NetworkTransmitBytesTotal:    100,
			UptimeSeconds:                60,
			SampleWindowMS:               30000,
		}
		sampler := &sequenceSampler{
			samples: []struct {
				req   *protocol.TelemetryRequest
				ready bool
				err   error
			}{
				{req: nil, ready: false, err: nil},
				{req: sampleReq, ready: true, err: nil},
				{req: sampleReq, ready: true, err: nil},
			},
		}
		cfg.sampler = sampler

		var createdClient *http.Client
		cfg.clientBuilder = func(rootCAs *x509.CertPool, cert *tls.Certificate) *http.Client {
			c := BuildAgentHTTPClient(rootCAs, cert)
			origTransport := c.Transport
			c.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				mu.Lock()
				reqClients = append(reqClients, c)
				mu.Unlock()
				return origTransport.RoundTrip(r)
			})
			createdClient = c
			return c
		}

		err := runPresenceWithConfig(ctx, nil, stateDir, cfg)
		if err != nil {
			t.Fatalf("expected clean exit, got: %v", err)
		}

		mu.Lock()
		defer mu.Unlock()

		if len(hbEndpoints) != 3 {
			t.Fatalf("expected 3 heartbeats, got %d", len(hbEndpoints))
		}
		if len(invEndpoints) != 1 {
			t.Fatalf("expected exactly 1 inventory PUT, got %d", len(invEndpoints))
		}
		if len(telemEndpoints) != 2 {
			t.Fatalf("expected exactly 2 telemetry PUTs, got %d", len(telemEndpoints))
		}

		if len(reqClients) < 6 {
			t.Fatalf("expected at least 6 requests, got %d", len(reqClients))
		}
		for i, c := range reqClients {
			if c != createdClient {
				t.Fatalf("request %d did not use the active client pointer", i)
			}
		}
	})

	t.Run("telemetry sampler receives fresh timestamp after inventory execution", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})

		_, caPEM, ts := setupTestCAAndServer(t, handler)
		defer ts.Close()

		stateDir, _, _ := setupTestEnrolledState(t, ts.URL)
		caFile := filepath.Join(stateDir, "custom-ca.pem")
		_ = os.WriteFile(caFile, caPEM, 0644)
		_ = ValidateAndPersistCAFile(stateDir, caFile)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		t0 := time.Unix(1700000000, 0)
		var mu sync.Mutex
		fakeTime := t0

		cfg := defaultPresenceConfig()
		cfg.nowFunc = func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return fakeTime
		}
		cfg.timerFunc = func(d time.Duration) (<-chan time.Time, func() bool) {
			cancel()
			ch := make(chan time.Time, 1)
			return ch, func() bool { return true }
		}
		cfg.jitterFunc = func(base time.Duration, pct float64) time.Duration {
			return base
		}

		cfg.collector = func() (*protocol.InventoryRequest, error) {
			mu.Lock()
			fakeTime = fakeTime.Add(5 * time.Second)
			mu.Unlock()
			return &protocol.InventoryRequest{
				ProtocolVersion:  1,
				Hostname:         "test-host",
				OSID:             "linux",
				OSName:           "Linux",
				OSVersion:        "1.0",
				KernelRelease:    "6.0",
				Architecture:     "amd64",
				CPULogicalCores:  4,
				MemoryTotalBytes: 1024,
			}, nil
		}

		var receivedTime time.Time
		cfg.sampler = &roundTripSampler{
			sampleFunc: func(now time.Time) (*protocol.TelemetryRequest, bool, error) {
				mu.Lock()
				receivedTime = now
				mu.Unlock()
				return nil, false, nil
			},
		}

		err := runPresenceWithConfig(ctx, nil, stateDir, cfg)
		if err != nil {
			t.Fatalf("runPresenceWithConfig failed: %v", err)
		}

		expectedTime := t0.Add(5 * time.Second)
		if !receivedTime.Equal(expectedTime) {
			t.Fatalf("expected telemetry sampler to receive %v, got %v", expectedTime, receivedTime)
		}
	})

	t.Run("heartbeat failure produces no telemetry collection/send", func(t *testing.T) {
		samplerCalled := false
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})

		_, caPEM, ts := setupTestCAAndServer(t, handler)
		defer ts.Close()

		stateDir, _, _ := setupTestEnrolledState(t, ts.URL)
		caFile := filepath.Join(stateDir, "custom-ca.pem")
		_ = os.WriteFile(caFile, caPEM, 0644)
		_ = ValidateAndPersistCAFile(stateDir, caFile)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cfg := defaultPresenceConfig()
		callCount := 0
		cfg.timerFunc = func(d time.Duration) (<-chan time.Time, func() bool) {
			callCount++
			if callCount >= 2 {
				cancel()
			}
			ch := make(chan time.Time, 1)
			ch <- time.Now()
			return ch, func() bool { return true }
		}
		cfg.sampler = &roundTripSampler{
			sampleFunc: func(now time.Time) (*protocol.TelemetryRequest, bool, error) {
				samplerCalled = true
				return nil, false, nil
			},
		}

		_ = runPresenceWithConfig(ctx, nil, stateDir, cfg)
		if samplerCalled {
			t.Fatal("expected telemetry sampler NOT to be called when heartbeat fails")
		}
	})

	t.Run("telemetry transient failure preserves heartbeat and logs single warning transition then recovery", func(t *testing.T) {
		failTelemetry := true
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == protocol.TelemetryEndpointPath {
				if failTelemetry {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			}
			w.WriteHeader(http.StatusNoContent)
		})

		_, caPEM, ts := setupTestCAAndServer(t, handler)
		defer ts.Close()

		stateDir, _, _ := setupTestEnrolledState(t, ts.URL)
		caFile := filepath.Join(stateDir, "custom-ca.pem")
		_ = os.WriteFile(caFile, caPEM, 0644)
		_ = ValidateAndPersistCAFile(stateDir, caFile)

		logBuf := &bytes.Buffer{}
		logger := slog.New(slog.NewTextHandler(logBuf, nil))

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sampleReq := &protocol.TelemetryRequest{
			ProtocolVersion:              1,
			CPUUsageBasisPoints:          1000,
			MemoryTotalBytes:             1000,
			MemoryUsedBytes:              500,
			MemoryAvailableBytes:         500,
			Load1mMilli:                  100,
			Load5mMilli:                  100,
			Load15mMilli:                 100,
			RootFilesystemTotalBytes:     1000,
			RootFilesystemUsedBytes:      500,
			RootFilesystemAvailableBytes: 500,
			NetworkReceiveBytesTotal:     100,
			NetworkTransmitBytesTotal:    100,
			UptimeSeconds:                60,
			SampleWindowMS:               30000,
		}

		callCount := 0
		cfg := defaultPresenceConfig()
		cfg.timerFunc = func(d time.Duration) (<-chan time.Time, func() bool) {
			callCount++
			if callCount == 3 {
				failTelemetry = false
			}
			if callCount >= 4 {
				cancel()
			}
			ch := make(chan time.Time, 1)
			ch <- time.Now()
			return ch, func() bool { return true }
		}
		cfg.jitterFunc = func(base time.Duration, pct float64) time.Duration {
			return base
		}
		cfg.sampler = &roundTripSampler{
			sampleFunc: func(now time.Time) (*protocol.TelemetryRequest, bool, error) {
				return sampleReq, true, nil
			},
		}

		err := runPresenceWithConfig(ctx, logger, stateDir, cfg)
		if err != nil {
			t.Fatalf("expected clean exit, got: %v", err)
		}

		logStr := logBuf.String()
		warnCount := strings.Count(logStr, "agent telemetry delivery failed; will retry")
		if warnCount != 1 {
			t.Fatalf("expected exactly 1 warning transition on repeated telemetry failure, got %d. Logs:\n%s", warnCount, logStr)
		}

		recoveryCount := strings.Count(logStr, "agent telemetry recovered")
		if recoveryCount != 1 {
			t.Fatalf("expected exactly 1 telemetry recovery info log, got %d. Logs:\n%s", recoveryCount, logStr)
		}
	})

	t.Run("telemetry 401 stops daemon immediately as permanent failure", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == protocol.TelemetryEndpointPath {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})

		_, caPEM, ts := setupTestCAAndServer(t, handler)
		defer ts.Close()

		stateDir, _, _ := setupTestEnrolledState(t, ts.URL)
		caFile := filepath.Join(stateDir, "custom-ca.pem")
		_ = os.WriteFile(caFile, caPEM, 0644)
		_ = ValidateAndPersistCAFile(stateDir, caFile)

		sampleReq := &protocol.TelemetryRequest{
			ProtocolVersion:              1,
			CPUUsageBasisPoints:          1000,
			MemoryTotalBytes:             1000,
			MemoryUsedBytes:              500,
			MemoryAvailableBytes:         500,
			Load1mMilli:                  100,
			Load5mMilli:                  100,
			Load15mMilli:                 100,
			RootFilesystemTotalBytes:     1000,
			RootFilesystemUsedBytes:      500,
			RootFilesystemAvailableBytes: 500,
			NetworkReceiveBytesTotal:     100,
			NetworkTransmitBytesTotal:    100,
			UptimeSeconds:                60,
			SampleWindowMS:               30000,
		}

		cfg := defaultPresenceConfig()
		cfg.sampler = &roundTripSampler{
			sampleFunc: func(now time.Time) (*protocol.TelemetryRequest, bool, error) {
				return sampleReq, true, nil
			},
		}

		err := runPresenceWithConfig(context.Background(), nil, stateDir, cfg)
		if err == nil {
			t.Fatal("expected error on telemetry 401, got nil")
		}
		if !errors.Is(err, ErrAuthRejected) {
			t.Fatalf("expected ErrAuthRejected, got: %v", err)
		}
	})

	t.Run("telemetry 409 stops daemon immediately as permanent failure", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == protocol.TelemetryEndpointPath {
				w.WriteHeader(http.StatusConflict)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})

		_, caPEM, ts := setupTestCAAndServer(t, handler)
		defer ts.Close()

		stateDir, _, _ := setupTestEnrolledState(t, ts.URL)
		caFile := filepath.Join(stateDir, "custom-ca.pem")
		_ = os.WriteFile(caFile, caPEM, 0644)
		_ = ValidateAndPersistCAFile(stateDir, caFile)

		sampleReq := &protocol.TelemetryRequest{
			ProtocolVersion:              1,
			CPUUsageBasisPoints:          1000,
			MemoryTotalBytes:             1000,
			MemoryUsedBytes:              500,
			MemoryAvailableBytes:         500,
			Load1mMilli:                  100,
			Load5mMilli:                  100,
			Load15mMilli:                 100,
			RootFilesystemTotalBytes:     1000,
			RootFilesystemUsedBytes:      500,
			RootFilesystemAvailableBytes: 500,
			NetworkReceiveBytesTotal:     100,
			NetworkTransmitBytesTotal:    100,
			UptimeSeconds:                60,
			SampleWindowMS:               30000,
		}

		cfg := defaultPresenceConfig()
		cfg.sampler = &roundTripSampler{
			sampleFunc: func(now time.Time) (*protocol.TelemetryRequest, bool, error) {
				return sampleReq, true, nil
			},
		}

		err := runPresenceWithConfig(context.Background(), nil, stateDir, cfg)
		if err == nil {
			t.Fatal("expected error on telemetry 409, got nil")
		}
		if !errors.Is(err, ErrProtocolMismatch) {
			t.Fatalf("expected ErrProtocolMismatch, got: %v", err)
		}
	})

	t.Run("telemetry unexpected 400 stops daemon immediately as permanent failure", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == protocol.TelemetryEndpointPath {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})

		_, caPEM, ts := setupTestCAAndServer(t, handler)
		defer ts.Close()

		stateDir, _, _ := setupTestEnrolledState(t, ts.URL)
		caFile := filepath.Join(stateDir, "custom-ca.pem")
		_ = os.WriteFile(caFile, caPEM, 0644)
		_ = ValidateAndPersistCAFile(stateDir, caFile)

		sampleReq := &protocol.TelemetryRequest{
			ProtocolVersion:              1,
			CPUUsageBasisPoints:          1000,
			MemoryTotalBytes:             1000,
			MemoryUsedBytes:              500,
			MemoryAvailableBytes:         500,
			Load1mMilli:                  100,
			Load5mMilli:                  100,
			Load15mMilli:                 100,
			RootFilesystemTotalBytes:     1000,
			RootFilesystemUsedBytes:      500,
			RootFilesystemAvailableBytes: 500,
			NetworkReceiveBytesTotal:     100,
			NetworkTransmitBytesTotal:    100,
			UptimeSeconds:                60,
			SampleWindowMS:               30000,
		}

		cfg := defaultPresenceConfig()
		cfg.sampler = &roundTripSampler{
			sampleFunc: func(now time.Time) (*protocol.TelemetryRequest, bool, error) {
				return sampleReq, true, nil
			},
		}

		err := runPresenceWithConfig(context.Background(), nil, stateDir, cfg)
		if err == nil {
			t.Fatal("expected error on telemetry 400, got nil")
		}
		if !IsPermanentError(err) {
			t.Fatalf("expected permanent error on 400, got: %v", err)
		}
	})
}

type roundTripSampler struct {
	sampleFunc func(now time.Time) (*protocol.TelemetryRequest, bool, error)
}

func (s *roundTripSampler) Sample(now time.Time) (*protocol.TelemetryRequest, bool, error) {
	return s.sampleFunc(now)
}
