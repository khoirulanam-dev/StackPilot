//go:build linux

package agent

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"stackpilot/internal/protocol"
)

const (
	maxCPUStatLineBytes = 4 * 1024
	maxLoadavgBytes     = 4 * 1024
	maxUptimeBytes      = 4 * 1024
	maxNetDevBytes      = 256 * 1024
)

type linuxSamplerConfig struct {
	statPath    string
	meminfoPath string
	loadavgPath string
	uptimePath  string
	netdevPath  string
	statfsFunc  func(path string) (blocks, bfree, bavail, bsize uint64, err error)
}

func defaultLinuxSamplerConfig() linuxSamplerConfig {
	return linuxSamplerConfig{
		statPath:    "/proc/stat",
		meminfoPath: "/proc/meminfo",
		loadavgPath: "/proc/loadavg",
		uptimePath:  "/proc/uptime",
		netdevPath:  "/proc/net/dev",
		statfsFunc:  defaultStatfs,
	}
}

func defaultStatfs(path string) (uint64, uint64, uint64, uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0, 0, 0, err
	}
	return stat.Blocks, stat.Bfree, stat.Bavail, uint64(stat.Bsize), nil
}

type linuxSampler struct {
	cfg            linuxSamplerConfig
	hasCPUBaseline bool
	lastCPUTotal   uint64
	lastCPUIdle    uint64
	lastCPUTime    time.Time
}

func newLinuxSampler(cfg linuxSamplerConfig) *linuxSampler {
	return &linuxSampler{cfg: cfg}
}

func newTelemetrySampler() telemetrySampler {
	return newLinuxSampler(defaultLinuxSamplerConfig())
}

func (s *linuxSampler) Sample(now time.Time) (*protocol.TelemetryRequest, bool, error) {
	curTotal, curIdle, err := readProcStatCPU(s.cfg.statPath)
	if err != nil {
		return nil, false, err
	}

	if !s.hasCPUBaseline {
		s.hasCPUBaseline = true
		s.lastCPUTotal = curTotal
		s.lastCPUIdle = curIdle
		s.lastCPUTime = now
		return nil, false, nil
	}

	elapsed := now.Sub(s.lastCPUTime)
	sampleWindowMS := elapsed.Milliseconds()

	// Bound sample window: 1 ms <= window <= 300,000 ms (5 minutes).
	// Stale windows, backward clock, counter reset, or zero total delta trigger silent rebaseline.
	if sampleWindowMS < 1 || sampleWindowMS > 300000 || curTotal < s.lastCPUTotal || curIdle < s.lastCPUIdle || curTotal == s.lastCPUTotal {
		s.lastCPUTotal = curTotal
		s.lastCPUIdle = curIdle
		s.lastCPUTime = now
		return nil, false, nil
	}

	totalDelta := curTotal - s.lastCPUTotal
	idleDelta := curIdle - s.lastCPUIdle
	if idleDelta > totalDelta {
		s.lastCPUTotal = curTotal
		s.lastCPUIdle = curIdle
		s.lastCPUTime = now
		return nil, false, nil
	}

	busyDelta := totalDelta - idleDelta
	var cpuBasisPoints int
	if busyDelta > math.MaxUint64/10000 {
		cpuBasisPoints = int(new(big.Int).Div(
			new(big.Int).Mul(new(big.Int).SetUint64(busyDelta), big.NewInt(10000)),
			new(big.Int).SetUint64(totalDelta),
		).Int64())
	} else {
		cpuBasisPoints = int((busyDelta * 10000) / totalDelta)
	}

	if cpuBasisPoints < 0 {
		cpuBasisPoints = 0
	}
	if cpuBasisPoints > 10000 {
		cpuBasisPoints = 10000
	}

	// Advance CPU baseline immediately so transient downstream collection failures do not extend sample window.
	s.lastCPUTotal = curTotal
	s.lastCPUIdle = curIdle
	s.lastCPUTime = now

	memTotal, memUsed, memAvail, err := readProcMeminfo(s.cfg.meminfoPath)
	if err != nil {
		return nil, false, err
	}

	load1, load5, load15, err := readProcLoadavg(s.cfg.loadavgPath)
	if err != nil {
		return nil, false, err
	}

	fsTotal, fsUsed, fsAvail, err := readRootFS(s.cfg.statfsFunc)
	if err != nil {
		return nil, false, err
	}

	netRX, netTX, err := readProcNetDev(s.cfg.netdevPath)
	if err != nil {
		return nil, false, err
	}

	uptimeSec, err := readProcUptime(s.cfg.uptimePath)
	if err != nil {
		return nil, false, err
	}

	req := &protocol.TelemetryRequest{
		ProtocolVersion:              protocol.CurrentVersion,
		CPUUsageBasisPoints:          cpuBasisPoints,
		MemoryTotalBytes:             memTotal,
		MemoryUsedBytes:              memUsed,
		MemoryAvailableBytes:         memAvail,
		Load1mMilli:                  load1,
		Load5mMilli:                  load5,
		Load15mMilli:                 load15,
		RootFilesystemTotalBytes:     fsTotal,
		RootFilesystemUsedBytes:      fsUsed,
		RootFilesystemAvailableBytes: fsAvail,
		NetworkReceiveBytesTotal:     netRX,
		NetworkTransmitBytesTotal:    netTX,
		UptimeSeconds:                uptimeSec,
		SampleWindowMS:               sampleWindowMS,
	}

	if err := protocol.ValidateTelemetryRequest(req); err != nil {
		return nil, false, fmt.Errorf("local telemetry validation failed: %w", err)
	}

	return req, true, nil
}

func readCPUStatFirstLine(path string, maxLineBytes int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	limited := io.LimitReader(f, maxLineBytes+1)
	reader := bufio.NewReader(limited)

	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}

	if int64(len(line)) > maxLineBytes {
		return "", fmt.Errorf("aggregate cpu line in %s exceeds maximum allowed size of %d bytes", path, maxLineBytes)
	}

	trimmed := strings.TrimRight(line, "\r\n")
	if trimmed == "" {
		return "", errors.New("empty /proc/stat file")
	}

	return trimmed, nil
}

func readProcStatCPU(path string) (total uint64, idle uint64, err error) {
	line, err := readCPUStatFirstLine(path, maxCPUStatLineBytes)
	if err != nil {
		return 0, 0, err
	}

	if !strings.HasPrefix(line, "cpu ") {
		return 0, 0, errors.New("aggregate cpu line not found in /proc/stat")
	}

	fields := strings.Fields(line)
	if len(fields) < 5 {
		return 0, 0, errors.New("malformed cpu line in /proc/stat: insufficient fields")
	}

	user, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid cpu user counter: %w", err)
	}
	nice, err := strconv.ParseUint(fields[2], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid cpu nice counter: %w", err)
	}
	system, err := strconv.ParseUint(fields[3], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid cpu system counter: %w", err)
	}
	idleVal, err := strconv.ParseUint(fields[4], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid cpu idle counter: %w", err)
	}

	var iowait, irq, softirq, steal uint64
	if len(fields) > 5 {
		iowait, err = strconv.ParseUint(fields[5], 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid cpu iowait counter: %w", err)
		}
	}
	if len(fields) > 6 {
		irq, err = strconv.ParseUint(fields[6], 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid cpu irq counter: %w", err)
		}
	}
	if len(fields) > 7 {
		softirq, err = strconv.ParseUint(fields[7], 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid cpu softirq counter: %w", err)
		}
	}
	if len(fields) > 8 {
		steal, err = strconv.ParseUint(fields[8], 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid cpu steal counter: %w", err)
		}
	}

	// Guest counters are already included in user and nice; omitting to avoid double-counting.
	idleAll := idleVal + iowait
	if idleAll < idleVal {
		return 0, 0, errors.New("cpu idle counter overflow")
	}

	nonIdle := user + nice
	if nonIdle < user {
		return 0, 0, errors.New("cpu user/nice counter overflow")
	}
	nonIdle += system
	if nonIdle < system {
		return 0, 0, errors.New("cpu system counter overflow")
	}
	nonIdle += irq
	if nonIdle < irq {
		return 0, 0, errors.New("cpu irq counter overflow")
	}
	nonIdle += softirq
	if nonIdle < softirq {
		return 0, 0, errors.New("cpu softirq counter overflow")
	}
	nonIdle += steal
	if nonIdle < steal {
		return 0, 0, errors.New("cpu steal counter overflow")
	}

	totalVal := idleAll + nonIdle
	if totalVal < idleAll {
		return 0, 0, errors.New("cpu total counter overflow")
	}

	return totalVal, idleAll, nil
}

func readProcMeminfo(path string) (total int64, used int64, available int64, err error) {
	data, err := readBoundedFile(path, maxMeminfoBytes)
	if err != nil {
		return 0, 0, 0, err
	}

	var hasTotal, hasAvailable bool
	var totalBytes, availBytes int64

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) != 3 || fields[0] != "MemTotal:" || fields[2] != "kB" {
				return 0, 0, 0, errors.New("malformed MemTotal line in /proc/meminfo")
			}
			kb, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				return 0, 0, 0, fmt.Errorf("invalid MemTotal integer %q: %w", fields[1], err)
			}
			if kb <= 0 {
				return 0, 0, 0, fmt.Errorf("invalid MemTotal value %d: must be positive", kb)
			}
			if kb > math.MaxInt64/1024 {
				return 0, 0, 0, fmt.Errorf("MemTotal value %d kB causes int64 overflow", kb)
			}
			totalBytes = kb * 1024
			hasTotal = true
		} else if strings.HasPrefix(line, "MemAvailable:") {
			fields := strings.Fields(line)
			if len(fields) != 3 || fields[0] != "MemAvailable:" || fields[2] != "kB" {
				return 0, 0, 0, errors.New("malformed MemAvailable line in /proc/meminfo")
			}
			kb, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				return 0, 0, 0, fmt.Errorf("invalid MemAvailable integer %q: %w", fields[1], err)
			}
			if kb < 0 {
				return 0, 0, 0, fmt.Errorf("invalid MemAvailable value %d: must be non-negative", kb)
			}
			if kb > math.MaxInt64/1024 {
				return 0, 0, 0, fmt.Errorf("MemAvailable value %d kB causes int64 overflow", kb)
			}
			availBytes = kb * 1024
			hasAvailable = true
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, 0, err
	}

	if !hasTotal {
		return 0, 0, 0, errors.New("MemTotal not found in /proc/meminfo")
	}
	if !hasAvailable {
		return 0, 0, 0, errors.New("MemAvailable not found in /proc/meminfo")
	}
	if availBytes > totalBytes {
		return 0, 0, 0, errors.New("MemAvailable exceeds MemTotal in /proc/meminfo")
	}

	usedBytes := totalBytes - availBytes
	return totalBytes, usedBytes, availBytes, nil
}

func parseLoadMilli(s string) (int64, error) {
	if strings.Contains(s, "-") || strings.Contains(s, "+") {
		return 0, errors.New("negative or signed load average")
	}
	lower := strings.ToLower(s)
	if strings.Contains(lower, "nan") || strings.Contains(lower, "inf") {
		return 0, errors.New("non-finite load average")
	}

	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid load average format: %w", err)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 9223372036854000.0 {
		return 0, errors.New("load average out of bounds")
	}

	milli := int64(math.Round(f * 1000))
	if milli < 0 {
		return 0, errors.New("negative load average")
	}
	return milli, nil
}

func readProcLoadavg(path string) (load1, load5, load15 int64, err error) {
	data, err := readBoundedFile(path, maxLoadavgBytes)
	if err != nil {
		return 0, 0, 0, err
	}

	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, 0, 0, errors.New("insufficient fields in /proc/loadavg")
	}

	l1, err := parseLoadMilli(fields[0])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid load 1m: %w", err)
	}
	l5, err := parseLoadMilli(fields[1])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid load 5m: %w", err)
	}
	l15, err := parseLoadMilli(fields[2])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid load 15m: %w", err)
	}

	return l1, l5, l15, nil
}

func readProcUptime(path string) (int64, error) {
	data, err := readBoundedFile(path, maxUptimeBytes)
	if err != nil {
		return 0, err
	}

	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0, errors.New("empty /proc/uptime")
	}

	token := fields[0]
	if strings.Contains(token, "-") || strings.Contains(token, "+") {
		return 0, errors.New("signed uptime value")
	}
	lower := strings.ToLower(token)
	if strings.Contains(lower, "nan") || strings.Contains(lower, "inf") {
		return 0, errors.New("non-finite uptime")
	}

	f, err := strconv.ParseFloat(token, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid uptime format: %w", err)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 9223372036854774784.0 {
		return 0, errors.New("uptime out of bounds")
	}

	sec := int64(math.Floor(f))
	if sec < 0 {
		return 0, errors.New("negative uptime")
	}
	return sec, nil
}

func readRootFS(statfsFunc func(path string) (blocks, bfree, bavail, bsize uint64, err error)) (total, used, available int64, err error) {
	blocks, bfree, bavail, bsize, err := statfsFunc("/")
	if err != nil {
		return 0, 0, 0, fmt.Errorf("statfs failed: %w", err)
	}
	if bsize == 0 {
		return 0, 0, 0, errors.New("statfs returned zero block size")
	}
	if blocks == 0 {
		return 0, 0, 0, errors.New("statfs returned zero total blocks")
	}
	if blocks > math.MaxInt64/bsize {
		return 0, 0, 0, errors.New("statfs total blocks overflow")
	}
	if bfree > blocks {
		return 0, 0, 0, errors.New("statfs free blocks exceed total blocks")
	}
	if bavail > bfree {
		return 0, 0, 0, errors.New("statfs available blocks exceed free blocks")
	}

	totalBytes := int64(blocks * bsize)
	freeBytes := int64(bfree * bsize)
	availableBytes := int64(bavail * bsize)
	usedBytes := totalBytes - freeBytes

	if totalBytes <= 0 || usedBytes < 0 || usedBytes > totalBytes || availableBytes < 0 || availableBytes > (totalBytes-usedBytes) {
		return 0, 0, 0, errors.New("invalid filesystem byte calculations")
	}

	return totalBytes, usedBytes, availableBytes, nil
}

func readProcNetDev(path string) (rxBytes, txBytes int64, err error) {
	data, err := readBoundedFile(path, maxNetDevBytes)
	if err != nil {
		return 0, 0, err
	}

	var rxTotal, txTotal uint64
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		colonIdx := strings.Index(line, ":")
		if colonIdx == -1 {
			continue
		}

		// Interface names are parsed transiently solely to filter loopback and must never be exposed or logged.
		iface := strings.TrimSpace(line[:colonIdx])
		if iface == "lo" {
			continue
		}

		rest := strings.TrimSpace(line[colonIdx+1:])
		fields := strings.Fields(rest)
		if len(fields) < 9 {
			return 0, 0, errors.New("malformed network statistics line")
		}

		rx, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return 0, 0, errors.New("invalid network receive counter")
		}
		tx, err := strconv.ParseUint(fields[8], 10, 64)
		if err != nil {
			return 0, 0, errors.New("invalid network transmit counter")
		}

		if rx > math.MaxInt64-rxTotal || tx > math.MaxInt64-txTotal {
			return 0, 0, errors.New("network byte counter overflow")
		}

		rxTotal += rx
		txTotal += tx
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}

	return int64(rxTotal), int64(txTotal), nil
}
