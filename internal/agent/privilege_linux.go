//go:build linux

package agent

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"stackpilot/internal/privilege"
)

type CapabilitySet struct {
	Inh uint64
	Prm uint64
	Eff uint64
	Bnd uint64
	Amb uint64
}

// parseCapabilities parses Linux capability bitmasks from a status file.
// The Agent process threads must possess zero effective, permitted, inheritable, or ambient
// capabilities. CapBnd may remain non-zero as unprivileged processes retain the bounding set.
func parseCapabilities(content string) (CapabilitySet, error) {
	var caps CapabilitySet
	var seenInh, seenPrm, seenEff, seenBnd, seenAmb bool

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "CapInh":
			v, err := strconv.ParseUint(val, 16, 64)
			if err != nil {
				return caps, fmt.Errorf("malformed CapInh field %q: %w", val, err)
			}
			caps.Inh = v
			seenInh = true
		case "CapPrm":
			v, err := strconv.ParseUint(val, 16, 64)
			if err != nil {
				return caps, fmt.Errorf("malformed CapPrm field %q: %w", val, err)
			}
			caps.Prm = v
			seenPrm = true
		case "CapEff":
			v, err := strconv.ParseUint(val, 16, 64)
			if err != nil {
				return caps, fmt.Errorf("malformed CapEff field %q: %w", val, err)
			}
			caps.Eff = v
			seenEff = true
		case "CapBnd":
			v, err := strconv.ParseUint(val, 16, 64)
			if err != nil {
				return caps, fmt.Errorf("malformed CapBnd field %q: %w", val, err)
			}
			caps.Bnd = v
			seenBnd = true
		case "CapAmb":
			v, err := strconv.ParseUint(val, 16, 64)
			if err != nil {
				return caps, fmt.Errorf("malformed CapAmb field %q: %w", val, err)
			}
			caps.Amb = v
			seenAmb = true
		}
	}

	if err := scanner.Err(); err != nil {
		return caps, fmt.Errorf("error reading status lines: %w", err)
	}

	if !seenInh || !seenPrm || !seenEff || !seenBnd || !seenAmb {
		return caps, errors.New("missing required Linux capability fields in thread status")
	}

	if caps.Inh != 0 || caps.Prm != 0 || caps.Eff != 0 || caps.Amb != 0 {
		return caps, fmt.Errorf("thread retains unauthorized Linux capabilities (CapInh=%016x, CapPrm=%016x, CapEff=%016x, CapAmb=%016x)",
			caps.Inh, caps.Prm, caps.Eff, caps.Amb)
	}

	return caps, nil
}

// checkAllThreadsCapabilities enumerates all thread status files under taskDir (e.g. /proc/self/task)
// and ensures every active thread possesses zero unauthorized capabilities.
func checkAllThreadsCapabilities(taskDir string) error {
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return fmt.Errorf("failed to enumerate task directory %s: %w", taskDir, err)
	}

	verifiedThreads := 0
	for _, entry := range entries {
		tid := entry.Name()
		statusPath := filepath.Join(taskDir, tid, "status")

		data, err := os.ReadFile(statusPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// Thread exited between directory read and status inspection
				continue
			}
			return fmt.Errorf("failed to read thread status at %s: %w", statusPath, err)
		}

		if _, err := parseCapabilities(string(data)); err != nil {
			return fmt.Errorf("capability check failed on thread %s: %w", tid, err)
		}
		verifiedThreads++
	}

	if verifiedThreads == 0 {
		return fmt.Errorf("no active threads found to validate in %s", taskDir)
	}

	return nil
}

func validateAgentEUID(euid int) error {
	if euid == 0 {
		return errors.New("stackpilot-agent daemon must not run as root (effective UID 0)")
	}
	return nil
}

// EnforceDaemonSecurity validates that the agent daemon is non-root, possesses zero unauthorized
// Linux capabilities across all runtime threads, and applies process-wide hardening.
func EnforceDaemonSecurity() error {
	if err := validateAgentEUID(os.Geteuid()); err != nil {
		return err
	}

	if err := checkAllThreadsCapabilities("/proc/self/task"); err != nil {
		return fmt.Errorf("capability boundary violation: %w", err)
	}

	if err := privilege.HardenProcess(); err != nil {
		return fmt.Errorf("process hardening failed: %w", err)
	}

	return nil
}
