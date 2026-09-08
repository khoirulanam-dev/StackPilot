//go:build !linux

package agent

import (
	"errors"
)

// EnforceDaemonSecurity returns an error on non-Linux platforms where Linux capability
// and privilege boundaries are unsupported.
func EnforceDaemonSecurity() error {
	return errors.New("stackpilot-agent daemon is only supported on Linux")
}
