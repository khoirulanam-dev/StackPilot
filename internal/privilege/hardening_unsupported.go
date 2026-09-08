//go:build !linux

package privilege

import (
	"errors"
	"os"
)

func HardenProcess() error {
	return errors.New("process hardening via prctl is only supported on Linux")
}

func ValidateHelperEUID(euid int) error {
	if euid != 0 {
		return errors.New("stackpilot-agent-helper must be run as root (effective UID 0)")
	}
	return nil
}

func GetEffectiveUID() int {
	return os.Geteuid()
}
