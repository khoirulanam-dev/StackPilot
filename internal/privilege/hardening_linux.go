//go:build linux

package privilege

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// allThreadsSyscallInvoker is an unexported type for testing hardening behavior.
type allThreadsSyscallInvoker func(trap, a1, a2, a3, a4, a5, a6 uintptr) (uintptr, uintptr, syscall.Errno)
type prctlInvoker func(option int, arg2, arg3, arg4, arg5 uintptr) error

func defaultAllThreadsSyscall(trap, a1, a2, a3, a4, a5, a6 uintptr) (uintptr, uintptr, syscall.Errno) {
	return syscall.AllThreadsSyscall6(trap, a1, a2, a3, a4, a5, a6)
}

func defaultPrctl(option int, arg2, arg3, arg4, arg5 uintptr) error {
	return unix.Prctl(option, arg2, arg3, arg4, arg5)
}

// HardenProcess applies process-wide kernel security restrictions:
//  1. PR_SET_NO_NEW_PRIVS=1 applied to all Go runtime OS threads via syscall.AllThreadsSyscall6.
//     This ensures no current or future child thread can gain privileges across execve.
//     If AllThreadsSyscall reports ENOTSUP (due to cgo linkage), it fails closed.
//  2. PR_SET_DUMPABLE=0 prevents ptrace attachment, core dumping, and inspection of /proc/[pid]/mem.
func HardenProcess() error {
	return hardenProcessWithInvokers(defaultAllThreadsSyscall, defaultPrctl)
}

func hardenProcessWithInvokers(allThreads allThreadsSyscallInvoker, prctl prctlInvoker) error {
	_, _, errno := allThreads(unix.SYS_PRCTL, uintptr(unix.PR_SET_NO_NEW_PRIVS), 1, 0, 0, 0, 0)
	if errno != 0 {
		if errors.Is(errno, syscall.ENOTSUP) {
			return fmt.Errorf("process-wide hardening unsupported (cgo-linked runtime): %w", errno)
		}
		return fmt.Errorf("failed to set PR_SET_NO_NEW_PRIVS on all runtime threads: %w", errno)
	}

	if err := prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("failed to set PR_SET_DUMPABLE: %w", err)
	}

	return nil
}

// ValidateHelperEUID enforces that the helper process is executing as root (effective UID 0).
func ValidateHelperEUID(euid int) error {
	if euid != 0 {
		return errors.New("stackpilot-agent-helper must be run as root (effective UID 0)")
	}
	return nil
}

// GetEffectiveUID returns the effective user ID of the current process.
func GetEffectiveUID() int {
	return os.Geteuid()
}
