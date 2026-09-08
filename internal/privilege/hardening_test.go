//go:build linux

package privilege

import (
	"errors"
	"strings"
	"syscall"
	"testing"
)

func TestValidateHelperEUID_Pure(t *testing.T) {
	if err := ValidateHelperEUID(0); err != nil {
		t.Fatalf("expected EUID 0 to be accepted for helper, got: %v", err)
	}

	if err := ValidateHelperEUID(1000); err == nil {
		t.Fatal("expected non-root EUID 1000 to be rejected for helper")
	}

	if err := ValidateHelperEUID(1); err == nil {
		t.Fatal("expected non-root EUID 1 to be rejected for helper")
	}
}

func TestHardenProcess_SeamCases(t *testing.T) {
	t.Run("all-thread syscall success", func(t *testing.T) {
		allThreadsCalled := false
		prctlCalled := false

		mockAllThreads := func(trap, a1, a2, a3, a4, a5, a6 uintptr) (uintptr, uintptr, syscall.Errno) {
			allThreadsCalled = true
			return 0, 0, 0
		}
		mockPrctl := func(option int, arg2, arg3, arg4, arg5 uintptr) error {
			prctlCalled = true
			return nil
		}

		err := hardenProcessWithInvokers(mockAllThreads, mockPrctl)
		if err != nil {
			t.Fatalf("expected success, got: %v", err)
		}
		if !allThreadsCalled || !prctlCalled {
			t.Fatalf("expected both allThreads and prctl to be called")
		}
	})

	t.Run("all-thread syscall failure fails closed", func(t *testing.T) {
		mockAllThreads := func(trap, a1, a2, a3, a4, a5, a6 uintptr) (uintptr, uintptr, syscall.Errno) {
			return 0, 0, syscall.EPERM
		}
		mockPrctl := func(option int, arg2, arg3, arg4, arg5 uintptr) error {
			return nil
		}

		err := hardenProcessWithInvokers(mockAllThreads, mockPrctl)
		if err == nil {
			t.Fatal("expected error on syscall failure")
		}
		if !strings.Contains(err.Error(), "failed to set PR_SET_NO_NEW_PRIVS on all runtime threads") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("cgo ENOTSUP fails closed with clear error", func(t *testing.T) {
		mockAllThreads := func(trap, a1, a2, a3, a4, a5, a6 uintptr) (uintptr, uintptr, syscall.Errno) {
			return 0, 0, syscall.ENOTSUP
		}
		mockPrctl := func(option int, arg2, arg3, arg4, arg5 uintptr) error {
			return nil
		}

		err := hardenProcessWithInvokers(mockAllThreads, mockPrctl)
		if err == nil {
			t.Fatal("expected error on ENOTSUP")
		}
		if !strings.Contains(err.Error(), "process-wide hardening unsupported (cgo-linked runtime)") {
			t.Errorf("unexpected error for ENOTSUP: %v", err)
		}
	})

	t.Run("PR_SET_DUMPABLE failure fails closed", func(t *testing.T) {
		mockAllThreads := func(trap, a1, a2, a3, a4, a5, a6 uintptr) (uintptr, uintptr, syscall.Errno) {
			return 0, 0, 0
		}
		mockPrctl := func(option int, arg2, arg3, arg4, arg5 uintptr) error {
			return errors.New("dumpable prctl failed")
		}

		err := hardenProcessWithInvokers(mockAllThreads, mockPrctl)
		if err == nil {
			t.Fatal("expected error when PR_SET_DUMPABLE fails")
		}
		if !strings.Contains(err.Error(), "failed to set PR_SET_DUMPABLE") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}
