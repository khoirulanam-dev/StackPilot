package job

import (
	"errors"
	"testing"
)

func TestState_ValidationAndTerminal(t *testing.T) {
	validStates := []State{
		StateQueued,
		StateDispatched,
		StateRunning,
		StateSucceeded,
		StateFailed,
		StateUnknown,
	}

	for _, s := range validStates {
		if !s.Valid() {
			t.Errorf("state %q expected to be valid", s)
		}
	}

	invalidStates := []State{
		"",
		"pending",
		"cancelled",
		"paused",
		"retrying",
		"QUEUED",
	}

	for _, s := range invalidStates {
		if s.Valid() {
			t.Errorf("state %q expected to be invalid", s)
		}
	}

	terminalStates := map[State]bool{
		StateSucceeded: true,
		StateFailed:    true,
		StateUnknown:   true,
	}

	for _, s := range validStates {
		expected := terminalStates[s]
		if s.IsTerminal() != expected {
			t.Errorf("state %q IsTerminal expected %v, got %v", s, expected, s.IsTerminal())
		}
	}
}

func TestState_Transitions(t *testing.T) {
	allStates := []State{
		StateQueued,
		StateDispatched,
		StateRunning,
		StateSucceeded,
		StateFailed,
		StateUnknown,
	}

	validTransitions := map[State]map[State]bool{
		StateQueued: {
			StateDispatched: true,
		},
		StateDispatched: {
			StateRunning: true,
			StateQueued:  true,
			StateFailed:  true,
		},
		StateRunning: {
			StateSucceeded: true,
			StateFailed:    true,
			StateUnknown:   true,
		},
		StateSucceeded: {},
		StateFailed:    {},
		StateUnknown:   {},
	}

	for _, from := range allStates {
		for _, to := range allStates {
			expectedValid := validTransitions[from][to]
			err := ValidateTransition(from, to)
			if expectedValid {
				if err != nil {
					t.Errorf("expected transition %s -> %s to be valid, got: %v", from, to, err)
				}
			} else {
				if err == nil {
					t.Errorf("expected transition %s -> %s to be rejected, got nil", from, to)
				}
				if !errors.Is(err, ErrInvalidStateTransition) {
					t.Errorf("expected ErrInvalidStateTransition for %s -> %s, got: %v", from, to, err)
				}
			}
		}
	}
}

func TestFailureCode_ValidationAndStateConsistency(t *testing.T) {
	validCodes := []FailureCode{
		FailureCodeExecutorError,
		FailureCodeDispatchExhausted,
		FailureCodeExecutionTimeout,
	}
	for _, fc := range validCodes {
		if !fc.Valid() {
			t.Errorf("failure code %q expected to be valid", fc)
		}
	}

	invalidCodes := []FailureCode{
		"",
		"unknown",
		"internal_error",
		"timeout",
	}
	for _, fc := range invalidCodes {
		if fc.Valid() {
			t.Errorf("failure code %q expected to be invalid", fc)
		}
	}

	executorErr := FailureCodeExecutorError
	dispatchExhausted := FailureCodeDispatchExhausted
	timeoutErr := FailureCodeExecutionTimeout
	emptyCode := FailureCode("")
	invalidCode := FailureCode("bad_code")

	cases := []struct {
		state     State
		fc        *FailureCode
		expectErr bool
	}{
		// Succeeded: must be empty
		{StateSucceeded, nil, false},
		{StateSucceeded, &emptyCode, false},
		{StateSucceeded, &executorErr, true},

		// Queued, Dispatched, Running: must be empty
		{StateQueued, nil, false},
		{StateQueued, &executorErr, true},
		{StateDispatched, nil, false},
		{StateDispatched, &dispatchExhausted, true},
		{StateRunning, nil, false},
		{StateRunning, &timeoutErr, true},

		// Failed: executor_error or dispatch_exhausted
		{StateFailed, &executorErr, false},
		{StateFailed, &dispatchExhausted, false},
		{StateFailed, nil, true},
		{StateFailed, &timeoutErr, true},
		{StateFailed, &invalidCode, true},

		// Unknown: execution_timeout only
		{StateUnknown, &timeoutErr, false},
		{StateUnknown, nil, true},
		{StateUnknown, &executorErr, true},
		{StateUnknown, &dispatchExhausted, true},
	}

	for _, tc := range cases {
		err := ValidateStateFailureCode(tc.state, tc.fc)
		if tc.expectErr && err == nil {
			t.Errorf("expected error for state %s with failure code %v", tc.state, tc.fc)
		}
		if !tc.expectErr && err != nil {
			t.Errorf("unexpected error for state %s with failure code %v: %v", tc.state, tc.fc, err)
		}
	}
}
