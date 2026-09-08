package job

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestJobConstants(t *testing.T) {
	if DispatchLease != 30*time.Second {
		t.Errorf("expected DispatchLease 30s, got %v", DispatchLease)
	}
	if MaxDispatchAttempts != 5 {
		t.Errorf("expected MaxDispatchAttempts 5, got %v", MaxDispatchAttempts)
	}
	if ExecutionResultDeadline != 60*time.Second {
		t.Errorf("expected ExecutionResultDeadline 60s, got %v", ExecutionResultDeadline)
	}
	if MaxActiveJobsPerAgent != 64 {
		t.Errorf("expected MaxActiveJobsPerAgent 64, got %v", MaxActiveJobsPerAgent)
	}

	expectedEvents := []string{
		EventJobCreated,
		EventJobDispatched,
		EventJobRequeued,
		EventJobStarted,
		EventJobSucceeded,
		EventJobFailed,
		EventJobUnknown,
	}
	for _, e := range expectedEvents {
		if e == "" {
			t.Error("event constant cannot be empty")
		}
	}

	expectedActors := []string{
		ActorTypeOperator,
		ActorTypeAgent,
		ActorTypeController,
	}
	for _, a := range expectedActors {
		if a == "" {
			t.Error("actor constant cannot be empty")
		}
	}
}

func TestValidateCanonicalUUID(t *testing.T) {
	validUUID := uuid.New().String()
	parsed, err := ValidateCanonicalUUID(validUUID)
	if err != nil {
		t.Fatalf("expected valid UUID %q to pass: %v", validUUID, err)
	}
	if parsed.String() != validUUID {
		t.Fatalf("parsed UUID string %q != original %q", parsed.String(), validUUID)
	}

	// Uppercase must be rejected
	upperUUID := strings.ToUpper(validUUID)
	if _, err := ValidateCanonicalUUID(upperUUID); !errors.Is(err, ErrInvalidUUID) {
		t.Errorf("expected ErrInvalidUUID for uppercase UUID, got: %v", err)
	}

	// Invalid format
	invalidUUIDs := []string{
		"",
		"not-a-uuid",
		"12345678-1234-1234-1234-1234567890a",
		"12345678-1234-1234-1234-1234567890abcdef",
		"{12345678-1234-1234-1234-1234567890ab}",
		"urn:uuid:12345678-1234-1234-1234-1234567890ab",
	}
	for _, u := range invalidUUIDs {
		if _, err := ValidateCanonicalUUID(u); !errors.Is(err, ErrInvalidUUID) {
			t.Errorf("expected ErrInvalidUUID for %q, got: %v", u, err)
		}
	}
}
