package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"stackpilot/internal/enrollment"
	"stackpilot/internal/job"
	"stackpilot/internal/protocol"
)

type mockAgentJobBackend struct {
	mu            sync.Mutex
	jobs          map[uuid.UUID]*job.Job
	events        map[uuid.UUID][]job.JobEvent
	claimErr      error
	startErr      error
	completeErr   error
	startCalls    int
	completeCalls int
}

func newMockAgentJobBackend() *mockAgentJobBackend {
	return &mockAgentJobBackend{
		jobs:   make(map[uuid.UUID]*job.Job),
		events: make(map[uuid.UUID][]job.JobEvent),
	}
}

func (m *mockAgentJobBackend) CreateJob(ctx context.Context, operatorID uuid.UUID, agentID uuid.UUID, action job.Action, idempotencyKeyHash [32]byte) (*job.Job, bool, error) {
	return nil, false, nil
}

func (m *mockAgentJobBackend) GetJobByID(ctx context.Context, jobID uuid.UUID) (*job.Job, error) {
	return nil, nil
}

func (m *mockAgentJobBackend) ListJobs(ctx context.Context, limit int, agentID *uuid.UUID, state *job.State) ([]job.Job, error) {
	return nil, nil
}

func (m *mockAgentJobBackend) ListJobEvents(ctx context.Context, jobID uuid.UUID, limit int) ([]job.JobEvent, error) {
	return nil, nil
}

func (m *mockAgentJobBackend) ClaimNextAgentJob(ctx context.Context, agentID uuid.UUID) (*protocol.JobAssignment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.claimErr != nil {
		return nil, m.claimErr
	}
	for _, j := range m.jobs {
		if j.AgentID == agentID && j.State == job.StateQueued {
			j.State = job.StateDispatched
			j.Attempt++
			now := time.Now()
			j.DispatchedAt = &now
			exp := now.Add(job.DispatchLease)
			j.DispatchExpiresAt = &exp
			return &protocol.JobAssignment{
				JobID:   j.ID.String(),
				Attempt: j.Attempt,
				Action:  j.ActionType,
			}, nil
		}
	}
	return nil, nil
}

func (m *mockAgentJobBackend) StartAgentJob(ctx context.Context, agentID uuid.UUID, jobID uuid.UUID, attempt int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startCalls++
	if m.startErr != nil {
		return m.startErr
	}
	j, ok := m.jobs[jobID]
	if !ok || j.AgentID != agentID || j.Attempt != attempt || j.State != job.StateDispatched {
		return job.ErrJobConflict
	}
	if j.DispatchExpiresAt != nil && time.Now().After(*j.DispatchExpiresAt) {
		return job.ErrJobConflict
	}
	j.State = job.StateRunning
	now := time.Now()
	j.StartedAt = &now
	deadline := now.Add(job.ExecutionResultDeadline)
	j.ExecutionDeadlineAt = &deadline
	j.DispatchExpiresAt = nil
	return nil
}

func (m *mockAgentJobBackend) CompleteAgentJob(ctx context.Context, agentID uuid.UUID, jobID uuid.UUID, attempt int, outcome string, failureCode string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.completeCalls++
	if m.completeErr != nil {
		return m.completeErr
	}
	j, ok := m.jobs[jobID]
	if !ok || j.AgentID != agentID || j.Attempt != attempt {
		return job.ErrJobConflict
	}

	if j.State == job.StateRunning {
		if j.ExecutionDeadlineAt != nil && time.Now().After(*j.ExecutionDeadlineAt) {
			j.State = job.StateUnknown
			fc := string(job.FailureCodeExecutionTimeout)
			j.FailureCode = &fc
			return job.ErrJobConflict
		}
		if outcome == "succeeded" {
			j.State = job.StateSucceeded
			j.FailureCode = nil
		} else if outcome == "failed" {
			j.State = job.StateFailed
			fc := string(job.FailureCodeExecutorError)
			j.FailureCode = &fc
		} else {
			return job.ErrJobConflict
		}
		now := time.Now()
		j.FinishedAt = &now
		return nil
	}

	// Idempotent replay: exact terminal match
	if string(j.State) == outcome {
		if outcome == "succeeded" && (j.FailureCode == nil || *j.FailureCode == "") && failureCode == "" {
			return nil
		}
		if outcome == "failed" && j.FailureCode != nil && *j.FailureCode == failureCode {
			return nil
		}
	}
	return job.ErrJobConflict
}

func helperSetupAgentJobTest(t *testing.T) (*fakeAuthBackend, *mockAgentJobBackend, http.Handler, [32]byte, *x509.Certificate, string) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	authBackend := &fakeAuthBackend{}
	jbBackend := newMockAgentJobBackend()
	handler := newRemoteHandler(logger, authBackend, authBackend, jbBackend)

	now := time.Now()
	pub, _, cert := helperGenerateEd25519Cert(t, now.Add(-5*time.Minute), now.Add(1*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, "", nil)

	var pubKeyBytes [32]byte
	copy(pubKeyBytes[:], pub)
	agentID := uuid.New().String()

	authBackend.mu.Lock()
	authBackend.agents = map[[32]byte]*enrollment.AgentRecord{
		pubKeyBytes: {
			ID:        agentID,
			PublicKey: pubKeyBytes,
			CreatedAt: now.UTC(),
		},
	}
	authBackend.mu.Unlock()

	return authBackend, jbBackend, handler, pubKeyBytes, cert, agentID
}

func TestAgentJob_StartSecurity(t *testing.T) {
	_, jbBackend, handler, _, cert, agentIDStr := helperSetupAgentJobTest(t)
	agentUUID := uuid.MustParse(agentIDStr)
	jobUUID := uuid.New()

	now := time.Now()
	exp := now.Add(job.DispatchLease)
	jbBackend.jobs[jobUUID] = &job.Job{
		ID:                jobUUID,
		AgentID:           agentUUID,
		State:             job.StateDispatched,
		Attempt:           1,
		DispatchedAt:      &now,
		DispatchExpiresAt: &exp,
	}

	t.Run("start without TLS certificate returns 401", func(t *testing.T) {
		body := `{"protocol_version":2,"job_id":"` + jobUUID.String() + `","attempt":1}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/job/start", strings.NewReader(body))
		req.TLS = &tls.ConnectionState{} // no peer certificates
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rr.Code)
		}
	})

	t.Run("start with wrong attempt returns 409", func(t *testing.T) {
		body := `{"protocol_version":2,"job_id":"` + jobUUID.String() + `","attempt":2}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/job/start", strings.NewReader(body))
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusConflict {
			t.Fatalf("expected 409, got %d", rr.Code)
		}
	})

	t.Run("valid start returns 204", func(t *testing.T) {
		body := `{"protocol_version":2,"job_id":"` + jobUUID.String() + `","attempt":1}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/job/start", strings.NewReader(body))
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", rr.Code)
		}
	})

	t.Run("duplicate start is NOT idempotent and returns 409", func(t *testing.T) {
		// Second start request for the already running job
		body := `{"protocol_version":2,"job_id":"` + jobUUID.String() + `","attempt":1}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/job/start", strings.NewReader(body))
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusConflict {
			t.Fatalf("expected 409 on duplicate start CAS, got %d", rr.Code)
		}
	})
}

func TestAgentJob_CompleteEndpoints(t *testing.T) {
	_, jbBackend, handler, _, cert, agentIDStr := helperSetupAgentJobTest(t)
	agentUUID := uuid.MustParse(agentIDStr)
	jobUUID := uuid.New()

	now := time.Now()
	deadline := now.Add(job.ExecutionResultDeadline)
	jbBackend.jobs[jobUUID] = &job.Job{
		ID:                  jobUUID,
		AgentID:             agentUUID,
		State:               job.StateRunning,
		Attempt:             1,
		StartedAt:           &now,
		ExecutionDeadlineAt: &deadline,
	}

	t.Run("success with failure_code returns 400", func(t *testing.T) {
		body := `{"protocol_version":2,"job_id":"` + jobUUID.String() + `","attempt":1,"outcome":"succeeded","failure_code":"executor_error"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/job/complete", strings.NewReader(body))
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}
	})

	t.Run("failed without failure_code returns 400", func(t *testing.T) {
		body := `{"protocol_version":2,"job_id":"` + jobUUID.String() + `","attempt":1,"outcome":"failed"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/job/complete", strings.NewReader(body))
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}
	})

	t.Run("valid complete succeeded returns 204", func(t *testing.T) {
		body := `{"protocol_version":2,"job_id":"` + jobUUID.String() + `","attempt":1,"outcome":"succeeded"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/job/complete", strings.NewReader(body))
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", rr.Code)
		}
	})

	t.Run("exact completion replay returns 204", func(t *testing.T) {
		body := `{"protocol_version":2,"job_id":"` + jobUUID.String() + `","attempt":1,"outcome":"succeeded"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/job/complete", strings.NewReader(body))
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("expected 204 on exact replay, got %d", rr.Code)
		}
	})

	t.Run("conflicting completion replay returns 409", func(t *testing.T) {
		body := `{"protocol_version":2,"job_id":"` + jobUUID.String() + `","attempt":1,"outcome":"failed","failure_code":"executor_error"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/job/complete", strings.NewReader(body))
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusConflict {
			t.Fatalf("expected 409 on conflicting replay, got %d", rr.Code)
		}
	})
}

func TestAgentJob_LateCompletionTransitionsToUnknown(t *testing.T) {
	_, jbBackend, handler, _, cert, agentIDStr := helperSetupAgentJobTest(t)
	agentUUID := uuid.MustParse(agentIDStr)
	jobUUID := uuid.New()

	past := time.Now().Add(-10 * time.Second)
	jbBackend.jobs[jobUUID] = &job.Job{
		ID:                  jobUUID,
		AgentID:             agentUUID,
		State:               job.StateRunning,
		Attempt:             1,
		StartedAt:           &past,
		ExecutionDeadlineAt: &past, // expired
	}

	body := `{"protocol_version":2,"job_id":"` + jobUUID.String() + `","attempt":1,"outcome":"succeeded"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/job/complete", strings.NewReader(body))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409 for late completion, got %d", rr.Code)
	}

	j := jbBackend.jobs[jobUUID]
	if j.State != job.StateUnknown {
		t.Fatalf("expected late job to become unknown, got %s", j.State)
	}
	if j.FailureCode == nil || *j.FailureCode != string(job.FailureCodeExecutionTimeout) {
		t.Fatalf("expected failure_code execution_timeout, got %v", j.FailureCode)
	}
}
