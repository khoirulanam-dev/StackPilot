package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"stackpilot/internal/job"
	"stackpilot/internal/operator"
	"stackpilot/internal/protocol"
)

type mockJobBackend struct {
	mu            sync.Mutex
	jobs          map[uuid.UUID]*job.Job
	events        map[uuid.UUID][]job.JobEvent
	idempotency   map[string]uuid.UUID // operatorID:idempotencyKeyHash -> jobID
	activeCount   map[uuid.UUID]int    // agentID -> active jobs count
	createJobErr  error
	getJobErr     error
	listJobsErr   error
	listEventsErr error
}

func newMockJobBackend() *mockJobBackend {
	return &mockJobBackend{
		jobs:        make(map[uuid.UUID]*job.Job),
		events:      make(map[uuid.UUID][]job.JobEvent),
		idempotency: make(map[string]uuid.UUID),
		activeCount: make(map[uuid.UUID]int),
	}
}

func (m *mockJobBackend) CreateJob(ctx context.Context, operatorID uuid.UUID, agentID uuid.UUID, action job.Action, idempotencyKeyHash [32]byte) (*job.Job, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.createJobErr != nil {
		return nil, false, m.createJobErr
	}

	key := fmt.Sprintf("%s:%x", operatorID, idempotencyKeyHash)
	if existingID, ok := m.idempotency[key]; ok {
		existing := m.jobs[existingID]
		if existing.AgentID != agentID || existing.ActionType != string(action) {
			return nil, false, job.ErrJobIdempotencyConflict
		}
		return existing, false, nil
	}

	if m.activeCount[agentID] >= job.MaxActiveJobsPerAgent {
		return nil, false, job.ErrQueueFull
	}

	newID := uuid.New()
	now := time.Now().UTC()
	j := &job.Job{
		ID:                  newID,
		AgentID:             agentID,
		CreatedByOperatorID: operatorID,
		CreatedByUsername:   "testop",
		IdempotencyKeyHash:  idempotencyKeyHash,
		ActionType:          string(action),
		State:               job.StateQueued,
		Attempt:             0,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	m.jobs[newID] = j
	m.idempotency[key] = newID
	m.activeCount[agentID]++

	ev := job.JobEvent{
		ID:              uuid.New(),
		JobID:           newID,
		EventType:       job.EventJobCreated,
		Attempt:         0,
		ActorType:       job.ActorTypeOperator,
		ActorIdentifier: "testop",
		OccurredAt:      now,
	}
	m.events[newID] = append(m.events[newID], ev)

	return j, true, nil
}

func (m *mockJobBackend) GetJobByID(ctx context.Context, jobID uuid.UUID) (*job.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.getJobErr != nil {
		return nil, m.getJobErr
	}
	j, ok := m.jobs[jobID]
	if !ok {
		return nil, job.ErrJobNotFound
	}
	return j, nil
}

func (m *mockJobBackend) ListJobs(ctx context.Context, limit int, agentID *uuid.UUID, state *job.State) ([]job.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.listJobsErr != nil {
		return nil, m.listJobsErr
	}

	var res []job.Job
	for _, j := range m.jobs {
		if agentID != nil && j.AgentID != *agentID {
			continue
		}
		if state != nil && j.State != *state {
			continue
		}
		res = append(res, *j)
		if len(res) >= limit {
			break
		}
	}
	return res, nil
}

func (m *mockJobBackend) ListJobEvents(ctx context.Context, jobID uuid.UUID, limit int) ([]job.JobEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.listEventsErr != nil {
		return nil, m.listEventsErr
	}
	if _, ok := m.jobs[jobID]; !ok {
		return nil, job.ErrJobNotFound
	}
	evs := m.events[jobID]
	if len(evs) > limit {
		evs = evs[:limit]
	}
	return evs, nil
}

func (m *mockJobBackend) ClaimNextAgentJob(ctx context.Context, agentID uuid.UUID) (*protocol.JobAssignment, error) {
	return nil, nil
}

func (m *mockJobBackend) StartAgentJob(ctx context.Context, agentID uuid.UUID, jobID uuid.UUID, attempt int) error {
	return nil
}

func (m *mockJobBackend) CompleteAgentJob(ctx context.Context, agentID uuid.UUID, jobID uuid.UUID, attempt int, outcome string, failureCode string) error {
	return nil
}

func helperSetupOperatorJobTestServer(t *testing.T) (*mockOperatorBackend, *mockJobBackend, http.Handler) {
	t.Helper()
	opBackend := newMockOperatorBackend()
	jbBackend := newMockJobBackend()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := newHandler(logger, nil, nil, opBackend, jbBackend)
	return opBackend, jbBackend, handler
}

func helperCreateOperatorToken(t *testing.T, opBackend *mockOperatorBackend, username string, role operator.Role) string {
	t.Helper()
	rec := opBackend.addOperator(username, "Password123!", role, false)
	rec.ID = uuid.New().String()
	rawToken, err := operator.GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken failed: %v", err)
	}
	tokenHash := operator.HashSessionToken(rawToken)
	_, _ = opBackend.CreateOperatorSession(context.Background(), rec.ID, tokenHash)
	return rawToken
}

func TestOperatorJobs_CreateRBAC(t *testing.T) {
	opBackend, _, handler := helperSetupOperatorJobTestServer(t)

	agentID := uuid.New().String()
	idempotencyKey := "key-1234567890123456"

	tests := []struct {
		name       string
		role       operator.Role
		wantStatus int
	}{
		{
			name:       "viewer forbidden to create job",
			role:       operator.RoleViewer,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "operator authorized to create job",
			role:       operator.RoleOperator,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "admin authorized to create job",
			role:       operator.RoleAdmin,
			wantStatus: http.StatusCreated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := helperCreateOperatorToken(t, opBackend, "user-"+string(tt.role), tt.role)

			body := map[string]string{
				"agent_id": agentID,
				"action":   "agent.ping",
			}
			jsonBytes, _ := json.Marshal(body)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/operator/jobs", bytes.NewReader(jsonBytes))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", idempotencyKey+"-"+string(tt.role))

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Fatalf("expected status %d, got %d (body: %s)", tt.wantStatus, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestOperatorJobs_CreateValidation(t *testing.T) {
	opBackend, _, handler := helperSetupOperatorJobTestServer(t)
	token := helperCreateOperatorToken(t, opBackend, "optester", operator.RoleOperator)
	agentID := uuid.New().String()

	t.Run("missing Idempotency-Key returns 400", func(t *testing.T) {
		body := map[string]string{
			"agent_id": agentID,
			"action":   "agent.ping",
		}
		jsonBytes, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/operator/jobs", bytes.NewReader(jsonBytes))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}
	})

	t.Run("invalid Idempotency-Key length returns 400", func(t *testing.T) {
		body := map[string]string{
			"agent_id": agentID,
			"action":   "agent.ping",
		}
		jsonBytes, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/operator/jobs", bytes.NewReader(jsonBytes))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "too-short")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}
	})

	t.Run("unknown fields in JSON returns 400", func(t *testing.T) {
		body := `{"agent_id":"` + agentID + `","action":"agent.ping","command":"echo hello"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/operator/jobs", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "valid-idemp-key-1234567")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for unknown fields, got %d", rr.Code)
		}
	})

	t.Run("unknown action returns 400", func(t *testing.T) {
		body := `{"agent_id":"` + agentID + `","action":"agent.reboot"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/operator/jobs", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "valid-idemp-key-1234568")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid action, got %d", rr.Code)
		}
	})

	t.Run("invalid agent UUID returns 400", func(t *testing.T) {
		body := `{"agent_id":"not-a-uuid","action":"agent.ping"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/operator/jobs", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "valid-idemp-key-1234569")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid UUID, got %d", rr.Code)
		}
	})
}

func TestOperatorJobs_IdempotencyReplay(t *testing.T) {
	opBackend, _, handler := helperSetupOperatorJobTestServer(t)
	token := helperCreateOperatorToken(t, opBackend, "optester", operator.RoleOperator)
	agentID := uuid.New().String()
	idempKey := "idemp-key-exact-replay-001"

	body := `{"agent_id":"` + agentID + `","action":"agent.ping"}`

	// First request: 201 Created
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/operator/jobs", strings.NewReader(body))
	req1.Header.Set("Authorization", "Bearer "+token)
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("Idempotency-Key", idempKey)
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusCreated {
		t.Fatalf("expected first request to return 201, got %d", rr1.Code)
	}

	var resp1 map[string]any
	_ = json.Unmarshal(rr1.Body.Bytes(), &resp1)
	jobID1 := resp1["id"]

	// Second request with same operator, key, and body: 200 OK with same job ID
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/operator/jobs", strings.NewReader(body))
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Idempotency-Key", idempKey)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("expected replay request to return 200, got %d", rr2.Code)
	}

	var resp2 map[string]any
	_ = json.Unmarshal(rr2.Body.Bytes(), &resp2)
	if resp2["id"] != jobID1 {
		t.Fatalf("expected identical job ID on replay, got %v vs %v", resp2["id"], jobID1)
	}

	// Conflicting request: same key, different agent: 409 Conflict
	otherAgent := uuid.New().String()
	bodyConf := `{"agent_id":"` + otherAgent + `","action":"agent.ping"}`
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/operator/jobs", strings.NewReader(bodyConf))
	req3.Header.Set("Authorization", "Bearer "+token)
	req3.Header.Set("Content-Type", "application/json")
	req3.Header.Set("Idempotency-Key", idempKey)
	rr3 := httptest.NewRecorder()
	handler.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusConflict {
		t.Fatalf("expected 409 for idempotency conflict, got %d", rr3.Code)
	}
}

func TestOperatorJobs_ListAndGet(t *testing.T) {
	opBackend, jbBackend, handler := helperSetupOperatorJobTestServer(t)
	tokenViewer := helperCreateOperatorToken(t, opBackend, "viewer1", operator.RoleViewer)

	// Pre-populate a job in jbBackend
	agentUUID := uuid.New()
	j, isNew, err := jbBackend.CreateJob(context.Background(), uuid.New(), agentUUID, "agent.ping", [32]byte{1, 2, 3})
	if err != nil || !isNew {
		t.Fatalf("failed to create initial job: %v", err)
	}

	t.Run("viewer can GET one known job", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/operator/jobs/"+j.ID.String(), nil)
		req.Header.Set("Authorization", "Bearer "+tokenViewer)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		var resp map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &resp)
		if resp["id"] != j.ID.String() {
			t.Fatalf("expected job ID %s, got %v", j.ID.String(), resp["id"])
		}
		// Invariant: internal hash or deadlines must not be exposed
		if _, ok := resp["idempotency_key_hash"]; ok {
			t.Error("exposed idempotency_key_hash")
		}
		if _, ok := resp["dispatch_expires_at"]; ok {
			t.Error("exposed dispatch_expires_at")
		}
	})

	t.Run("GET unknown job returns 404", func(t *testing.T) {
		unknownID := uuid.New().String()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/operator/jobs/"+unknownID, nil)
		req.Header.Set("Authorization", "Bearer "+tokenViewer)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", rr.Code)
		}
	})

	t.Run("non-GET on single job returns 405 with Allow: GET", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/operator/jobs/"+j.ID.String(), nil)
		req.Header.Set("Authorization", "Bearer "+tokenViewer)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", rr.Code)
		}
		if rr.Header().Get("Allow") != "GET" {
			t.Fatalf("expected Allow: GET, got %q", rr.Header().Get("Allow"))
		}
	})

	t.Run("viewer can GET job events", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/operator/jobs/"+j.ID.String()+"/events", nil)
		req.Header.Set("Authorization", "Bearer "+tokenViewer)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d (body: %s)", rr.Code, rr.Body.String())
		}
		var evs []map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &evs)
		if len(evs) != 1 {
			t.Fatalf("expected 1 event, got %d", len(evs))
		}
		if evs[0]["event_type"] != job.EventJobCreated {
			t.Errorf("expected job.created event, got %v", evs[0]["event_type"])
		}
	})

	t.Run("viewer can list jobs with query filtering", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/operator/jobs?limit=10&agent_id="+agentUUID.String()+"&state=queued", nil)
		req.Header.Set("Authorization", "Bearer "+tokenViewer)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		var jobsList []map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &jobsList)
		if len(jobsList) != 1 {
			t.Fatalf("expected 1 job, got %d", len(jobsList))
		}
	})

	t.Run("list jobs rejects unknown query parameter with 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/operator/jobs?foo=bar", nil)
		req.Header.Set("Authorization", "Bearer "+tokenViewer)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}
	})

	t.Run("list jobs rejects limit > 200 with 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/operator/jobs?limit=201", nil)
		req.Header.Set("Authorization", "Bearer "+tokenViewer)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}
	})
}
