package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"stackpilot/internal/agent"
	"stackpilot/internal/enrollment"
	"stackpilot/internal/job"
	"stackpilot/internal/operator"
	"stackpilot/internal/protocol"
)

func setupE2EEnrolledState(t *testing.T, controllerURL string) (string, [32]byte) {
	t.Helper()

	tempDir := t.TempDir()
	stateDir := filepath.Join(tempDir, "state")
	if err := agent.EnsureStateDir(stateDir); err != nil {
		t.Fatalf("EnsureStateDir failed: %v", err)
	}

	pub, _, err := agent.LoadOrGenerateKey(stateDir, rand.Reader)
	if err != nil {
		t.Fatalf("LoadOrGenerateKey failed: %v", err)
	}

	meta := &agent.IdentityMetadata{
		Version:       1,
		AgentID:       "018f0000-0000-7000-8000-000000000005",
		ControllerURL: controllerURL,
		PublicKey:     agent.FormatPublicKeyBase64RawURL(pub),
	}
	if err := agent.WriteIdentityMetadata(stateDir, meta); err != nil {
		t.Fatalf("WriteIdentityMetadata failed: %v", err)
	}

	var pubKey [32]byte
	copy(pubKey[:], pub)
	return stateDir, pubKey
}

func setupE2ECAAndServer(t *testing.T, handler http.Handler) (*tls.Certificate, []byte, *httptest.Server) {
	t.Helper()

	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey failed: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "StackPilot Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caPriv)
	if err != nil {
		t.Fatalf("CreateCertificate CA failed: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	srvPub, srvPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey srv failed: %v", err)
	}
	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(101),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, srvPub, caPriv)
	if err != nil {
		t.Fatalf("CreateCertificate srv failed: %v", err)
	}
	srvTLSCert := tls.Certificate{
		Certificate: [][]byte{srvDER},
		PrivateKey:  srvPriv,
	}

	ts := httptest.NewUnstartedServer(handler)
	ts.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{srvTLSCert},
		ClientAuth:   tls.RequestClientCert,
	}
	ts.StartTLS()

	return &srvTLSCert, caPEM, ts
}

// unifiedE2EBackend is a complete in-memory backend supporting enrollment, presence, operator auth, and jobs.
type unifiedE2EBackend struct {
	mu          sync.Mutex
	agents      map[[32]byte]*enrollment.AgentRecord
	operators   map[string]*operator.OperatorRecord
	sessions    map[[32]byte]*operator.Principal
	jobs        map[uuid.UUID]*job.Job
	events      map[uuid.UUID][]job.JobEvent
	auditEvents []operator.AuditEventRecord
	idempotency map[string]uuid.UUID
}

func newUnifiedE2EBackend() *unifiedE2EBackend {
	return &unifiedE2EBackend{
		agents:      make(map[[32]byte]*enrollment.AgentRecord),
		operators:   make(map[string]*operator.OperatorRecord),
		sessions:    make(map[[32]byte]*operator.Principal),
		jobs:        make(map[uuid.UUID]*job.Job),
		events:      make(map[uuid.UUID][]job.JobEvent),
		idempotency: make(map[string]uuid.UUID),
	}
}

func (b *unifiedE2EBackend) Ping(ctx context.Context) error { return nil }

func (b *unifiedE2EBackend) RegisterAgent(ctx context.Context, tokenHash [32]byte, publicKey [32]byte) (*enrollment.AgentRecord, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	agentUUID, err := uuid.NewV7()
	if err != nil {
		return nil, false, err
	}
	rec := &enrollment.AgentRecord{
		ID:        agentUUID.String(),
		PublicKey: publicKey,
		CreatedAt: time.Now().UTC(),
	}
	b.agents[publicKey] = rec
	return rec, true, nil
}

func (b *unifiedE2EBackend) FindAgentByPublicKey(ctx context.Context, publicKey [32]byte) (*enrollment.AgentRecord, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if rec, ok := b.agents[publicKey]; ok {
		return rec, nil
	}
	return nil, enrollment.ErrAgentNotFound
}

func (b *unifiedE2EBackend) RecordAgentHeartbeat(ctx context.Context, publicKey [32]byte, protocolVersion int) (*enrollment.AgentRecord, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	rec, ok := b.agents[publicKey]
	if !ok {
		return nil, false, enrollment.ErrAgentNotFound
	}
	now := time.Now().UTC()
	rec.LastSeenAt = &now
	rec.ProtocolVersion = &protocolVersion

	agentUUID, _ := uuid.Parse(rec.ID)
	hasActive := false
	for _, j := range b.jobs {
		if j.AgentID == agentUUID && (j.State == job.StateQueued || j.State == job.StateDispatched || j.State == job.StateRunning) {
			hasActive = true
			break
		}
	}
	return rec, hasActive, nil
}

func (b *unifiedE2EBackend) RecordAgentInventory(ctx context.Context, publicKey [32]byte, req *protocol.InventoryRequest) error {
	return nil
}

func (b *unifiedE2EBackend) RecordAgentTelemetry(ctx context.Context, publicKey [32]byte, req *protocol.TelemetryRequest) error {
	return nil
}

func (b *unifiedE2EBackend) GetOperatorByUsername(ctx context.Context, username string) (*operator.OperatorRecord, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if rec, ok := b.operators[operator.NormalizeUsername(username)]; ok {
		return rec, nil
	}
	return nil, operator.ErrOperatorNotFound
}

func (b *unifiedE2EBackend) CreateOperatorSession(ctx context.Context, operatorID string, tokenHash [32]byte) (*operator.SessionRecord, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	sessID := uuid.New().String()
	p := &operator.Principal{
		OperatorID: operatorID,
		Username:   "operator1",
		Role:       operator.RoleOperator,
		SessionID:  sessID,
		ExpiresAt:  time.Now().Add(12 * time.Hour),
	}
	b.sessions[tokenHash] = p
	return &operator.SessionRecord{
		ID:         sessID,
		OperatorID: operatorID,
		CreatedAt:  time.Now(),
		ExpiresAt:  p.ExpiresAt,
	}, nil
}

func (b *unifiedE2EBackend) FindOperatorSessionByTokenHash(ctx context.Context, tokenHash [32]byte) (*operator.Principal, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if p, ok := b.sessions[tokenHash]; ok {
		return p, nil
	}
	return nil, operator.ErrAuthenticationFailed
}

func (b *unifiedE2EBackend) RevokeOperatorSession(ctx context.Context, sessionID string, operatorID string, username string) error {
	return nil
}

func (b *unifiedE2EBackend) RecordAndListAuditEvents(ctx context.Context, actorOperatorID string, actorUsername string, limit int) ([]operator.AuditEventRecord, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.auditEvents, nil
}

func (b *unifiedE2EBackend) CreateJob(ctx context.Context, operatorID uuid.UUID, agentID uuid.UUID, action job.Action, idempotencyKeyHash [32]byte) (*job.Job, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	key := fmt.Sprintf("%s:%x", operatorID, idempotencyKeyHash)
	if existingID, ok := b.idempotency[key]; ok {
		return b.jobs[existingID], false, nil
	}

	newID := uuid.New()
	now := time.Now().UTC()
	j := &job.Job{
		ID:                  newID,
		AgentID:             agentID,
		CreatedByOperatorID: operatorID,
		CreatedByUsername:   "operator1",
		IdempotencyKeyHash:  idempotencyKeyHash,
		ActionType:          string(action),
		State:               job.StateQueued,
		Attempt:             0,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	b.jobs[newID] = j
	b.idempotency[key] = newID

	b.events[newID] = append(b.events[newID], job.JobEvent{
		ID:              uuid.New(),
		JobID:           newID,
		EventType:       job.EventJobCreated,
		Attempt:         0,
		ActorType:       job.ActorTypeOperator,
		ActorIdentifier: "operator1",
		OccurredAt:      now,
	})

	opIDStr := operatorID.String()
	jobIDStr := newID.String()
	b.auditEvents = append(b.auditEvents, operator.AuditEventRecord{
		ID:              uuid.New().String(),
		OccurredAt:      now,
		ActorOperatorID: &opIDStr,
		ActorUsername:   "operator1",
		Action:          operator.ActionJobCreated,
		TargetJobID:     &jobIDStr,
		Outcome:         operator.OutcomeSuccess,
	})

	return j, true, nil
}

func (b *unifiedE2EBackend) GetJobByID(ctx context.Context, jobID uuid.UUID) (*job.Job, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if j, ok := b.jobs[jobID]; ok {
		return j, nil
	}
	return nil, job.ErrJobNotFound
}

func (b *unifiedE2EBackend) ListJobs(ctx context.Context, limit int, agentID *uuid.UUID, state *job.State) ([]job.Job, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var res []job.Job
	for _, j := range b.jobs {
		res = append(res, *j)
	}
	return res, nil
}

func (b *unifiedE2EBackend) ListJobEvents(ctx context.Context, jobID uuid.UUID, limit int) ([]job.JobEvent, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.events[jobID], nil
}

func (b *unifiedE2EBackend) ClaimNextAgentJob(ctx context.Context, agentID uuid.UUID) (*protocol.JobAssignment, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, j := range b.jobs {
		if j.AgentID == agentID && j.State == job.StateQueued {
			j.State = job.StateDispatched
			j.Attempt++
			now := time.Now()
			j.DispatchedAt = &now
			exp := now.Add(job.DispatchLease)
			j.DispatchExpiresAt = &exp

			b.events[j.ID] = append(b.events[j.ID], job.JobEvent{
				ID:              uuid.New(),
				JobID:           j.ID,
				EventType:       job.EventJobDispatched,
				Attempt:         j.Attempt,
				ActorType:       job.ActorTypeController,
				ActorIdentifier: "controller",
				OccurredAt:      now,
			})

			return &protocol.JobAssignment{
				JobID:   j.ID.String(),
				Attempt: j.Attempt,
				Action:  j.ActionType,
			}, nil
		}
	}
	return nil, nil
}

func (b *unifiedE2EBackend) StartAgentJob(ctx context.Context, agentID uuid.UUID, jobID uuid.UUID, attempt int) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	j, ok := b.jobs[jobID]
	if !ok || j.AgentID != agentID || j.Attempt != attempt || j.State != job.StateDispatched {
		return job.ErrJobConflict
	}
	j.State = job.StateRunning
	now := time.Now()
	j.StartedAt = &now
	deadline := now.Add(job.ExecutionResultDeadline)
	j.ExecutionDeadlineAt = &deadline
	j.DispatchExpiresAt = nil

	b.events[j.ID] = append(b.events[j.ID], job.JobEvent{
		ID:              uuid.New(),
		JobID:           j.ID,
		EventType:       job.EventJobStarted,
		Attempt:         attempt,
		ActorType:       job.ActorTypeAgent,
		ActorIdentifier: agentID.String(),
		OccurredAt:      now,
	})
	return nil
}

func (b *unifiedE2EBackend) CompleteAgentJob(ctx context.Context, agentID uuid.UUID, jobID uuid.UUID, attempt int, outcome string, failureCode string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	j, ok := b.jobs[jobID]
	if !ok || j.AgentID != agentID || j.Attempt != attempt || j.State != job.StateRunning {
		return job.ErrJobConflict
	}
	now := time.Now()
	j.FinishedAt = &now
	evType := job.EventJobSucceeded
	if outcome == "succeeded" {
		j.State = job.StateSucceeded
	} else {
		j.State = job.StateFailed
		j.FailureCode = &failureCode
		evType = job.EventJobFailed
	}

	b.events[j.ID] = append(b.events[j.ID], job.JobEvent{
		ID:              uuid.New(),
		JobID:           j.ID,
		EventType:       evType,
		Attempt:         attempt,
		ActorType:       job.ActorTypeAgent,
		ActorIdentifier: agentID.String(),
		OccurredAt:      now,
	})
	return nil
}

func TestE2E_FullJobLifecycle(t *testing.T) {
	backend := newUnifiedE2EBackend()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	localHandler := newHandler(logger, backend, backend, backend, backend)
	localServer := httptest.NewServer(localHandler)
	defer localServer.Close()

	remoteHandler := newRemoteHandler(logger, backend, backend, backend)
	srvCert, caPEM, remoteServer := setupE2ECAAndServer(t, remoteHandler)
	_ = srvCert
	defer remoteServer.Close()

	agentStateDir, agentPubKey := setupE2EEnrolledState(t, remoteServer.URL)
	caFile := filepath.Join(agentStateDir, "controller-ca.pem")
	_ = os.WriteFile(caFile, caPEM, 0600)
	if err := agent.ValidateAndPersistCAFile(agentStateDir, caFile); err != nil {
		t.Fatalf("ValidateAndPersistCAFile failed: %v", err)
	}

	agentRec, _, err := backend.RegisterAgent(context.Background(), [32]byte{}, agentPubKey)
	if err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}

	meta, _ := agent.LoadIdentityMetadata(agentStateDir)
	meta.AgentID = agentRec.ID
	_ = agent.WriteIdentityMetadata(agentStateDir, meta)

	opID := uuid.New().String()
	opPW := "Operator-Pass-123!"
	hPW, _ := operator.HashPassword(opPW)
	backend.operators["operator1"] = &operator.OperatorRecord{
		ID:           opID,
		Username:     "operator1",
		PasswordHash: hPW,
		Role:         operator.RoleOperator,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	rawToken, _ := operator.GenerateSessionToken()
	tokenHash := operator.HashSessionToken(rawToken)
	_, _ = backend.CreateOperatorSession(context.Background(), opID, tokenHash)

	agentUUID := uuid.MustParse(agentRec.ID)
	createBody := fmt.Sprintf(`{"agent_id":"%s","action":"agent.ping"}`, agentUUID.String())
	req, _ := http.NewRequest(http.MethodPost, localServer.URL+"/api/v1/operator/jobs", strings.NewReader(createBody))
	req.Header.Set("Authorization", "Bearer "+rawToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "e2e-job-key-12345678")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("CreateJob HTTP request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 201 Created, got %d: %s", resp.StatusCode, string(b))
	}
	var createdJob map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&createdJob)
	jobIDStr := createdJob["id"].(string)
	jobUUID := uuid.MustParse(jobIDStr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	presenceErrCh := make(chan error, 1)
	go func() {
		presenceErrCh <- agent.RunPresence(ctx, nil, agentStateDir)
	}()

	for {
		backend.mu.Lock()
		j := backend.jobs[jobUUID]
		var done bool
		if j != nil && (j.State == job.StateSucceeded || j.State == job.StateFailed) {
			done = true
		}
		backend.mu.Unlock()
		if done {
			cancel()
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for agent to process job")
		case err := <-presenceErrCh:
			t.Fatalf("presence loop exited prematurely: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}
	<-presenceErrCh

	getReq, _ := http.NewRequest(http.MethodGet, localServer.URL+"/api/v1/operator/jobs/"+jobIDStr, nil)
	getReq.Header.Set("Authorization", "Bearer "+rawToken)
	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("GetJob failed: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", getResp.StatusCode)
	}
	var finalJob map[string]any
	_ = json.NewDecoder(getResp.Body).Decode(&finalJob)
	if finalJob["state"] != "succeeded" {
		t.Fatalf("expected job state succeeded, got %v", finalJob["state"])
	}

	eventsReq, _ := http.NewRequest(http.MethodGet, localServer.URL+"/api/v1/operator/jobs/"+jobIDStr+"/events", nil)
	eventsReq.Header.Set("Authorization", "Bearer "+rawToken)
	eventsResp, err := http.DefaultClient.Do(eventsReq)
	if err != nil {
		t.Fatalf("GetJobEvents failed: %v", err)
	}
	defer eventsResp.Body.Close()
	var evs []map[string]any
	_ = json.NewDecoder(eventsResp.Body).Decode(&evs)

	if len(evs) != 4 {
		t.Fatalf("expected 4 events, got %d", len(evs))
	}
	expectedTypes := []string{
		job.EventJobCreated,
		job.EventJobDispatched,
		job.EventJobStarted,
		job.EventJobSucceeded,
	}
	for i, exp := range expectedTypes {
		if evs[i]["event_type"] != exp {
			t.Errorf("event %d: expected %q, got %q", i, exp, evs[i]["event_type"])
		}
	}

	_ = jobUUID
}
