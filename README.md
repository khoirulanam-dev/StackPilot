# StackPilot

## What it is
StackPilot is a serious open-source infrastructure control plane designed for Linux infrastructure. It is built to be security-first, performance-first, and resource-efficient.

## Current status
**Early Development (Pre-Release)**
StackPilot is currently in the M0.11 stage (Job & Typed Action Engine). It is pre-release and **NOT** production-ready.

Job & Typed Action Engine:
- Typed action domain: `agent.ping` ONLY
- Strict typed action boundary: no arbitrary commands, no shell strings, no argv/args arrays, no generic payload/JSONB, no subprocesses (`os/exec`)
- Persistent jobs with PostgreSQL-backed state machine: `queued`, `dispatched`, `running`, `succeeded`, `failed`, `unknown`
- Heartbeat-carried job assignment: idle Agent has no extra polling loop, ticker, or worker pool (assignments delivered via existing heartbeat HTTP responses)
- At-most-once execution contract: receiving a job does not authorize execution; Agent must successfully obtain HTTP 204 from `/api/v1/agent/job/start` via an atomic, non-idempotent transition
- Completion idempotency: terminal outcome reporting (`succeeded`, `failed` with `executor_error`) via `/api/v1/agent/job/complete` is safe for replay
- Dispatch leasing: 30-second lease with bounded retry (max 5 dispatch attempts before failing with `dispatch_exhausted`)
- Execution deadline: 60-second result deadline; expired running jobs transition to `unknown` with `execution_timeout` (never automatically retried)
- Bounded concurrency: max 1 in-flight job (`dispatched` or `running`) per Agent enforced by partial unique index; max 64 active jobs per Agent
- Append-only job event history: `job.created`, `job.dispatched`, `job.requeued`, `job.started`, `job.succeeded`, `job.failed`, `job.unknown`
- Operator job RBAC: `jobs.read` permission for viewing jobs and events; `operations.execute` for submitting jobs with `Idempotency-Key` header (scoped per operator)
- Protocol version: upgraded to version 2

Operator Security Boundary:
- Operator identity with secure password hashing (Argon2id: memory=32MiB, iterations=3, parallelism=1)
- Operator bootstrap CLI with password via `--password-stdin`
- Three typed operator roles: `viewer`, `operator`, `admin`
- Explicit RBAC permission matrix (`servers.read`, `jobs.read`, `operations.execute`, `operators.manage`, `audit.read`)
- Opaque random session tokens (`sp_session_...`) stored only as SHA-256 hashes
- Local-only loopback HTTP operator API (`127.0.0.1` / `[::1]`)
- Session management: 12-hour absolute lifetime, max 8 active sessions per operator
- Immutable, append-only operator audit log (`operator.created`, `operator.login`, `operator.logout`, `operator.audit.read`, `job.created`)
- Privileged admin-only audit read endpoint with bounded pagination (`limit` 1..200, default 100)

Collected server inventory (current snapshot only):
- Hostname
- OS ID / name / version
- Kernel release
- Architecture
- Logical CPU count
- Total RAM

Collected runtime telemetry (current snapshot only):
- CPU usage (basis points, derived across consecutive samples)
- Memory total / used / available bytes
- Load averages (1m, 5m, 15m in milli)
- Root filesystem total / used / available bytes (mounted at `/`)
- Aggregate network receive / transmit byte counters (excluding `lo`)
- Uptime seconds

Strict boundaries:
- Pre-release and not production-ready
- No UI, web control plane, or dashboards yet
- No SSO, OIDC, SAML, LDAP, or MFA yet
- No real server operations yet
- No privileged execution yet
- No remote shell or arbitrary command execution
- No application orchestration yet

## Development
To build and test the project locally, you need:
* Go 1.27.1
* Node.js 24 LTS
* PostgreSQL 18.x development baseline
* Frontend package manager pinned in `web/package.json`

```bash
# Build controller, agent, and frontend
make build

# Run tests
make test

# Build frontend
make web-build
```

### Controller Configuration

#### Local Listener
- `STACKPILOT_LISTEN_ADDRESS` (default: `127.0.0.1:7447`): HTTP listen address (`host:port`). Remains loopback HTTP only (`127.0.0.1` / `[::1]`). Remote and wildcard addresses are rejected.
- `STACKPILOT_LOG_LEVEL` (default: `info`): Logging verbosity (`debug`, `info`, `warn`, `error`).
- `STACKPILOT_DATABASE_URL` (**required**, no default): PostgreSQL connection URL (e.g. `postgres://user:password@127.0.0.1:5432/dbname?sslmode=disable`). Scheme must be `postgres` or `postgresql`.

#### Remote Agent Listener
- `STACKPILOT_AGENT_LISTEN_ADDRESS`: Remote agent TLS listen address (`host:port`). Optional, disabled by default.
- `STACKPILOT_AGENT_TLS_CERT_FILE`: Path to server X.509 certificate file for remote listener (required when remote listener is enabled).
- `STACKPILOT_AGENT_TLS_KEY_FILE`: Path to server private key file for remote listener (required when remote listener is enabled).

Remote listener properties:
- Optional
- Disabled by default
- TLS 1.3 minimum
- Requests client certificate for agent authentication (`/api/v1/agent/self`)

### Operator Bootstrap CLI

Initial operators are created explicitly via the controller CLI:

```bash
printf '%s\n' '<strong-password>' | \
stackpilot-controller operator create \
  --username admin \
  --role admin \
  --password-stdin
```

- `--password-stdin`: Required. Password must be supplied via stdin (minimum 12 bytes, maximum 128 bytes, valid UTF-8, no control characters).
- `--role`: Required. Must be one of `viewer`, `operator`, or `admin`.
- `--username`: Required. Canonical lowercase ASCII (3..64 characters, `^[a-z0-9][a-z0-9._-]{2,63}$`).

### Agent Enrollment & Transport Check

#### HTTPS Remote Enrollment
```bash
# Issue token on controller and pipe directly to agent enroll over HTTPS
stackpilot-controller enrollment-token create | \
stackpilot-agent enroll \
  --controller https://controller.example.com:7448 \
  --ca-file /path/internal-ca.pem \
  --state-dir /path/state
```

The enrollment token still comes from stdin.

#### Verify Secure Transport
```bash
stackpilot-agent transport-check --state-dir /path/state
```

#### Run Agent Presence Daemon
```bash
stackpilot-agent --state-dir /path/state
```

Behavior:
- Sends an immediate authenticated presence heartbeat on startup
- Maintains presence via periodic heartbeats at ~30-second intervals with jitter (±10%)
- Reconnects with bounded exponential backoff on transient errors (1s to 30s cap)
- Automatically rotates in-memory ephemeral TLS client certificate before 1-hour expiration
- Reuses TLS identity established during M0.6 enrollment without requiring extra flags
- Controller maintains `last_seen_at` (database time) and `protocol_version` in PostgreSQL

* Token is read from stdin and never written to disk.
* Agent generates and stores an Ed25519 private key in `--state-dir` with restrictive permissions (mode `0600`).
* Private key never leaves the agent host; only the public key is registered.
* Ephemeral client certificates are generated in memory and never written to disk.
* Controller authorizes agents via database lookup of the Ed25519 public key.

## Security
StackPilot is designed to be security-first. Please see [SECURITY.md](SECURITY.md) for vulnerability reporting guidelines.

## License
StackPilot is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for more details.
