# StackPilot

## What it is
StackPilot is a serious open-source infrastructure control plane designed for Linux infrastructure. It is built to be security-first, performance-first, and resource-efficient.

## Current status
**Early Development (Pre-Release)**
StackPilot is currently in the M0.7 stage (Agent Presence & Heartbeat Foundation). It is pre-release and **NOT** production-ready.
- No inventory
- No metrics
- No remote commands
- No UI

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
