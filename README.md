# StackPilot

## What it is
StackPilot is a serious open-source infrastructure control plane designed for Linux infrastructure. It is built to be security-first, performance-first, and resource-efficient.

## Current status
**Early Development (Pre-Release)**
StackPilot is currently in the M0.5 stage (Secure Agent Enrollment & Cryptographic Identity). It is **NOT** production-ready.

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
The controller supports the following environment variables:
- `STACKPILOT_LISTEN_ADDRESS` (default: `127.0.0.1:7447`): HTTP listen address (`host:port`). Accepts literal loopback IP and port only; remote and wildcard addresses are rejected while authentication is not implemented.
- `STACKPILOT_LOG_LEVEL` (default: `info`): Logging verbosity (`debug`, `info`, `warn`, `error`).
- `STACKPILOT_DATABASE_URL` (**required**, no default): PostgreSQL connection URL (e.g. `postgres://user:password@127.0.0.1:5432/dbname?sslmode=disable`). Scheme must be `postgres` or `postgresql`.

### Enrollment Tokens & Agent Enrollment
Enrollment tokens can be generated locally via the controller CLI, and agents can enroll locally via loopback.
Note that the StackPilot controller service (`stackpilot-controller`) must already be running on the configured loopback address before executing agent enrollment:

```bash
# Issue an enrollment token and pipe directly to agent enroll
stackpilot-controller enrollment-token create | \
stackpilot-agent enroll \
  --controller http://127.0.0.1:7447 \
  --state-dir /path/to/agent/state
```

* In M0.5, the enrollment endpoint remains loopback-only (`127.0.0.1` / `[::1]`). Remote transport and mTLS will be introduced in subsequent milestones.
* Requires configured PostgreSQL database connection (`STACKPILOT_DATABASE_URL`).
* The plaintext token is read from stdin and is never stored on disk.
* The Agent generates and stores a local Ed25519 private key in `--state-dir` with restrictive permissions (mode `0600`).
* The private key never leaves the Agent host; only the 32-byte public key is sent to the controller.
* Tokens are one-time use and valid for 15 minutes. Idempotent retry with the same token and same public key is supported.

## Security
StackPilot is designed to be security-first. Please see [SECURITY.md](SECURITY.md) for vulnerability reporting guidelines.

## License
StackPilot is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for more details.
