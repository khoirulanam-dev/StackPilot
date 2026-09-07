# StackPilot

## What it is
StackPilot is a serious open-source infrastructure control plane designed for Linux infrastructure. It is built to be security-first, performance-first, and resource-efficient.

## Current status
**Early Development (Pre-Release)**
StackPilot is currently in the M0.3 stage (PostgreSQL Persistence & Migration Foundation). It is **NOT** production-ready.

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

## Security
StackPilot is designed to be security-first. Please see [SECURITY.md](SECURITY.md) for vulnerability reporting guidelines.

## License
StackPilot is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for more details.
