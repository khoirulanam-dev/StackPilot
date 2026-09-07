# StackPilot

## What it is
StackPilot is a serious open-source infrastructure control plane designed for Linux infrastructure. It is built to be security-first, performance-first, and resource-efficient.

## Current status
**Early Development (Pre-Release)**
StackPilot is currently in the M0.1 stage, which establishes the repository foundation. It is **NOT** production-ready.

## Development
To build the project locally, you need Go 1.27.1, Node.js 24 LTS, and the frontend package manager version pinned in web/package.json.

```bash
# Build controller, agent, and frontend
make build

# Run tests
make test

# Build frontend
make web-build
```

## Security
StackPilot is designed to be security-first. Please see [SECURITY.md](SECURITY.md) for vulnerability reporting guidelines.

## License
StackPilot is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for more details.
