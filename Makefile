.PHONY: build test lint web-build clean

build: web-build
	@echo "Building Go binaries..."
	mkdir -p build
	go build -o build/stackpilot-controller ./cmd/controller
	CGO_ENABLED=0 go build -o build/stackpilot-agent ./cmd/agent
	CGO_ENABLED=0 go build -o build/stackpilot-agent-helper ./cmd/agent-helper

test:
	@echo "Running tests..."
	go test ./...
	go test -race ./...

lint:
	@echo "Running go vet and fmt..."
	go vet ./...
	@if [ -n "$$(gofmt -l .)" ]; then \
		echo "Go code is not formatted. Run gofmt -w ."; \
		exit 1; \
	fi

web-build:
	@echo "Building frontend..."
	cd web && corepack pnpm install --frozen-lockfile && corepack pnpm build

clean:
	@echo "Cleaning artifacts..."
	rm -rf build/
	rm -rf web/dist/
