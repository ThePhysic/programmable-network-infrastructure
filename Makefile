.PHONY: build test integration clean

build:
	go build -trimpath -o bin/netlab-agent ./cmd/netlab-agent

test:
	go test -race ./cmd/... ./internal/...
	go vet ./cmd/... ./internal/...
	python3 -m unittest discover -s tests -v

integration: build
	python3 scripts/integration.py

clean:
	rm -f bin/netlab-agent
