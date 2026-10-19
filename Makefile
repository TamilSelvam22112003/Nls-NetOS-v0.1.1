GO ?= go
BINARY ?= nls-router
.PHONY: build test lint fmt
build:
	mkdir -p bin
	$(GO) build -trimpath -ldflags="-s -w" -o bin/$(BINARY) ./cmd/...
test:
	$(GO) test ./...
lint:
	golangci-lint run ./...
fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')
