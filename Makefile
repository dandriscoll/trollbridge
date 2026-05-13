.DEFAULT_GOAL := help

GO      ?= go
PKG     := ./...
BIN     := trollbridge
LDFLAGS := -s -w
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build
build:           ## Build the static binary into ./bin/trollbridge
	CGO_ENABLED=0 $(GO) build -trimpath \
	  -ldflags='$(LDFLAGS) -X github.com/dandriscoll/trollbridge/internal/server.Version=$(VERSION)' \
	  -o bin/$(BIN) ./cmd/trollbridge

.PHONY: test
test:            ## Run all tests
	CGO_ENABLED=0 $(GO) test $(PKG)

.PHONY: test-race
test-race:       ## Run all tests with the race detector
	CGO_ENABLED=1 $(GO) test -race $(PKG)

.PHONY: fuzz
fuzz:            ## Run the regex + YAML fuzz suites for ~30s each
	$(GO) test -run=NONE -fuzz=FuzzRuleRegex_PathRegex -fuzztime=15s ./internal/policy/
	$(GO) test -run=NONE -fuzz=FuzzRuleRegex_BodyPattern -fuzztime=15s ./internal/policy/
	$(GO) test -run=NONE -fuzz=FuzzYAMLLoad -fuzztime=30s ./internal/config/

.PHONY: vet
vet:             ## go vet
	$(GO) vet $(PKG)

.PHONY: tidy
tidy:            ## go mod tidy
	$(GO) mod tidy

.PHONY: clean
clean:           ## Remove ./bin
	rm -rf bin

.PHONY: help
help:            ## This help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | sort | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "%-12s %s\n", $$1, $$2}'
