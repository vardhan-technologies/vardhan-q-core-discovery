BINARY_NAME=bin/qcore

.PHONY: all build test test-rules benchmark scan clean help

all: test build

build:
	@mkdir -p bin
	go build -ldflags="-s -w" -o $(BINARY_NAME) cmd/qcore/main.go
	@echo "Build complete: $(BINARY_NAME)"

test:
	go test -v ./...

benchmark: build
	./$(BINARY_NAME) benchmark

test-rules: build
	./$(BINARY_NAME) rules test

list-rules: build
	./$(BINARY_NAME) rules list

scan: build
	./$(BINARY_NAME) scan testdata/samples

cbom: build
	./$(BINARY_NAME) scan testdata/samples -f cbom -o cbom.json
	@echo "Generated CycloneDX 1.6 CBOM: cbom.json"

sarif: build
	./$(BINARY_NAME) scan testdata/samples -f sarif -o results.sarif
	@echo "Generated SARIF 2.1.0: results.sarif"

clean:
	rm -rf bin/ cbom.json results.sarif

help:
	@echo "Vardhan Q-Core Makefile commands:"
	@echo "  make build       - Compile static CLI binary"
	@echo "  make test        - Run unit and integration tests"
	@echo "  make benchmark   - Run accuracy release gate benchmark (precision & recall)"
	@echo "  make test-rules  - Verify all rules and their positive/negative fixtures"
	@echo "  make list-rules  - Display all active detection rules"
	@echo "  make scan        - Run terminal discovery scan on sample repository"
	@echo "  make cbom        - Generate CycloneDX 1.6 Cryptographic Bill of Materials"
	@echo "  make sarif       - Generate SARIF 2.1.0 file for GitHub Code Scanning"
