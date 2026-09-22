# Makefile for OAuth 2.0 Client Credentials Grant & Custom Skills Management

.PHONY: help check install install-agents install-all self-eval test fmt lint tidy vulncheck build release-check release-snapshot license-check license-add clean publish-pr ai-pr oauth-e2e

help:
	@echo "Available commands:"
	@echo "  Go Development & Testing:"
	@echo "    fmt              Format Go source files"
	@echo "    lint             Run golangci-lint static analysis"
	@echo "    tidy             Run go mod tidy"
	@echo "    vulncheck        Run govulncheck vulnerability scanner"
	@echo "    test             Run Go unit tests with race detector and 100% statement coverage"
	@echo "    oauth-e2e        Run OAuth2 & ACME HTTP-01 E2E tests"
	@echo "    build            Build binaries to bin/oauth-cli and bin/sample-server"
	@echo "    release-check    Validate GoReleaser configuration"
	@echo "    release-snapshot Run GoReleaser snapshot build"
	@echo "    license-check    Verify license & author headers in Go files"
	@echo "    license-add      Automatically add license headers to Go files"
	@echo "    publish-pr       Verify formatting/lints/tests, push to origin, and create GitHub PR"
	@echo "    ai-pr            Trigger AI agent to draft a GitHub PR in Japanese"
	@echo "  Custom Skills Management:"
	@echo "    check            Validate custom skill frontmatter and syntax"
	@echo "    install          Install custom skills globally to ~/.claude/skills/"
	@echo "    install-agents   Install/Sync custom skills to .agents/skills/ (Antigravity)"
	@echo "    install-all      Install custom skills to both Claude and Antigravity"
	@echo "    self-eval        Run requirements self-evaluation and update checklist"
	@echo "  General:"
	@echo "    clean            Clean up build artifacts and temporary files"

# --- Go Development ---

fmt:
	@echo "==> Formatting Go source files..."
	@go fmt ./...
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run --fix ./...; \
	fi

lint:
	@echo "==> Running golangci-lint..."
	@golangci-lint run ./...

tidy:
	@echo "==> Tidying Go modules..."
	@go mod tidy

vulncheck:
	@echo "==> Running govulncheck..."
	@go run golang.org/x/vuln/cmd/govulncheck@latest ./...

test:
	@bash scripts/check_coverage.sh

build:
	@echo "==> Building binaries..."
	@mkdir -p bin
	@go build -v -o bin/oauth-cli ./cmd/oauth-cli
	@go build -v -o bin/sample-server ./sample-server

oauth-e2e: build
	@echo "==> Running OAuth2 & ACME HTTP-01 E2E tests..."
	@go test -v -race ./sample-server/...

release-check:
	@echo "==> Validating GoReleaser configuration..."
	@if command -v goreleaser >/dev/null 2>&1; then \
		goreleaser check; \
	else \
		go run github.com/goreleaser/goreleaser/v2@latest check; \
	fi

release-snapshot:
	@echo "==> Building GoReleaser snapshot..."
	@if command -v goreleaser >/dev/null 2>&1; then \
		goreleaser release --snapshot --clean; \
	else \
		go run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean; \
	fi

license-check:
	@echo "==> Checking Go source files license headers..."
	@python3 scripts/check_license.py --check

license-add:
	@echo "==> Adding license headers to Go source files..."
	@python3 scripts/check_license.py --add

publish-pr:
	@bash scripts/publish_pr.sh

ai-pr:
	@claude "github-pr-creator スキルを使用して、現在のブランチの変更とコミットログを分析し、pull_request_template.md に従って日本語のプルリクエストをドラフト（下書き）で作成してください。"

# --- Custom Skills Management ---

check:
	@echo "==> Validating skill files format..."
	@python3 scripts/check_skills.py

install:
	@echo "==> Installing custom skills globally to ~/.claude/skills/..."
	@mkdir -p ~/.claude/skills/
	@cp -R .claude/skills/* ~/.claude/skills/
	@echo "Claude skills successfully installed!"

install-agents:
	@echo "==> Syncing custom skills to .agents/skills/ (Antigravity)..."
	@mkdir -p .agents/skills/
	@cp -R .claude/skills/* .agents/skills/
	@echo "Antigravity skills successfully synced!"

install-all: install install-agents
	@echo "All custom skills successfully installed for Claude and Antigravity!"

self-eval:
	@echo "==> Running self-evaluation..."
	@python3 scripts/self_eval.py

# --- General ---

clean:
	@echo "==> Cleaning up build artifacts..."
	@rm -rf bin/ dist/ test_reports/ coverage.out
	@go clean -testcache
