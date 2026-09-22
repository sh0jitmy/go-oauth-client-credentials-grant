# AGENTS.md - Antigravity Agent Guidelines

This document provides behavioral constraints, architectural conventions, and execution workflows for Google Antigravity and other AI coding agents working in this repository.

## Repository Overview

`go-oauth-client-credentials-grant` provides:
1. **OAuth 2.0 Client Credentials Grant & RFC 8707 Resource Indicators**: Enterprise-grade authorization server, Gin middleware, and client SDK (`pkg/oauth2`, `pkg/oauth2/client`) with 100.0% statement unit test coverage, strict absolute URI validation, and OTel/slog audit instrumentation.
2. **ACME HTTP-01 Challenge Protection**: Reference Gin server (`sample-server/`) demonstrating OAuth2-protected challenge execution (`/start`, `/complete`) and unauthenticated public verification endpoints (`/.well-known/acme-challenge/:token`).
3. **Evaluation CLI Tool**: Fully functional command-line client (`cmd/oauth-cli`) implementing 9 subcommands for seamless registration, token acquisition, and ACME challenge workflows.
4. **Zero-npm Standalone HTMX Dashboard & SSG**: High-performance UI server (`internal/web`) using `//go:embed`, local HTMX, and pre-rendered static site export.
5. **SQLite Governance & Reliability**: CGO-free WAL-mode persistence, SHA-256 verified backup archives (`tar.gz`), atomic transactional restore, and retention cleaner.
6. **Multi-Tier E2E Testing Framework & HTML Reporting**: Fast No-Docker SQLite E2E (`make sqlite-e2e`), OAuth2 & ACME HTTP-01 E2E (`make oauth-e2e` with automatic HTML report generation & GitHub Pages publishing), Headless Chrome frontend UI assertions (`make frontend-e2e`), and Docker Compose full-stack E2E (`make docker-e2e`).
7. **SSOT Version Management**: Version centrally defined in `internal/version/version.go`, Go version unified across GitHub Actions and `go.mod` via `go-version-file: 'go.mod'`, release automation via GoReleaser v2.

---

## Agent Behavioral Rules

1. **Custom Skills First**:
   - Relevant skills are located in `.agents/skills/` and `.claude/skills/`.
   - Adhere to `golang-design`, `golang-implementation`, `quality-inspector`, `sre-deployment`, and `git-strategy` for architecture and implementation decisions.
2. **Package Isolation (`pkg/oauth2`)**:
   - `pkg/oauth2` and `pkg/oauth2/client` MUST remain zero-dependency standalone modules capable of being installed via `go get` without importing `internal/` or `ent/`.
3. **100% Statement Coverage**:
   - Every statement in `pkg/oauth2` and `pkg/oauth2/client` MUST be covered by unit tests. Verified automatically via `make test` (`scripts/check_coverage.sh`).
4. **License Header Integrity**:
   - Every Go source file must contain the standard Apache-2.0 and Author header.
   - Always verify with `make license-check` before concluding tasks.
5. **SSOT Principle**:
   - Never hardcode Go versions in GitHub Actions workflows; always use `go-version-file: 'go.mod'`.
   - Version injection must go through `internal/version.Version`.
6. **E2E HTML Reporting & Sensitive Data Masking**:
   - `make oauth-e2e` MUST always run through `scripts/oauth_e2e.sh` and generate `test_reports/index.html` and `test_reports/history.json`.
   - All sensitive data (access tokens, client secrets, HMAC headers, authorization credentials) MUST be masked (`***MASKED***`) in HTML reports.
   - GitHub Actions workflow MUST upload raw outputs as artifacts and deploy the report to GitHub Pages on both success and failure (`if: always()`).

---

## Standard Development & Testing Commands

```bash
# Code generation & formatting
make generate
make fmt
make lint

# Verification & Multi-Tier E2E
make test            # Unit tests with -race and 100% coverage assertion
make oauth-e2e       # OAuth 2.0 & ACME HTTP-01 Challenge E2E (generates test_reports/index.html)
make sqlite-e2e      # Ultra-fast No-Docker SQLite E2E
make frontend-e2e    # Headless Chrome HTMX UI & snapshot verification
make docker-e2e      # Multi-container Docker Compose E2E
make ssg-build       # Static site generation export

# Build & Release
make build           # Build bin/app, bin/web, bin/oauth-cli, bin/sample-server
make release-check   # Validate GoReleaser v2 configuration
make license-check   # Verify license headers
```

