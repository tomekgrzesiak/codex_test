# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
go build

# Run
go run main.go

# Test
go test ./...

# Regenerate API code from OpenAPI spec
go generate ./...
```

## Architecture

This is a Go REST API server implementing a subset of the Petstore OpenAPI specification.

**Request flow:** chi router → server_impl.go (business logic) → postgres_repository.go → PostgreSQL

**Key layers:**
- `main.go` — wires everything together: config, DB pool, chi router with middleware, Google OAuth routes (if enabled), HTTP server with graceful shutdown
- `internal/petstore/server_impl.go` — implements the three API endpoints (ListPets, CreatePets, ShowPetById)
- `internal/petstore/postgres_repository.go` — PostgreSQL persistence; auto-creates `pets` table on init; returns typed errors (`ErrPetExists`, `ErrPetNotFound`)
- `internal/petstore/petstore.gen.go` — generated from `api/petstore.json` via `oapi-codegen`; do not edit manually
- `internal/auth/google/handler.go` — Google OAuth 2.0 authorization code flow (login + callback handlers)
- `internal/config/config.go` — merges `config.yaml` + environment variables with `DEMO_` prefix via Viper

**Code generation:** `api/petstore.json` (OpenAPI 3.0) → `oapi-codegen` (config in `api/oapi-codegen.yaml`) → `internal/petstore/petstore.gen.go`. Regenerate with `go generate ./...`.

**Tech stack:** Go 1.24, chi v5 (routing), pgx v5 (PostgreSQL), Viper (config), golang.org/x/oauth2 (Google OAuth), oapi-codegen (API types/server interface).
