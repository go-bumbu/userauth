# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is userauth

`userauth` (module `github.com/go-bumbu/userauth`) is a Go library for user
authentication. It provides pluggable user stores, multiple auth strategies
(cookie sessions, basic auth, header auth), multi-factor authentication (TOTP,
recovery codes, email/SMS codes), and a delivery interface for verification
codes. It is consumed by applications like Persona.

## Commands

```bash
go test ./...                    # run all tests
go test ./... -cover             # with coverage
go test ./userstore/dbusers/     # single package
go test ./... -run TestName      # single test
make lint                        # run golangci-lint
make verify                      # tests + lint + benchmark + license-check + coverage
make run-demo                    # run demo app on :8084
```

## Architecture

- **Core**: `userauth.go` — `LoginHandler`, interfaces (`UserGetter`, `TOTPGetter`, etc.), `VerificationCodeService`
- **Auth handlers**: `handlers/auth/` — `cookieauth` (sessions), `basicauth`, `headerauth`, `chain`
- **Login handlers**: `handlers/login/` — JSON login, form login, logout, 2FA verify
- **Pending login**: `pendinglogin/` — memory, cookie, db implementations (state between step-1 and 2FA)
- **User stores**: `userstore/` — `staticusers` (YAML/JSON, read-only), `dbusers` (GORM+SQLite)
- **Delivery**: `delivery/` — `smtp`, `file` backends for verification codes
- **Hashing**: `hashutil/` — bcrypt, SHA-256, AES-256-GCM, numeric code generation
- **Local dependency**: `go.mod` has `replace` directive for sibling module `go-bumbu/http`

### Key flows

- **Login with 2FA**: POST `/login` → `LoginHandler.CanLogin` → if 2FA required, store pending login → return `{requires2fa}` → POST `/verify-*` → verify factor → create session
- **Session lifecycle** (`cookieauth.Manager`): rolling expiry (1h default), absolute deadline (24h), write throttle (2min) to limit store writes

## Code Conventions

- **Interface-driven**: small interfaces defined at the consumer, not the implementer
- **Read/write split**: login uses read-only interfaces; configuration uses write interfaces
- **Transport-agnostic**: core `LoginHandler` operates on IDs/passwords, not HTTP
- **Tests**: table-driven, `go-cmp` for comparisons

## Documentation

- [`docs/autodoc/overview.md`](docs/autodoc/overview.md) — Package layout, key flows, interface composition, session lifecycle
- [`docs/autodoc/features.md`](docs/autodoc/features.md) — Feature status table (auth strategies, MFA, stores, delivery)
