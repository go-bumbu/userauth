# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

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
```

## Architecture

- **Core**: `userauth.go` -- `LoginHandler`, interfaces (`UserGetter`, `TOTPGetter`, etc.), `VerificationCodeService`
- **Auth handlers**: `handlers/auth/` -- `cookieauth` (sessions), `basicauth`, `headerauth`, `chain`
- **Login handlers**: `handlers/login/` -- JSON login, form login, logout, 2FA verify
- **Pending login**: `pendinglogin/` -- memory, cookie, db implementations
- **User stores**: `userstore/` -- `staticusers` (YAML/JSON), `dbusers` (GORM+SQLite)
- **Delivery**: `delivery/` -- `smtp`, `file` backends for verification codes
- **Hashing**: `hashutil/` -- bcrypt, SHA-256, AES-256-GCM, numeric code generation
- **Local dependencies**: `go.mod` has `replace` directive for `go-bumbu/http`

## Code Conventions

- **Interface-driven**: small interfaces defined at the consumer, not the implementer
- **Read/write split**: login uses read-only interfaces; config uses write interfaces
- **Tests**: table-driven, `go-cmp` for comparisons

## Documentation

- [`docs/autodoc/overview.md`](docs/autodoc/overview.md) -- Package layout, key flows, interface composition, session lifecycle
- [`docs/autodoc/features.md`](docs/autodoc/features.md) -- Feature status table (auth strategies, MFA, stores, delivery)
