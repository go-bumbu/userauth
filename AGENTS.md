# userauth — What this library is for

`userauth` (module `github.com/go-bumbu/userauth`) is a Go library for user
authentication. It provides pluggable user stores, multiple auth strategies
(cookie sessions, basic auth, header auth), multi-factor authentication (TOTP,
recovery codes, email/SMS codes), and a delivery interface for verification
codes. It is consumed by applications like Persona.

The compacted implementation decisions live in [docs/agents/](docs/agents/) —
read the file that matches your task:

| Task | Read |
|---|---|
| Layering, interfaces, stores, sessions, hashing, design decisions | [docs/agents/architecture.md](docs/agents/architecture.md) |
| Anything under `flow/login/` (engine, policies, methods, attempt stores, JSON transport) | [docs/agents/loginflow.md](docs/agents/loginflow.md) |
| "Is X implemented?" — feature status and gaps | [docs/agents/features.md](docs/agents/features.md) |
| Writing/running tests, `make verify`, coverage, lint | [docs/agents/testing.md](docs/agents/testing.md) |
| Releases, tagging, versioning | [docs/agents/releasing.md](docs/agents/releasing.md) |

## Commands

```bash
go test ./...                    # run all tests
go test ./... -cover             # with coverage
go test ./userstore/userdb/      # single package
go test ./... -run TestName      # single test
make lint                        # run golangci-lint
make verify                      # tests + lint + benchmark + license-check + coverage
make run-demo                    # run demo app on :8084
```

## Architecture

- **Core**: `userauth.go` — vocabulary only: domain types (`User`), capability interfaces (`UserGetter`, `TOTPGetter`, etc.), errors
- **Auth handlers**: `auth/` — per-request authentication: `cookieauth` (sessions + `LogoutHandler`), `basicauth`, `headerauth`, `chain`
- **Engines**: `flow/` — multi-step flows that establish credentials: `flow/login` (multi-factor login; attempt stores under `flow/login/attemptstore/`) and `flow/register` (registration; `pendingstore/`, `invite/`)
- **User stores**: `userstore/` — `staticusers` (YAML/JSON, read-only), `userdb` (GORM+SQLite)
- **Credential services**: `service/` — `verificationcode` (one-time codes + `Deliverer`), `totp` (enrolment + validation), `recoverycodes`, `pat` (personal access tokens), `throttle` (brute-force backoff), `cipher` (secret encryption); each owns policy and delegates persistence to its own store interface
- **Hashing**: `internal/hashutil/` — bcrypt, SHA-256, AES-256-GCM, numeric code generation
- **Local dependency**: `go.mod` has `replace` directive for sibling module `go-bumbu/http`

Placement rules: root = shared vocabulary; adapters live next to the interface
they implement; nest under a package only if it owns your interface; multi-step
= `flow/`, per-request = `auth/`. Full model in
[docs/agents/architecture.md](docs/agents/architecture.md).

### Key flows

- **Login with 2FA**: `login.Flow.Submit` verifies one factor per call, persisting progress in an `AttemptStore` until the `Policy` is satisfied, then creates the session; `flow/login/handlers.JSON` exposes this as POST login/verify/request-code endpoints
- **Session lifecycle** (`cookieauth.Manager`): rolling expiry (1h default), absolute deadline (24h), write throttle (2min) to limit store writes

## Code Conventions

- **Interface-driven**: small interfaces defined at the consumer, not the implementer
- **Read/write split**: login uses read-only interfaces; configuration uses write interfaces
- **Transport-agnostic**: the `flow/login` engine operates on IDs/passwords/codes; HTTP lives in transports
- **Tests**: table-driven, `go-cmp` for comparisons

