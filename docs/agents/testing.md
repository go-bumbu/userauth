# Testing — strategy, make targets, lint

## Strategy

- Table-driven tests, `go-cmp` for comparisons.
- DB-backed packages (`userstore/userdb`, `flow/login/attemptstore/db`) test
  against in-memory SQLite (`:memory:`) — no fixtures, no external services.
- HTTP handlers are tested with `httptest`; the demo under `demo/examples/`
  doubles as integration coverage for the wired-together library
  (`SeededStore()` builds the shared in-memory store with the demo accounts).
- `userdb` tests are split per concern, mirroring the source files
  (`user_test.go`, `setup_test.go`, …).
- Exported API examples live in `example_test.go` files (e.g.
  `flow/login/example_test.go`) and run as part of the test suite.

## Make targets

| Target | What it runs |
|---|---|
| `make test` | `go test ./... -cover` — the fast suite |
| `make lint` | `golangci-lint run` |
| `make benchmark` | `go test -run=^$ -bench=. ./...` |
| `make license-check` | `go-licence-detector` against `allowedLicenses.json` |
| `make coverage` | total-coverage gate, threshold **80%** (`COVERAGE_THRESHOLD`) |
| `make verify` | test + license-check + lint + benchmark + coverage — the full gate before calling work done |
| `make cover-report` | HTML coverage report (`cover.html`) |
| `make run-demo` | run the demo app on :8084 |

- The coverage gate is on the **total** figure across the module, not
  per-package. If it falls below threshold, write the missing tests — never
  lower the threshold.
- Useful single-target invocations: `go test ./userstore/userdb/`,
  `go test ./... -run TestName`.

## CI (`.github/workflows/`)

Three workflows, all triggered on push to `main`/`master` and on every pull
request. Each one just calls the make targets above, so a green `make verify`
locally means green CI.

| Workflow | Runs |
|---|---|
| `test.yml` | `make test`, `make coverage`, `make benchmark` |
| `golangci-lint.yml` | `golangci-lint` via `golangci-lint-action`, version pinned to the local one (`v2.12.2`) |
| `license-check.yml` | installs `go-licence-detector`, then `make license-check` |

- Go version comes from `go-version-file: go.mod` — bump `go.mod` and CI
  follows.
- `CGO_ENABLED: 1` is required: the DB-backed stores test against in-memory
  SQLite through `mattn/go-sqlite3`, a cgo driver, and the tests panic when it
  is built without cgo.
- The `replace github.com/go-bumbu/http => ../http` directive is inert in CI —
  no package requires that module — so the missing sibling checkout is fine.
  If something starts importing it, CI needs the sibling repo checked out.

## Linters (`.golangci.yaml`)

Standard set (errcheck, govet, ineffassign, staticcheck, unused) plus
`nolintlint`, `gocyclo` (min-complexity 20), `nestif` (min-complexity 5),
`gosec`, `dupl`.

- Test files (`*_test.go`) are excluded from `nestif` and `dupl`.
- `nolint` directives must name the specific linter and carry an explanation
  (`nolintlint` enforces both). Fix the code instead of silencing the tool — a
  valid `//nolint` is rare.
