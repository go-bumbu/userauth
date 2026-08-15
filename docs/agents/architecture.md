# Architecture — layering, interfaces, design decisions

`userauth` (module `github.com/go-bumbu/userauth`) is a Go **library** for user
authentication: pluggable user stores, multiple auth strategies, multi-factor
login, and session management. It is consumed by applications like Persona.

This file distills the design decisions made across the documents in
[`../superpowers/`](../superpowers/) so they can be consulted without re-reading
them. The superpowers docs are historical records — where they contradict this
file or the code, the code wins (naming in particular has moved on; see below).

Related agent docs: [loginflow.md](loginflow.md) (the login engine internals),
[register.md](register.md) (the registration engine and invites),
[features.md](features.md) (feature status), [testing.md](testing.md),
[releasing.md](releasing.md).

## Package model (restructured 2026-08-03)

The tree is organized by role; every package is one of five kinds:

```
userauth.go              vocabulary: domain types, capability interfaces, errors — no logic
auth/                    request boundary: per-request authentication (chain, basicauth,
                         cookieauth [+ LogoutHandler], headerauth)
flow/                    engines: multi-step flows that establish credentials
  login/                 login engine (handlers/, attemptstore/{memory,cookie,db})
  register/              registration engine (handlers/, pendingstore/{memory,cookie,db},
                         invite/{memory,db})
userstore/               user persistence: adapters for the root user interfaces
  staticusers/  userdb/
service/verificationcode/  shared one-time-code service: Service, CodeStore, CodeVerifier,
  store/memory/            Deliverer, with its own store/ and deliver/{smtp,file} adapters
internal/hashutil/       crypto plumbing (bcrypt, SHA-256, AES-GCM) — not public API
demo/                    consumer of the library; never imported by it
```

Placement rules (they generated this tree; new packages should follow them):

1. **Root = vocabulary only.** Types/interfaces/errors shared by ≥2 independent
   subtrees. No implementation.
2. **Adapters sit next to the interface they implement** — root interface →
   top-level dir (`userstore/`), engine interface → nested (`attemptstore/`),
   service interface → nested (`service/verificationcode/store/`).
3. **Nest under X only if X owns your interface**; category dirs (`flow/`,
   `service/`) contain only their kind and no `.go` files.
4. **One consumer → nest under it; multiple consumers → top level**
   (`invite` vs `verificationcode`).
5. **Engines remember between requests; authenticators decide fresh per
   request.** New multi-step thing → `flow/`; new credential check → `auth/`.

- **`userauth.go` is the domain core**: `User`, `TOTPData`, `SecondFactor`, all
  capability interfaces, `ErrUserNotFound`/`ErrUserDisabled`. No HTTP.
- **`flow/login` (package `login`) is the only login engine.** The old fixed
  login handlers and the `pendinglogin` package were removed in the
  `refactor-handler` branch; `LogoutHandler` now lives in `auth/cookieauth`.
  Anything login-shaped goes through `login.Flow` — see
  [loginflow.md](loginflow.md).
- **`flow/register` is the registration counterpart**: a pending registration
  accumulates verified checks (email verification, invite code) until all
  pass, then the account is created in exactly one place. Simpler than
  the login engine by design (flat check list, no Policy) and deliberately not
  enumeration-safe about taken usernames (409). `flow/register/invite` is the
  admin-facing invite-code service (issue/list/revoke/consume) that the
  engine consumes via a consumer-side interface — see
  [register.md](register.md).
- **`auth` authenticates requests, not logins.** `AuthHandler` is
  `Name() + HandleAuth(w, r) (allowAccess, stopEvaluation bool)`;
  `chain.Authenticator` evaluates a list in order, first success wins,
  `stopEvaluation` short-circuits (e.g. basicauth enforce mode).

## Design principles

- **Interface-driven, defined at the consumer**: every capability is a small
  interface declared where it is consumed, not where it is implemented
  (e.g. `flow/login` defines `UserLogin` and `AttemptStore`; `cookieauth.Manager`
  satisfies `UserLogin` implicitly).
- **Read/write split**: login uses read-only interfaces (`UserGetter`,
  `TOTPGetter`, `RecoveryCodeVerifier`, `CodeVerifier`, `SecondFactorProvider`);
  configuration uses separate write interfaces (`TOTPConfigurator`,
  `RecoveryCodeConfigurator`, `UserRegistrar`, `UserUpdater`) so read-only
  stores can still participate in login.
- **Transport-agnostic core**: the login engine works on user IDs,
  passwords and codes; HTTP lives in transports (`flow/login/handlers`).

## Personal access tokens: service = policy, store = persistence

`service/pat` owns token format, secret hashing, expiry, scopes, and the
once-only-plaintext rule. Persistence is delegated to a `TokenStore`; user
lookup (enabled check at verify time) to a `userauth.UserGetter`.

- **`pat.Service` owns all policy**: token generation (base36 token IDs, base62
  secrets), SHA-256 hashing, expiry, per-user limits, last-used throttling, and
  the optional recoverable-secret storage. The hash-only vs recoverable storage
  decision happens at mint time via the `Storage` enum (`HashOnly` vs
  `Recoverable`).
- **Hash-only tokens** store only the SHA-256 hash of the secret. The token can
  be verified only when presented whole (the "apiKey" flow via `Verify`) —
  wire format `<prefix>_<tokenID>_<secret>`.
- **Recoverable tokens** additionally store the secret encrypted via a
  consumer-provided `SecretCipher` implementation, enabling `VerifyMatch` for
  credentials derived from the secret (e.g. Subsonic's salted-token auth). The
  ciphertext is bound to its record via AEAD additional authenticated data
  (the token ID as context) so cross-record transplants fail. Key management
  is the consumer's concern — the library never manages keys. Recoverable
  tokens still work as apiKeys (dual-use: the hash remains populated).
- **`TokenStore` implementations are pure persistence**: `Insert`, `GetByTokenID`,
  `ListByUser`, `Delete`, `Touch` (last-used updates). The default is
  `userstore/userdb`, in-memory is `service/pat/store/memory`.
- **`ParseToken`** splits the wire format into its three segments; **`finishVerify`**
  is the shared tail of `Verify` and `VerifyMatch` (expiry, owner lookup and
  enabled flag, throttled last-used touch).

## Verification codes: service = policy, store = persistence

Redesigned 2026-06-30 (`../superpowers/specs/2026-06-30-verification-code-hybrid-design.md`):

The whole subsystem lives in `service/verificationcode` (extracted from the
root package in the 2026-08-03 restructure): `Service`, `CodeStore`,
`CodeVerifier` and `Deliverer` are all defined there.

- **`verificationcode.Service` owns all policy**: numeric code
  generation, SHA-256 hashing, expiry, the wrong-guess attempt cap, and the
  defaults (length 6, 10 min, 5 attempts). Both hashing sites (issue and
  verify) live in this one type, so the issue/verify hash agreement cannot
  drift. Construct via `verificationcode.NewService` — zero-valued opts get
  the defaults. The attempt cap cannot be disabled, only sized: codes are
  short, so the cap is what makes them non-brute-forceable.
- **`CodeStore` implementations are pure persistence with zero crypto
  knowledge**: `StoreCode(userID, hash, expiresAt)` +
  `ConsumeCode(userID, hash, maxAttempts)` — consume is atomic (one-time
  use); stores count wrong guesses and delete the code at maxAttempts, but
  never decide the limit (the service does).
  `service/verificationcode/store/memory` is the in-repo implementation; one instance backs
  one channel (email or SMS).
- **`CodeVerifier`** (`Verify(userID, code)`) is the channel-neutral login-side
  interface; the service implements it. It replaced the identical
  `EmailCodeVerifier`/`SMSCodeVerifier` pair.
- `userdb`'s own `VerifyEmailCode`/`VerifySMSCode` predate this design and do
  **not** satisfy `CodeVerifier` (phase 2 of the redesign — a `CodeStore`
  adapter on the DB store — has not landed).
- **`Deliverer`** (`Deliver(ctx, to, code, expiresAt)`) is orthogonal:
  `service/verificationcode/deliver/smtp` (HTML template, `@/path` password-from-file) and
  `service/verificationcode/deliver/file` (one file per code, for dev). `expiresAt` is informational —
  expiry is enforced by the store.

## User stores

| Store | Package | Implements | Storage |
|---|---|---|---|
| Static users | `userstore/staticusers` | `UserGetter`, `TOTPGetter`, `RecoveryCodeVerifier`, `SecondFactorProvider` | In-memory from YAML/JSON, read-only |
| DB users | `userstore/userdb` | All read interfaces + `TOTPConfigurator`, `RecoveryCodeConfigurator`, `RecoveryCodeCountGetter`, `UserUpdater`, `UserRegistrar` (`Create`) | GORM (+SQLite in tests/demo) |

The DB store was refactored 2026-06-30
(`../superpowers/specs/2026-06-30-dbuser-refactor-design.md`): package
`dbusers`/`DbManager` became `New(db, Opts) (*Store, error)`, the single 550-line
`db.go` was split per concern (`store.go`, `models.go`, `user.go`, `totp.go`,
`recovery.go`, `email.go`, `sms.go`, `secondfactor.go`), and paginated
`List(ListOpts) (ListResult, error)` was added (default limit 50, cap 200,
ordered by `login_id ASC`, returns `Total`). Note: the spec named the package
`dbuser`; it has since been renamed again to **`userdb`** — the spec's naming is
stale, the structure is not.

`userdb` tables: `user_models`, `user_totp`, `user_recovery_codes`,
`user_email_verification_codes`, `user_sms_verification_codes`,
`user_second_factor_flags`, `user_pending_email_changes`. Schema auto-migrates
in `New`, which also validates the TOTP encryption key length.

## Hashing strategy (`internal/hashutil`)

- **Passwords and recovery codes: bcrypt** — slow hash for low-entropy secrets
  (recovery codes moved off SHA-256 deliberately; see TODO.md review items).
- **Verification codes: SHA-256** — short-lived (10 min default), needs
  deterministic lookup for the store's consume-by-hash.
- **TOTP secrets: optional AES-256-GCM at rest** with a server-side key
  (validated in `userdb.New`).

## Session lifecycle (`auth/cookieauth.Manager`)

Three time windows, all defaulted in `cookieauth.New(Cfg)`:

- **Rolling expiry** (`SessionDur`, default 1h) — idle timeout, renewed per
  request when `AllowRenew` is true.
- **Absolute deadline** (`MaxSessionDur`, default 24h) — never renewed; forces
  re-login.
- **Write throttle** (`MinWriteSpace`, default 2min) — skips session-store
  writes that would land closer together than this.

On success the manager puts `UserData` into the request context. Cookie stores:
`NewFsStore` (filesystem) or `NewCookieStore` (client-side), both
gorilla/sessions.

## Dependencies

- `gorilla/mux`, `gorilla/sessions`, `gorilla/securecookie` — HTTP + sessions
- `pquerna/otp` — TOTP generation/validation
- `golang.org/x/crypto` — bcrypt
- `gorm.io/gorm` + `gorm.io/driver/sqlite` — `userdb`, `flow/login/attemptstore/db`
- `go-bumbu/http` — sibling module, **local `replace ../http` directive** in go.mod

## Known debt

TODO.md carries a 2026-04-03 architecture review with the open items (rate
limiting hooks, session listing/revocation, `AttemptStore` leaking HTTP
concerns, coarse error types, audit hooks). Check it before adding a capability
— the gap may already be catalogued with a chosen direction.
