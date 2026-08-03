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

## Layering

```
loginflow/handlers   register/handlers (JSON transports)   auth/* (per-request auth)
        |                    |                                     |
    loginflow (engine)   register (engine)             chain / cookieauth / basicauth / headerauth
   /     |      \       /    |        \                            |
userstore attemptstore pendingstore register/invite  userauth.go  <- domain types + capability interfaces
(staticusers, userdb)  (memory,     (memory, db)        VerificationCodeService
         |              cookie, db)                          |
       GORM                                    codestore/memory, userdb (stores)
                                               support/delivery/{smtp,file} (Deliverer)
```

- **`userauth.go` is the domain core**: `User`, `TOTPData`, `SecondFactor`, all
  capability interfaces, `ErrUserNotFound`/`ErrUserDisabled`, and
  `VerificationCodeService`. No HTTP.
- **`loginflow` is the only login engine.** The old fixed login handlers
  (`handlers/login/form.go`, `json.go`, `emailcode.go`, `verify2fa.go`) and the
  `pendinglogin` package were removed in the `refactor-handler` branch;
  `handlers/login` now holds only `LogoutHandler`. Anything login-shaped goes
  through `loginflow.Flow` — see [loginflow.md](loginflow.md).
- **`register` is the registration counterpart**: a pending registration
  accumulates verified checks (email verification, invite code) until all
  pass, then the account is created in exactly one place. Simpler than
  loginflow by design (flat check list, no Policy) and deliberately not
  enumeration-safe about taken usernames (409). `register/invite` is the
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
  (e.g. `loginflow` defines `UserLogin` and `AttemptStore`; `cookieauth.Manager`
  satisfies `UserLogin` implicitly).
- **Read/write split**: login uses read-only interfaces (`UserGetter`,
  `TOTPGetter`, `RecoveryCodeVerifier`, `CodeVerifier`, `SecondFactorProvider`);
  configuration uses separate write interfaces (`TOTPConfigurator`,
  `RecoveryCodeConfigurator`, `UserRegistrar`, `UserUpdater`) so read-only
  stores can still participate in login.
- **Transport-agnostic core**: the `loginflow` engine works on user IDs,
  passwords and codes; HTTP lives in transports (`loginflow/handlers`).

## Verification codes: service = policy, store = persistence

Redesigned 2026-06-30 (`../superpowers/specs/2026-06-30-verification-code-hybrid-design.md`):

- **`userauth.VerificationCodeService` owns all policy**: numeric code
  generation, SHA-256 hashing, expiry, and the defaults (length 6, 10 min).
  Both hashing sites (issue and verify) live in this one type, so the
  issue/verify hash agreement cannot drift. Construct via
  `NewVerificationCodeService` — zero-valued opts get the defaults.
- **`CodeStore` implementations are pure persistence with zero crypto
  knowledge**: `StoreCode(userID, hash, expiresAt)` +
  `ConsumeCode(userID, hash)` — consume is atomic (one-time use).
  `codestore/memory` is the in-repo implementation; one instance backs
  one channel (email or SMS).
- **`CodeVerifier`** (`Verify(userID, code)`) is the channel-neutral login-side
  interface; the service implements it. It replaced the identical
  `EmailCodeVerifier`/`SMSCodeVerifier` pair.
- `userdb`'s own `VerifyEmailCode`/`VerifySMSCode` predate this design and do
  **not** satisfy `CodeVerifier` (phase 2 of the redesign — a `CodeStore`
  adapter on the DB store — has not landed).
- **`Deliverer`** (`Deliver(ctx, to, code, expiresAt)`) is orthogonal:
  `support/delivery/smtp` (HTML template, `@/path` password-from-file) and
  `support/delivery/file` (one file per code, for dev). `expiresAt` is informational —
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

## Hashing strategy (`support/hashutil`)

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
- `gorm.io/gorm` + `gorm.io/driver/sqlite` — `userdb`, `loginflow/attemptstore/db`
- `go-bumbu/http` — sibling module, **local `replace ../http` directive** in go.mod

## Known debt

TODO.md carries a 2026-04-03 architecture review with the open items (rate
limiting hooks, session listing/revocation, `AttemptStore` leaking HTTP
concerns, coarse error types, audit hooks). Check it before adding a capability
— the gap may already be catalogued with a chosen direction.
