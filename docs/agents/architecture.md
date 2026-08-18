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
  staticusers/  userdb/    userdb owns users, groups and pending email changes only
    userdb/preset/         one-call bundle of every GORM store, with the delete cascade
service/secondfactor/    composes SecondFactorProvider from per-factor availability;
  store/{memory,db}/       Flags store for factors that are a user preference
service/totp/            authenticator-app service
  store/{memory,db}/
service/recoverycodes/   one-time recovery code service
  store/{memory,db}/
service/pat/             personal access tokens
  store/{memory,db}/
service/verificationcode/  shared one-time-code service
  store/{memory,db}/       db is one instance per channel over one table
service/throttle/        brute-force backoff policy: Backoff + Store, consumed by the
  store/{memory,db}/       login engine (verifier throttle, guard, resend limit) and basicauth
service/cipher/          Secret interface + single-key AESGCM, shared by pat and totp
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
  user configuration uses separate write interfaces (`UserRegistrar`,
  `UserUpdater`) so read-only stores can still participate in login. Credential
  *lifecycles* (TOTP enrolment, recovery codes, PATs, verification codes) are
  not store interfaces at all — they are services with their own persistence
  interfaces.
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
  `service/pat/store/db`, in-memory is `service/pat/store/memory`.
- **`ParseToken`** splits the wire format into its three segments; **`finishVerify`**
  is the shared tail of `Verify` and `VerifyMatch` (expiry, owner lookup and
  enabled flag, throttled last-used touch).

## TOTP and recovery codes: service = policy, store = persistence

Restructured 2026-08 (`feat/totp-service`). Before it, TOTP was split across three
layers: enrolment lived in the demo, secret encryption in `userdb`, and code
validation in `flow/login`. Now:

- **`service/totp` owns everything about the authenticator factor**: secret
  generation, the `otpauth://` URI, the enrolment ceremony, code validation
  (30s period, 6 digits, `Opts.Skew` periods of drift, default 1), and
  encryption of the secret at rest via `Opts.Cipher`.
  - Enrolment is two-phase on purpose: `Enroll` stores the secret **disabled**,
    and only `Confirm` (a working code) enables it — a user who abandons setup is
    never locked into a secret they cannot produce codes for. `Pending` re-renders
    an unconfirmed enrolment so a reloaded setup page keeps the same QR.
  - `Disable` **deletes** the record rather than flagging it off: a disabled
    factor that keeps its secret is a credential nobody is watching.
  - `Verify` returns `(false, nil)` for wrong code / pending / not enrolled, and
    reserves errors for store and cipher failures, so a policy can call it
    blindly without turning a missing factor into a 500.
  - `QRPNG(uri, size)` renders the URI as a PNG; it validates the `otpauth`
    scheme itself because `otp.NewKeyFromURL` accepts almost anything.
  - `FromGetter(userauth.TOTPGetter, skew)` adapts read-only stores
    (`staticusers`) that hold a secret and have no enrolment lifecycle.
- **`service/recoverycodes` owns the recovery factor**: generation, bcrypt
  hashing, how many a user gets (`Opts.Count`, default 6, max 20 — verification
  cost is linear in the count), and single-use consumption. `Issue` replaces the
  whole set, so it doubles as regenerate. It implements
  `userauth.RecoveryCodeVerifier`, so `login.RecoveryMethod` consumes it
  unchanged.
- **Both `Store` interfaces are pure persistence** and see only opaque strings:
  `totp.Store` is Get/Set/Delete over a `Record{Secret, KeyID, Enabled}`;
  `recoverycodes.Store` is Replace/Hashes/Delete/Count over bcrypt hashes (the
  service compares and then deletes the matching hash — the store never compares).
  In-memory implementations live under each `store/memory`, the GORM ones are
  `service/totp/store/db` and `service/recoverycodes/store/db`, and both are held to the
  same `storetest.Run` conformance suite.
- **Encryption moved from `userdb` into the service** (`Opts.Cipher`,
  `service/cipher`). Compatibility: the AEAD context is empty, matching the old
  `hashutil.Encrypt(secret, key, nil)` call, and `cipher.AESGCM.Decrypt` treats an
  empty stored key id as "my key" — so rows written before the `key_id` column
  existed still decrypt. Moving the key is a **config change, no data migration**;
  `userdb.Opts.TOTPEncryptionKey` is gone. Guarded by
  `TestTOTPSecretsEncryptedBeforeTheServiceOwnedTheCipher`.
- **Throttling stayed out of both services.** The shared `service/throttle`
  backoff is applied by `login.TOTPMethod` / `RecoveryMethod`, so all
  small-keyspace factors escalate together. `TOTPMethod` checks `Enabled` before
  entering the throttle, so a user without TOTP costs no backoff budget.
- **The write-side root interfaces are gone**: `TOTPConfigurator`,
  `RecoveryCodeConfigurator` and `RecoveryCodeCountGetter` were removed — enrolment
  and issuance are policy, so they live behind the services' own store
  interfaces. `TOTPData` / `TOTPGetter` remain for read-only stores, and
  `RecoveryCodeVerifier` remains as the login-side interface.

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
- **Phase 2 landed 2026-08-18**: `service/verificationcode/store/db` is the GORM
  `CodeStore`, one instance per channel over the `user_verification_codes` table, with
  the `attempts` column the contract needs. `userdb`'s own
  `VerifyEmailCode`/`VerifySMSCode` are gone — they hashed inside the store and
  could not count attempts.
- **`Deliverer`** (`Deliver(ctx, to, code, expiresAt)`) is orthogonal:
  `service/verificationcode/deliver/smtp` (HTML template, `@/path` password-from-file) and
  `service/verificationcode/deliver/file` (one file per code, for dev). `expiresAt` is informational —
  expiry is enforced by the store.

## User stores

| Store | Package | Implements | Storage |
|---|---|---|---|
| Static users | `userstore/staticusers` | `UserGetter`, `TOTPGetter` (wrap in `totp.FromGetter`), `RecoveryCodeVerifier`, `SecondFactorProvider` | In-memory from YAML/JSON, read-only |
| DB users | `userstore/userdb` | `UserGetter`, `UserUpdater`, `UserRegistrar`, `List`, `Bootstrap` | GORM; owns `user_models`, `user_groups`, `user_pending_email_changes` |

Factor and token persistence is **not** in `userdb`: each service ships its own
GORM store, and each owns one table plus its migration
(`service/totp/store/db` → `user_totp`, `service/recoverycodes/store/db` →
`user_recovery_codes`, `service/pat/store/db` → `user_pats`,
`service/verificationcode/store/db` → `user_verification_codes`,
`service/secondfactor/store/db` → `user_second_factor_flags`). A setup that offers
no authenticator factor never creates `user_totp`.

`userdb.Delete` cascades into whatever is registered in `Opts.OnDelete` (the
`UserPurger` contract), after its own transaction has removed the user row. The
purge is deliberately not atomic — the contract carries no `*gorm.DB` so that a
purger on any backend can join the cascade, and a failed purge leaks rows in
satellite tables keyed to the canonical user UUID, which is never reused. A known
exception: `flow/login/guard` keys the throttle store on the raw login
identifier, not the UUID, so `login_throttle` rows survive deletion and are
inherited by the next account with the same login ID — a new user starts
throttled with the old one's failure count (availability impact, not
confidentiality — the inherited state is a failure counter, not a credential).
`userstore/userdb/preset.Full` wires all of it in one call for consumers who want
the full feature set.

`AvailableSecondFactors` is no longer a user-store method: compose a
`secondfactor.Provider` from one `Availability` per factor, so a partial setup
reports exactly the factors it wired.

The DB store was refactored 2026-06-30
(`../superpowers/specs/2026-06-30-dbuser-refactor-design.md`): package
`dbusers`/`DbManager` became `New(db, Opts) (*Store, error)`, the single 550-line
`db.go` was split per concern (`store.go`, `models.go`, `user.go`, `totp.go`,
`recovery.go`, `email.go`, `sms.go`, `secondfactor.go`), and paginated
`List(ListOpts) (ListResult, error)` was added (default limit 50, cap 200,
ordered by `login_id ASC`, returns `Total`). Note: the spec named the package
`dbuser`; it has since been renamed again to **`userdb`** — the spec's naming is
stale, the structure is not.

## Hashing strategy (`internal/hashutil`)

- **Passwords and recovery codes: bcrypt** — slow hash for low-entropy secrets
  (recovery codes moved off SHA-256 deliberately; see TODO.md review items).
- **Verification codes: SHA-256** — short-lived (10 min default), needs
  deterministic lookup for the store's consume-by-hash.
- **TOTP secrets: optional AES-256-GCM at rest**, owned by `service/totp` via
  `Opts.Cipher` (`service/cipher.AESGCM` validates the 32-byte key). The store
  keeps ciphertext plus the key id and never decrypts.

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

The 2026-08-18 modular-store split closed the schema-coupling item. Still open:
`AttemptStore` leaking HTTP concerns, coarse error types, audit hooks, session
listing/revocation.

TODO.md carries the full 2026-04-03 architecture review. Check it before adding
a capability — the gap may already be catalogued with a chosen direction.
