## Braindump of todos


### session handler
* session http to implement login/logout handlers
* session admin should allow extra features

### Authentication
* allow multiple user stores? use-case in db users + predefined static ones

### register
* [x] invite code — `register/invite/` package + `register.InviteCheck`
* [x] email verification — `register.EmailCheck` on top of VerificationCodeService

## session store
* the current FS store based on gorilla only allows basic get and set, but to allow a user manage all the sessions
  a custom store will be needed to be implemented

### Other
allow API middle ware
* add a function that checks the request context and returns information about the user
  * should also allow to run without any authentication, e.g. fe26
* rename package to userauth
* JWT middleware?

### food for thought

instead of having severeal user implementaitons, use one with several storage and retrieval interfaces

---

## Coverage gate exclusions

- **userstore/userdb/preset** (excluded 2026-08-18): Sits at 73.9% against the
  80% gate and structurally cannot reach it. `Full` is seven sequential
  constructor calls each with its own error return, and over one shared
  `*gorm.DB` only the first is reachable. The alternative — collapsing the
  seven returns into one site via a table of constructor closures — was
  rejected because it lets a coverage metric dictate the shape of production
  code. **Trigger for revisiting:** if `preset` ever grows real logic beyond
  construction and error wrapping, it goes back under the gate.

---

## Release tracking

- 2026-08-18: `userdb` split into modular GORM stores (breaking). See
  `docs/agents/migration-modular-gorm-stores.md`. Next release must be a minor
  bump with the migration note in the release body.

---

## Architecture Review (2026-04-03)

Items identified during a full architecture review of the library.

### Construction & Validation

- [ ] **Inconsistent constructor patterns**
  Some packages use options structs (`cookieauth.Cfg`), some use positional args (`basicauth.NewHandler`),
  `loginflow.Flow` is a bare struct validated lazily by `check()`. Standardize on options structs.

### Security

- [x] **Recovery codes use SHA-256, should use bcrypt/argon2**
  Recovery codes are short, low-entropy strings. SHA-256 is fast enough to brute-force all possible codes from a
  stolen DB. Use a slow hash like bcrypt.
- [x] **TOTP secret stored in plaintext**
  `TOTPData.Secret` is stored unencrypted in the DB. A compromised DB exposes every user's TOTP secret. Encrypt
  at rest with a server-side key.
- [x] **No rate limiting or brute-force protection hooks**
  Addressed 2026-08 (`feat/brute-force-protection`): per-code attempt caps in `verificationcode.Service`,
  verifier backoff for TOTP/recovery (`service/throttle.Backoff`), per-loginID `login.Guard` in `Flow.Submit`,
  issuance rate limiting (`Flow.Resend`), and a throttled `basicauth`. Per-IP/volumetric limiting stays the
  caller's/proxy's job. Still open: audit/event hooks so consumers can feed fail2ban/alerting.
- [ ] **No CSRF protection**
  Left entirely to the consumer with no guidance or helpers.

### Error Handling

- [ ] **Password verification errors are swallowed**
  `loginflow.PasswordMethod.Verify` (and `basicauth`) return `false, nil` for both wrong passwords and corrupted
  hashes. Callers cannot distinguish "wrong password" from "your database is corrupt."
- [ ] **Error types are too coarse**
  Only `ErrUserNotFound` and `ErrUserDisabled` exist. Missing: `ErrInvalidCredentials`, `ErrTOTPRequired`,
  `ErrCodeExpired` vs `ErrCodeInvalid`, `ErrAccountLocked`.

### Session Management

- [ ] **No session listing or revocation API**
  No way to list active sessions, revoke a specific session, or revoke all sessions (e.g., after password change).
  Critical for a multi-service auth gateway.
- [ ] **No session metadata**
  No tracking of device, IP, user-agent, or last-active time per session.

### User Lifecycle

- [ ] **No `UserUpdater` / `UserDeleter` interfaces**
  `UserGetter` and `UserRegistrar` exist but there's no standard interface for updating user fields, deleting
  users, or changing passwords. `dbusers` has some methods but they're not abstracted.
- [ ] **No password policy enforcement**
  `dbusers.Create` accepts any password. No hooks for minimum length/complexity, breach checking, or password
  history. Partially addressed: `register.Flow` has a `PasswordValidator` hook, so self-registration can enforce
  a policy; `userdb.Create` itself is still unhooked.
- [ ] **No account recovery flow**
  Recovery codes exist but there's no email-based password reset flow.

### Design & Coupling

- [ ] **`loginflow.AttemptStore` leaks HTTP concerns**
  `Set`/`Clear` take `*http.Request` and `http.ResponseWriter` that memory and DB implementations ignore.
  The interface is shaped by the cookie implementation, not the domain. Separate storage from HTTP transport.
  `register.PendingStore` consciously repeats the same shape for consistency — redesign both together.
- [x] **Email/SMS code generation lives in `dbusers`**
  `GenerateEmailVerificationCode` and `GenerateSMSVerificationCode` are methods on `DbManager`. Code generation
  is domain logic (length, expiry, charset), not storage logic. Move to core or a dedicated service.
- [x] **TOTP enrolment lived in the demo, TOTP/recovery crypto lived in `userdb`**
  Addressed 2026-08: `service/totp` (enrolment, validation, secret encryption via `Opts.Cipher`) and
  `service/recoverycodes` (generation, bcrypt hashing, single-use consumption) own the policy;
  `service/totp/store/db` and `service/recoverycodes/store/db` are pure persistence behind the service
  interfaces, and the write-side root interfaces were removed. The AES cipher shared with `service/pat`
  moved to `service/cipher`.
- [ ] **`dbusers` is coupled to GORM**
  No storage interface at the `userauth` package level. If you want raw SQL or a different ORM, you must rewrite
  the entire store. Define a persistence interface in core. Note: the actual SQL used is portable GORM (no
  SQLite-specific code), so switching databases within GORM is fine — the coupling concern is about GORM itself.
- [ ] **No graceful bcrypt cost migration**
  If you want to increase bcrypt difficulty over time, there's no mechanism to re-hash on successful login.

### Observability

- [ ] **No audit trail or event hooks**
  No mechanism for logging "user X logged in", "2FA failed for user X", "recovery code consumed". An
  `EventListener` or callback interface would allow consumers to plug in logging/alerting without modifying
  the library.

### Missing Capabilities

- [ ] Token-based auth (JWT / opaque tokens)
- [ ] **Review tokenauth Enforce policy**
  `auth/tokenauth` enforce only stops chain evaluation when a token is *presented* and invalid;
  absent tokens always fall through (unlike headerauth, which stops on absence). Revisit whether
  this asymmetry is right once real consumers exist (PAT design, 2026-08-06).
- [ ] OAuth2 / OIDC provider support
- [ ] Graceful bcrypt cost migration on login

---

## Move to services (2026-08-17 review)

Where policy still lives in the wrong layer, found by reviewing what remains after
`service/totp` + `service/recoverycodes` landed. The pattern to follow is
established three times now (`pat`, `verificationcode`, `totp`): **the service owns
policy and crypto, the store is pure persistence behind a narrow interface, and a
`storetest` conformance suite holds every implementation to the same contract** —
see `docs/agents/architecture.md`.

Ordered by value. #1 has landed. #2 is a refactor of existing behaviour, #3 is a new
capability that deserves its own design pass, and #4 is the structural one that
re-homes what is left of `userdb` — its first two phases landed with the modular
store split on 2026-08-18, leaving only the `service/user` extraction itself.

### 1. ~~Finish the `verificationcode.CodeStore` adapter in `userdb` (phase 2)~~

**DONE 2026-08-18.** `service/verificationcode/store/db` is the GORM `CodeStore`,
one instance per channel over the `verification_codes` table. The `attempts`
column exists and atomic consume-or-count is implemented. The old
`StoreEmailCode`, `VerifyEmailCode`, `StoreSMSCode`, `VerifySMSCode` methods are
deleted. `service/verificationcode/storetest` conformance suite added and run
against both `store/memory` and `store/db`.

The design question about second-factor enrolment flags was resolved:
`service/secondfactor/store/db` now owns the `second_factor_flags` table (one
row per factor) and the `Flags` store is composed into `secondfactor.Provider`
for email/SMS availability. The asymmetry with TOTP is deliberate: TOTP
enrolment is a secret (the TOTP store owns it), email/SMS enrolment is a
user preference (the flags store owns it).

### 2. `service/password` — password crypto and policy are split five ways

Genuine new-service candidate, small and high-leverage. Today:

| Site | What it does |
|---|---|
| `userstore/userdb/user.go:67` | `bcrypt.GenerateFromPassword(pw, s.bcryptDifficulty)` — store-configured cost |
| `flow/register/register.go:296` | `hashutil.HashPassword` — **`bcrypt.DefaultCost`, ignoring the store's cost** |
| `demo/examples/profile/profile.go:204` | `userauth.HashPassword` — DefaultCost again |
| `flow/login/methods.go:60` | `hashutil.VerifyPassword` |
| `auth/basicauth/basicauth.go:147` | `hashutil.VerifyPassword` (duplicated) |

- Concrete bug: a store configured with cost 12 gets **cost-10 hashes** from
  self-registration. Nothing keeps the two in step.
- `userdb.SetPasswordHash` takes a hash, so every consumer hashes for itself (the
  demo does), and `PasswordValidator` (`flow/register/register.go:93`) is wired
  into the register flow only — `userdb.Create` stays unhooked.
- A service owning algorithm + cost, `Hash`, `Verify`, `ValidatePolicy` and
  **rehash-on-successful-verify** closes four open items above at once: password
  policy enforcement, graceful bcrypt cost migration (listed twice), swallowed
  password-verification errors (verify can return a reason instead of
  `false, nil` for both wrong password and corrupt hash), and part of the
  `dbusers`-coupling item.
- The store keeps `HashPw` on `userauth.User` (read) and a hash-setter (write);
  the service sits between them and is the only thing that picks a cost.

### 3. `service/session` — session registry (biggest missing capability)

- `cookieauth.Manager` (`auth/cookieauth/cookie.go:38`) is a per-request
  authenticator over `gorilla/sessions` with three time windows but **no
  registry**: no listing active sessions, no revoking one, no revoke-all. Also no
  device / IP / user-agent / last-active metadata. Both are listed under
  *Session Management* above.
- Boundary: `cookieauth` stays transport + validation; the service owns session
  records behind its own `Store`. Do not fold the registry into the authenticator.
- Largest item here: `gorilla/sessions`' store interface cannot enumerate, so this
  needs a real session store (already noted under *session store* at the top).
- Pairs with #2 — revoke-all-sessions is what a password change should trigger.

### 4. `service/user` — the last store that still owns its own policy

**Phases 1 and 2 landed 2026-08-18** with the modular GORM store split (see
`docs/agents/migration-modular-gorm-stores.md`). What that delivered, and what it
taught, is recorded below the remaining work — read it before starting phase 3,
because two of this item's original assumptions turned out to be wrong.

**Still open — phase 3, the extraction itself.** `userstore/userdb` is the one place
where "service owns policy, store owns persistence" was never applied. Everything
else in `service/` follows it; `userdb` predates the pattern. Extract the policy into
`service/user` and leave a pure-persistence GORM store behind.

**Policy still living in the store** (the extraction list, line numbers as of
2026-08-18):

| Site | Policy |
|---|---|
| `store.go` + `user.go` | bcrypt cost — belongs to #2, *not* to `service/user` |
| `store.go` + `user.go` | `usernameFormat` / `ValidateLoginID` on create |
| `store.go` + `user.go` | `defaultEnabled` for new accounts |
| `user.go` | UUIDv7 minting — identity policy |
| `user.go` | `List` limit default 50 / cap 200 |
| `bootstrap.go` | `Bootstrap` create-if-empty ceremony |

The hardcoded delete cascade is **no longer on this list** — it became the
`userdb.UserPurger` contract in phase 1.

**Boundary with #2 (`service/password`) — get this right or the two items collide:**
`service/user` owns the *identity* lifecycle and never touches a hash. It takes an
already-hashed password on create and exposes a hash-setter; picking algorithm and
cost, `Verify`, policy validation and rehash-on-login all stay in `service/password`.
Land #2 first and `service/user` inherits a store that no longer calls bcrypt. This
did **not** happen in phase 2 — #2 has not landed, so the store still calls bcrypt.

**Target layout:**

```
userauth.go                  vocabulary — unchanged (User, UserGetter, UserUpdater, …)
service/user/                Service: loginID format, UUID minting, defaultEnabled,
                             Bootstrap, list caps, delete cascade
  store/db/                  user_models + user_groups + user_pending_email_changes
  store/memory/              new; lets consumers test without SQLite
  storetest/                 conformance suite, as totp/ and recoverycodes/ have
userstore/staticusers/       stays: read-only, no lifecycle, no service needed
```

- **Why the location changes.** `userstore/userdb` is correct *today* under placement
  rule 2 (root interface ⇒ top-level dir), because `UserGetter`/`UserUpdater`/
  `UserRegistrar` are root vocabulary. Once a service owns the persistence interface,
  the store moves under it like every other one. The root interfaces do **not** move —
  they are consumed by `auth/`, `flow/login`, `flow/register` and `service/pat`, so
  they stay vocabulary; `service/user.Service` implements them and every consumer
  compiles unchanged. The break is at wiring only.
- **`staticusers` stays on the root interfaces directly.** The asymmetry (read-only
  store bypasses the service, lifecycle store goes through it) is the established
  `TOTPGetter` + `totp.FromGetter` precedent, not a new wart.
- **The `Purger` contract moves from the store to the service.** It currently lives on
  `userdb.Store` as `Opts.OnDelete []UserPurger`; when the service owns the lifecycle
  it should own the cascade too.
- **Open questions to settle in the design pass:** does `service/user` own
  `SetLoginID` (re-validating format) or does that stay a store write? Do
  `CreateUser` / `CreateUserWithHashedPassword` / the YAML-tagged `userdb.User` struct
  stay store-level types or move to the service? Does `Bootstrap` belong on the
  service or in a `preset`? Where does `user_pending_email_changes` go, given the
  *Belongs in a flow* item below wants it in a flow rather than either layer?

#### What phases 1-2 delivered (2026-08-18)

- Satellite `store/db` packages for `totp`, `recoverycodes`, `pat`,
  `verificationcode` and `secondfactor`, each owning one table and its own
  `AutoMigrate`. `userdb` now creates three tables instead of nine, and imports none
  of the five services (asserted by `go list -deps`).
- The delete cascade became `userdb.UserPurger` (`PurgeUser(userID string) error`) in
  `Opts.OnDelete`, non-atomic delete-then-purge, exactly as this item proposed.
- `AvailableSecondFactors` became composable: it is gone from `userdb`, and
  `secondfactor.Provider` composes one `Availability` per factor. The flags question
  raised in #1 was resolved — `service/secondfactor` owns a row-per-factor table, and
  the asymmetry with TOTP is deliberate (TOTP enrolment is a secret, email/SMS
  enrolment is a user preference).
- One-call ergonomics kept via `userstore/userdb/preset.Full`, which lives in a
  subpackage precisely so `userdb` does not import the factor services.
- The naming note held: every nested `db` package is import-aliased (`totpdb`,
  `patdb`, `recoverydb`, `codedb`, `flagsdb`).

#### Two assumptions this item got wrong — do not repeat them in phase 3

- **"Zero data migration" was only true for the tables that moved.** `user_totp`,
  `user_recovery_codes` and `user_pats` moved untouched. But
  `user_email_verification_codes` / `user_sms_verification_codes` were *replaced* by a
  generic `user_verification_codes` table, and the boolean-per-factor
  `user_second_factor_flags` by a row-per-factor table of the same name — which needs
  a real data migration. Skipping the flags migration silently downgrades every
  email/SMS 2FA user to password-only, because an empty factor list reads as "policy
  satisfied". The justification for not migrating ("`SetEmailCodeEnabled` has zero
  consumers") was a claim about *this repo*; it was public API of a published library.
- **"UUIDs are never reused, so an orphaned row is inert" does not hold universally.**
  It holds for satellites keyed on the canonical user UUID. `flow/login/guard.go`
  deliberately keys the throttle store on the raw **login identifier**, which is the
  one identifier that does recycle — so `login_throttle` rows survive deletion and are
  inherited by the next account with the same login ID. Consequence is availability
  (an inherited failure counter), not confidentiality. Scope the guarantee when you
  restate it.

### Belongs in a flow, not a service

- [ ] **Pending email change** — `userdb.StorePendingEmailChange` /
  `GetPendingEmailChange` / `ConsumePendingEmailChange` (`userstore/userdb/email.go`)
  store a SHA-256 code hash. The fix is a multi-step flow (request → verify → apply)
  composing `verificationcode` for the code lifecycle, so crypto stays in one
  place. By the placement rules multi-step ⇒ `flow/`.
- [ ] **Password reset / account recovery** (open item above) — `flow/passwordreset`
  composing `verificationcode` for the code and `service/password` (#2) for the
  new hash. Not a service.

### Explicitly *not* services

Recorded so the next pass does not re-litigate them:

- **Audit / event hooks** (open item above) — a thin `EventListener` / `Recorder`
  interface consumed by the engines. No policy, no store: a service here would be
  pure ceremony.
- **Groups** (`userstore/userdb/groups.go`) — identity facts, never policy; what a
  membership permits is the consuming application's business.
- **`userdb.List` pagination** and **`staticusers`** — storage and read-only
  data respectively. Nothing to extract.
- **`AvailableSecondFactors`** — a derived read. `staticusers` implements
  `SecondFactorProvider` directly; compose a `secondfactor.Provider` from the
  satellite stores for the full setup. Not a service.
- **`login.AttemptStore` / `register.PendingStore`** — correctly engine-scoped;
  their real problem is the HTTP leak listed under *Design & Coupling*.

### Placement judgment call

- [ ] **`flow/register/invite` → `service/invite`?** It is already
  `Service` + `Store` + `Opts` with two backends (`flow/register/invite/invite.go:64-158`),
  i.e. service-shaped, and is nested only because registration is its single
  consumer. Placement rule 4 says multiple consumers ⇒ top level, so move it when
  a second consumer appears (an admin UI issuing invites, or a second flow) — not
  before.
