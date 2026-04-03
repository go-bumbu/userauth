## Braindump of todos


### session handler
* session http to implement login/logout handlers
* session admin should allow extra features

### Authentication
* allow multiple user stores? use-case in db users + predefined static ones

### register
* invite code
* email verification

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

## Architecture Review (2026-04-03)

Items identified during a full architecture review of the library.

### Construction & Validation

- [ ] **LoginHandler needs a constructor with validation**
  Currently a bare struct with public fields. If a 2FA verifier is set but `SecondFactors` is nil, 2FA silently
  never triggers. A `NewLoginHandler()` should validate invariants at startup.
- [ ] **Inconsistent constructor patterns**
  Some packages use options structs (`cookieauth.Cfg`), some use positional args (`basicauth.NewHandler`),
  `LoginHandler` has no constructor at all. Standardize on options structs.

### Security

- [x] **Recovery codes use SHA-256, should use bcrypt/argon2**
  Recovery codes are short, low-entropy strings. SHA-256 is fast enough to brute-force all possible codes from a
  stolen DB. Use a slow hash like bcrypt.
- [x] **TOTP secret stored in plaintext**
  `TOTPData.Secret` is stored unencrypted in the DB. A compromised DB exposes every user's TOTP secret. Encrypt
  at rest with a server-side key.
- [ ] **No rate limiting or brute-force protection hooks**
  No interface for account lockout, login attempt tracking, or rate limiting. Provide at minimum a
  `LoginAttemptRecorder` interface so consumers don't have to wrap `CanLogin` themselves.
- [ ] **No CSRF protection**
  Left entirely to the consumer with no guidance or helpers.

### Error Handling

- [ ] **Password verification errors are swallowed**
  `CanLogin` returns `Authenticated: false, nil` for both wrong passwords and corrupted hashes. Callers cannot
  distinguish "wrong password" from "your database is corrupt."
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
  history.
- [ ] **No account recovery flow**
  Recovery codes exist but there's no email-based password reset flow.

### Design & Coupling

- [ ] **`PendingLogin` interfaces leak HTTP concerns**
  `SetPendingLogin` takes `*http.Request` and `http.ResponseWriter` that memory and DB implementations ignore.
  The interface is shaped by the cookie implementation, not the domain. Separate storage from HTTP transport.
- [x] **Email/SMS code generation lives in `dbusers`**
  `GenerateEmailVerificationCode` and `GenerateSMSVerificationCode` are methods on `DbManager`. Code generation
  is domain logic (length, expiry, charset), not storage logic. Move to core or a dedicated service.
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
- [ ] OAuth2 / OIDC provider support
- [ ] Graceful bcrypt cost migration on login
