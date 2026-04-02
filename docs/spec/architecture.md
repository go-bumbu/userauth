# Architecture

`userauth` (module `github.com/go-bumbu/userauth`) is a Go library that provides user authentication with pluggable stores, multiple auth strategies, multi-factor authentication, and session management.

## Design Principles

- **Interface-driven**: every capability (user lookup, TOTP, recovery codes, registration, delivery) is a small interface. Consumers wire only what they need.
- **Interfaces on the consumer**: interfaces are defined where they are consumed, not where they are implemented. For example, `handlers/login` defines `UserLogin`, `UserLogout`, `PendingLoginSetter`, and `PendingLoginGetter` — the session manager and pending login stores satisfy them implicitly.
- **Read/write split**: login and auth verification depend on read-only interfaces (`UserGetter`, `TOTPGetter`, `RecoveryCodeVerifier`). Configuration interfaces (`TOTPConfigurator`, `RecoveryCodeConfigurator`, `UserRegistrar`) are separate, so read-only stores (e.g. static files) can participate in login without implementing writes.
- **Transport-agnostic core**: `LoginHandler` operates on user IDs and passwords, not HTTP. HTTP-specific adapters live in sub-packages.

## Package Map

```
userauth.go                    # Core types, LoginHandler, credential + 2FA verification
hashutil/                      # Password hashing (bcrypt) and recovery-code hashing (SHA-256)
handlers/
  auth/                        # AuthHandler interface (Name, HandleAuth → allow/stop)
    cookieauth/                # Session manager: cookie-based sessions (gorilla/sessions),
                               #   session store constructors (filesystem, cookie),
                               #   request-context helpers (CtxGetUserData/CtxSetUserData)
    basicauth/                 # HTTP Basic Auth handler (optional enforce mode)
    headerauth/                # Trusts an upstream header (default X-User-Auth)
    chain/                     # Chain authenticator: evaluates a list of AuthHandlers in order
  login/                       # HTTP login adapters (decoupled from session implementation):
                               #   JsonAuthHandler (JSON API), FormAuthHandler (HTML form),
                               #   LogoutHandler, Verify2FAHandler (generic, strategy via func param)
                               #   Defines consumer interfaces: UserLogin, UserLogout,
                               #   PendingLoginSetter, PendingLoginGetter
pendinglogin/
  memory/                      # In-memory pending login store (dev/testing, staticusers)
  db/                          # GORM-backed pending login store (production, standalone)
userstore/
  staticusers/                 # In-memory store loaded from YAML/JSON file
  dbusers/                     # GORM+SQLite store with registration, TOTP, recovery codes,
                               #   email/SMS verification codes, second-factor flags
delivery/
  smtp/                        # Sends verification codes via SMTP (HTML template)
  file/                        # Writes verification codes to disk (dev/testing)
```

## Core Types

### LoginHandler

Central entry point for credential verification. Stateless; depends on injected read interfaces.

```
LoginHandler
  .UserStore       UserGetter              # required: user lookup
  .SecondFactors   SecondFactorProvider     # optional: which 2FA methods are enabled per user
  .TOTP            TOTPGetter              # optional: TOTP secret lookup
  .RecoveryCode    RecoveryCodeVerifier    # optional: one-time recovery code check
  .EmailCode       EmailCodeVerifier       # optional: email OTP check
  .SMSCode         SMSCodeVerifier         # optional: SMS OTP check
```

**Flow**: `CanLogin(userID, password)` returns a `LoginResult`:
1. Look up user via `UserStore.GetUser` — fail if not found or disabled.
2. Verify password via `hashutil.VerifyPassword` (bcrypt).
3. If `SecondFactors` is wired, call `AvailableSecondFactors` — if any are enabled, return `Requires2FA: true` with the list.
4. Otherwise return `Authenticated: true`.

Individual `Verify*` methods handle the second step of 2FA login.

### AuthHandler Interface

```go
type AuthHandler interface {
    Name() string
    HandleAuth(w http.ResponseWriter, r *http.Request) (allowAccess, stopEvaluation bool)
}
```

Defined in `handlers/auth`. Used by the chain authenticator to evaluate multiple strategies in order. `stopEvaluation` lets a handler short-circuit the chain (e.g. Basic Auth in enforce mode).

### Session Manager (handlers/auth/cookieauth)

Implements `AuthHandler`. Manages cookie-based sessions with:
- **Rolling expiry** (`SessionDur`): renewed on each request (if `AllowRenew` is true).
- **Hard expiry** (`MaxSessionDur`): forces re-login regardless of activity.
- **Write throttle** (`MinWriteSpace`): avoids excessive store writes on rapid requests.
- **Session data** stored via gorilla/sessions (filesystem or cookie backend).
- Puts `UserData` into request context on authenticated requests.

### Login Handlers (handlers/login)

HTTP handlers for login, logout, and 2FA verification. Decoupled from the session implementation via consumer-defined interfaces:

| Interface | Methods | Purpose |
|-----------|---------|---------|
| `UserLogin` | `LoginUser(r, w, userID, keepLoggedIn)` | Create a session on successful auth |
| `UserLogout` | `LogoutUser(r, w)` | Destroy a session |
| `PendingLoginSetter` | `SetPendingLogin(r, w, data)` | Store pending login state when 2FA is required |
| `PendingLoginGetter` | `GetPendingLogin(r, userID)`, `ClearPendingLogin(r, w, userID)` | Read/clear pending login during 2FA verify |

**Handlers:**
- `JsonAuthHandler` — JSON POST login. On 2FA, stores pending login and returns `{requires2fa, userID, available_second_factors}`.
- `FormAuthHandler` — HTML form POST login with redirect. No 2FA support.
- `LogoutHandler` — destroys session, optional redirect.
- `Verify2FAHandler` — generic 2FA verifier. Takes a verify function (e.g. `auth.VerifyTOTP`) as parameter. Reads pending login for `keepMeLoggedIn`, clears it on success.

### 2FA Login Flow

1. **POST `/login`** `{username, password, sessionRenew}` — password OK, 2FA required → pending login stored server-side → responds `{requires2fa, userID, available_second_factors}`
2. **POST `/verify-*`** `{userID, code}` — reads pending login → verifies code → creates session with stored `keepMeLoggedIn` → clears pending login

`keepMeLoggedIn` is captured once during login and carried server-side to the verification step — it is not part of the 2FA verify payload.

## Pending Login Store

When a user's password is valid but 2FA is required, the login handler needs to carry state (`userID`, `keepMeLoggedIn`) from the initial login request to the subsequent 2FA verification request. This avoids requiring the client to re-submit login preferences during 2FA, and keeps `userID` server-controlled between steps.

`PendingLoginSetter` stores this state when 2FA is triggered; `PendingLoginGetter` retrieves it during verification. The handler enforces expiry regardless of implementation. Three implementations, same interface:

| Implementation | Package | Storage | Use case |
|---------------|---------|---------|----------|
| In-memory | `pendinglogin/memory` | `sync.Mutex` + map | Dev/testing, staticusers |
| DB-backed | `pendinglogin/db` | GORM (pending_logins table) | Production, multi-instance |
| Cookie | `pendinglogin/cookie` | Signed+encrypted cookie (gorilla/securecookie) | Stateless servers |

All are standalone packages — `pendinglogin/db` owns its own model and auto-migration, independent from `dbusers`.

## User Stores

| Store | Interfaces Implemented | Storage |
|-------|----------------------|---------|
| `staticusers` | `UserGetter`, `TOTPGetter`, `RecoveryCodeVerifier`, `SecondFactorProvider` | In-memory (loaded from YAML/JSON) |
| `dbusers` | `UserGetter`, `UserRegistrar`, `TOTPConfigurator`, `RecoveryCodeConfigurator`, `RecoveryCodeVerifier`, `RecoveryCodeCountGetter`, `SecondFactorProvider`, `EmailCodeVerifier`, `SMSCodeVerifier` | GORM + SQLite |

### dbusers Schema

| Table | Purpose |
|-------|---------|
| `user_models` | User accounts (login_id, hashed pw, enabled, emails) |
| `user_totp` | TOTP secrets per user |
| `user_recovery_codes` | One-time recovery code hashes (max 6 per user) |
| `user_email_verification_codes` | Time-limited email OTP hashes |
| `user_sms_verification_codes` | Time-limited SMS OTP hashes |
| `user_second_factor_flags` | Per-user email/SMS 2FA enabled flags |

## Auth Strategies

### Cookie/Session Auth
Primary strategy. `handlers/login` provides JSON and form-based login handlers that call `LoginHandler.CanLogin`, then create a session via `UserLogin.LoginUser`. Supports the full 2FA flow with server-side pending login state.

### Basic Auth
`basicauth.AuthHandler` checks `Authorization: Basic` headers. In enforce mode, sends `WWW-Authenticate` header to prompt the browser. Does not create sessions.

### Header Auth
`headerauth.HeaderHandler` trusts a header (default `X-User-Auth`) set by an upstream proxy (Authelia, mod_auth_mellon, etc.). No credential verification — presence of the header means authenticated.

### Chain Auth
`chain.Authenticator` evaluates a list of `AuthHandler`s in order, stopping on first success or when a handler sets `stopEvaluation`.

## Delivery (Verification Codes)

The `Deliverer` interface is transport-agnostic:
```go
type Deliverer interface {
    Deliver(ctx context.Context, to string, code string, expiresAt time.Time) error
}
```

| Implementation | Use Case |
|---------------|----------|
| `delivery/smtp` | Production: sends HTML email via SMTP. Supports templating and password-from-file. |
| `delivery/file` | Dev/testing: writes codes to timestamped files on disk. |

Code expiry is enforced by the store (`dbusers.VerifyEmailCode` / `VerifySMSCode`), not the delivery layer. The `expiresAt` passed to `Deliver` is informational — used to render "expires in X minutes" in the message template.

## Username Policy

`UsernameFormat` (any / email / plain) is enforced at registration time by `dbusers.Create`. `ValidateLoginID` is available for use anywhere.

## Dependencies

- `gorilla/mux`, `gorilla/sessions`, `gorilla/securecookie` — HTTP routing and session storage
- `pquerna/otp` — TOTP generation and validation
- `golang.org/x/crypto` — bcrypt
- `gorm.io/gorm` + `gorm.io/driver/sqlite` — database for `dbusers` and `pendinglogin/db`
- `go-bumbu/http` — sibling module (local replace directive)
