# Overview

`userauth` (module `github.com/go-bumbu/userauth`) is a Go library for user
authentication with pluggable stores, multiple auth strategies, multi-factor
authentication, and session management.

## Design Principles

- **Interface-driven**: every capability is a small interface; consumers wire
  only what they need
- **Interfaces on the consumer**: defined where consumed, not where implemented
  (e.g. `handlers/login` defines `UserLogin`, `UserLogout`)
- **Read/write split**: login uses read-only interfaces (`UserGetter`,
  `TOTPGetter`); config interfaces (`TOTPConfigurator`, `UserRegistrar`) are
  separate so read-only stores can participate in login
- **Transport-agnostic core**: `LoginHandler` works on user IDs and passwords,
  not HTTP

## Package Layout

```
userauth.go                    Core types, LoginHandler, credential + 2FA verification
hashutil/                      bcrypt (passwords, recovery codes), SHA-256 (verification
                               codes), AES-256-GCM (TOTP secrets), numeric code generation
handlers/
  auth/                        AuthHandler interface (Name, HandleAuth)
    cookieauth/                Session manager: cookie-based sessions (gorilla/sessions),
                               filesystem/cookie store, request-context helpers
    basicauth/                 HTTP Basic Auth (optional enforce mode)
    headerauth/                Trusts upstream header (default X-User-Auth)
    chain/                     Evaluates multiple AuthHandlers in order
  login/                       HTTP login adapters: JsonAuthHandler, FormAuthHandler,
                               LogoutHandler, Verify2FAHandler
pendinglogin/
  memory/                      In-memory map (dev/testing)
  cookie/                      Signed+encrypted cookie (stateless)
  db/                          GORM row (production, multi-instance)
userstore/
  staticusers/                 In-memory from YAML/JSON file (read-only)
  dbusers/                     GORM+SQLite: registration, TOTP, recovery codes,
                               email/SMS codes, second-factor flags
delivery/
  smtp/                        Sends verification codes via SMTP (HTML template)
  file/                        Writes codes to disk (dev/testing)
```

## Key Flows

### Login
```
POST /login {username, password, sessionRenew}
  -> JsonAuthHandler -> LoginHandler.CanLogin(userID, password)
     -> UserStore.GetUser -> check Enabled -> hashutil.VerifyPassword
     -> SecondFactorProvider.AvailableSecondFactors (if wired)
        -> no 2FA  -> LoginUser() -> session created, 200
        -> has 2FA -> SetPendingLogin() -> 200 {requires2fa, userID, available_second_factors}
```

### 2FA Verification
```
POST /verify-* {userID, code}
  -> Verify2FAHandler -> GetPendingLogin(userID) -> check not expired
     -> verify func (VerifyTOTP / VerifyRecoveryCode / VerifyEmailCode / VerifySMSCode)
     -> LoginUser(keepMeLoggedIn from pending) -> ClearPendingLogin -> 200
```

`keepMeLoggedIn` is captured at login and carried server-side -- not part of
the 2FA verify payload.

### Request Authentication
```
Request + Cookie
  -> chain.Authenticator.EvalAuth()
     -> cookieauth.Manager.HandleAuth() -- read session, verify expiry, renew
     -> basicauth.HandleAuth()          -- fallback: Authorization header
     -> headerauth.HandleAuth()         -- fallback: trust upstream header
  First success wins. stopEvaluation short-circuits the chain.
```

## Interface Composition

### LoginHandler (core, read-only)
```
LoginHandler
  .UserStore       UserGetter              required
  .SecondFactors   SecondFactorProvider     optional
  .TOTP            TOTPGetter              optional
  .RecoveryCode    RecoveryCodeVerifier     optional
  .EmailCode       EmailCodeVerifier        optional
  .SMSCode         SMSCodeVerifier          optional
```

### Write interfaces (configuration handlers only)
```
TOTPConfigurator            SetTOTP(userID, data)          extends TOTPGetter
RecoveryCodeConfigurator    SetRecoveryCodes(userID, hashes)
RecoveryCodeCountGetter     GetRecoveryCodesCount(userID)
UserRegistrar               Create(id, pw)
```

### Login handler interfaces (consumer-defined)
```
UserLogin            LoginUser(r, w, userID, keepLoggedIn)
UserLogout           LogoutUser(r, w)
PendingLoginSetter   SetPendingLogin(r, w, data)
PendingLoginGetter   GetPendingLogin(r, userID), ClearPendingLogin(r, w, userID)
```

## Session Lifecycle

`cookieauth.Manager` manages two time windows:
- **Rolling expiry** (`SessionDur`, default 1h) -- renewed on each request
  when `AllowRenew` is true. Idle timeout.
- **Absolute deadline** (`MaxSessionDur`, default 24h) -- never renewed.
  Forces re-login.
- **Write throttle** (`MinWriteSpace`, default 2min) -- avoids excessive
  store writes.

## User Stores

| Store | Implements | Storage |
|-------|-----------|---------|
| `staticusers` | UserGetter, TOTPGetter, RecoveryCodeVerifier, SecondFactorProvider | In-memory from YAML/JSON |
| `dbusers` | All read + write interfaces | GORM + SQLite |

### dbusers Tables
| Table | Purpose |
|-------|---------|
| `user_models` | Accounts (login_id, hashed pw, enabled, emails) |
| `user_totp` | TOTP secrets per user |
| `user_recovery_codes` | One-time recovery code hashes (max 6) |
| `user_email_verification_codes` | Time-limited email OTP hashes |
| `user_sms_verification_codes` | Time-limited SMS OTP hashes |
| `user_second_factor_flags` | Per-user email/SMS 2FA enabled flags |

## Dependencies

- `gorilla/mux`, `gorilla/sessions`, `gorilla/securecookie` -- HTTP + sessions
- `pquerna/otp` -- TOTP generation/validation
- `golang.org/x/crypto` -- bcrypt
- `gorm.io/gorm` + `gorm.io/driver/sqlite` -- DB for dbusers, pendinglogin/db
- `go-bumbu/http` -- sibling module (local replace directive)
