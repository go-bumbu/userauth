# Features

## Authentication Strategies

| Feature | Status | Notes |
|---|---|---|
| Cookie/session auth | Implemented | `cookieauth.Manager` -- rolling + absolute expiry, gorilla/sessions |
| HTTP Basic Auth | Implemented | `basicauth` -- optional enforce mode, no sessions |
| Header auth | Implemented | `headerauth` -- trusts upstream header (default `X-User-Auth`) |
| Auth chain | Implemented | `chain.Authenticator` -- evaluates handlers in order, first success wins |

**Cookie/session auth** — Primary strategy. `cookieauth.Manager` implements
`AuthHandler` and manages gorilla/sessions with two expiry windows: rolling
(idle timeout, renewed on activity) and absolute (hard limit). Puts `UserData`
into request context on success.

**HTTP Basic Auth** — Checks `Authorization: Basic` headers. In enforce mode,
sends `WWW-Authenticate` to prompt the browser. Does not create sessions — each
request is independently authenticated.

**Header auth** — Trusts a header set by an upstream proxy (default
`X-User-Auth`). No credential verification — presence of the header means
authenticated. Used behind reverse proxies like Authelia.

**Auth chain** — Evaluates a list of `AuthHandler`s in order, stopping on first
success or when a handler sets `stopEvaluation`. This is how cookie, basic, and
header auth are composed together.

## Login

| Feature | Status | Notes |
|---|---|---|
| JSON API login | Implemented | `handlers/login.JsonAuthHandler` -- full 2FA support |
| Form-based login | Implemented | `handlers/login.FormAuthHandler` -- HTML form, no 2FA |
| Logout | Implemented | `handlers/login.LogoutHandler` -- session destruction |
| 2FA verification endpoint | Implemented | `handlers/login.Verify2FAHandler` -- generic, strategy via func param |

**JSON API login** — Accepts `{username, password, sessionRenew}`. Delegates to
`LoginHandler.CanLogin` for credential check. If 2FA is required, stores a
pending login and returns `{requires2fa, userID, available_second_factors}`
instead of creating a session.

**Form-based login** — HTML form POST with redirect on success. Simpler than
JSON — no 2FA support. Intended for basic setups without a SPA frontend.

**Logout** — Destroys the session via `UserLogout` interface. Optional redirect
after logout.

**2FA verification endpoint** — Generic handler that takes a verify function as
parameter (e.g. `LoginHandler.VerifyTOTP`). Reads the pending login for
`keepMeLoggedIn`, verifies the code, creates a session, and clears the pending
login.

## Multi-Factor Authentication

| Feature | Status | Notes |
|---|---|---|
| TOTP (authenticator app) | Implemented | Read (`TOTPGetter`) and write (`TOTPConfigurator`) interfaces; `dbusers` and `staticusers` |
| Recovery codes | Implemented | `RecoveryCodeVerifier` + `RecoveryCodeConfigurator`; one-time use, bcrypt hashed |
| Email 2FA | Partial | Store layer implemented (`dbusers.VerifyEmailCode`, second-factor flags); needs delivery wiring by consumer |
| SMS 2FA | Partial | Store layer implemented (`dbusers.VerifySMSCode`, second-factor flags); needs delivery wiring by consumer |

**TOTP** — Authenticator app flow using `pquerna/otp`. `TOTPGetter` reads the
shared secret; `TOTPConfigurator` extends it with writes for setup/disable.
Both `dbusers` (persistent) and `staticusers` (read-only) implement the read
interface.

**Recovery codes** — One-time backup codes hashed with bcrypt (low entropy
needs slow hash). `RecoveryCodeVerifier` checks and consumes a code atomically.
`RecoveryCodeConfigurator` replaces all codes for a user. Max 6 codes per user
in `dbusers`.

**Email 2FA** — The store layer is complete: `dbusers` has
`GenerateEmailVerificationCode`, `VerifyEmailCode`, and per-user
`email_code_enabled` flag. What's missing is the consumer wiring — an HTTP
handler that generates a code, calls `Deliverer.Deliver`, and the frontend
flow.

**SMS 2FA** — Same architecture as email 2FA. Store layer complete in `dbusers`
(`GenerateSMSVerificationCode`, `VerifySMSCode`, `sms_code_enabled` flag).
Missing the same consumer wiring and frontend flow.

## Pending Login

| Feature | Status | Notes |
|---|---|---|
| In-memory store | Implemented | `pendinglogin/memory` -- dev/testing |
| Cookie store | Implemented | `pendinglogin/cookie` -- signed+encrypted, stateless |
| DB store | Implemented | `pendinglogin/db` -- GORM, production/multi-instance |

**Pending login** — When password is valid but 2FA is required, state
(`userID`, `keepMeLoggedIn`, expiry) must be carried from the login request to
the 2FA verification request. Three implementations share the same interface
(`PendingLoginSetter`/`PendingLoginGetter`). Memory is for dev, cookie is
stateless (signed+encrypted via gorilla/securecookie), DB is for
production/multi-instance. `pendinglogin/db` owns its own GORM model and
auto-migration, independent from `dbusers`.

## User Stores

| Feature | Status | Notes |
|---|---|---|
| Static users (YAML/JSON) | Implemented | `userstore/staticusers` -- read-only, no registration |
| DB users (GORM+SQLite) | Implemented | `userstore/dbusers` -- full CRUD, all 2FA interfaces |
| User registration | Implemented | `UserRegistrar` interface; `dbusers` implements it |
| Username format policy | Implemented | `UsernameFormat` (any/email/plain); enforced at registration |

**Static users** — Loads users from a YAML/JSON file into memory at startup.
Read-only — implements `UserGetter`, `TOTPGetter`, `RecoveryCodeVerifier`, and
`SecondFactorProvider` but no write interfaces. Suitable for simple setups
where users are predefined.

**DB users** — Full-featured GORM+SQLite store implementing all read and write
interfaces. Handles registration, TOTP setup/disable, recovery codes,
email/SMS verification codes, and second-factor flags. Auto-migrates its schema
on startup.

**User registration** — Gated by the `UserRegistrar` interface. If the store
implements it, registration endpoints can be offered. `dbusers.Create` enforces
the username format policy and hashes the password with bcrypt.

**Username format policy** — `UsernameFormat` enum (any/email/plain) validated
by `ValidateLoginID`. Enforced at registration time. `ParseUsernameFormat`
accepts string or numeric config values.

## Delivery (Verification Codes)

| Feature | Status | Notes |
|---|---|---|
| Deliverer interface | Implemented | Transport-agnostic `Deliver(ctx, to, code, expiresAt)` |
| SMTP delivery | Implemented | `delivery/smtp` -- HTML template, password-from-file support |
| File delivery | Implemented | `delivery/file` -- writes to disk, dev/testing |
| VerificationCodeService | Implemented | Generates codes, hashes with SHA-256, delegates storage |

**Deliverer interface** — Transport-agnostic: `Deliver(ctx, to, code,
expiresAt)`. Implementations decide formatting and transport. `to` is
uninterpreted (email, phone, etc.). `expiresAt` is informational — code expiry
is enforced by the store, not the delivery layer.

**SMTP delivery** — Sends HTML email via SMTP. Supports an embedded default
template or a custom template path. Password can be literal or read from a file
(`@/path/to/file` syntax).

**File delivery** — Writes one file per delivery to a directory:
`<timestamp>-<sanitized-to>.txt` with `to`, `code`, and `expiresAt` fields.
Intended for local dev and testing — check the directory to see what codes were
"sent".

**VerificationCodeService** — Separates code generation from storage. Generates
a numeric code of configurable length, hashes it with SHA-256, delegates
storage via a callback function, and returns the plain code. Instantiated per
channel (email, SMS) with different config.

## Hashing

| Feature | Status | Notes |
|---|---|---|
| Password hashing (bcrypt) | Implemented | `hashutil.HashPassword` / `VerifyPassword` |
| Recovery code hashing (bcrypt) | Implemented | Low entropy needs slow hash |
| Verification code hashing (SHA-256) | Implemented | Short-lived codes, deterministic lookup |
| TOTP secret encryption (AES-256-GCM) | Implemented | Optional encryption at rest |

**Hashing strategy** — Passwords and recovery codes use bcrypt (slow hash for
low-entropy secrets). Verification codes (email/SMS) use SHA-256 for
deterministic DB lookup since they're short-lived (10-15 min). TOTP secrets can
optionally be encrypted at rest with AES-256-GCM using a server-side key.
