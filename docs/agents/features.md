# Features — status and where each lives

Status of every user-facing capability. Before implementing something "missing",
check here and in TODO.md — several gaps are known and have a chosen direction.

## Authentication strategies (`auth/`)

| Feature | Status | Where |
|---|---|---|
| Cookie/session auth | Implemented | `cookieauth.Manager` — rolling + absolute expiry (see architecture.md) |
| HTTP Basic Auth | Implemented | `basicauth` — optional enforce mode (`WWW-Authenticate`), no sessions, per-request verify |
| Header auth | Implemented | `headerauth` — trusts upstream header (default `X-User-Auth`), no verification; for reverse proxies like Authelia |
| Auth chain | Implemented | `chain.Authenticator` — in-order evaluation, first success wins, `stopEvaluation` short-circuits |

## Login (`flow/login/`, see [loginflow.md](loginflow.md))

| Feature | Status | Where |
|---|---|---|
| Multi-factor login engine | Implemented | `login.Flow` — policies, methods, attempt stores |
| JSON API login | Implemented | `flow/login/handlers.JSON` — login/verify/request-code; presets `NewPasswordTOTP`, `NewEmailCode` |
| Form-based login | DIY by design | caller-owned transport over `Flow.Submit`; pattern in `demo/examples/login/password.go` |
| Logout | Implemented | `handlers/login.LogoutHandler(UserLogout, redirect)` |
| Attempt stores | Implemented | `flow/login/attemptstore/{memory,cookie,db}` |

## Self-registration (`register/`, see [register.md](register.md))

| Feature | Status | Where |
|---|---|---|
| Registration engine | Implemented | `register.Flow` — pluggable checks, pending stores, single creation point |
| Email verification | Implemented | `register.EmailCheck` over `VerificationCodeService` + `Deliverer` |
| Invite codes | Implemented | `flow/register/invite` (issue/list/revoke/consume, multi-use, expiry, email binding) + `register.InviteCheck` |
| Password policy hook | Implemented | `register.PasswordValidator` (registration only; `userdb.Create` is unhooked) |
| JSON API registration | Implemented | `register/handlers.JSON` — register/verify/request-code; preset `New(Cfg)` |
| Form-based registration | DIY by design | caller-owned transport over `Flow.Start`/`Flow.VerifyCheck`; pattern in `demo/examples/register.go` |
| Pending stores | Implemented | `register/pendingstore/{memory,cookie,db}` |
| Invite stores | Implemented | `register/invite/{memory,db}` — atomic consume |

## Multi-factor authentication

| Feature | Status | Notes |
|---|---|---|
| TOTP (authenticator app) | Implemented | `TOTPGetter` (read) / `TOTPConfigurator` (write); both stores implement read; secrets optionally AES-256-GCM at rest |
| Recovery codes | Implemented | one-time, bcrypt-hashed, max 6 per user in `userdb`; `VerifyRecoveryCode` consumes atomically |
| Email 2FA | Partial | store layer complete in `userdb` (`VerifyEmailCode`, `email_code_enabled` flag); consumer must wire delivery + frontend |
| SMS 2FA | Partial | same shape: `VerifySMSCode`, `sms_code_enabled`; same missing consumer wiring |

`SecondFactorProvider.AvailableSecondFactors` (implemented by both stores)
feeds the `SecondFactorAfter` policy: it reports which of totp/email/sms a user
has enabled.

## User stores (`userstore/`)

| Feature | Status | Notes |
|---|---|---|
| Static users (YAML/JSON) | Implemented | `staticusers` — read-only, no registration |
| DB users (GORM) | Implemented | `userdb` — full CRUD, all 2FA interfaces, paginated `List` |
| User registration | Implemented | `UserRegistrar`; `userdb.Create` enforces username format + bcrypt |
| Username format policy | Implemented | `UsernameFormat` (any/email/plain), `ValidateLoginID`, enforced at registration |
| Pending email change | Implemented | `userdb`: `StorePendingEmailChange` / `VerifyPendingEmailChange` (code-confirmed address change) |

## Verification codes and delivery

| Feature | Status | Notes |
|---|---|---|
| `VerificationCodeService` | Implemented | policy owner: generate, SHA-256 hash, expiry, defaults (6 digits / 10 min) |
| `CodeStore` backends | Partial | `service/verificationcode/store/memory` only; the `userdb` adapter (phase 2 of the hybrid design) has not landed — `userdb`'s verify methods do not satisfy `CodeVerifier` |
| SMTP delivery | Implemented | `service/verificationcode/deliver/smtp` — HTML template (embedded default or custom path), `@/path` password-from-file |
| File delivery | Implemented | `service/verificationcode/deliver/file` — one `<timestamp>-<to>.txt` per code; dev/testing |

## Personal Access Tokens (`service/pat/`)

| Feature | Status | Notes |
|---|---|---|
| PAT storage modes | Implemented | `service/pat` — `Mint(..., Storage)`: `HashOnly` (SHA-256 only, verified whole via `Verify`) or `Recoverable` (secret additionally encrypted via `Opts.Cipher` `SecretCipher`; verified via `VerifyMatch(tokenID, match)` for challenge-style credentials). `ErrNotRecoverable` distinguishes "hash-only token presented as challenge" from bad credentials. Token IDs are lowercase base36 so they can serve as virtual usernames; `ParseToken` splits plaintext into (tokenID, secret). Key management is the consumer's: the lib ships single-key `AESGCMCipher`. |
| Token stores | Implemented | `TokenStore` interface — in-memory (`store/memory`) and GORM (`userstore/userdb`) |
| Token management | Implemented | `Service.Mint` (create, per-user limit enforced), `List` (user's tokens), `Revoke` (delete), throttled last-used tracking |

## Not implemented (catalogued in TODO.md)

Rate limiting / lockout hooks, CSRF helpers, session listing/revocation,
password policy, email-based password reset, audit/event hooks, JWT/OAuth2/OIDC,
bcrypt cost migration on login.
