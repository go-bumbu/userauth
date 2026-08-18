# Demo TODO

Feature-coverage gaps between the library and the demo, grouped by package.

## Login (`flow/login`)
- [x] Password form login
- [x] Passwordless email-code login (`login.CodeMethod` / `EmailCodeMethod`)
- [x] TOTP verification step (`login.TOTPMethod`)
- [x] Recovery code verification step (`login.RecoveryMethod`)
- [x] JSON login endpoints (`flow/login/handlers` — `NewPasswordTOTP` preset)
- [ ] JSON email-code login (`flow/login/handlers.NewEmailCode` preset)
- [ ] Email code as a *second* factor (`login.CodeMethod` after password)
- [ ] SMS 2FA verification step (`login.CodeMethod` with an SMS deliverer)

## Login attempt stores (`flow/login/attemptstore`)
- [x] In-memory (`attemptstore/memory`) — current process, no persistence
- [ ] Cookie-based (`attemptstore/cookie`) — survives process restart
- [ ] DB-backed (`attemptstore/db`) — multi-instance safe

## Registration (`flow/register`)
- [x] Username+password registration
- [x] Email-verified registration (pending store + verification code)
- [x] JSON registration API (`flow/register/handlers` preset)
- [ ] Invite-based registration (`flow/register/invite`)
- [ ] Non-memory pending stores (`pendingstore/cookie`, `pendingstore/db`)

## Profile / user self-service (`userstore/userdb`)
- [x] Password change, email change
- [x] TOTP enrolment with QR provisioning (`Store.SetTOTP`)
- [x] Recovery code issuance and remaining count
- [ ] Email change with verification (`Store.StorePendingEmailChange` / `ConsumePendingEmailChange` — caller hashes the code)

## Admin (`userstore/userdb`)
- [x] Paginated user list (`Store.List`)
- [x] Create user, enable/disable (`Store.Create`, `Store.SetEnabled`)
- [ ] Set / verify primary email (`Store.SetPrimaryEmail`, `SetPrimaryEmailVerified`)
- [ ] Password reset by admin (`Store.SetPasswordHash`)

## Verification code delivery (`service/verificationcode/deliver`)
- [ ] File deliverer (`deliver/file`) — write code to disk (useful for dev/test)
- [ ] SMTP deliverer (`deliver/smtp`) — send code via email

## Personal access tokens (`service/pat`)
- [x] Hash-only token in an auth chain (`Verify` via `tokenauth` + `ChainVerifier`)
- [x] Recoverable token: salted-challenge login via `VerifyMatch` (Subsonic-style
      user+token), same token as Bearer apiKey (`ParseToken`, `AESGCMCipher`)
- [x] Self-service token management on the profile (`flow/pat/handlers` JSON API
      and HTML forms)

## Auth chain (`auth/chain`)
- [x] `chain.Authenticator` — cookie session first, basic auth fallback,
      unauthorized callback redirecting to login

## Misc
- [ ] `staticusers.FromFile` — load static users from YAML/JSON
- [ ] `ValidateLoginID` with different `UsernameFormat` policies (any / email-only / plain)
