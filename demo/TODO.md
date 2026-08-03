# Demo TODO

## 2FA / Multi-step login
- [ ] JSON login endpoints (`loginflow/handlers` — `JSON.LoginHandler`/`VerifyHandler`/`RequestCodeHandler`)
- [x] Login attempt state management (`loginflow.AttemptStore`, bridges factor submissions)
- [x] TOTP verification step (`loginflow.TOTPMethod`)
- [ ] Email 2FA verification step (`loginflow.CodeMethod` as second factor)
- [ ] SMS 2FA verification step (`loginflow.CodeMethod` with an SMS deliverer)
- [x] Recovery code verification step (`loginflow.RecoveryMethod`)

## User management
- [ ] User registration (`UserRegistrar` / `dbusers.DbManager.Create`)
- [ ] Enable/disable a user account (`UserUpdater.SetEnabled`)
- [ ] Set/update primary email (`UserUpdater.SetPrimaryEmail`, `.SetPrimaryEmailVerified`)
- [ ] Password hash update (`dbusers.DbManager.SetPasswordHash`)

## TOTP setup flow
- [x] Configure TOTP for a user (`TOTPConfigurator.SetTOTP`)
- [x] Show TOTP QR/secret provisioning
- [x] AES-256-GCM encryption of TOTP secret at rest (`hashutil.Encrypt/Decrypt`)

## Recovery codes
- [x] Generate and store recovery codes (`hashutil.GenerateRecoveryCodes`, `RecoveryCodeConfigurator.SetRecoveryCodes`)
- [x] Show remaining recovery code count (`RecoveryCodeCountGetter`)

## Verification code delivery
- [ ] `VerificationCodeService` — generate and hash a one-time code
- [ ] File deliverer (`delivery/file`) — write code to disk (useful for dev/test)
- [ ] SMTP deliverer (`delivery/smtp`) — send code via email

## Email change verification
- [ ] Initiate email change (`dbusers.StorePendingEmailChange`)
- [ ] Verify and confirm email change (`dbusers.VerifyPendingEmailChange`)

## Database-backed user store
- [ ] `dbusers.DbManager` as a drop-in replacement for `staticusers`
- [ ] `dbusers.ManagerOpts` (bcrypt cost, default-enabled, username format, TOTP encryption key)

## Login attempt stores
- [x] In-memory (`loginflow/attemptstore/memory`) — current session, no persistence
- [ ] Cookie-based (`loginflow/attemptstore/cookie`) — survives process restart
- [ ] DB-backed (`loginflow/attemptstore/db`) — multi-instance safe

## Auth chain
- [ ] `chain.Authenticator` — chain multiple auth handlers with authorized/unauthorized callbacks

## Misc
- [ ] `ValidateLoginID` with different `UsernameFormat` policies (any / email-only / plain)
- [ ] `cookieauth.CtxGetUserData` / `CtxSetUserData` — reading user identity downstream in a handler
