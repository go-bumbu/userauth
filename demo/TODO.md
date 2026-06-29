# Demo TODO

## 2FA / Multi-step login
- [ ] JSON login endpoint (`handlers/login/json.go` — `JsonAuthHandler`)
- [x] Pending login state management (bridges step 1 → step 2 of 2FA)
- [x] TOTP verification step (`LoginHandler.VerifyTOTP`)
- [ ] Email 2FA verification step (`LoginHandler.VerifyEmailCode`)
- [ ] SMS 2FA verification step (`LoginHandler.VerifySMSCode`)
- [x] Recovery code verification step (`LoginHandler.VerifyRecoveryCode`)
- [ ] The `Verify2FAHandler` endpoint wiring them all together

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

## Pending login stores
- [x] In-memory (`pendinglogin/memory`) — current session, no persistence
- [ ] Cookie-based (`pendinglogin/cookie`) — survives process restart
- [ ] DB-backed (`pendinglogin/db`) — multi-instance safe

## Auth chain
- [ ] `chain.Authenticator` — chain multiple auth handlers with authorized/unauthorized callbacks

## Misc
- [ ] `ValidateLoginID` with different `UsernameFormat` policies (any / email-only / plain)
- [ ] `cookieauth.CtxGetUserData` / `CtxSetUserData` — reading user identity downstream in a handler
