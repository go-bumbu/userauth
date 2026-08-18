# Migrating to the modular GORM stores

Breaking change, 2026-08-18. `userstore/userdb` no longer owns factor or token
tables. Import paths and wiring change; **the tables it kept need no data
migration** — same names, same columns, no foreign keys.

## Fastest path: keep the full feature set

Replace `userdb.New(db, opts)` with `preset.Full(db, opts)`:

```go
stores, err := preset.Full(db, userdb.Opts{BcryptDifficulty: 12, DefaultEnabled: true})
// stores.Users     — the user store (userauth.UserGetter, UserUpdater, UserRegistrar)
// stores.TOTP      — hand to totp.NewService
// stores.Recovery  — hand to recoverycodes.NewService
// stores.PATs      — hand to pat.NewService
// stores.Provider  — userauth.SecondFactorProvider
```

Then drop the old accessors:

| before | after |
|---|---|
| `users.TOTPStore()` | `stores.TOTP` |
| `users.RecoveryCodeStore()` | `stores.Recovery` |
| `users.PATStore()` | `stores.PATs` |
| `users` as a `SecondFactorProvider` | `stores.Provider` |
| `users.SetEmailCodeEnabled(id, true)` | `stores.Flags.SetEnabled(id, userauth.SecondFactorEmail, true)` |
| `users.StoreEmailCode` / `users.VerifyEmailCode` | `verificationcode.NewService(stores.EmailCodes, opts)` — `Generate` / `Verify` |
| `users.StoreSMSCode` / `users.VerifySMSCode` | `verificationcode.NewService(stores.SMSCodes, opts)` |
| `users.VerifyPendingEmailChange(id, code)` | `users.ConsumePendingEmailChange(id, hash)` — you hash the code |

## Partial setup

Construct only what you need; a store you never construct creates no table.
Password login plus PATs, and nothing else:

```go
patStore, err := patdb.New(db)
users, err := userdb.New(db, userdb.Opts{
    BcryptDifficulty: 12,
    OnDelete:         []userdb.UserPurger{patStore},
})
```

**Register every satellite store in `Opts.OnDelete`.** It is how deleting a user
removes their credentials; a store the user store does not know about is not
cleaned up at all.

The purge runs after the user row is deleted and is **not** transactional: a
purger that fails is reported, and its rows stay. Those rows are keyed to a UUID
that is never reused (only the login ID recycles), so they are inert — a partial
purge leaks rows, never access. The contract carries no `*gorm.DB` on purpose,
so a satellite store on any backend can take part in the cascade.

## Tables

Kept, untouched: `user_models`, `user_groups`, `user_pending_email_changes`.

Same schema, now owned by a service package: `user_totp`,
`user_recovery_codes`, `user_pats`.

Replaced by generic tables — the old ones are no longer migrated, and the
library never issues destructive DDL, so **drop them by hand when you are
ready**:

| dropped from migration | replaced by |
|---|---|
| `user_email_verification_codes` | `verification_codes` (channel `email`) |
| `user_sms_verification_codes` | `verification_codes` (channel `sms`) |
| `user_second_factor_flags` | `second_factor_flags` (row per factor) |

Outstanding verification codes are not carried over. They expire in 10 minutes
by default, so the worst case is that a user in the middle of a login requests a
new code.
