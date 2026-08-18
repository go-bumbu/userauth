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

Password plus TOTP (no email or SMS verification):

```go
totpStore, err := totpdb.New(db)
users, err := userdb.New(db, userdb.Opts{
    BcryptDifficulty: 12,
    OnDelete:         []userdb.UserPurger{totpStore},
})
// build the SecondFactorProvider directly rather than using stores.Provider
provider := secondfactor.Provider{TOTP: totpStore}
// hand provider to login.SecondFactorAfter
```

**Warning:** `preset.Full` wires `stores.Provider.Email` and `Provider.SMS`
unconditionally from the flags store, so a TOTP-only consumer who uses
`stores.Provider` will find that the moment any user's email flag is set, the
login policy will demand a factor no registered method can satisfy. Build your
own `secondfactor.Provider` when you do not offer every factor, and leave
unwired factors as nil.

To use the flags store as a `SecondFactorProvider`, wrap it with
`secondfactor.Flag`:

```go
flagStore, err := flagsdb.New(db)
emailFactor := secondfactor.Flag{Store: flagStore, Factor: userauth.SecondFactorEmail}
provider := secondfactor.Provider{Email: emailFactor}
// pass provider to login.SecondFactorAfter
```

**Register every satellite store in `Opts.OnDelete`.** It is how deleting a user
removes their credentials; a store the user store does not know about is not
cleaned up at all.

The purge runs after the user row is deleted and is **not** transactional: a
purger that fails is reported, and its rows stay in satellite tables keyed to
the canonical user UUID, which is never reused (only the login ID recycles), so
they are inert — a partial purge leaks rows, never access. The contract carries
no `*gorm.DB` on purpose, so a satellite store on any backend can take part in
the cascade.

A known exception to the "never reused" guarantee: `flow/login/guard` keys the
throttle store on the raw login identifier, not the UUID, so `login_throttle`
rows survive deletion and are inherited by the next account with the same login
ID — a new user starts throttled with the old one's failure count (availability
impact only — the inherited state is a failure counter, not a credential).

**On a purge failure, re-calling `Delete` will not retry the purgers**: the user
row is already gone, so it returns `ErrUserNotFound` before reaching the purge
loop. If a purger fails, the caller must purge the affected satellite stores
directly via their own `PurgeUser` methods.

## Tables

Kept, untouched: `user_models`, `user_groups`, `user_pending_email_changes`.

Same schema, now owned by a service package: `user_totp`,
`user_recovery_codes`, `user_pats`.

Replaced by generic tables — the old ones are no longer migrated, and the
library never issues destructive DDL, so **drop them by hand when you are
ready**:

| dropped from migration | replaced by |
|---|---|
| `user_email_verification_codes` | `user_verification_codes` (channel `email`) |
| `user_sms_verification_codes` | `user_verification_codes` (channel `sms`) |
| `user_second_factor_flags` (old schema) | `user_second_factor_flags` (new schema, row per factor) |

Outstanding verification codes are not carried over. They expire in 10 minutes
by default, so the worst case is that a user in the middle of a login requests a
new code.

---

## ⚠️ CRITICAL: Migrate second-factor flags or silently disable every user's 2FA

The old `user_second_factor_flags` table had `email_enabled` and `sms_enabled`
boolean columns. The new table has the same name but a different schema: one row
per `(user_id, factor)` pair. Nothing reads the old shape. **If you skip this
migration, every user who had email or SMS 2FA enabled will be downgraded to
password-only logins with no error and no log line** — `AvailableSecondFactors`
returns an empty slice and `SecondFactorAfter` treats that as "policy
satisfied".

The old and new tables share a name, so you must rename the old table aside
before `AutoMigrate` runs, then copy its data into the new schema. Follow these
steps **in order**:

1. Rename the old table so `AutoMigrate` can create the new one:
   ```sql
   ALTER TABLE user_second_factor_flags RENAME TO user_second_factor_flags_old;
   ```

2. Run `AutoMigrate` (via your application startup or `preset.Full`). This
   creates the new empty `user_second_factor_flags` table with `(user_id,
   factor, enabled)` columns.

3. Migrate the enabled flags from the old schema to the new one:
   ```sql
   INSERT INTO user_second_factor_flags (user_id, factor, enabled, created_at, updated_at)
   SELECT user_id, 'email', email_enabled, created_at, updated_at
     FROM user_second_factor_flags_old WHERE email_enabled;

   INSERT INTO user_second_factor_flags (user_id, factor, enabled, created_at, updated_at)
   SELECT user_id, 'sms', sms_enabled, created_at, updated_at
     FROM user_second_factor_flags_old WHERE sms_enabled;
   ```

4. Verify the migration: check that every user who had a flag enabled in the old
   table now has a corresponding row in the new one.

5. Drop the old table when you are satisfied:
   ```sql
   DROP TABLE user_second_factor_flags_old;
   ```

**Getting the ordering wrong loses the data.** If `AutoMigrate` runs before step
1, it alters the existing table instead of creating a new one, and you cannot
distinguish old from new rows. If you run step 3 before step 2, the INSERT fails
because the target table does not exist yet.
