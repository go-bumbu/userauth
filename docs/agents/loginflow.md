# The login engine (`loginflow`)

Read this before touching anything under `loginflow/`. The engine is
transport-agnostic and composable: a login attempt accumulates verified factors
until a `Policy` says the requirements are met, and only then is the session
created. It owns the security invariants callers tend to get wrong — do not
move these out to transports:

- the user must exist and be enabled **at every step**, not just the first;
- a factor only counts if the policy currently offers it (no submitting TOTP
  before password, no double-counting a replayed factor);
- **all credential-shaped failures produce the same `Result{OK:false}`**
  (unknown user, disabled user, wrong code, method not offered) so transports
  stay enumeration-safe without trying. A non-nil error means internal failure
  (5xx), never "try again";
- attempts expire (`DefaultAttemptExpiry` 5 min) and the session is created in
  exactly one place (`Flow.Submit`).

## Composition

```
Flow
  .Users     UserGetter     required
  .Policy    Policy         required — RequireAny(Chain...), SecondFactorAfter, PolicyFunc
  .Session   UserLogin      required — cookieauth.Manager satisfies it implicitly
  .Methods   []Method       PasswordMethod, TOTPMethod, RecoveryMethod, CodeMethod
  .Attempts  AttemptStore   required only for multi-step policies
  .Expiry    time.Duration  attempt lifetime, default 5m
```

- **Methods** verify one factor via capability interfaces (`TOTPGetter`,
  `RecoveryCodeVerifier`, `CodeVerifier`). Well-known IDs: `password`, `totp`,
  `email`, `sms`, `recovery`. `Method.Verify` must return `(false, nil)` for
  wrong input and reserve errors for internal failures.
- **`Initiator`** is the optional issuance side of a deliverable factor
  (generate + persist + deliver a code). `CodeMethod` implements it;
  `EmailCodeMethod(codes, deliver)` wires the common email case with
  `VerificationCodeService` as both issuer and verifier. `Flow.Initiate` is
  enumeration-safe by construction: unknown/disabled users and not-offered
  methods are silently skipped, delivery failures are logged, not returned.
  Deliverers should queue and return — synchronous SMTP leaks issuance through
  response timing.
- **Policies return decisions only, never side effects.** `RequireAny(Chain...)`
  covers static rules ("password then totp", "or email code alone");
  `SecondFactorAfter(first, provider)` is the classic dynamic 2FA policy (first
  factor alone unless the `SecondFactorProvider` reports enrolled second
  factors; the first factor is excluded from the required seconds); `PolicyFunc`
  for anything dynamic.

## Semantics worth remembering

- `keepLoggedIn` is captured from the **first accepted factor** of an attempt
  and only applied when the session is created — later submissions cannot
  change it (`Attempt.SessionKeepLoggedIn`).
- After the engine resolves the user, everything is keyed by the canonical
  `user.Id` — attempts, verifiers, and the session must agree on one key.
- Attempt-store read errors are treated as "no attempt": the safe consequence
  is the user re-verifies factors. Clear-after-login failures are logged, not
  returned.
- `Attempts` may be nil for single-step policies (per-request auth); a
  multi-step policy with nil `Attempts` errors at the first incomplete
  submission.

## Attempt stores (`loginflow/attemptstore/`)

`Attempt.Satisfied` is an authentication claim — whoever controls it can skip
factors. Implementations MUST keep it server-side or in an authenticated
(signed/encrypted) client token, never a plain cookie.

| Store | Use | Notes |
|---|---|---|
| `memory` | dev/testing | in-memory map |
| `cookie` | stateless / multi-instance | gorilla/securecookie signed+encrypted; instances must share keys |
| `db` | production, multi-instance | GORM, `login_attempts` table, one row per user; owns its own model + auto-migration, independent from `userdb` |

Known wart (TODO.md): the `AttemptStore` interface takes `*http.Request` /
`http.ResponseWriter` that memory and db ignore — it is shaped by the cookie
implementation. Live with it until the interface is redesigned.

## JSON transport (`loginflow/handlers`)

`JSON` wraps a `*Flow` as three `http.Handler`s for SPAs:

```
POST login        {username, password|input, keepLoggedIn} -> LoginHandler
POST verify       {username, method, code}                 -> VerifyHandler
POST request-code {username, method}                       -> RequestCodeHandler
Response: {done:true} | {done:false, next:["totp",...]} | uniform 401
```

Presets construct the whole Flow from a config struct:

- `NewPasswordTOTP(PasswordTOTPCfg)` — password login with optional TOTP second
  factor (only for users with TOTP enrolled) and optional recovery-code
  stand-in. Requires `Attempts` when TOTP is set.
- `NewEmailCode(EmailCodeCfg)` — passwordless email-code login; single factor,
  so no attempt store.

Form-based login is deliberately DIY: callers own form parsing/rendering and
call `Flow.Submit` directly (`demo/examples/login/password.go` shows the
pattern).
