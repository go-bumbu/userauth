# The registration engine (`register`) and invites (`register/invite`)

Read this before touching anything under `register/`. The engine
is the registration counterpart of [loginflow](loginflow.md): transport-
agnostic, a pending registration accumulates verified checks until all are
satisfied, and only then is the account created. It shares loginflow's
philosophy but is deliberately simpler — and differs from it in one documented
way (enumeration, below).

## Why not loginflow?

loginflow's core invariant is "the user exists and is enabled at every step";
registration is the exact inverse. And registration needs no `RequireAny`
combinatorics: a deployment requires a fixed set of checks, all of them. So
there is no `Policy` — `Flow.Checks` is a flat list and "remaining = all
checks minus satisfied" is the whole policy. Empty list = open registration
(Start creates the account immediately).

## Composition

```
register.Flow
  .Users           UserGetter          required — login ID availability
  .Creator         UserCreator         required — creates the account (hash in, never plaintext)
  .Checks          []Check             optional — EmailCheck, InviteCheck, custom
  .Pending         PendingStore        required for round-trip checks (email)
  .Password        PasswordValidator   optional — default requires non-empty
  .UsernameFormat  userauth.UsernameFormat
  .Session         SessionCreator      optional — auto-login after creation (cookieauth.Manager fits)
  .Expiry          time.Duration       pending lifetime, default 30m
```

A `Check` verifies one requirement (`ID() + Verify(loginID, input)`,
`(false, nil)` for wrong input, errors reserved for internal failures — same
contract as `loginflow.Method`). Three optional capability interfaces refine
when a check runs:

- **`PreVerifier`** — verified synchronously at `Start` from the submitted
  input, no round trip (`InviteCheck`).
- **`Initiator`** — issuance side of a deliverable round-trip check: generate
  + persist + deliver a code (`EmailCheck`, reusing
  `userauth.VerificationCodeService` and a `Deliverer`).
- **`Finalizer`** — runs inside the engine's single creation point, just
  before the user is created; returning false aborts the registration and
  clears pending state. `InviteCheck` consumes the invite here, atomically.

## Semantics worth remembering

- **The account is created in exactly one place** (`finish()`): re-checks
  login availability (the pending window is a race), runs Finalizers, creates
  the user, optionally auto-logs-in, clears pending state.
- **Pending registrations only ever hold the bcrypt hash.** `Start` hashes
  the password; the plaintext never reaches a `PendingStore`. This matters
  because the cookie store ships the record to the client and the db store
  persists it.
- **Re-Start overwrites**: starting again for the same login ID replaces the
  pending registration (fresh hash, fresh expiry, checks reset). Prevents
  parking someone's username in pending state.
- **Enumeration posture — deliberate difference from loginflow**: `Start`
  returns `ErrUserExists` for a taken login ID; the JSON transport renders
  409 "username taken". Everything else stays uniform: wrong/expired code,
  missing pending registration, invalid invite and replayed checks are all
  `Result{OK:false}` → one 401. The "we sent a different email to existing
  accounts" dance is explicitly out of scope.
- **Invite TOCTOU**: `Validate` at Start is a fail-fast courtesy; `Consume`
  at creation (via `Finalize`) is authoritative. Consume runs **before**
  create: a create failure after a successful consume burns one use — the
  alternative (create-then-consume) could exceed the use limit, which is
  worse. An invite exhausted/revoked while the registration was pending
  aborts it and clears the pending state.
- **User-facing errors are typed**: `ErrUserExists` (409) and
  `*ValidationError` (400, message shown to the user — password policy,
  login format). Anything else is internal (500). `UserCreator`
  implementations may return `ErrUserExists` (wrapped) for unique-index
  races.
- Delivery failures at Start/Initiate are logged, not returned; a session
  failure after creation is logged but still reports Done (the account
  exists; the user can log in normally).
- `Flow.Initiate` (resend code) is a silent no-op without a usable pending
  registration, so the resend endpoint cannot probe registrations in
  progress.

## Pending stores (`register/pendingstore/`)

Same table as loginflow's attempt stores, same `(r, w)` interface wart
(consciously repeated; TODO.md tracks the redesign for both):

| Store | Use | Notes |
|---|---|---|
| `memory` | dev/testing | in-memory map |
| `cookie` | stateless / multi-instance | gorilla/securecookie signed+encrypted, `_pending_registration` cookie; instances must share keys |
| `db` | production, multi-instance | GORM, `pending_registrations` table, one row per login ID; owns its model + auto-migration |

## Invites (`register/invite/`)

Admin-facing with its own lifecycle: `invite.Service` (policy: code
generation, defaults) over an `invite.Store` (pure persistence) — the same
split as `VerificationCodeService`/`CodeStore`. API: `Issue(IssueOpts)`,
`List`, `Revoke`, `Validate`, `Consume`. Invites support multi-use
(`UsesLeft`), expiry, and optional email binding.

- **Codes are stored plaintext, deliberately**: admins must list them, and
  they are long random strings (default 12 alphanumeric ≈ 62 bits), not
  low-entropy user secrets.
- **`Store.Consume` must be atomic**: the db implementation uses one
  conditional `UPDATE … SET uses_left = uses_left - 1 WHERE …` and checks
  `RowsAffected`; the memory implementation holds its mutex across
  check-and-decrement. `(false, nil)` for any invalid-code-shaped reason.
- `*invite.Service` structurally satisfies `register.InviteConsumer` (the
  consumer-side interface — register does not import invite).

## JSON transport (`register/handlers`)

Wraps a `*register.Flow` as three `http.Handler`s, response shape identical
to the login transport so SPAs share client code:

```
POST register     {username, password, email?, inviteCode?} -> RegisterHandler
POST verify       {username, check, code}                   -> VerifyHandler
POST request-code {username, check?}                        -> RequestCodeHandler (always 202)
Response: {done:true} | {done:false, next:["email"]}
        | 409 username taken | 400 validation msg | uniform 401
```

`handlers.New(Cfg)` is the single preset: checks compose additively from
what is non-nil (`Codes`+`Deliver` → email verification, `Invites` → invite
gating, neither → open registration). It stays free of userdb/GORM imports —
the caller adapts their store to `UserCreator` (see `demo/examples/register.go`
`userdbCreator`: ~6 lines over `userdb.CreateUserWithHashedPassword`).

Form-based registration is deliberately DIY: callers own form
parsing/rendering and call `Flow.Start` / `Flow.VerifyCheck` directly
(`demo/examples/register.go` shows the pattern).
