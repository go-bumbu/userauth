# userauth demo

This folder hosts small, self-contained HTTP handlers that each demonstrate
one way to use the userauth library. The packages under `examples/` mirror
the library structure — every example uses only the library's public API, so
each file can be copied into a real application as a starting point.

- `examples/auth` — authentication methods (`auth/...`): every request is
  authenticated on its own, no session is established
  - HTTP Basic auth (`auth/basicauth`)
  - Trusted-header auth, identity injected by a reverse proxy (`auth/headerauth`)
  - Cookie-session auth, the session middleware in isolation (`auth/cookieauth`)
  - Auth chain: cookie session with basic-auth fallback (`auth/chain`)
  - Personal access token in an auth chain (`service/pat` + `auth/tokenauth`)
  - Recoverable PAT ("user+token" mode): Subsonic-style salted-challenge login
    via `VerifyMatch`, same token also valid as a Bearer apiKey (`service/pat`)
- `examples/login` — login flows (`flow/login`): credentials are verified once
  and a cookie session is established
  - Password form login
  - Passwordless email-code login (`service/verificationcode`)
  - Two-step password + TOTP login (`login.TOTPMethod`)
  - Recovery-code login for the lost-authenticator case (`login.RecoveryMethod`)
  - Password+TOTP JSON API for SPAs (`flow/login/handlers` preset)
- `examples/register` — user self-registration (`flow/register`)
  - HTML forms: username+password and email-verified sign-up
  - The same email-verified flow as a JSON API (`flow/register/handlers` preset)
- `examples/profile` — an authenticated self-service area on `userstore/userdb`
  - Password login with a dynamic TOTP/recovery-code second factor (`login.PolicyFunc`)
  - TOTP enrolment (QR provisioning) and recovery-code issuance
  - Password and email change
- `examples/admin` — admin user management on `userstore/userdb`
  - Paginated user list, create, enable/disable
  - Initial admin bootstrap (`Store.Bootstrap`): seeds the first admin only
    while the store is empty, plus a `needsSetup` JSON endpoint for SPA
    first-run setup flows

Demo-only plumbing lives in `demo/internal`: `deliver` fakes code delivery
(display board / server log) and `demotest` holds shared test helpers.

Each exported constructor builds a ready-to-mount `http.Handler`. On top of
that, every example package exports a `Section` (see `examples/examples.go`)
that carries the index-page copy *and* a `Mount` hook per example. The demo
router (`demo/router`) iterates the sections to mount all handlers and hands
the same section data to the landing page template — so the selection page
always reflects exactly what is mounted, and each library aspect (auth
methods, login flows, registration, profile, admin) gets its own tab. Run it
with:

    go run ./demo

and open http://localhost:8085.
