# userauth demo

This folder hosts small, self-contained HTTP handlers that each demonstrate
one way to use the userauth library, grouped by concern:

- `examples/auth` — authentication methods: every request is authenticated on
  its own, no session is established
  - HTTP Basic auth
  - Trusted-header auth (identity injected by a reverse proxy)
  - Cookie-session auth (the session middleware in isolation)
- `examples/login` — login flows: credentials are verified once and a cookie
  session is established
  - Password form login
  - Passwordless email-code login
- `examples` — user management backed by a database store
  - User self-registration
  - A TOTP-protected profile area
  - A paginated user-admin screen

Each exported constructor builds a ready-to-mount `http.Handler`; the demo
router stitches them together.
