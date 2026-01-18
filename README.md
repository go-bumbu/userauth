# userauth
simple user management and authentication library

userauth makes use of several interfaces to connect the different pieces:
* The login handler uses a _userstore_ to retrieve user information and allow or deny login

The different authentication methods use the login handler to handle the login at http level.
In theory the login handler could also be used by other authentication methods that are not http based.

# User stores

## staticusers

This is a simple in memory implementation of the user store, it has some convenience functions to load
users from a yaml or json file on start up (for hardcoded users)

## dbusers

This is a more advanced user store that stores users in a DB using gorm as DB abstraction,
It will have additional methods not needed for authentication such as registration and invite.

# Auth methods

## basicauth 
This is a simple basic auth middleware that can tell the browser to prompt for user+ password using basicauth.

## session
This uses a session store (gorilla.sessionstore) to store a login session and handle the different sessions data 
once the user is logged in.

The session store allows to have longer lasting sessions (keep me logged-in), and yet force a re-authentication 
after a bigger expiry time

The user data the session stores is scoped for the use-cases intended for the session store.

## httpheader

This authentication handler delegates the authentication to an upstream service. It assumes that 
if a given header is set and populated, authentication will be granted.

This can be used with services like Authelia or apache mod_auth_mellon

the default header is "X-User-Auth" but can be configured at initialization time.

### Usage

#### Middleware
using the middleware to secure a handler, this will ensure that non logged users cannot access the handler

note: this does NOT take care of authorization
```
// setup a new session handler
authSession, _ := session.New(session.Cfg{
    Store:         store,          // the session store
    SessionDur:    SessionDur,     // duration of the session before loggedout (in case of inactivity)
    MaxSessionDur: MaxSessionDur,  // max duration before a re-login is enforced
    MinWriteSpace: update,         // throttle session write operations 
})

// use the middleware 
secureHandler := authSession.Middleware(myContentHandler)

```

#### Auth handlers

to login users you can use the form or json auth handler as drop in or guidance 




