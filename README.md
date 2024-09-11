# userauth
userauth makes use of several of interfaces to connect the different pieces:

The login handler uses a _userstore_ to retrieve user information and allow or deny login

The different authentication methods use the login handler to handle the login at http level.
In theory the login handler could also be used by other authentication methods that are not http based.

## User stores

### staticusers

This is a simple in memory implementation of the user store, it has some convenience functions to load
users from a yaml or json file on start up (for hardcoded users)

### dbusers

This is a more advanced user store that stores users in a DB using gorm as DB abstraction,
It will have additional methods not needed for authentication such as registration and invite.

## Auth methods

### basicauth 
This is a simple basic auth middleware that can tell the browser to prompt for user+ password using basicauth.

### sessionauth
This uses a session store (gorilla.sessionstore) to store a login session and handle the different sessions data 
once the user is logged in

