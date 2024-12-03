## Braindump of todos

* create an pluggable authenticator that allows to configure multiple auth mechanisms, e.g. session and api token

### session handler
* session http to implement login/logout handlers
* session admin should allow extra features
  * 



### Authentication
* user login
* enable/disable user
* cookie based session
* token based session
* basic auth
* 2fa
* email verification
  * included email server?
  * external email server ?
* allow multiple user stores? use-case in db users + predefined static ones

### register
* invite code
* email verification

## session store
* the current FS store based on gorilla only allows basic get and set, but to allow a user manage all the sessions
  a custom store will be needed to be implemented

### Other
allow API middle ware
* add a function that checks the request context and returns information about the user
  * should also allow to run without any authentication, e.g. fe26
* rename package to userauth
* JWT middleware? 





### food for thought


instead of having severeal user implementaitons, use one with several storage and retrieval interfaces