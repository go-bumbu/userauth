package userdb

// UserPurger deletes one user's rows from a satellite table — a TOTP enrolment,
// recovery codes, personal access tokens, verification codes, or a table the
// consuming application owns.
//
// Store.Delete calls every registered purger after the user row is gone, and
// carries no transaction across them: a purger may live on another database or
// another backend entirely, and requiring a shared *gorm.DB would shut those out
// of the cascade. The cost is that a failed purge leaves rows behind. It is a
// leak, never an escalation — the canonical user ID is a UUID that is never
// reused (only the login ID recycles), so rows keyed to a deleted user can never
// be reached by a future account.
//
// Satisfying it requires no import of this package: the method is matched
// structurally. Every store shipped under service/*/store/db provides it.
type UserPurger interface {
	PurgeUser(userID string) error
}
