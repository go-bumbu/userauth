package userdb

// UserPurger deletes one user's rows from a satellite table — a TOTP enrolment,
// recovery codes, personal access tokens, verification codes, second-factor
// flags, or a table the consuming application owns.
//
// Store.Delete calls every registered purger after the user row is gone, and
// carries no transaction across them: a purger may live on another database or
// another backend entirely, and requiring a shared *gorm.DB would shut those out
// of the cascade. The cost is that a failed purge leaves rows behind. It is a
// leak, never an escalation, for satellite tables keyed to the canonical user
// UUID, which is never reused (only the login ID recycles). A known exception:
// flow/login/guard keys the throttle store on the raw login identifier, not the
// UUID, so login_throttle rows survive deletion and are inherited by the next
// account with the same login ID — a new user starts throttled with the old
// one's failure count (availability impact only — the inherited state is a
// failure counter, not a credential).
//
// Satisfying it requires no import of this package: the method is matched
// structurally. The GORM stores under service/{totp,recoverycodes,pat,verificationcode,secondfactor}/store/db
// provide it, as do the in-memory stores under service/*/store/memory. The
// throttle store (service/throttle/store/db) does not, by design: throttle state
// is keyed on the login identifier and deliberately outlives account deletion.
type UserPurger interface {
	PurgeUser(userID string) error
}
