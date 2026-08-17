package userdb

import (
	"slices"
	"testing"
)

//nolint:gocyclo // one subtest per contract rule; splitting them hides the shared store setup
func TestRecoveryCodeStore(t *testing.T) {
	mng := setup(t)
	defer clean()

	userID := mustCreateUser(t, mng, "recovery-set-user")
	store := mng.RecoveryCodeStore()

	t.Run("stores hashes and skips empty ones", func(t *testing.T) {
		// an empty hash is not a code — storing one would create a row nothing
		// can ever match
		if err := store.Replace(userID, []string{"hash-1", "hash-2", ""}); err != nil {
			t.Fatal(err)
		}
		count, err := store.Count(userID)
		if err != nil {
			t.Fatal(err)
		}
		if count != 2 {
			t.Errorf("stored %d codes, want 2", count)
		}
		got, err := store.Hashes(userID)
		if err != nil {
			t.Fatal(err)
		}
		slices.Sort(got)
		if !slices.Equal(got, []string{"hash-1", "hash-2"}) {
			t.Errorf("Hashes = %v, want [hash-1 hash-2]", got)
		}
	})

	t.Run("replace drops all previous codes", func(t *testing.T) {
		if err := store.Replace(userID, []string{"new-hash"}); err != nil {
			t.Fatal(err)
		}
		got, err := store.Hashes(userID)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got, []string{"new-hash"}) {
			t.Errorf("Hashes = %v, want [new-hash]", got)
		}
	})

	t.Run("nil clears every code", func(t *testing.T) {
		if err := store.Replace(userID, nil); err != nil {
			t.Fatal(err)
		}
		count, err := store.Count(userID)
		if err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Errorf("stored %d codes after clearing, want 0", count)
		}
	})

	t.Run("delete consumes one code", func(t *testing.T) {
		if err := store.Replace(userID, []string{"h1", "h2"}); err != nil {
			t.Fatal(err)
		}
		if err := store.Delete(userID, "h1"); err != nil {
			t.Fatal(err)
		}
		got, err := store.Hashes(userID)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got, []string{"h2"}) {
			t.Errorf("Hashes after Delete = %v, want [h2]", got)
		}
		// deleting something that is not there is not an error
		if err := store.Delete(userID, "h1"); err != nil {
			t.Errorf("Delete of a consumed code: %v", err)
		}
	})

	t.Run("codes of other users are untouched", func(t *testing.T) {
		otherID := mustCreateUser(t, mng, "recovery-other-user")
		if err := store.Replace(userID, []string{"shared"}); err != nil {
			t.Fatal(err)
		}
		if err := store.Replace(otherID, []string{"shared"}); err != nil {
			t.Fatal(err)
		}
		// the same hash value for two users must be independent
		if err := store.Delete(userID, "shared"); err != nil {
			t.Fatal(err)
		}
		count, err := store.Count(otherID)
		if err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Errorf("other user has %d codes, want 1", count)
		}
	})

	t.Run("user with no codes reports none", func(t *testing.T) {
		emptyID := mustCreateUser(t, mng, "recovery-empty-user")
		got, err := store.Hashes(emptyID)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Errorf("Hashes = %v, want empty", got)
		}
	})
}
