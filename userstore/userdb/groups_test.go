package userdb

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGroups(t *testing.T) {
	mng := setup(t)
	defer clean()

	mustCreate := func(t *testing.T, usr User) string {
		t.Helper()
		if err := mng.CreateUser(usr); err != nil {
			t.Fatalf("create user: %s", err)
		}
		got, err := mng.GetUserByLogin(usr.LoginID)
		if err != nil {
			t.Fatalf("read back user: %s", err)
		}
		return got.ID
	}

	mustGetGroups := func(t *testing.T, id string) []string {
		t.Helper()
		groups, err := mng.GetGroups(id)
		if err != nil {
			t.Fatalf("get groups: %s", err)
		}
		return groups
	}

	mustSetGroups := func(t *testing.T, id string, groups []string) {
		t.Helper()
		if err := mng.SetGroups(id, groups); err != nil {
			t.Fatalf("set groups: %s", err)
		}
	}

	t.Run("user without groups yields empty slice", func(t *testing.T) {
		id := mustCreate(t, User{LoginID: "nogroups@mail.com", Pw: "1234"})
		if groups := mustGetGroups(t, id); len(groups) != 0 {
			t.Errorf("expected no groups, got %v", groups)
		}
	})

	t.Run("unknown user yields empty slice, not error", func(t *testing.T) {
		if groups := mustGetGroups(t, "does-not-exist"); len(groups) != 0 {
			t.Errorf("expected no groups, got %v", groups)
		}
	})

	t.Run("create user with initial groups", func(t *testing.T) {
		id := mustCreate(t, User{
			LoginID: "admin@mail.com",
			Pw:      "1234",
			Groups:  []string{"admin", "staff", "admin", ""},
		})
		want := []string{"admin", "staff"} // deduped, empties dropped, sorted
		if diff := cmp.Diff(want, mustGetGroups(t, id)); diff != "" {
			t.Errorf("groups mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("set groups replaces previous memberships", func(t *testing.T) {
		id := mustCreate(t, User{LoginID: "replace@mail.com", Pw: "1234", Groups: []string{"old"}})
		mustSetGroups(t, id, []string{"new-b", "new-a"})
		want := []string{"new-a", "new-b"}
		if diff := cmp.Diff(want, mustGetGroups(t, id)); diff != "" {
			t.Errorf("groups mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("set empty removes all memberships", func(t *testing.T) {
		id := mustCreate(t, User{LoginID: "clear@mail.com", Pw: "1234", Groups: []string{"a", "b"}})
		mustSetGroups(t, id, nil)
		if groups := mustGetGroups(t, id); len(groups) != 0 {
			t.Errorf("expected no groups after clearing, got %v", groups)
		}
	})

	t.Run("delete user removes memberships", func(t *testing.T) {
		id := mustCreate(t, User{LoginID: "gone@mail.com", Pw: "1234", Groups: []string{"a"}})
		if err := mng.Delete(id); err != nil {
			t.Fatal(err)
		}
		var count int64
		if err := mng.db.Model(&groupModel{}).Where("user_id = ?", id).Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Errorf("expected 0 group rows after user delete, got %d", count)
		}
	})

	t.Run("memberships are isolated per user", func(t *testing.T) {
		id1 := mustCreate(t, User{LoginID: "iso1@mail.com", Pw: "1234", Groups: []string{"shared", "only1"}})
		id2 := mustCreate(t, User{LoginID: "iso2@mail.com", Pw: "1234", Groups: []string{"shared"}})

		if diff := cmp.Diff([]string{"only1", "shared"}, mustGetGroups(t, id1)); diff != "" {
			t.Errorf("user1 groups mismatch (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff([]string{"shared"}, mustGetGroups(t, id2)); diff != "" {
			t.Errorf("user2 groups mismatch (-want +got):\n%s", diff)
		}
	})
}
