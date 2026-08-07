package memory_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-bumbu/userauth/flow/register/invite"
	"github.com/go-bumbu/userauth/flow/register/invite/memory"
	"github.com/google/go-cmp/cmp"
)

func TestStore(t *testing.T) {
	t.Run("save and get", func(t *testing.T) {
		store := memory.New()
		inv := invite.Invite{Code: "abc", Note: "n", UsesLeft: 2, CreatedAt: time.Now().UTC()}
		if err := store.Save(inv); err != nil {
			t.Fatal(err)
		}
		got, err := store.Get("abc")
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(inv, got); diff != "" {
			t.Errorf("invite mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("get missing", func(t *testing.T) {
		store := memory.New()
		if _, err := store.Get("nope"); !errors.Is(err, invite.ErrInviteNotFound) {
			t.Fatalf("want ErrInviteNotFound, got %v", err)
		}
	})

	t.Run("delete", func(t *testing.T) {
		store := memory.New()
		if err := store.Save(invite.Invite{Code: "abc", UsesLeft: 1}); err != nil {
			t.Fatal(err)
		}
		if err := store.Delete("abc"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Get("abc"); !errors.Is(err, invite.ErrInviteNotFound) {
			t.Fatalf("want ErrInviteNotFound after delete, got %v", err)
		}
	})

	t.Run("concurrent consume of single-use invite", func(t *testing.T) {
		store := memory.New()
		if err := store.Save(invite.Invite{Code: "once", UsesLeft: 1}); err != nil {
			t.Fatal(err)
		}
		const n = 16
		var wg sync.WaitGroup
		results := make(chan bool, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ok, err := store.Consume("once", "")
				if err != nil {
					t.Error(err)
				}
				results <- ok
			}()
		}
		wg.Wait()
		close(results)
		succeeded := 0
		for ok := range results {
			if ok {
				succeeded++
			}
		}
		if succeeded != 1 {
			t.Errorf("want exactly 1 successful consume, got %d", succeeded)
		}
	})
}

func TestList(t *testing.T) {
	store := memory.New()
	got, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("want empty list, got %d invites", len(got))
	}
	invites := []invite.Invite{
		{Code: "a", Note: "first", UsesLeft: 1},
		{Code: "b", Note: "second", UsesLeft: 2},
	}
	for _, inv := range invites {
		if err := store.Save(inv); err != nil {
			t.Fatal(err)
		}
	}
	got, err = store.List()
	if err != nil {
		t.Fatal(err)
	}
	byCode := map[string]invite.Invite{}
	for _, inv := range got {
		byCode[inv.Code] = inv
	}
	if len(byCode) != len(invites) {
		t.Fatalf("want %d invites, got %d", len(invites), len(got))
	}
	for _, want := range invites {
		if diff := cmp.Diff(want, byCode[want.Code]); diff != "" {
			t.Errorf("invite %q mismatch (-want +got):\n%s", want.Code, diff)
		}
	}
}
