package session

import (
	"testing"
	"time"
)

func TestLookup_ReturnsTheSessionForItsToken(t *testing.T) {
	s := NewStore()

	token, created, err := s.Create("devvm", 8*time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, ok := s.Lookup(token)
	if !ok {
		t.Fatal("Lookup did not find a session that was just created")
	}
	if got.ID != created.ID || got.Machine != "devvm" {
		t.Errorf("Lookup = %+v, want id %q for machine devvm", got, created.ID)
	}
	if left := time.Until(got.ExpiresAt); left < 7*time.Hour+59*time.Minute || left > 8*time.Hour {
		t.Errorf("session ends in %s, want about 8h", left)
	}
}

func TestLookup_RejectsUnknownAndEmptyTokens(t *testing.T) {
	s := NewStore()
	if _, _, err := s.Create("devvm", time.Hour); err != nil {
		t.Fatalf("Create: %v", err)
	}

	for _, token := range []string{"", "not-a-token"} {
		if _, ok := s.Lookup(token); ok {
			t.Errorf("Lookup(%q) found a session", token)
		}
	}
}

func TestLookup_RejectsTheSessionIDAsAToken(t *testing.T) {
	s := NewStore()
	_, created, err := s.Create("devvm", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// The ID travels in Telegram button data, so it must not open the window.
	if _, ok := s.Lookup(created.ID); ok {
		t.Error("the session ID was accepted as a token")
	}
}

func TestLookup_RejectsAnExpiredSession(t *testing.T) {
	s := NewStore()
	token, _, err := s.Create("devvm", time.Millisecond)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	time.Sleep(5 * time.Millisecond)

	if _, ok := s.Lookup(token); ok {
		t.Error("Lookup found a session past its expiry")
	}
}

func TestCreate_GivesEachSessionItsOwnTokenAndID(t *testing.T) {
	s := NewStore()
	tokenA, a, _ := s.Create("devvm", time.Hour)
	tokenB, b, _ := s.Create("devvm", time.Hour)

	if tokenA == tokenB || a.ID == b.ID {
		t.Error("two sessions share a token or an ID")
	}
	if len(tokenA) != 64 {
		t.Errorf("token is %d hex chars, want 64 (32 random bytes)", len(tokenA))
	}
}

func TestEnd_ClosesEverySessionOfThatMachine(t *testing.T) {
	s := NewStore()
	tokenA, a, _ := s.Create("devvm", time.Hour)
	tokenB, _, _ := s.Create("devvm", time.Hour)
	tokenOther, _, _ := s.Create("laptop", time.Hour)

	machine, ended := s.End(a.ID)

	if machine != "devvm" || ended != 2 {
		t.Errorf("End = (%q, %d), want (devvm, 2)", machine, ended)
	}
	if _, ok := s.Lookup(tokenA); ok {
		t.Error("the ended session still opens the window")
	}
	if _, ok := s.Lookup(tokenB); ok {
		t.Error("a second session of the same machine survived End")
	}
	if _, ok := s.Lookup(tokenOther); !ok {
		t.Error("End closed another machine's session")
	}
}

func TestEnd_UnknownIDEndsNothing(t *testing.T) {
	s := NewStore()
	token, _, _ := s.Create("devvm", time.Hour)

	if _, ended := s.End("missing"); ended != 0 {
		t.Errorf("End(missing) ended %d sessions, want 0", ended)
	}
	if _, ok := s.Lookup(token); !ok {
		t.Error("End(missing) closed a live session")
	}
}

func TestCleanup_RemovesOnlyExpiredSessions(t *testing.T) {
	s := NewStore()
	s.Create("devvm", time.Millisecond)
	live, _, _ := s.Create("laptop", time.Hour)

	time.Sleep(5 * time.Millisecond)

	if removed := s.Cleanup(); removed != 1 {
		t.Errorf("Cleanup removed %d sessions, want 1", removed)
	}
	if _, ok := s.Lookup(live); !ok {
		t.Error("Cleanup removed a live session")
	}
}
