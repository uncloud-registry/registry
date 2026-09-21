package controlplane

import (
	"testing"
	"time"
)

// TestInviteFlashStoreExpiryCapAndAtomicity unit-tests the private one-time flash
// store directly: atomic single consumption, expired/unknown reveal nothing, wrong
// principal/registry must not consume, and cap enforcement with pruning.
func TestInviteFlashStoreExpiryCapAndAtomicity(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	s := &inviteFlashStore{
		now:     func() time.Time { return now },
		entries: map[string]inviteFlash{},
	}

	// Atomic single consumption.
	id1, err := s.store("tok-1", 10, 100)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if got, ok := s.consume(id1, 10, 100); !ok || got != "tok-1" {
		t.Fatalf("expected first consume to return token, got ok=%v", ok)
	}
	if _, ok := s.consume(id1, 10, 100); ok {
		t.Fatalf("second consume of the same flash must fail")
	}

	// Expired flash reveals nothing.
	id2, err := s.store("tok-2", 10, 100)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	now = now.Add(inviteFlashTTL + time.Second)
	if _, ok := s.consume(id2, 10, 100); ok {
		t.Fatalf("expired flash must reveal nothing")
	}

	// Unknown flash reveals nothing.
	if _, ok := s.consume("nope", 10, 100); ok {
		t.Fatalf("unknown flash must reveal nothing")
	}

	// Wrong user and wrong registry reveal nothing and must NOT consume.
	id3, err := s.store("tok-3", 10, 100)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if _, ok := s.consume(id3, 99, 100); ok {
		t.Fatalf("wrong user must not reveal")
	}
	if _, ok := s.consume(id3, 10, 999); ok {
		t.Fatalf("wrong registry must not reveal")
	}
	if got, ok := s.consume(id3, 10, 100); !ok || got != "tok-3" {
		t.Fatalf("owner must still be able to consume after wrong-principal attempts")
	}

	// Cap enforcement + pruning: fill to the cap, next store fails safely; advance the
	// clock past TTL and a store() prunes expired entries to free space.
	for i := 0; i < inviteFlashMax; i++ {
		if _, err := s.store("filler", 10, 100); err != nil {
			t.Fatalf("unexpected store failure before cap at %d: %v", i, err)
		}
	}
	if _, err := s.store("overflow", 10, 100); err == nil {
		t.Fatalf("expected store to fail safely at capacity")
	}
	now = now.Add(inviteFlashTTL + time.Second)
	if _, err := s.store("after-prune", 20, 200); err != nil {
		t.Fatalf("expected pruning to free capacity before store, got %v", err)
	}
}