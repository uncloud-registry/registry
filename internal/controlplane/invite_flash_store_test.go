package controlplane

import (
	"sync"
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

// TestInviteFlashStoreConcurrentConsumeExactlyOnce proves atomic one-time
// consumption under genuine same-ID concurrency, which a sequential test cannot
// exercise. n goroutines all target the SAME flash ID/user/registry behind a
// ready/start barrier so they call consume at the same instant; exactly one must
// get the exact token and every other must get empty/false. Timeouts bound the
// test against deadlock and every goroutine is joined (no leaks).
func TestInviteFlashStoreConcurrentConsumeExactlyOnce(t *testing.T) {
	t.Parallel()

	const (
		consumers = 64
		userID    = int64(10)
		registry  = int64(100)
		timeout   = 30 * time.Second
	)

	s := &inviteFlashStore{
		now:     func() time.Time { return time.Unix(1_700_000_001, 0) }, // fresh, non-expired
		entries: map[string]inviteFlash{},
	}

	const want = "tok-concurrent"
	id, err := s.store(want, userID, registry)
	if err != nil {
		t.Fatalf("store: %v", err)
	}

	// Ready/start barrier: nobody may consume until every goroutine is parked on
	// start, so the consume calls overlap as much as the scheduler permits.
	start := make(chan struct{})
	results := make(chan struct {
		token string
		ok    bool
	}, consumers)

	var wg sync.WaitGroup
	for i := 0; i < consumers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			tok, ok := s.consume(id, userID, registry)
			results <- struct {
				token string
				ok    bool
			}{tok, ok}
		}()
	}
	close(start) // release all consumers at once

	// Bounded wait for every goroutine; skipping any counts as a failure rather
	// than leaking it.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for %d concurrent consumers (possible deadlock)", consumers)
	}
	close(results)

	successes := 0
	gotToken := ""
	for r := range results {
		if !r.ok {
			if r.token != "" {
				t.Fatalf("failed consume returned a non-empty token %q", r.token)
			}
			continue
		}
		successes++
		gotToken = r.token
	}
	if successes != 1 {
		t.Fatalf("expected exactly 1 successful consume, got %d", successes)
	}
	if gotToken != want {
		t.Fatalf("consumed token = %q, want %q", gotToken, want)
	}

	// The flash must be fully removed: a follow-up consume is a no-op.
	if _, ok := s.consume(id, userID, registry); ok {
		t.Fatalf("flash remained consumable after exactly-once concurrent consumption")
	}
}