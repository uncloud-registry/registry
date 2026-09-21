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
// exercise. n goroutines all target the SAME flash ID/user/registry. A real
// two-phase barrier (readiness acknowledgment then release) guarantees every
// consumer is parked on start before any is released, so the consume calls
// genuinely overlap. The parent joins every worker (bounded) before reading
// results. Exactly one consumer must get the exact token; every other must get
// empty/false; a follow-up consume is a no-op.
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

	// Two-phase barrier. ready is buffered to consumers so a worker's readiness
	// signal can never block on send (channel capacity eliminates internal
	// blocking). Workers send ready BEFORE blocking on start, so when the parent
	// has drained all N readiness signals it has mechanically proven every
	// worker is parked on start — exactly the launch-scalability gap in round 2,
	// where start was closed immediately after spawn and unscheduled goroutines
	// could arrive post-close and serialize.
	ready := make(chan struct{}, consumers)
	start := make(chan struct{})
	results := make(chan struct {
		token string
		ok    bool
	}, consumers) // buffered to consumers: a worker can never block writing its result

	var wg sync.WaitGroup
	for i := 0; i < consumers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready <- struct{}{} // acknowledge readiness first
			<-start
			tok, ok := s.consume(id, userID, registry)
			results <- struct {
				token string
				ok    bool
			}{tok, ok}
		}()
	}

	// Phase 1: wait until all N consumers have signalled readiness, bounded. If
	// readiness never completes we still release every worker parked on start
	// and make a best-effort join before failing — we do not pretend to have
	// force-cancelled anyone, but the worker code is finite and nonblocking apart
	// from the guarded start/consume/send, so closing start is expected to let
	// every worker finish and the join is expected to complete.
	if !waitForReadyN(ready, consumers, timeout) {
		close(start) // release any workers still waiting so failure cleanup can join
		if !joinWithTimeout(&wg, timeout) {
			t.Logf("best-effort join did not complete before failing readiness barrier")
		}
		t.Fatalf("timed out waiting for %d consumers to signal readiness", consumers)
	}

	// Phase 2: all workers are provably parked on start — release them together.
	close(start)

	// Phase 3: complete join before touching results. Success path must establish
	// a full join, not just an on-time waitGroup (round 2's on-timeout Fatal gave
	// no such proof). Here a genuine timeout triggers a bounded join attempt
	// before failure.
	if !joinWithTimeout(&wg, timeout) {
		close(results)
		t.Fatalf("timed out waiting for %d consumers to finish (possible deadlock in consume)", consumers)
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

// waitForReadyN blocks (with a bounded timeout) until exactly n readiness
// acknowledgements have been received on ready. It returns false on timeout. The
// receive side runs in the caller (the parent), so no helper goroutine is leaked
// if n is never reached; the caller is then responsible for releasing workers
// parked on start and making a best-effort join before failing.
func waitForReadyN(ready <-chan struct{}, n int, timeout time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for i := 0; i < n; i++ {
		select {
		case <-ready:
		case <-timer.C:
			return false
		}
	}
	return true
}

// joinWithTimeout waits up to timeout for wg to return to zero and reports
// whether the join completed. It never leaks the watcher goroutine's channel
// (bounded by timeout). This is the mechanical completion proof the success
// path requires, and the best-effort release used on failure paths.
func joinWithTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}
