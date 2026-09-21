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

// testBarrier is a strict N-worker rendezvous used to prove that a fixed set of
// goroutines has all passed into a blocking wait before any is released. It uses
// a sync.Cond so that "arrived" and "parked" are the same state: each worker
// records its arrival and immediately falls into cond.Wait, whose unlock-and-park
// is atomic. This is what makes the barrier a mechanical proof rather than a
// scheduling coincidence — see waitAllArrived's happens-before argument.
//
// A single bounded cancellation path exists: waiting aborts the barrier (marks it
// aborted and broadcasts) so every parked and future worker exits instead of
// parking forever. Abort can never undercut a success decision, because success
// commits the released state under the same mutex before any late timer callback
// can observe it (the callback only aborts while the barrier is still waiting).
type testBarrier struct {
	mu       sync.Mutex
	cond     *sync.Cond
	arrived  int
	target   int
	released bool
	aborted  bool
}

func newTestBarrier(n int) *testBarrier {
	b := &testBarrier{target: n}
	b.cond = sync.NewCond(&b.mu)
	return b
}

// arrive is called by each worker. It records the arrival, wakes the parent the
// moment the target is reached, then blocks in cond.Wait until the barrier is
// released or aborted. It returns true if the worker is released normally (it
// should proceed) and false if the barrier was aborted (it must not consume).
func (b *testBarrier) arrive() bool {
	b.mu.Lock()
	b.arrived++
	if b.arrived == b.target {
		b.cond.Broadcast() // wake the parent blocked in waitAllArrived
	}
	for !b.released && !b.aborted {
		b.cond.Wait()
	}
	proceed := b.released && !b.aborted
	b.mu.Unlock()
	return proceed
}

// waitAllArrived blocks, bounded by timeout, until every target worker has
// arrived and is parked in cond.Wait. It returns true on success, having already
// committed the release (and broadcast) under the mutex so the parked workers all
// proceed; it returns false on timeout, having aborted the barrier so no worker
// is left parked indefinitely.
//
// happens-before proof that success implies all N workers parked:
// a worker's increment and its cond.Wait are contiguous statements executed
// under b.mu. A worker can release that mutex only by passing through
// cond.Wait's atomic unlock-and-park. Therefore no party can observe
// arrived == target — which requires reacquiring the mutex from the final
// arriving worker — without that final worker having already parked; every
// earlier worker parked when it released the mutex after its own increment. So
// once waitAllArrived sees arrived == target, all N workers are parked in
// cond.Wait, and the subsequent broadcast releases a provably-complete cohort.
//
// Bound/cancellation: a time.AfterFunc callback locks the same mutex, and — only
// if the barrier has not yet been released — marks it aborted and broadcasts so
// every parked and future worker exits. It cannot run while waitAllArrived holds
// the mutex, and the callback no-ops once released is committed, so a timer that
// fires on the success boundary never undercuts a committed release.
func (b *testBarrier) waitAllArrived(timeout time.Duration) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.arrived == b.target {
		b.released = true
		b.cond.Broadcast()
		return true
	}
	timer := time.AfterFunc(timeout, func() {
		b.mu.Lock()
		if !b.released {
			b.aborted = true
			b.cond.Broadcast()
		}
		b.mu.Unlock()
	})
	defer timer.Stop()
	for b.arrived < b.target && !b.aborted {
		b.cond.Wait()
	}
	if b.aborted {
		return false
	}
	// Commit release before releasing the mutex, so no racing timer can inject an
	// abort once we have established that all workers are parked.
	b.released = true
	b.cond.Broadcast()
	return true
}

// consumeResult is one worker's completion record. Every worker sends exactly one
// result, whether it was released or aborted, so the parent can account for all N.
type consumeResult struct {
	token     string
	ok        bool
	proceeded bool // true if the barrier released this worker to consume; false if aborted
}

// collectN receives exactly n results from resultsCh, bounded by timeout.
// Receiving all n proves every worker has sent its single completion record, i.e.
// the join is complete, without any WaitGroup or a channel close. resultsCh is
// never closed by the test: it is buffered to the worker count, so a worker can
// always deliver even if the parent has stopped reading, and a timed-out parent
// simply fails while the (bounded-by-abort) workers finish in the background.
// On timeout it returns whatever it collected so the caller can fail honestly.
func collectN(resultsCh <-chan consumeResult, n int, timeout time.Duration) []consumeResult {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	got := make([]consumeResult, 0, n)
	for len(got) < n {
		select {
		case r := <-resultsCh:
			got = append(got, r)
		case <-timer.C:
			return got
		}
	}
	return got
}

// TestInviteFlashStoreConcurrentConsumeExactlyOnce proves atomic one-time
// consumption under genuine same-ID concurrency, which a sequential test cannot
// exercise: n goroutines all target the SAME flash ID/user/registry. A true
// condition-variable barrier establishes that every consumer is parked in a
// blocking wait before any is released, so the consume calls genuinely overlap,
// and completion is proven by collecting exactly n results (each worker sends one)
// with a bounded select. Exactly one consumer must get the exact token; every
// other must get empty/false; a follow-up consume is a no-op.
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

	barrier := newTestBarrier(consumers)
	// Buffered to the consumer count so a worker's completion send can never
	// block, even if the parent has stopped reading after a timeout. Never closed.
	results := make(chan consumeResult, consumers)

	for i := 0; i < consumers; i++ {
		go func() {
			if !barrier.arrive() {
				// Barrier aborted (readiness timeout): do not consume, but still send
				// a distinct completion record so cleanup can account for all N.
				results <- consumeResult{proceeded: false}
				return
			}
			tok, ok := s.consume(id, userID, registry)
			results <- consumeResult{token: tok, ok: ok, proceeded: true}
		}()
	}

	// Phase 1: prove every worker is parked in cond.Wait before releasing any.
	if !barrier.waitAllArrived(timeout) {
		t.Fatalf("timed out waiting for all %d consumers to park on the barrier", consumers)
	}

	// Phase 2: waitAllArrived committed the release, so every provably-parked
	// worker is now released together and the consume calls genuinely overlap.

	// Phase 3: bounded completion collection. Receiving exactly consumers results
	// proves every worker finished (each sent exactly one record); no WaitGroup
	// watcher and, crucially, no close of a channel workers might still write to.
	got := collectN(results, consumers, timeout)
	if len(got) != consumers {
		t.Fatalf("joined only %d/%d consumers before timeout", len(got), consumers)
	}

	successes := 0
	proceeded := 0
	gotToken := ""
	for _, r := range got {
		if r.proceeded {
			proceeded++
		}
		if !r.ok {
			if r.token != "" {
				t.Fatalf("failed consume returned a non-empty token %q", r.token)
			}
			continue
		}
		successes++
		gotToken = r.token
	}
	if proceeded != consumers {
		t.Fatalf("barrier aborted %d worker(s) unexpectedly; all %d should have proceeded", consumers-proceeded, consumers)
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
