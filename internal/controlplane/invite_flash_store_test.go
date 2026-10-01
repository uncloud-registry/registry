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
// result, whether it was released or aborted, so after the WaitGroup join the
// parent can account for all N. The completion proof is the join itself, not
// these records: a worker sends its record *before* it returns, so counting
// records alone would not prove the goroutine exited (see the test's
// close-after-join ordering).
type consumeResult struct {
	token     string
	ok        bool
	proceeded bool // true if the barrier released this worker to consume; false if aborted
}

// TestInviteFlashStoreConcurrentConsumeExactlyOnce proves atomic one-time
// consumption under genuine same-ID concurrency, which a sequential test cannot
// exercise: n goroutines all target the SAME flash ID/user/registry. A true
// condition-variable barrier establishes that every consumer is parked in a
// blocking wait before any is released, so the consume calls genuinely overlap.
//
// Termination is proven by a real WaitGroup join, not by counting results: a
// worker sends its completion record *before* it returns, so receiving n records
// would not by itself prove the goroutines exited. Each worker therefore defers
// wg.Done() and sends exactly one record into a channel buffered to n; the parent
// calls wg.Wait() synchronously, which returns only after every worker's deferred
// Done has run — i.e. after every worker has sent — and only then closes the
// results channel and drains exactly n records. Close-after-join is race-free by
// construction (no worker can send to a closed channel), and the barrier-abort
// (readiness-timeout) path joins and drains all n aborted records too. Exactly
// one consumer must get the exact token; every other must get empty/false; a
// follow-up consume is a no-op.
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
	// Buffered to the worker count so a worker's completion send can never
	// block, even before the parent begins draining. Closed only after the
	// WaitGroup join, so the close is never observed by any worker.
	results := make(chan consumeResult, consumers)

	// wg tracks goroutine lifecycle only. Each worker defers Done, and because
	// the deferred call runs on function return — after that worker's send —
	// wg.Wait() returning implies every worker has sent its single record.
	var wg sync.WaitGroup
	wg.Add(consumers)
	for i := 0; i < consumers; i++ {
		go func() {
			defer wg.Done()
			if !barrier.arrive() {
				// Barrier aborted (readiness timeout): do not consume, but still
				// send a distinct completion record so cleanup accounts for all N.
				results <- consumeResult{proceeded: false}
				return
			}
			tok, ok := s.consume(id, userID, registry)
			results <- consumeResult{token: tok, ok: ok, proceeded: true}
		}()
	}

	// Phase 1: prove every worker is parked in cond.Wait before releasing any.
	// On success waitAllArrived commits the release (broadcast) under the mutex,
	// so the provably-parked cohort proceeds together and the consumes genuinely
	// overlap. On readiness timeout it aborts and broadcasts instead, so every
	// parked and future worker observes aborted and skips the consume; no worker
	// is left parked indefinitely. The readiness timeout is kept because barrier
	// abort is cancellable.
	ready := barrier.waitAllArrived(timeout)

	// Phase 2: real goroutine join, synchronous, no watchdog/timer goroutine.
	// wg.Wait cannot block here: the barrier has either released or aborted every
	// worker, so each worker's only potentially-blocking step (cond.Wait) is
	// unblocked, and its send into the buffer-`consumers` channel can never
	// block. When Wait returns, every worker has exited and sent exactly one
	// record. A deadlocked production consume could NOT be joined this way and
	// is not force-cancelled here; the honest hard bound is `go test -timeout`
	// (process level), which terminates the test and dumps goroutine stacks.
	wg.Wait()

	// Phase 3: only now, with every worker joined (all sends finished), close and
	// drain. No worker can write to a closed channel by construction.
	close(results)
	records := make([]consumeResult, 0, consumers)
	for r := range results {
		records = append(records, r)
	}
	if len(records) != consumers {
		t.Fatalf("joined and drained %d/%d consumer records; a worker failed to account", len(records), consumers)
	}

	if !ready {
		// Readiness timeout. The abort path still fully accounts for all N:
		// each worker was joined above and sent a proceeded:false no-op. Verify
		// that no worker consumed, then fail honestly.
		for _, r := range records {
			if r.proceeded {
				t.Fatalf("aborted barrier but a worker reported proceeded")
			}
			if r.ok || r.token != "" {
				t.Fatalf("aborted worker must not have consumed (ok=%v token=%q)", r.ok, r.token)
			}
		}
		t.Fatalf("timed out waiting for all %d consumers to park on the barrier", consumers)
	}

	successes := 0
	proceeded := 0
	gotToken := ""
	for _, r := range records {
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
