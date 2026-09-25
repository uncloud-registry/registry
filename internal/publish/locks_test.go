package publish

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRepositoryLockerSameKeySerializes proves that two WithLock calls for the
// SAME canonical owner/repository key never run their callbacks concurrently:
// the second callback must not start until the first has fully returned.
func TestRepositoryLockerSameKeySerializes(t *testing.T) {
	l := NewRepositoryLocker()

	insideFirst := make(chan struct{})
	releaseFirst := make(chan struct{})
	entered := make(chan struct{})
	started := make(chan struct{})

	go func() {
		close(started)
		err := l.WithLock(context.Background(), "0xaliceowner", "backend/api", func(_ context.Context) error {
			close(insideFirst)
			<-releaseFirst
			return nil
		})
		if err != nil {
			t.Errorf("first holder: unexpected error %v", err)
		}
		close(entered)
	}()
	<-started
	<-insideFirst // first holder is inside the lock

	// While the first holder holds the lock, attempt a second acquisition of the
	// SAME key. It must block (not run) until the first holder returns.
	var overlapped atomic.Bool
	secondDone := make(chan struct{})
	go func() {
		err := l.WithLock(context.Background(), "0xaliceowner", "backend/api", func(_ context.Context) error {
			select {
			case <-releaseFirst:
				// first holder still holding: overlapping is a violation
				overlapped.Store(true)
			default:
			}
			return nil
		})
		if err != nil {
			t.Errorf("second holder: unexpected error %v", err)
		}
		close(secondDone)
	}()

	// Give the second acquisition a moment to start waiting and ensure it did not
	// proceed while the first holder is still inside.
	time.Sleep(50 * time.Millisecond)
	select {
	case <-secondDone:
		t.Fatal("second callback ran before the first holder released the lock")
	default:
	}
	if overlapped.Load() {
		t.Fatal("callbacks for the same key overlapped")
	}

	close(releaseFirst)
	<-entered
	<-secondDone
}

// TestRepositoryLockerDifferentKeysConcurrent proves that different
// owner/repository keys are NOT mutually exclusive: callbacks for distinct keys
// overlap concurrently.
func TestRepositoryLockerDifferentKeysConcurrent(t *testing.T) {
	l := NewRepositoryLocker()

	entered := make(chan struct{})
	release := make(chan struct{})
	count := int32(0)
	var mu sync.Mutex
	var concurrent int
	maxConcurrent := 0

	run := func(owner, repo string) {
		err := l.WithLock(context.Background(), owner, repo, func(_ context.Context) error {
			mu.Lock()
			concurrent++
			if concurrent > maxConcurrent {
				maxConcurrent = concurrent
			}
			mu.Unlock()
			atomic.AddInt32(&count, 1)
			entered <- struct{}{}
			<-release
			mu.Lock()
			concurrent--
			mu.Unlock()
			return nil
		})
		if err != nil {
			t.Errorf("holder %s/%s: unexpected error %v", owner, repo, err)
		}
	}

	go run("0xaliceowner", "repo-a")
	go run("0xaliceowner", "repo-b")
	go run("0xbobowner", "repo-a")

	for i := 0; i < 3; i++ {
		<-entered
	}
	if atomic.LoadInt32(&count) != 3 {
		t.Fatalf("expected all 3 callbacks to run, got %d", count)
	}
	mu.Lock()
	got := maxConcurrent
	mu.Unlock()
	if got < 2 {
		t.Fatalf("different keys must run concurrently; observed max concurrency %d", got)
	}
	close(release)
}

// TestRepositoryLockerCanceledWaiter proves a waiter whose context is canceled
// returns promptly with the request-context sentinel (context.Canceled), that
// the already-held lock is not disturbed, and that a later acquisition of the
// same key still works.
func TestRepositoryLockerCanceledWaiter(t *testing.T) {
	l := NewRepositoryLocker()

	firstInside := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstDone := make(chan struct{})
	go func() {
		err := l.WithLock(context.Background(), "0xaliceowner", "repo", func(_ context.Context) error {
			close(firstInside)
			<-releaseFirst
			return nil
		})
		if err != nil {
			t.Errorf("holder: unexpected error %v", err)
		}
		close(firstDone)
	}()
	<-firstInside

	// A waiter with a cancelable context. It blocks on the lock, then we cancel.
	waitCtx, cancel := context.WithCancel(context.Background())
	waitErr := make(chan error, 1)
	waiterStarted := make(chan struct{})
	go func() {
		close(waiterStarted)
		waitErr <- l.WithLock(waitCtx, "0xaliceowner", "repo", func(_ context.Context) error {
			return errors.New("canceled waiter must never run its callback")
		})
	}()
	<-waiterStarted
	// Ensure the waiter is actually waiting before canceling.
	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case err := <-waitErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled waiter must return context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled waiter did not return promptly")
	}

	// The holder is undisturbed.
	select {
	case <-firstDone:
		t.Fatal("first holder was released by the canceled waiter")
	case <-time.After(30 * time.Millisecond):
	}
	close(releaseFirst)
	<-firstDone

	// The lock is reusable after both left.
	if err := l.WithLock(context.Background(), "0xaliceowner", "repo", func(_ context.Context) error {
		return nil
	}); err != nil {
		t.Fatalf("re-acquire after cancel: %v", err)
	}
}

// TestRepositoryLockerEntryReclamation proves entries are removed once the last
// holder and waiter are gone, so the internal key map never grows unboundedly.
func TestRepositoryLockerEntryReclamation(t *testing.T) {
	l := NewRepositoryLocker()

	for i := 0; i < 20; i++ {
		key := fmt.Sprintf("repo-%d", i)
		if err := l.WithLock(context.Background(), "0xaliceowner", key, func(_ context.Context) error {
			return nil
		}); err != nil {
			t.Fatalf("lock %s: %v", key, err)
		}
	}
	// If entries were never reclaimed, the map would hold 20 stale keys.
	l.mu.Lock()
	n := len(l.locks)
	l.mu.Unlock()
	if n != 0 {
		t.Fatalf("expected 0 live lock entries after all work, got %d", n)
	}

	// A canceled waiter must also release its reference and (with the holder)
	// reclaim the entry: hold the key with a holder, spawn a blocked waiter,
	// cancel the waiter, then release the holder — the key map must be empty.
	hold := make(chan struct{})
	holderDone := make(chan struct{})
	go func() {
		_ = l.WithLock(context.Background(), "0xaliceowner", "held", func(_ context.Context) error {
			<-hold
			return nil
		})
		close(holderDone)
	}()
	time.Sleep(20 * time.Millisecond)
	wCtx, cancel := context.WithCancel(context.Background())
	waiterErr := make(chan error, 1)
	go func() {
		waiterErr <- l.WithLock(wCtx, "0xaliceowner", "held", func(_ context.Context) error { return nil })
	}()
	time.Sleep(20 * time.Millisecond) // ensure the waiter is blocked on the key
	cancel()
	if err := <-waiterErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter must return context.Canceled, got %v", err)
	}
	close(hold)
	<-holderDone

	l.mu.Lock()
	n = len(l.locks)
	l.mu.Unlock()
	if n != 0 {
		t.Fatalf("canceled-waiter scenario left %d live lock entries", n)
	}
}

// TestRepositoryLockerPanicCleanup proves a panicking callback does not leak the
// lock or its entry: the panic identity is preserved and the same key can be
// acquired immediately after.
func TestRepositoryLockerPanicCleanup(t *testing.T) {
	l := NewRepositoryLocker()

	panicked := make(chan any, 1)
	go func() {
		defer func() { panicked <- recover() }()
		_ = l.WithLock(context.Background(), "0xaliceowner", "repo", func(_ context.Context) error {
			panic("marker-panic-value-912")
		})
	}()
	got := <-panicked
	if got != "marker-panic-value-912" {
		t.Fatalf("panic identity not preserved, got %v", got)
	}

	// The lock + entry must be reclaimed after the panic.
	l.mu.Lock()
	n := len(l.locks)
	l.mu.Unlock()
	if n != 0 {
		t.Fatalf("panicked callback leaked %d lock entries", n)
	}
	if err := l.WithLock(context.Background(), "0xaliceowner", "repo", func(_ context.Context) error {
		return nil
	}); err != nil {
		t.Fatalf("re-acquire after panic: %v", err)
	}
}

// TestRepositoryLockerHighContentionRace hammers a few keys with many
// concurrent acquisitions (with cancellations) under -race and verifies every
// callback runs exactly as many times as authenticated acquisitions succeed.
func TestRepositoryLockerHighContentionRace(t *testing.T) {
	l := NewRepositoryLocker()

	const keys = 4
	const perKey = 40
	var completed atomic.Int32
	var canceled atomic.Int32
	var wg sync.WaitGroup

	for k := 0; k < keys; k++ {
		repo := fmt.Sprintf("repo-%d", k)
		for i := 0; i < perKey; i++ {
			wg.Add(1)
			go func(repo string, i int) {
				defer wg.Done()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if i%3 == 0 {
					// A portion cancel their context while (possibly) waiting.
					cancel()
				}
				err := l.WithLock(ctx, "0xaliceowner", repo, func(_ context.Context) error {
					completed.Add(1)
					return nil
				})
				if err != nil {
					if errors.Is(err, context.Canceled) {
						canceled.Add(1)
						return
					}
					t.Errorf("lock %s: unexpected error %v", repo, err)
				}
			}(repo, i)
		}
	}
	wg.Wait()

	if completed.Load() != keys*perKey-canceled.Load() {
		t.Fatalf("completed %d callbacks, canceled %d, want %d total", completed.Load()+canceled.Load(), canceled.Load(), keys*perKey)
	}
	l.mu.Lock()
	n := len(l.locks)
	l.mu.Unlock()
	if n != 0 {
		t.Fatalf("high contention left %d live lock entries", n)
	}
}
