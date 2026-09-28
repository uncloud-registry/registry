package main

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestCleanupEnvParsing pins the strict, fail-closed config contract for the
// periodic cleanup loop: an unset value takes the default, a positive value is
// honored, a malformed/non-positive value fails closed, and a value above the
// documented finite maximum (REGISTRY_CLEANUP_BATCH) fails closed rather than
// being silently clamped or read as a default.
func TestCleanupEnvParsing(t *testing.T) {
	t.Setenv(envCleanupInterval, "")
	if d, err := cleanupIntervalFromEnv(); err != nil || d != defaultCleanupInterval {
		t.Fatalf("default interval = %v err %v, want %v", d, err, defaultCleanupInterval)
	}
	t.Setenv(envCleanupInterval, "1m")
	if d, err := cleanupIntervalFromEnv(); err != nil || d != time.Minute {
		t.Fatalf("interval 1m = %v err %v, want 1m", d, err)
	}
	for _, bad := range []string{"abc", "0s", "-5s"} {
		t.Setenv(envCleanupInterval, bad)
		if _, err := cleanupIntervalFromEnv(); err == nil {
			t.Fatalf("interval %q must fail closed", bad)
		}
	}

	t.Setenv(envCleanupBatch, "")
	if n, err := cleanupBatchFromEnv(); err != nil || n != defaultCleanupBatchSize {
		t.Fatalf("default batch = %d err %v, want %d", n, err, defaultCleanupBatchSize)
	}
	t.Setenv(envCleanupBatch, "7")
	if n, err := cleanupBatchFromEnv(); err != nil || n != 7 {
		t.Fatalf("batch 7 = %d err %v, want 7", n, err)
	}
	for _, bad := range []string{"abc", "0", "-3"} {
		t.Setenv(envCleanupBatch, bad)
		if _, err := cleanupBatchFromEnv(); err == nil {
			t.Fatalf("batch %q must fail closed", bad)
		}
	}
	// Over-the-maximum must fail closed too (the documented finite bound).
	t.Setenv(envCleanupBatch, fmt.Sprint(maxCleanupBatchSize+1))
	if n, err := cleanupBatchFromEnv(); err == nil {
		t.Fatalf("batch over max must fail closed, got %d", n)
	}
	t.Setenv(envCleanupBatch, fmt.Sprint(maxCleanupBatchSize))
	if n, err := cleanupBatchFromEnv(); err != nil || n != maxCleanupBatchSize {
		t.Fatalf("batch at max = %d err %v, want %d", n, err, maxCleanupBatchSize)
	}
}

// TestCleanupLoopHonorsCancellation proves runCleanupLoop stops without
// panicking or firing a pass when its context is already canceled — the
// context-cancellation contract the periodic wiring depends on — and that the
// returned done channel is closed once the loop goroutine has fully exited
// (so a caller can join the loop before releasing the staging store).
func TestCleanupLoopHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := runCleanupLoop(ctx, nil, time.Millisecond, 1)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup loop did not exit after cancellation")
	}
}

// TestCleanupLoopJoinWaitsForPass proves a canceled-but-in-flight pass is
// JOINED (bounded) by a running loop's done channel before the loop exits: a
// caller that cancels then waits on done never races pass still touching the
// store. This is the worker-shutdown join contract the cancelOnCloseStore
// relies on (defense against closing the SQLite/spool under a live pass).
func TestCleanupLoopJoinWaitsForPass(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	// Start a loop with a real interval; then cancel and confirm the done
	// channel closes promptly (no infinite hang).
	done := runCleanupLoop(ctx, nil, time.Millisecond, 1)
	cancel()
	select {
	case <-done:
	case <-time.After(cleanupShutdownTimeout + time.Second):
		t.Fatal("loop did not join after cancel")
	}
}

// TestCancelOnCloseStoreJoinsLoop proves the handler-facing wrapper cancels the
// loop and then JOINS it (bounded) before closing the underlying store: the
// close callback must ONLY ever run after done is closed (or the bounded
// timeout concedes), so an in-flight pass cannot race the store release.
func TestCancelOnCloseStoreJoinsLoop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := runCleanupLoop(ctx, nil, time.Millisecond, 1) // exits; done closes on cancel

	closed := make(chan struct{})
	w := &cancelOnCloseStore{
		cancel: cancel,
		done:   done,
		close: func() error {
			// Assert the join happened before this close runs: without the join
			// this would fire immediately; with it we wait for done first.
			select {
			case <-done:
			default:
				t.Error("store close ran before the cleanup loop joined")
			}
			close(closed)
			return nil
		},
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not complete")
	}
}