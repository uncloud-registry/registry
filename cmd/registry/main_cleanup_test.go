package main

import (
	"context"
	"testing"
	"time"
)

// TestCleanupEnvParsing pins the strict, fail-closed config contract for the
// periodic cleanup loop: an unset value takes the default, a positive value is
// honored, and a malformed/non-positive value fails closed instead of being
// silently read as a default.
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
}

// TestCleanupLoopHonorsCancellation proves runCleanupLoop stops without
// panicking or firing a pass when its context is already canceled — the
// context-cancellation contract the periodic wiring depends on. It never
// touches a real staging service.
func TestCleanupLoopHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// A canceled context must not start a ticker pass or panic; this exercises
	// the select's ctx.Done branch deterministically.
	runCleanupLoop(ctx, nil, time.Millisecond, 1)
}
