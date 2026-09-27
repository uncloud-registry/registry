package publish

import (
	"context"
	"sync"

	"github.com/uncloud-registry/registry/internal/spec"
)

// RepositoryLocker serializes repository publication for one canonical
// owner+repository key while letting DIFFERENT keys proceed concurrently. It is
// an IN-PROCESS corrective boundary only: cross-process publication safety is
// enforced by the authoritative control-plane generation comparison at commit
// time (see PublishCommitWithConflictRebuild), never by this lock alone.
type RepositoryLocker struct {
	mu    sync.Mutex
	locks map[lockKey]*lockEntry
}

// lockKey is the exact, comparable identity of one owner+repository pair. It
// is a plain struct of the two full (untruncated, unhashed) fields, so Go's
// built-in struct equality — exact, field-by-field string comparison — is
// what decides whether two calls share a key; there is no hashing step and
// therefore no collision to reason about. Held only as an internal map key
// and reclaimed with its entry (see acquireEntry/releaseEntry); it is never
// placed in an error or any other externally observable output.
type lockKey struct {
	owner string
	repo  string
}

// lockEntry is the reference-counted state for one canonical owner+repository
// key. held and waiters are both guarded by RepositoryLocker.mu — including
// from a waiter's own goroutine when it checks whether its cancellation is
// still in time — so a waiter's admission and its cancellation are always
// resolved by the same mutex and can never both take effect.
type lockEntry struct {
	refs    int
	held    bool
	waiters []*waiter // FIFO: index 0 is next to be granted
}

// waiter is one blocked caller's admission ticket. ch is closed exactly once,
// by whichever release() call pops this waiter off the front of the queue;
// once that happens the waiter owns the lock and must eventually release it,
// regardless of whether its context is later (or concurrently) canceled.
type waiter struct {
	ch chan struct{}
}

// NewRepositoryLocker returns an empty keyed publication locker.
func NewRepositoryLocker() *RepositoryLocker {
	return &RepositoryLocker{locks: make(map[lockKey]*lockEntry)}
}

// WithLock runs fn while holding the lock for the canonical owner+repository
// key. Same-key callbacks never overlap; different keys run concurrently.
// Waiters are admitted in FIFO order. A waiter honors ctx cancellation
// promptly and returns the ACTUAL request-context sentinel (context.Canceled /
// context.DeadlineExceeded) — but only if the cancellation actually preempted
// the grant: once a waiter has been admitted, cancellation has no authority
// over it and cannot make Lock return an error while it now owns the lock, so
// there is never a leaked (held-but-nobody-releases) lock and never a
// concurrent second holder. A panicking fn does not leak the lock or its
// entry, and the panic value propagates unchanged. Entries are
// reference-counted and removed once the last holder and waiter for a key are
// gone, so the key map never grows unboundedly.
func (l *RepositoryLocker) WithLock(ctx context.Context, owner, repo string, fn func(context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	key := canonicalLockKey(owner, repo)
	ent := l.acquireEntry(key)
	defer l.releaseEntry(key, ent)

	w, granted := l.enqueue(ent)
	if !granted {
		select {
		case <-w.ch:
			// Admitted while waiting.
		case <-ctx.Done():
			if l.abandon(ent, w) {
				return ctx.Err()
			}
			// abandon reported the waiter was no longer in the queue: release
			// already popped and granted it under the same mutex before this
			// cancellation could take effect. The grant committed first, so
			// it — not the cancellation — owns the outcome: fall through and
			// run fn as the holder.
		}
	}

	defer l.release(ent)
	return fn(ctx)
}

func (l *RepositoryLocker) acquireEntry(key lockKey) *lockEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	ent := l.locks[key]
	if ent == nil {
		ent = &lockEntry{}
		l.locks[key] = ent
	}
	ent.refs++
	return ent
}

func (l *RepositoryLocker) releaseEntry(key lockKey, ent *lockEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ent.refs--
	if ent.refs <= 0 {
		delete(l.locks, key)
	}
}

// enqueue admits the caller to ent: immediately (granted=true) if the key is
// free, or by appending a waiter to the FIFO queue (granted=false) otherwise.
func (l *RepositoryLocker) enqueue(ent *lockEntry) (w *waiter, granted bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !ent.held {
		ent.held = true
		return nil, true
	}
	w = &waiter{ch: make(chan struct{})}
	ent.waiters = append(ent.waiters, w)
	return w, false
}

// abandon removes w from ent's queue if it is still pending, reporting
// whether the removal happened. This is the sole authority check that
// resolves the grant-vs-cancel race: if w is no longer in the queue,
// release() already popped and granted it first.
func (l *RepositoryLocker) abandon(ent *lockEntry, w *waiter) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, q := range ent.waiters {
		if q == w {
			ent.waiters = append(ent.waiters[:i], ent.waiters[i+1:]...)
			return true
		}
	}
	return false
}

// release hands the lock to the next FIFO waiter, or marks ent free if none
// are queued. held stays true across a hand-off — it only ever goes false
// when the queue is empty — so a concurrent enqueue can never jump ahead of
// queued waiters while a hand-off is in flight.
func (l *RepositoryLocker) release(ent *lockEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(ent.waiters) == 0 {
		ent.held = false
		return
	}
	next := ent.waiters[0]
	ent.waiters = ent.waiters[1:]
	close(next.ch)
}

// canonicalLockKey maps an owner+repository pair to their exact lock
// identity. The owner is normalized exactly like feed construction
// (spec.NormalizeOwner), matching the same identity contract used for feed
// ownership comparisons; the repository is used verbatim, in full, with no
// truncation. Because the result is a plain struct compared field-by-field,
// two calls produce the same key if and only if their normalized owner and
// full repository strings are identical — there is no hashing step, no
// length bound, and so no way for distinct pairs to alias.
func canonicalLockKey(owner, repo string) lockKey {
	return lockKey{owner: spec.NormalizeOwner(owner), repo: repo}
}
