package publish

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
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
	locks map[string]*lockEntry
}

// lockEntry is the reference-counted holder for one canonical owner+repository
// key. Its gate channel carries exactly one admission token: a token present
// means the key is currently free; a waiter becomes the holder by receiving it
// and must restore it on release. refs is guarded by RepositoryLocker.mu.
type lockEntry struct {
	gate chan struct{}
	refs int
}

// NewRepositoryLocker returns an empty keyed publication locker.
func NewRepositoryLocker() *RepositoryLocker {
	return &RepositoryLocker{locks: make(map[string]*lockEntry)}
}

// WithLock runs fn while holding the lock for the canonical owner+repository
// key. Same-key callbacks never overlap; different keys run concurrently. A
// waiter honors ctx cancellation promptly and returns the ACTUAL request-context
// sentinel (context.Canceled / context.DeadlineExceeded). A panicking fn does
// not leak the lock or its entry, and the panic value/sentinel propagates
// unchanged. Entries are reference-counted and removed once the last holder and
// waiter for a key are gone, so the key map never grows unboundedly. Key inputs
// are canonicalized and hashed to a bounded token, so attacker-controlled or
// oversized repository strings can neither collide with unrelated keys nor
// appear in any error.
func (l *RepositoryLocker) WithLock(ctx context.Context, owner, repo string, fn func(context.Context) error) error {
	key := canonicalLockKey(owner, repo)
	ent := l.acquireEntry(key)
	// Decrement the reference and reclaim the entry once this user is done — on
	// every exit path, including a panicking callback.
	defer l.releaseEntry(key, ent)

	// Wait (context-aware) for the admission token. The go runtime wakes the
	// waiting receivers; a canceled context returns immediately.
	select {
	case <-ent.gate:
		// Became the holder: the token is now held, restore it on exit.
		defer func() { ent.gate <- struct{}{} }()
	case <-ctx.Done():
		return ctx.Err()
	}

	return fn(ctx)
}

func (l *RepositoryLocker) acquireEntry(key string) *lockEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	ent := l.locks[key]
	if ent == nil {
		ent = &lockEntry{gate: make(chan struct{}, 1)}
		ent.gate <- struct{}{} // a fresh key starts free
		l.locks[key] = ent
	}
	ent.refs++
	return ent
}

func (l *RepositoryLocker) releaseEntry(key string, ent *lockEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ent.refs--
	if ent.refs <= 0 {
		delete(l.locks, key)
	}
}

// canonicalLockKey maps an owner+repository pair to a bounded, collision-safe
// key token. The owner is normalized exactly like feed construction
// (spec.NormalizeOwner); both inputs are length-bounded before being
// length-prefixed into the hash, so no raw value can form a boundary collision
// or grow the key map, and no raw owner/repository text is ever retained or
// exposed.
func canonicalLockKey(owner, repo string) string {
	o := spec.NormalizeOwner(owner)
	if len(o) > 64 {
		o = o[:64]
	}
	r := repo
	if len(r) > 4096 {
		r = r[:4096]
	}
	h := sha256.New()
	h.Write([]byte("uncloud-repository-publication-lock:v1\x00"))
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(o)))
	h.Write(lb[:])
	h.Write([]byte(o))
	binary.BigEndian.PutUint32(lb[:], uint32(len(r)))
	h.Write(lb[:])
	h.Write([]byte(r))
	return hex.EncodeToString(h.Sum(nil))
}
