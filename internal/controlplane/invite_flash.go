package controlplane

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

const (
	// inviteFlashTTL bounds how long an unused one-time invite flash lives. It only
	// needs to survive the browser following the creation redirect; a short TTL
	// minimises the window an un-consumed raw token sits in memory.
	inviteFlashTTL = 10 * time.Minute

	// inviteFlashMax is a conservative cap on concurrently stored flashes so
	// unauthenticated-influenced traffic cannot grow server memory without bound.
	// store() fails safely once this many live entries exist.
	inviteFlashMax = 1024

	// errInviteFlashFull is returned when the flash store is at capacity.
)

type inviteFlash struct {
	token      string
	userID     int64
	registryID int64
	expiresAt  time.Time
}

// inviteFlashStore is a small private, mutex-protected, in-memory one-time store
// that carries a raw invite token from the invite-creation POST (which must not
// expose the token in a redirect URL) to the very next GET of the registry-detail
// page. Each entry is bound to the authenticated creator userID and registryID and
// is consumed atomically (deleted before the token is returned) so a replayed or
// concurrent read can never retrieve it twice. The raw token is never written to a
// URL, a cookie, a log, or an error.
type inviteFlashStore struct {
	mu      sync.Mutex
	now     func() time.Time // injectable clock for tests
	entries map[string]inviteFlash
}

func newInviteFlashStore() *inviteFlashStore {
	return &inviteFlashStore{
		now:     time.Now,
		entries: make(map[string]inviteFlash),
	}
}

// randomFlashID returns a cryptographically random opaque flash ID. It carries no
// invite data and is unguessable.
func randomFlashID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// store records the raw token bound to userID+registryID and returns a fresh random
// flash ID. It prunes expired entries and refuses to grow past inviteFlashMax.
func (s *inviteFlashStore) store(token string, userID, registryID int64) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	if len(s.entries) >= inviteFlashMax {
		return "", &flashStoreFullError{}
	}
	id, err := randomFlashID()
	if err != nil {
		return "", err
	}
	s.entries[id] = inviteFlash{
		token:      token,
		userID:     userID,
		registryID: registryID,
		expiresAt:  s.now().Add(inviteFlashTTL),
	}
	return id, nil
}

// consume returns the raw token exactly once. For unknown, expired, wrong-user, or
// wrong-registry flash IDs it returns nothing. Adaptive security: a wrong principal
// must not be able to prevent the intended owner's consumption, so the entry is only
// deleted for the matching owner; the raw token (if any) is deleted before it is
// returned, making concurrent or replayed reads single-shot.
func (s *inviteFlashStore) consume(id string, userID, registryID int64) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	e, ok := s.entries[id]
	if !ok || s.now().After(e.expiresAt) {
		return "", false
	}
	if e.userID != userID || e.registryID != registryID {
		// Reveal nothing and do NOT consume a flash owned by someone else: the owner
		// must still be able to consume it.
		return "", false
	}
	delete(s.entries, id)
	return e.token, true
}

// pruneLocked removes expired entries. Callers must hold s.mu.
func (s *inviteFlashStore) pruneLocked() {
	now := s.now()
	for id, e := range s.entries {
		if now.After(e.expiresAt) {
			delete(s.entries, id)
		}
	}
}

// flashStoreFullError reports that the one-time flash store is at capacity. It is
// logged/returned without any invite data.
type flashStoreFullError struct{}

func (e *flashStoreFullError) Error() string { return "invite flash store full" }