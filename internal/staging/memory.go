package staging

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"sync"
	"time"

	"github.com/uncloud-registry/registry/internal/spec"
)

// MemoryStore is the in-memory dev/test implementation of the registry-facing
// RegistryStore contract. It is deliberately NOT durable and is used only by
// identity/memory wiring and tests; production Bee mode uses the durable
// Service. Its streaming append still obeys the bounded contract (no unbounded
// read by body size): exactly maxBytes bytes are read through a fixed buffer
// and a maxBytes+1 probe detects overflow, mirroring the durable copyBound.
type MemoryStore struct {
	mu       sync.Mutex
	sessions map[string]*memorySession
}

type memorySession struct {
	id, repo, actor string
	state           State
	offset          int64
	data            []byte
	digest          string
	beeRef          string
	mediaType       string
	size            int64
	createdAt       time.Time
	expiresAt       time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		sessions: map[string]*memorySession{},
	}
}

func (m *MemoryStore) Create(_ context.Context, repo string, actor string, ttl time.Duration) (Session, error) {
	if err := validateRepo(repo); err != nil {
		return Session{}, err
	}
	if err := validateActor(actor); err != nil {
		return Session{}, err
	}
	if ttl <= 0 {
		return Session{}, ErrInvalidInput
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return Session{}, ErrDependency
	}
	id := hex.EncodeToString(raw[:])
	now := time.Now().UTC()
	m.sessions[id] = &memorySession{
		id: id, repo: repo, actor: actor, state: StateActive,
		createdAt: now, expiresAt: now.Add(ttl),
	}
	return m.toSession(m.sessions[id]), nil
}

func (m *MemoryStore) Status(ctx context.Context, id, repo, actor string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.lookupUnlocked(id, repo, actor)
	if !ok {
		return Session{}, ErrNotFound
	}
	return m.toSession(s), nil
}

func (m *MemoryStore) Append(ctx context.Context, id, repo, actor string, expectedOffset int64, src io.Reader, maxBytes int64) (Session, error) {
	if err := validateID(id); err != nil {
		return Session{}, err
	}
	if err := validateRepo(repo); err != nil {
		return Session{}, err
	}
	if err := validateActor(actor); err != nil {
		return Session{}, err
	}
	if expectedOffset < 0 || maxBytes < 0 {
		return Session{}, ErrInvalidInput
	}
	if src == nil {
		return Session{}, ErrInvalidInput
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[id]
	if !ok {
		return Session{}, ErrNotFound
	}
	if s.repo != repo || s.actor != actor {
		return Session{}, ErrNotFound // confidential, never an existence oracle
	}
	if s.state == StateCreating {
		return Session{}, ErrNotFound
	}
	if !s.expiresAt.After(time.Now()) {
		return Session{}, ErrExpired
	}
	if s.state != StateActive {
		return Session{}, ErrInvalidState
	}
	if s.offset != expectedOffset {
		return Session{}, ErrOffsetMismatch
	}
	wrote, overflowing, err := copyBounded(&memoryWriter{s: s}, src, maxBytes, copyBufSize)
	if err != nil {
		return Session{}, ErrSourceRead
	}
	if overflowing {
		return Session{}, ErrTooLarge
	}
	s.offset += wrote
	return m.toSession(s), nil
}

// memoryWriter appends streamed bytes into a session's in-memory payload.
type memoryWriter struct{ s *memorySession }

func (w *memoryWriter) Write(p []byte) (int, error) {
	w.s.data = append(w.s.data, p...)
	return len(p), nil
}

func (m *MemoryStore) Open(ctx context.Context, id, repo, actor string) (io.ReadCloser, Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.lookupUnlocked(id, repo, actor)
	if !ok {
		return nil, Session{}, ErrNotFound
	}
	if s.state == StateCreating {
		return nil, Session{}, ErrNotFound
	}
	if !s.expiresAt.After(time.Now()) {
		return nil, Session{}, ErrExpired
	}
	if s.state != StateActive && s.state != StateFinalized {
		return nil, Session{}, ErrInvalidState
	}
	data := make([]byte, len(s.data))
	copy(data, s.data)
	return nopCloser{bytes.NewReader(data)}, m.toSession(s), nil
}

func (m *MemoryStore) MarkFinalized(_ context.Context, id, repo, actor, digest, beeRef, mediaType string, size int64) error {
	if err := validateID(id); err != nil {
		return err
	}
	if err := validateRepo(repo); err != nil {
		return err
	}
	if err := validateActor(actor); err != nil {
		return err
	}
	if err := validateDigest(digest); err != nil {
		return err
	}
	if beeRef == "" {
		// The dev/test memory store accepts the symbolic object-store refs
		// ("mem-ref-...") the in-memory object uploader returns; the DURABLE
		// service independently enforces the strict 64-hex bee-ref grammar.
		return ErrInvalidInput
	}
	if mediaType == "" {
		// Like the durable service's media-type grammar below an empty value
		// is invalid; a non-empty (possibly adversarial) value is RETAINED by
		// the dev store exactly as uploaded so publication-time media/descriptor
		// validation (the Task 14 no-echo invariant) can reject it with a 400.
		return ErrInvalidInput
	}
	if size < 0 {
		return ErrInvalidInput
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.lookupUnlocked(id, repo, actor)
	if !ok {
		return ErrNotFound
	}
	if !s.expiresAt.After(time.Now()) {
		return ErrExpired
	}
	switch s.state {
	case StateFinalized:
		if s.digest == digest && s.beeRef == beeRef && s.mediaType == mediaType && s.size == size {
			return nil // idempotent for byte-identical metadata
		}
		return ErrFinalizeConflict
	case StateActive:
		if size != s.offset {
			return ErrInvalidInput
		}
		s.digest, s.beeRef, s.mediaType, s.size = digest, beeRef, mediaType, size
		s.state = StateFinalized
		return nil
	default:
		return ErrInvalidState
	}
}

func (m *MemoryStore) Delete(_ context.Context, id, repo, actor string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return nil // idempotent
	}
	if s.repo != repo || s.actor != actor {
		return nil // confidential
	}
	delete(m.sessions, id)
	return nil
}

func (m *MemoryStore) ListStagedBlobs(ctx context.Context, repo string, actor string) ([]spec.StagedBlob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []spec.StagedBlob{}
	for _, s := range m.sessions {
		if s.state == StateFinalized && s.repo == repo && s.actor == actor {
			out = append(out, s.stagedBlob())
		}
	}
	return out, nil
}

func (m *MemoryStore) ClearStagedBlobsByDigest(ctx context.Context, repo string, actor string, digests []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	wanted := make(map[string]struct{}, len(digests))
	for _, d := range digests {
		wanted[d] = struct{}{}
	}
	for id, s := range m.sessions {
		if s.state == StateFinalized && s.repo == repo && s.actor == actor {
			if _, ok := wanted[s.digest]; ok {
				delete(m.sessions, id)
			}
		}
	}
	return nil
}

// lookupUnlocked returns the session only when it exists AND belongs to the
// repo/actor caller; any other outcome is absent (confidential).
func (m *MemoryStore) lookupUnlocked(id, repo, actor string) (*memorySession, bool) {
	s, ok := m.sessions[id]
	if !ok {
		return nil, false
	}
	if s.repo != repo || s.actor != actor || s.state == StateCreating {
		return nil, false
	}
	return s, true
}

func (m *MemoryStore) toSession(s *memorySession) Session {
	return Session{
		ID: s.id, Repo: s.repo, Actor: s.actor, State: s.state,
		Offset: s.offset, Digest: s.digest, BeeRef: s.beeRef,
		MediaType: s.mediaType, Size: s.size, CreatedAt: s.createdAt, ExpiresAt: s.expiresAt,
	}
}

func (s *memorySession) stagedBlob() spec.StagedBlob {
	return spec.StagedBlob{
		UploadID: s.id, Repo: s.repo, Actor: s.actor, Digest: s.digest,
		SwarmRef: s.beeRef, Size: s.size, MediaType: s.mediaType,
		CreatedAt: s.createdAt.UTC().Format(time.RFC3339),
		ExpiresAt: s.expiresAt.UTC().Format(time.RFC3339),
	}
}

// nopCloser adapts a reader into an io.ReadCloser whose Close is a no-op.
type nopCloser struct{ io.Reader }

func (nopCloser) Close() error { return nil }

var _ RegistryStore = (*MemoryStore)(nil)
