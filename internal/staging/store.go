package staging

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/uncloud-registry/registry/internal/spec"
)

type Store interface {
	CreateSession(ctx context.Context, repo string, actor string, ttl time.Duration) (spec.UploadSession, error)
	GetSession(ctx context.Context, uploadID string) (spec.UploadSession, bool, error)
	Append(ctx context.Context, uploadID string, chunk []byte) (spec.UploadSession, error)
	Bytes(ctx context.Context, uploadID string) ([]byte, error)
	DeleteSession(ctx context.Context, uploadID string) error
	StageBlob(ctx context.Context, blob spec.StagedBlob) error
	GetStagedBlob(ctx context.Context, uploadID string) (spec.StagedBlob, bool, error)
	ListStagedBlobs(ctx context.Context, repo string, actor string) ([]spec.StagedBlob, error)
	// ClearStagedBlobs removes every staged entry for the repo/actor pair.
	ClearStagedBlobs(ctx context.Context, repo string, actor string) error
	// ClearStagedBlobsByDigest removes ONLY the staged entries whose digests
	// are in digests for the repo/actor pair; unrelated staged blobs are
	// retained. Clearing an unknown digest is a no-op. This is the
	// referenced-only consumption primitive: after a successful publication,
	// exactly the digests the published manifest referenced are consumed while
	// unrelated staged blobs survive for a later manifest.
	ClearStagedBlobsByDigest(ctx context.Context, repo string, actor string, digests []string) error
}

type MemoryStore struct {
	mu       sync.Mutex
	nextID   int64
	sessions map[string]memorySession
	staged   map[string]spec.StagedBlob
}

type memorySession struct {
	spec.UploadSession
	data []byte
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		nextID:   1,
		sessions: map[string]memorySession{},
		staged:   map[string]spec.StagedBlob{},
	}
}

func (m *MemoryStore) CreateSession(_ context.Context, repo string, actor string, ttl time.Duration) (spec.UploadSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	id := fmt.Sprintf("upload-%d", m.nextID)
	m.nextID++

	session := spec.UploadSession{
		ID:        id,
		Repo:      repo,
		Actor:     actor,
		Offset:    0,
		CreatedAt: now.Format(time.RFC3339),
		ExpiresAt: now.Add(ttl).Format(time.RFC3339),
	}
	m.sessions[id] = memorySession{UploadSession: session, data: nil}
	return session, nil
}

func (m *MemoryStore) GetSession(_ context.Context, uploadID string) (spec.UploadSession, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[uploadID]
	if !ok {
		return spec.UploadSession{}, false, nil
	}
	return session.UploadSession, true, nil
}

func (m *MemoryStore) Append(_ context.Context, uploadID string, chunk []byte) (spec.UploadSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[uploadID]
	if !ok {
		return spec.UploadSession{}, fmt.Errorf("upload session %q not found", uploadID)
	}

	session.data = append(session.data, chunk...)
	session.Offset = int64(len(session.data))
	m.sessions[uploadID] = session
	return session.UploadSession, nil
}

func (m *MemoryStore) Bytes(_ context.Context, uploadID string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[uploadID]
	if !ok {
		return nil, fmt.Errorf("upload session %q not found", uploadID)
	}

	out := make([]byte, len(session.data))
	copy(out, session.data)
	return out, nil
}

func (m *MemoryStore) DeleteSession(_ context.Context, uploadID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.sessions, uploadID)
	return nil
}

func (m *MemoryStore) StageBlob(_ context.Context, blob spec.StagedBlob) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.staged[blob.UploadID] = blob
	return nil
}

func (m *MemoryStore) GetStagedBlob(_ context.Context, uploadID string) (spec.StagedBlob, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	blob, ok := m.staged[uploadID]
	if !ok {
		return spec.StagedBlob{}, false, nil
	}
	return blob, true, nil
}

func (m *MemoryStore) ListStagedBlobs(_ context.Context, repo string, actor string) ([]spec.StagedBlob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	blobs := make([]spec.StagedBlob, 0)
	for _, blob := range m.staged {
		if blob.Repo == repo && blob.Actor == actor {
			blobs = append(blobs, blob)
		}
	}
	return blobs, nil
}

func (m *MemoryStore) ClearStagedBlobs(_ context.Context, repo string, actor string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for uploadID, blob := range m.staged {
		if blob.Repo == repo && blob.Actor == actor {
			delete(m.staged, uploadID)
		}
	}
	return nil
}

// ClearStagedBlobsByDigest removes only the staged entries whose digest is in
// digests for the given repo/actor pair, leaving every unrelated staged entry
// in place. Unknown digests are ignored.
func (m *MemoryStore) ClearStagedBlobsByDigest(_ context.Context, repo string, actor string, digests []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	wanted := make(map[string]struct{}, len(digests))
	for _, digest := range digests {
		wanted[digest] = struct{}{}
	}
	for uploadID, blob := range m.staged {
		if blob.Repo == repo && blob.Actor == actor {
			if _, ok := wanted[blob.Digest]; ok {
				delete(m.staged, uploadID)
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Durable staging service: shared types, sentinel errors, and validators.
//
// These definitions are shared by the durable Service (Task 15) and are kept
// compatible with the in-memory Store above: nothing here changes the Store
// contract used by Tasks 1-14 callers.
// ---------------------------------------------------------------------------

// State is the durable session lifecycle state persisted in SQLite.
type State string

const (
	// StateActive accepts streaming appends.
	StateActive State = "active"
	// StateFinalized carries complete validated blob metadata; appends are
	// rejected and the file bytes are frozen.
	StateFinalized State = "finalized"
	// StateDeleting is a durable tombstone set before a session's file is
	// removed, so an interrupted deletion is completed by a later delete or by
	// startup reconciliation instead of stranding an unknown file.
	StateDeleting State = "deleting"
)

// Session is the durable upload-session snapshot returned by Service
// methods. Timestamps are native time.Time values derived from signed Unix
// nanoseconds persisted in SQLite.
type Session struct {
	ID        string
	Repo      string
	Actor     string
	State     State
	Offset    int64
	Size      int64
	Digest    string
	BeeRef    string
	MediaType string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Sentinel errors. Every sentinel has fixed, data-free text: no root or
// database paths, no DSNs, no session IDs / repo / actor / digest / ref
// values, no SQL, and no raw dependency detail ever appear in Error() output
// or in any exported accessor.
var (
	// ErrNotFound reports that no session exists for the caller. It is also
	// the observable surface for owner/repo mismatch, so a caller can never
	// distinguish "no such upload" from "exists but not yours".
	ErrNotFound = errors.New("staging upload not found")
	// ErrOwnerMismatch is the typed identity of the not-found family for
	// sessions that exist but belong to another repo/actor. errors.Is(err,
	// ErrNotFound) is true for it, and its text is identical, preserving
	// existence confidentiality.
	ErrOwnerMismatch error = ownerMismatchError{}
	// ErrExpired reports a session whose canonical expiry has passed.
	ErrExpired = errors.New("staging upload expired")
	// ErrOffsetMismatch reports an append whose expected offset does not
	// equal the durable committed offset.
	ErrOffsetMismatch = errors.New("staging upload offset mismatch")
	// ErrInvalidInput reports a caller-supplied value that fails the bounded
	// canonical grammar (ID, repo, actor, digest, Bee ref, media type, TTL,
	// or size), or an impossible arithmetic request.
	ErrInvalidInput = errors.New("staging invalid input")
	// ErrInvalidState reports an operation impossible in the session's
	// current lifecycle state.
	ErrInvalidState = errors.New("staging invalid upload state")
	// ErrTooLarge reports an append that would exceed the caller's maximum
	// byte bound or overflow the durable offset.
	ErrTooLarge = errors.New("staging upload exceeds maximum size")
	// ErrDependency reports a filesystem or database failure. The raw cause
	// is retained privately for server-side diagnosis and never surfaces.
	ErrDependency = errors.New("staging backend unavailable")
	// ErrSourceRead reports a failure of the caller-supplied reader during a
	// streaming append; no partial bytes are ever accepted.
	ErrSourceRead = errors.New("staging source read failed")
	// ErrFinalizeConflict reports a second finalization whose metadata
	// differs from the already-finalized row.
	ErrFinalizeConflict = errors.New("staging upload already finalized with different metadata")
)

// ownerMismatchError is the not-found family identity for existing-but-foreign
// sessions. It reports the same fixed text as ErrNotFound so existence is
// never revealed, while errors.Is can still distinguish the class internally.
type ownerMismatchError struct{}

func (ownerMismatchError) Error() string { return ErrNotFound.Error() }

func (ownerMismatchError) Is(target error) bool {
	return target == ErrNotFound || target == ErrOwnerMismatch
}

// typedError carries a fixed-text sentinel and a private cause. Error() and
// Unwrap() expose only the sentinel; the cause is available to package
// internals via causeOf for server-side diagnosis.
type typedError struct {
	sentinel error
	cause    error
}

func (e *typedError) Error() string { return e.sentinel.Error() }

func (e *typedError) Unwrap() error { return e.sentinel }

func typed(sentinel, cause error) error {
	if cause == nil {
		return sentinel
	}
	return &typedError{sentinel: sentinel, cause: cause}
}

func causeOf(err error) error {
	var te *typedError
	if errors.As(err, &te) {
		return te.cause
	}
	return nil
}

// copyBufSize is the fixed streaming-copy buffer used by Append. Bounded
// memory by construction: no production read path allocates by body size.
const copyBufSize = 32 * 1024

// validID reports whether id is a canonical unpredictable server-side
// identifier: exactly 64 lowercase ASCII hex characters (32 bytes of
// crypto/rand), containing no separators, dots, NUL, Unicode, or alternate
// separators. This is the ONLY form ever accepted; any caller-supplied
// deviation is rejected before database or filesystem access.
func validateID(id string) error {
	return validateHex(id, 64)
}

func validateHex(s string, n int) error {
	if len(s) != n {
		return ErrInvalidInput
	}
	for i := 0; i < n; i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return ErrInvalidInput
		}
	}
	return nil
}

// validateRepo enforces the bounded canonical repository grammar: lowercase
// ASCII alphanumerics, dots, underscores, and hyphens separated by single
// slashes; no empty or dot segments (so no ".."), no "//", no leading or
// trailing slash; at most 200 bytes.
func validateRepo(repo string) error {
	if len(repo) == 0 || len(repo) > 200 {
		return ErrInvalidInput
	}
	segStart := true
	for i := 0; i < len(repo); i++ {
		c := repo[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			segStart = false
		case c == '.':
			if segStart || (i > 0 && repo[i-1] == '.') {
				return ErrInvalidInput
			}
		case c == '_' || c == '-':
			if segStart {
				return ErrInvalidInput
			}
		case c == '/':
			if segStart {
				return ErrInvalidInput
			}
			segStart = true
		default:
			return ErrInvalidInput
		}
	}
	if segStart {
		return ErrInvalidInput
	}
	return nil
}

// validateActor enforces the bounded canonical actor grammar: an ASCII
// alphanumeric first character, then ASCII alphanumerics plus ':', '_', '@',
// '.', '-'; no separators or dot-only segments; at most 200 bytes.
func validateActor(actor string) error {
	if len(actor) == 0 || len(actor) > 200 {
		return ErrInvalidInput
	}
	if !isAlnum(actor[0]) {
		return ErrInvalidInput
	}
	for i := 0; i < len(actor); i++ {
		c := actor[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == ':' || c == '_' || c == '@' || c == '.' || c == '-':
		default:
			return ErrInvalidInput
		}
	}
	return nil
}

func isAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// validateDigest enforces the canonical sha256 digest grammar:
// "sha256:" followed by exactly 64 lowercase hex bytes.
func validateDigest(digest string) error {
	if len(digest) != len("sha256:")+64 || digest[:7] != "sha256:" {
		return ErrInvalidInput
	}
	return validateHex(digest[7:], 64)
}

// validateBeeRef enforces the canonical Bee reference grammar: exactly 64
// lowercase hex bytes (a 32-byte swarm reference).
func validateBeeRef(ref string) error {
	return validateHex(ref, 64)
}

// validateMediaType enforces the bounded canonical media-type grammar used
// for finalized blobs: lowercase ASCII alphanumerics, '.', '+', '-', '_',
// '/' separators; at most 200 bytes.
func validateMediaType(media string) error {
	if len(media) == 0 || len(media) > 200 {
		return ErrInvalidInput
	}
	for i := 0; i < len(media); i++ {
		c := media[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '.' || c == '+' || c == '-' || c == '_' || c == '/':
		default:
			return ErrInvalidInput
		}
	}
	return nil
}
