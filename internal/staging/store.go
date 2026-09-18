package staging

import (
	"context"
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
	ClearStagedBlobs(ctx context.Context, repo string, actor string) error
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
