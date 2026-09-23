package resolve

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/uncloud-registry/registry/internal/spec"
)

// ErrFeedNotFound is the conclusive not-found outcome for a repository/policy
// feed that has never been written. Feed resolvers wrap this sentinel; callers
// use errors.Is to distinguish a definitively absent feed from a resolver
// failure (network, timeout, decode, malformed), and only treat the wrapped
// outcome as generation zero.
var ErrFeedNotFound = errors.New("feed not found")

// ErrDocumentNotFound is the conclusive not-found outcome for an immutable
// object/document read (a definitive HTTP 404 on a Bee read). It lets the
// optional resolver distinguish "the repository feed payload has never been
// written" from corruption or transport failures when a feed reference maps to
// itself and the document reader performs the actual feed read.
var ErrDocumentNotFound = errors.New("document not found")

type RegistryIdentity struct {
	Host string
	// Owner is the registry's feed-owner address as configured on the control
	// plane, used to derive its deterministic feeds.
	Owner string
	// RegistryID is the unambiguous control-plane registry identifier for the
	// host, so the data plane can route an internal feed commit to the exact
	// registry. It is 0 when the resolver does not carry an explicit ID — an
	// in-memory/dev identity — in which case authenticated control-plane feed
	// commits (which require a positive RegistryID) fail closed rather than
	// silently assigning an ID.
	RegistryID int64
}

type Reader interface {
	Read(ctx context.Context, ref string) ([]byte, error)
}

type RegistryIdentityResolver interface {
	ResolveRegistry(ctx context.Context, host string) (RegistryIdentity, error)
}

type FeedResolver interface {
	ResolveFeed(ctx context.Context, feed string) (string, error)
}

type RegistryResolver struct {
	Registries RegistryIdentityResolver
	Docs       Reader
	Feeds      FeedResolver
}

func (r RegistryResolver) ResolveRegistry(ctx context.Context, host string) (RegistryIdentity, error) {
	registry, err := r.Registries.ResolveRegistry(ctx, host)
	if err != nil {
		return RegistryIdentity{}, fmt.Errorf("resolve registry identity: %w", err)
	}
	return registry, nil
}

func (r RegistryResolver) ResolveRepoState(ctx context.Context, registry RegistryIdentity, repo string) (spec.RepoStateDocument, error) {
	stateRef, err := r.Feeds.ResolveFeed(ctx, spec.RepoStateFeedRef(registry.Owner, repo))
	if err != nil {
		return spec.RepoStateDocument{}, fmt.Errorf("resolve repo state feed: %w", err)
	}

	data, err := r.Docs.Read(ctx, stateRef)
	if err != nil {
		return spec.RepoStateDocument{}, fmt.Errorf("read repo state document: %w", err)
	}

	doc, err := spec.DecodeRepoStateDocument(data)
	if err != nil {
		return spec.RepoStateDocument{}, err
	}
	if doc.Repo != repo {
		return spec.RepoStateDocument{}, fmt.Errorf("repo state document repo mismatch: got %q want %q", doc.Repo, repo)
	}

	return doc, nil
}

// ResolveRepoStateOptional is the SAFE first-publication variant of
// ResolveRepoState: it resolves the current repo state but treats a
// CONCLUSIVELY ABSENT repository feed (never written) as (zero state,
// found=false, nil) instead of an error. Every other failure — feed
// resolution network/timeout, document read/decode, integrity, repo
// mismatch — stays a wrapped error. It never synthesizes or writes state, so
// callers can run it on every authorized manifest PUT and only create
// generation zero when found=false. A feed that RESOLVES but points at a
// missing or malformed document is corruption and remains an error; only a
// missing feed (or a feed:// reference whose payload read definitively 404s,
// the Bee-mode wiring) counts as absent.
func (r RegistryResolver) ResolveRepoStateOptional(ctx context.Context, registry RegistryIdentity, repo string) (spec.RepoStateDocument, bool, error) {
	stateRef, err := r.Feeds.ResolveFeed(ctx, spec.RepoStateFeedRef(registry.Owner, repo))
	if err != nil {
		if errors.Is(err, ErrFeedNotFound) {
			return spec.RepoStateDocument{}, false, nil
		}
		return spec.RepoStateDocument{}, false, fmt.Errorf("resolve repo state feed: %w", err)
	}

	data, err := r.Docs.Read(ctx, stateRef)
	if err != nil {
		// A feed:// reference IS the repository feed itself (Bee mode maps the
		// repo feed to itself and reads its payload through the document
		// reader), so a definitive not-found on that read is the same
		// conclusively-missing-feed outcome. A plain content reference that
		// 404s is corruption.
		if strings.HasPrefix(stateRef, "feed://") && errors.Is(err, ErrDocumentNotFound) {
			return spec.RepoStateDocument{}, false, nil
		}
		return spec.RepoStateDocument{}, false, fmt.Errorf("read repo state document: %w", err)
	}

	doc, err := spec.DecodeRepoStateDocument(data)
	if err != nil {
		return spec.RepoStateDocument{}, false, err
	}
	if doc.Repo != repo {
		return spec.RepoStateDocument{}, false, fmt.Errorf("repo state document repo mismatch: got %q want %q", doc.Repo, repo)
	}
	return doc, true, nil
}

type StaticRegistryIdentityResolver struct {
	Hosts map[string]RegistryIdentity
}

func (s StaticRegistryIdentityResolver) ResolveRegistry(_ context.Context, host string) (RegistryIdentity, error) {
	ref, ok := s.Hosts[host]
	if !ok {
		return RegistryIdentity{}, fmt.Errorf("host %q not found", host)
	}
	return ref, nil
}

type MemoryReader struct {
	Documents map[string][]byte
}

func (m MemoryReader) Read(_ context.Context, ref string) ([]byte, error) {
	data, ok := m.Documents[ref]
	if !ok {
		return nil, fmt.Errorf("document %q not found: %w", ref, ErrDocumentNotFound)
	}
	out := make([]byte, len(data))
	copy(out, data)
	return out, nil
}

func (m MemoryReader) Get(ctx context.Context, ref string) ([]byte, error) {
	return m.Read(ctx, ref)
}

type StaticFeedResolver struct {
	Feeds map[string]string
}

func (s StaticFeedResolver) ResolveFeed(_ context.Context, feed string) (string, error) {
	ref, ok := s.Feeds[feed]
	if !ok {
		return "", fmt.Errorf("feed %q not found: %w", feed, ErrFeedNotFound)
	}
	return ref, nil
}

type MemoryDocumentStore struct {
	mu        sync.RWMutex
	nextID    int64
	Documents map[string][]byte
}

func NewMemoryDocumentStore() *MemoryDocumentStore {
	return &MemoryDocumentStore{
		nextID:    1,
		Documents: map[string][]byte{},
	}
}

func (m *MemoryDocumentStore) Read(_ context.Context, ref string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	data, ok := m.Documents[ref]
	if !ok {
		return nil, fmt.Errorf("document %q not found: %w", ref, ErrDocumentNotFound)
	}
	out := make([]byte, len(data))
	copy(out, data)
	return out, nil
}

func (m *MemoryDocumentStore) Get(ctx context.Context, ref string) ([]byte, error) {
	return m.Read(ctx, ref)
}

func (m *MemoryDocumentStore) Put(_ context.Context, data []byte, _ string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	ref := fmt.Sprintf("mem-ref-%d", m.nextID)
	m.nextID++
	out := make([]byte, len(data))
	copy(out, data)
	m.Documents[ref] = out
	return ref, nil
}

type MemoryFeedStore struct {
	mu    sync.RWMutex
	Feeds map[string]string
}

func NewMemoryFeedStore() *MemoryFeedStore {
	return &MemoryFeedStore{Feeds: map[string]string{}}
}

func (m *MemoryFeedStore) ResolveFeed(_ context.Context, feed string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ref, ok := m.Feeds[feed]
	if !ok {
		return "", fmt.Errorf("feed %q not found: %w", feed, ErrFeedNotFound)
	}
	return ref, nil
}

func (m *MemoryFeedStore) UpdateFeed(_ context.Context, feed string, ref string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Feeds[feed] = ref
	return nil
}
