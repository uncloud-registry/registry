package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/uncloud-registry/registry/internal/spec"
	"github.com/uncloud-registry/registry/internal/swarm"
)

// RegistryFeedUpdater writes a registry policy/repo feed update. batchID is
// the exact Bee postage batch to stamp the update with; it is carried
// unchanged into the swarm updater so the signer never substitutes the content
// reference as the postage batch.
type RegistryFeedUpdater interface {
	UpdateRegistryFeed(ctx context.Context, registry Registry, feed string, ref string, batchID string) error
}

type MembershipSubject struct {
	UserID  int64
	Role    string
	CanPull bool
	CanPush bool
}

type BootstrapPublication struct {
	FeedOwnerAddress string `json:"feedOwnerAddress"`
	AuthPolicyFeed   string `json:"authPolicyFeed"`
	StampPolicyFeed  string `json:"stampPolicyFeed"`
}

type Publisher struct {
	// Documents is the writable/readable object store: Put uploads a policy
	// document and returns its content address; Get reads a content address
	// back so the reconciler can prove read-back. The same store must serve
	// both, so an outbox worker that uploaded a document can later read it.
	Documents ObjectStore
	// Feeds writes a policy feed update pointing at an uploaded document.
	Feeds RegistryFeedUpdater
	// FeedsReader independently resolves a policy feed to the ref currently
	// stored at it, so the reconciler can verify the feed really points at
	// the uploaded object before marking a job verified. Without it,
	// CreateRegistry fails closed (a no-op/wrong/overwritten feed updater
	// must never complete a job).
	FeedsReader FeedResolver
}

// MemoryRegistryFeedStore is the combined in-memory feed updater + resolver
// used by tests. Its single map holds feed->ref exactly as written, so
// reconciliation resolves the SAME state the updater wrote. Tests may also
// mutate Feeds directly to simulate an independent/overwritten feed mapping
// (a mis-directed feed) and prove the reconciler refuses to complete a job
// whose resolved ref does not equal the uploaded object ref. Batches records
// the exact batchID each feed was updated with, so tests can assert the
// signer's batch propagation precisely.
type MemoryRegistryFeedStore struct {
	Feeds   map[string]string
	Batches map[string]string
	mu      sync.Mutex
}

func (m *MemoryRegistryFeedStore) UpdateRegistryFeed(_ context.Context, _ Registry, feed string, ref string, batchID string) error {
	if m == nil {
		return errors.New("feed store is not configured")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Feeds == nil {
		m.Feeds = map[string]string{}
	}
	if m.Batches == nil {
		m.Batches = map[string]string{}
	}
	m.Feeds[feed] = ref
	m.Batches[feed] = batchID
	return nil
}

func (m *MemoryRegistryFeedStore) ResolveFeed(_ context.Context, feed string) (string, error) {
	if m == nil {
		return "", errors.New("feed store is not configured")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ref, ok := m.Feeds[feed]
	if !ok {
		return "", fmt.Errorf("feed %q not found", feed)
	}
	return ref, nil
}

func (p Publisher) PublishBootstrap(ctx context.Context, registry Registry, memberships []MembershipSubject) (BootstrapPublication, error) {
	authFeed := authPolicyFeedRef(registry)
	stampFeed := stampPolicyFeedRef(registry)

	if _, err := p.publishAuthPolicy(ctx, registry, memberships); err != nil {
		return BootstrapPublication{}, err
	}
	if _, err := p.publishStampPolicy(ctx, registry, memberships); err != nil {
		return BootstrapPublication{}, err
	}

	return BootstrapPublication{
		FeedOwnerAddress: registry.FeedOwnerAddress,
		AuthPolicyFeed:   authFeed,
		StampPolicyFeed:  stampFeed,
	}, nil
}

func (p Publisher) PublishAuthPolicy(ctx context.Context, registry Registry, memberships []MembershipSubject) (string, error) {
	return p.publishAuthPolicy(ctx, registry, memberships)
}

func (p Publisher) PublishStampPolicy(ctx context.Context, registry Registry, memberships []MembershipSubject) (string, error) {
	return p.publishStampPolicy(ctx, registry, memberships)
}

func (p Publisher) PublishRawAuthPolicy(ctx context.Context, registry Registry, doc spec.AuthPolicyDocument) (string, error) {
	data, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("marshal auth policy document: %w", err)
	}
	ref, err := p.Documents.Put(ctx, data, registry.DefaultStampBatchID)
	if err != nil {
		return "", fmt.Errorf("upload auth policy document: %w", err)
	}
	feed := authPolicyFeedRef(registry)
	if err := p.Feeds.UpdateRegistryFeed(ctx, registry, feed, ref, registry.DefaultStampBatchID); err != nil {
		return "", fmt.Errorf("update auth policy feed: %w", err)
	}
	return feed, nil
}

func (p Publisher) PublishRawStampPolicy(ctx context.Context, registry Registry, doc spec.StampPolicyDocument) (string, error) {
	data, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("marshal stamp policy document: %w", err)
	}
	ref, err := p.Documents.Put(ctx, data, registry.DefaultStampBatchID)
	if err != nil {
		return "", fmt.Errorf("upload stamp policy document: %w", err)
	}
	feed := stampPolicyFeedRef(registry)
	if err := p.Feeds.UpdateRegistryFeed(ctx, registry, feed, ref, registry.DefaultStampBatchID); err != nil {
		return "", fmt.Errorf("update stamp policy feed: %w", err)
	}
	return feed, nil
}

func (p Publisher) publishAuthPolicy(ctx context.Context, registry Registry, memberships []MembershipSubject) (string, error) {
	pushActors := []string{"role:write"}
	pullActors := []string{"role:read", "role:write"}
	if registry.AnonymousPull {
		pullActors = append([]string{"anonymous"}, pullActors...)
	}

	doc := spec.AuthPolicyDocument{
		Version:       1,
		DefaultAccess: "deny",
		DefaultRepo: &spec.RepoAuthPolicyEntry{
			Pull: pullActors,
			Push: pushActors,
		},
		Repos: map[string]spec.RepoAuthPolicyEntry{},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("marshal auth policy document: %w", err)
	}
	ref, err := p.Documents.Put(ctx, data, registry.DefaultStampBatchID)
	if err != nil {
		return "", fmt.Errorf("upload auth policy document: %w", err)
	}
	feed := authPolicyFeedRef(registry)
	if err := p.Feeds.UpdateRegistryFeed(ctx, registry, feed, ref, registry.DefaultStampBatchID); err != nil {
		return "", fmt.Errorf("update auth policy feed: %w", err)
	}
	return feed, nil
}

func (p Publisher) publishStampPolicy(ctx context.Context, registry Registry, memberships []MembershipSubject) (string, error) {
	doc := spec.StampPolicyDocument{
		Version: 1,
		DefaultPolicy: spec.StampAccessPolicy{
			BatchID:      registry.DefaultStampBatchID,
			AllowPushFor: []string{"role:write"},
		},
		Repos: map[string]spec.StampAccessPolicy{},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("marshal stamp policy document: %w", err)
	}
	ref, err := p.Documents.Put(ctx, data, registry.DefaultStampBatchID)
	if err != nil {
		return "", fmt.Errorf("upload stamp policy document: %w", err)
	}
	feed := stampPolicyFeedRef(registry)
	if err := p.Feeds.UpdateRegistryFeed(ctx, registry, feed, ref, registry.DefaultStampBatchID); err != nil {
		return "", fmt.Errorf("update stamp policy feed: %w", err)
	}
	return feed, nil
}

func authPolicyFeedRef(registry Registry) string {
	return spec.AuthPolicyFeedRef(registry.FeedOwnerAddress)
}

func stampPolicyFeedRef(registry Registry) string {
	return spec.StampPolicyFeedRef(registry.FeedOwnerAddress)
}

type MemoryRegistryFeedUpdater struct {
	Feeds map[string]string
}

func (m *MemoryRegistryFeedUpdater) UpdateRegistryFeed(_ context.Context, _ Registry, feed string, ref string, _ string) error {
	m.Feeds[feed] = ref
	return nil
}

// FeedKeyDecryptor resolves the transient decrypted feed-owner signing key for
// a registry. It is the boundary between at-rest encryption and the signer:
// stored ciphertext must never be handed to a signer, and decrypted key
// material must never be persisted, logged, or stringified. The decrypted
// bytes are owned by the operation and handed to fn for the immediate signing
// call only; the implementer wipes them after fn returns. Service implements
// it via Service.WithDecryptedFeedKey; the constrained signing consumer
// (Task 9/10) builds on the same contract.
type FeedKeyDecryptor interface {
	WithDecryptedFeedKey(ctx context.Context, registryID int64, fn func([]byte) error) error
}

// BeeRegistryFeedUpdater signs sequence-feed updates with the registry's
// feed-owner key. The key is obtained ONLY through a FeedKeyDecryptor — never
// from storage directly and never by stringifying decrypted bytes; without
// one configured, updates fail closed rather than handing stored ciphertext
// to the signer. The signer is constructed from the raw key bytes inside the
// callback, so the plaintext is wiped as soon as the signing call returns.
type BeeRegistryFeedUpdater struct {
	BaseURL    string
	HTTPClient *http.Client
	Keys       FeedKeyDecryptor
}

func (b BeeRegistryFeedUpdater) UpdateRegistryFeed(ctx context.Context, registry Registry, feed string, ref string, batchID string) error {
	if b.Keys == nil {
		return errors.New("registry feed key decryptor is not configured; refusing to sign feed updates with stored ciphertext")
	}
	return b.Keys.WithDecryptedFeedKey(ctx, registry.ID, func(key []byte) error {
		updater, err := swarm.NewBeeSequenceFeedUpdaterBytes(b.BaseURL, b.HTTPClient, key)
		if err != nil {
			return err
		}
		// The explicit postage batch flows through unchanged; the updater
		// validates feed/owner/reference/batch strictly BEFORE any network
		// call and never substitutes the content reference as the batch.
		return updater.Update(ctx, swarm.FeedUpdate{
			Feed:      feed,
			Reference: ref,
			BatchID:   batchID,
		})
	})
}
