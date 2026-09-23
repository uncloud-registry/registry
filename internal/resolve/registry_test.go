package resolve

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/uncloud-registry/registry/internal/spec"
)

// repoStateDoc is a minimal valid repo-state document for resolution tests.
func repoStateDoc(t *testing.T, repo string, generation int64) []byte {
	t.Helper()
	return []byte(`{
		"version":1,
		"repo":"` + repo + `",
		"generation":` + fmt.Sprintf("%d", generation) + `,
		"updatedAt":"2026-04-05T12:00:00Z",
		"tags":{"latest":"sha256:manifest1"},
		"manifests":{"sha256:manifest1":{"swarmRef":"manifest-ref","mediaType":"application/vnd.oci.image.manifest.v1+json","size":19}},
		"blobs":{"sha256:blob1":{"swarmRef":"blob-ref","size":10,"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip"}}
	}`)
}

// failingFeedResolver returns a fixed error from ResolveFeed (e.g. a
// Bee/network/timeout failure that is NOT a not-found outcome).
type failingFeedResolver struct{ err error }

func (f failingFeedResolver) ResolveFeed(_ context.Context, _ string) (string, error) {
	return "", f.err
}

// identityFeedResolver maps a feed reference to itself, exactly like the
// Bee-mode registry wiring where the repo-state feed payload is read directly
// through the document reader (a definitive 404 on that read is the
// conclusively-missing-feed outcome).
type identityFeedResolver struct{}

func (identityFeedResolver) ResolveFeed(_ context.Context, feed string) (string, error) {
	return feed, nil
}

// failingDocReader returns a fixed error from Read (a network/timeout/decode
// failure on the referenced document).
type failingDocReader struct{ err error }

func (f failingDocReader) Read(_ context.Context, _ string) ([]byte, error) {
	return nil, f.err
}

// TestResolveRepoStateOptional proves the optional resolver returns a found
// state for a present feed, (zero,false,nil) ONLY for a conclusively missing
// repository feed, and an error for every other failure (feed resolution
// network/timeout, document read, decode, repo mismatch).
func TestResolveRepoStateOptional(t *testing.T) {
	t.Parallel()

	const owner = "0xaliceowner"
	const repo = "backend/api"
	feed := spec.RepoStateFeedRef(owner, repo)

	t.Run("present-feed-returns-state", func(t *testing.T) {
		docs := NewMemoryDocumentStore()
		docs.Documents["repo-state-ref"] = repoStateDoc(t, repo, 3)
		feeds := NewMemoryFeedStore()
		feeds.Feeds[feed] = "repo-state-ref"

		r := RegistryResolver{Registries: StaticRegistryIdentityResolver{}, Docs: docs, Feeds: feeds}
		state, found, err := r.ResolveRepoStateOptional(context.Background(), RegistryIdentity{Owner: owner}, repo)
		if err != nil {
			t.Fatalf("resolve optional: %v", err)
		}
		if !found {
			t.Fatal("expected found=true for a present feed")
		}
		if state.Generation != 3 || state.Repo != repo {
			t.Fatalf("unexpected state: %+v", state)
		}
	})

	t.Run("missing-feed-returns-not-found", func(t *testing.T) {
		docs := NewMemoryDocumentStore()
		feeds := NewMemoryFeedStore() // no repo feed
		feeds.Feeds[spec.AuthPolicyFeedRef(owner)] = "auth-policy-ref"
		feeds.Feeds[spec.StampPolicyFeedRef(owner)] = "stamp-policy-ref"

		r := RegistryResolver{Registries: StaticRegistryIdentityResolver{}, Docs: docs, Feeds: feeds}
		state, found, err := r.ResolveRepoStateOptional(context.Background(), RegistryIdentity{Owner: owner}, repo)
		if err != nil {
			t.Fatalf("missing feed must not be an error, got %v", err)
		}
		if found {
			t.Fatal("expected found=false for a conclusively missing feed")
		}
		if state.Generation != 0 || state.Version != 0 {
			t.Fatalf("expected zero repo state, got %+v", state)
		}
	})

	t.Run("wrapped-feed-not-found-is-absent", func(t *testing.T) {
		docs := NewMemoryDocumentStore()
		r := RegistryResolver{
			Docs:  docs,
			Feeds: failingFeedResolver{err: fmt.Errorf("resolve: %w", ErrFeedNotFound)},
		}
		if _, found, err := r.ResolveRepoStateOptional(context.Background(), RegistryIdentity{Owner: owner}, repo); err != nil || found {
			t.Fatalf("feed-not-found sentinel must be absent (found=%v err=%v)", found, err)
		}
	})

	t.Run("feed-network-error-is-error", func(t *testing.T) {
		docs := NewMemoryDocumentStore()
		r := RegistryResolver{
			Docs:  docs,
			Feeds: failingFeedResolver{err: errors.New("bee resolve timed out")},
		}
		if _, found, err := r.ResolveRepoStateOptional(context.Background(), RegistryIdentity{Owner: owner}, repo); err == nil || found {
			t.Fatalf("network/timeout must remain an error (found=%v err=%v)", found, err)
		}
	})

	t.Run("identity-feed-absent-payload-is-not-found", func(t *testing.T) {
		// Bee-mode wiring: the feed resolver maps the repo feed to itself and
		// the document reader performs the actual feed read; a definitive 404
		// on that read is the conclusively-missing-feed outcome.
		r := RegistryResolver{
			Docs:  failingDocReader{err: fmt.Errorf("bee read failed with status 404: %w", ErrDocumentNotFound)},
			Feeds: identityFeedResolver{},
		}
		if _, found, err := r.ResolveRepoStateOptional(context.Background(), RegistryIdentity{Owner: owner}, repo); err != nil || found {
			t.Fatalf("identity-feed 404 must be absent (found=%v err=%v)", found, err)
		}
	})

	t.Run("identity-feed-network-error-is-error", func(t *testing.T) {
		r := RegistryResolver{
			Docs:  failingDocReader{err: errors.New("bee read timed out")},
			Feeds: identityFeedResolver{},
		}
		if _, found, err := r.ResolveRepoStateOptional(context.Background(), RegistryIdentity{Owner: owner}, repo); err == nil || found {
			t.Fatalf("read network/timeout must remain an error (found=%v err=%v)", found, err)
		}
	})

	t.Run("present-feed-missing-doc-is-error", func(t *testing.T) {
		docs := NewMemoryDocumentStore() // no document at the resolved ref
		feeds := NewMemoryFeedStore()
		feeds.Feeds[feed] = "mem-ref-missing"

		r := RegistryResolver{Registries: StaticRegistryIdentityResolver{}, Docs: docs, Feeds: feeds}
		if _, found, err := r.ResolveRepoStateOptional(context.Background(), RegistryIdentity{Owner: owner}, repo); err == nil || found {
			t.Fatalf("a feed pointing at a missing document is corruption, not absence (found=%v err=%v)", found, err)
		}
	})

	t.Run("malformed-doc-is-error", func(t *testing.T) {
		docs := NewMemoryDocumentStore()
		docs.Documents["repo-state-ref"] = []byte(`{"not":"a repo state document"`)
		feeds := NewMemoryFeedStore()
		feeds.Feeds[feed] = "repo-state-ref"

		r := RegistryResolver{Registries: StaticRegistryIdentityResolver{}, Docs: docs, Feeds: feeds}
		if _, found, err := r.ResolveRepoStateOptional(context.Background(), RegistryIdentity{Owner: owner}, repo); err == nil || found {
			t.Fatalf("malformed repo state must be an error (found=%v err=%v)", found, err)
		}
	})

	t.Run("repo-mismatch-is-error", func(t *testing.T) {
		docs := NewMemoryDocumentStore()
		docs.Documents["repo-state-ref"] = repoStateDoc(t, "other/repo", 3)
		feeds := NewMemoryFeedStore()
		feeds.Feeds[feed] = "repo-state-ref"

		r := RegistryResolver{Registries: StaticRegistryIdentityResolver{}, Docs: docs, Feeds: feeds}
		if _, found, err := r.ResolveRepoStateOptional(context.Background(), RegistryIdentity{Owner: owner}, repo); err == nil || found {
			t.Fatalf("repo mismatch must be an error (found=%v err=%v)", found, err)
		}
	})
}
