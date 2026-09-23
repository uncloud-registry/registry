package controlplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

// Part C: the reconciler and CreateRegistry must FAIL CLOSED on nil-capable
// TYPED-NIL interface values — a non-nil interface holding a nil pointer whose
// receiver methods would PANIC if invoked — in every dependency slot, before
// any key generation or database write, returning the data-free sentinel
// instead of a panic. Valid non-pointer (value) implementations must NOT be
// rejected.

// Each receiver method panics if it were ever invoked, so a test passing a
// typed nil and observing NO panic + NO DB effects proves fail-closed is
// actually reached BEFORE the dependency is used, rather than being rescued by
// a later nil check.
type panicObjectStore struct{}

func (*panicObjectStore) Put(_ context.Context, _ []byte, _ string) (string, error) {
	panic("panicObjectStore.Put must never be invoked")
}

func (*panicObjectStore) Get(_ context.Context, _ string) ([]byte, error) {
	panic("panicObjectStore.Get must never be invoked")
}

type panicFeedUpdater struct{}

func (*panicFeedUpdater) UpdateRegistryFeed(_ context.Context, _ Registry, _, _, _ string, _ bool) error {
	panic("panicFeedUpdater.UpdateRegistryFeed must never be invoked")
}

type panicFeedResolver struct{}

func (*panicFeedResolver) ResolveFeed(_ context.Context, _ string) (string, error) {
	panic("panicFeedResolver.ResolveFeed must never be invoked")
}

func typedNilObjectStore() ObjectStore         { return (*panicObjectStore)(nil) }
func typedNilFeedUpdater() RegistryFeedUpdater { return (*panicFeedUpdater)(nil) }
func typedNilFeedResolver() FeedResolver       { return (*panicFeedResolver)(nil) }
func typedNilStore() *Store                    { return (*Store)(nil) }

// TestTypedNilNewReconcilerRejected confirms a typed-nil in ANY constructor
// slot yields the data-free sentinel, a nil reconciler, and never a panic.
func TestTypedNilNewReconcilerRejected(t *testing.T) {
	validDoc := &memoryUploader{refs: map[string][]byte{}}
	validFeed := &MemoryRegistryFeedStore{Feeds: map[string]string{}}
	st := mustOpenFileStore(t, filepath.Join(t.TempDir(), "tn_rec.db"))

	cases := []struct {
		name     string
		store    *Store
		doc      ObjectStore
		feed     RegistryFeedUpdater
		resolver FeedResolver
	}{
		{"typed-nil store", typedNilStore(), validDoc, validFeed, validFeed},
		{"typed-nil documents", st, typedNilObjectStore(), validFeed, validFeed},
		{"typed-nil feeds", st, validDoc, typedNilFeedUpdater(), validFeed},
		{"typed-nil resolver", st, validDoc, validFeed, typedNilFeedResolver()},
		{"every slot typed-nil", typedNilStore(), typedNilObjectStore(), typedNilFeedUpdater(), typedNilFeedResolver()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := NewReconciler(c.store, c.doc, c.feed, c.resolver)
			if err == nil || !errors.Is(err, errReconcilerNotConfigured) {
				t.Fatalf("expected errReconcilerNotConfigured, got %v", err)
			}
			if r != nil {
				t.Fatal("fail-closed construction must return a nil reconciler")
			}
		})
	}
}

// TestTypedNilRunOnceFailsClosedNoPanicNoDbEffects drives a Reconciler built as
// a struct literal (bypassing the constructor) with a typed-nil in each slot;
// RunOnce must return the sentinel, never panic, and touch no rows.
func TestTypedNilRunOnceFailsClosedNoPanicNoDbEffects(t *testing.T) {
	ctx := context.Background()
	st := mustOpenFileStore(t, filepath.Join(t.TempDir(), "tn_runonce.db"))

	validDoc := &memoryUploader{refs: map[string][]byte{}}
	validFeed := &MemoryRegistryFeedStore{Feeds: map[string]string{}}
	recs := []*Reconciler{
		{Store: typedNilStore(), Documents: validDoc, Feeds: validFeed, ResolveFeeds: validFeed},
		{Store: st, Documents: typedNilObjectStore(), Feeds: validFeed, ResolveFeeds: validFeed},
		{Store: st, Documents: validDoc, Feeds: typedNilFeedUpdater(), ResolveFeeds: validFeed},
		{Store: st, Documents: validDoc, Feeds: validFeed, ResolveFeeds: typedNilFeedResolver()},
		{Store: typedNilStore(), Documents: typedNilObjectStore(), Feeds: typedNilFeedUpdater(), ResolveFeeds: typedNilFeedResolver()},
	}
	for _, rec := range recs {
		if err := rec.RunOnce(ctx); err == nil || !errors.Is(err, errReconcilerNotConfigured) {
			t.Fatalf("expected data-free errReconcilerNotConfigured, got %v (rec %+v)", err, rec)
		}
	}
	if n := countRows(t, st.DB, "registry_publication_jobs"); n != 0 {
		t.Fatalf("fail-closed RunOnce must not create jobs, got %d", n)
	}
}

// TestTypedNilCreateRegistryFailsClosedNoPanicNoDbEffects proves typed-nil
// dependencies in EACH publisher slot (and the Store) make CreateRegistry fail
// closed before key randomness or any DB write, with zero rows, no panic.
func TestTypedNilCreateRegistryFailsClosedNoPanicNoDbEffects(t *testing.T) {
	ctx := context.Background()
	st := mustOpenFileStore(t, filepath.Join(t.TempDir(), "tn_create.db"))
	seed, _, err := (&Service{Store: st, Tokens: newTestSessionManager(t)}).RegisterUser(ctx, "typednil@example.com", "password123")
	if err != nil {
		t.Fatalf("seed owner: %v", err)
	}

	validDoc := &memoryUploader{refs: map[string][]byte{}}
	validFeed := &MemoryRegistryFeedStore{Feeds: map[string]string{}}
	cases := []struct {
		name string
		svc  *Service
	}{
		{"typed-nil Store", &Service{Store: typedNilStore(), Tokens: newTestSessionManager(t), RegistryDomain: "uncloud-registry.com"}},
		{"typed-nil publisher pointer", &Service{Store: st, Tokens: newTestSessionManager(t), RegistryDomain: "uncloud-registry.com",
			FeedKeys: newTestFeedKeyCipher(t), Publisher: (*Publisher)(nil)}},
		{"typed-nil documents", &Service{Store: st, Tokens: newTestSessionManager(t), RegistryDomain: "uncloud-registry.com",
			FeedKeys: newTestFeedKeyCipher(t), Publisher: &Publisher{Documents: typedNilObjectStore(), Feeds: validFeed, FeedsReader: validFeed}}},
		{"typed-nil feeds", &Service{Store: st, Tokens: newTestSessionManager(t), RegistryDomain: "uncloud-registry.com",
			FeedKeys: newTestFeedKeyCipher(t), Publisher: &Publisher{Documents: validDoc, Feeds: typedNilFeedUpdater(), FeedsReader: validFeed}}},
		{"typed-nil feeds reader", &Service{Store: st, Tokens: newTestSessionManager(t), RegistryDomain: "uncloud-registry.com",
			FeedKeys: newTestFeedKeyCipher(t), Publisher: &Publisher{Documents: validDoc, Feeds: validFeed, FeedsReader: typedNilFeedResolver()}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := c.svc.CreateRegistry(ctx, seed.ID, "tnreg1", "tnreg1.eth", false, "batch-1"); !errors.Is(err, errProvisioningNotConfigured) {
				t.Fatalf("expected errProvisioningNotConfigured, got %v", err)
			}
		})
	}
	for _, table := range []string{"registries", "registry_memberships", "registry_publication_jobs"} {
		if n := countRows(t, st.DB, table); n != 0 {
			t.Fatalf("fail-closed creation must not write to %s, got %d rows", table, n)
		}
	}
}

// value-receiver implementations. A non-pointer struct value satisfies the
// interfaces with reflect Kind == struct (not nil-capable), so they must never
// be rejected by isNilDependency.
type valueDocs struct{}

func (valueDocs) Put(_ context.Context, _ []byte, _ string) (string, error) { return "v", nil }
func (valueDocs) Get(_ context.Context, _ string) ([]byte, error)           { return nil, nil }

type valueFeeds struct{}

func (valueFeeds) UpdateRegistryFeed(_ context.Context, _ Registry, _, _, _ string, _ bool) error {
	return nil
}

func (valueFeeds) ResolveFeed(_ context.Context, _ string) (string, error) { return "v", nil }

// TestTypedNilAcceptsValidNonPointerImplementations proves isNilDependency does
// not reject valid struct-VALUE (non-pointer) interface implementations.
func TestTypedNilAcceptsValidNonPointerImplementations(t *testing.T) {
	st := mustOpenFileStore(t, filepath.Join(t.TempDir(), "tn_value.db"))
	r, err := NewReconciler(st, valueDocs{}, valueFeeds{}, valueFeeds{})
	if err != nil {
		t.Fatalf("value (non-pointer) implementations must not be rejected, got %v", err)
	}
	if r == nil {
		t.Fatal("expected a constructed reconciler for value implementations")
	}
}
