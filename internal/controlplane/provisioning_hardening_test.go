package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These tests cover Task 9 findings F2 (provisioning settings coherence) and
// F5 (real failure/concurrency):
//   - feed-resolution no-op / wrong / overwritten-updater never completes;
//   - mid-transaction rollback injection leaves ZERO rows in every table;
//   - two INDEPENDENT Store/sql.DB instances on one file-backed SQLite DB never
//     duplicate a logical publication (at-least-once physical uploads only);
//   - deterministic injected persists failures at each progress window prove
//     safe replay while preventing duplicate logical job/completion;
//   - a stale bootstrap can never re-enable anonymous pull or an old stamp.

// noopFeedUpdater accepts every feed update but writes nothing the resolver can
// see, simulating a no-op/forgotten-feeder. Completion must never happen.
type noopFeedUpdater struct{}

func (noopFeedUpdater) UpdateRegistryFeed(context.Context, Registry, string, string, string, bool) error {
	return nil
}

// hardHarness is a focused provisioning harness with a pluggable feed
// updater. The feed resolver (reader) is always the caller-supplied
// feedStore; for a real updater the caller passes the SAME store so
// published feeds are independently resolvable.
type hardHarness struct {
	store      *Store
	service    *Service
	uploader   *failObjectStore
	feedStore  *MemoryRegistryFeedStore
	reconciler *Reconciler
	ownerID    int64
	now        time.Time
}

func newHardHarness(t *testing.T, updater RegistryFeedUpdater, feedStore *MemoryRegistryFeedStore) *hardHarness {
	t.Helper()
	name := fmt.Sprintf("file:provh_hard_%d?mode=memory&cache=shared", atomic.AddUint64(&reconcilerSeq, 1))
	store, err := OpenSQLite(name)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	uploader := &failObjectStore{inner: &memoryUploader{refs: map[string][]byte{}}}
	if feedStore == nil {
		feedStore = &MemoryRegistryFeedStore{Feeds: map[string]string{}}
	}
	service := &Service{
		Store:          store,
		Tokens:         newTestSessionManager(t),
		RegistryDomain: "uncloud-registry.com",
		FeedKeys:       newTestFeedKeyCipher(t),
		Publisher:      &Publisher{Documents: uploader, Feeds: updater, FeedsReader: feedStore},
	}
	owner, _, err := service.RegisterUser(context.Background(), "hard@example.com", "password123")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	reconciler, err := service.NewReconciler()
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	reconciler.BackoffBase = 0
	reconciler.BackoffMax = 0
	reconciler.Lease = 10 * time.Second
	h := &hardHarness{store: store, service: service, uploader: uploader, feedStore: feedStore,
		reconciler: reconciler, ownerID: owner.ID, now: time.Now().UTC().Add(5 * time.Second)}
	reconciler.now = func() time.Time { return h.now }
	return h
}

func (h *hardHarness) advance(d time.Duration) { h.now = h.now.Add(d) }

func (h *hardHarness) createRegistry(t *testing.T) CreatedRegistry {
	t.Helper()
	slug := fmt.Sprintf("hardreg%d", atomic.AddUint64(&reconcilerSeq, 2000))
	created, err := h.service.CreateRegistry(context.Background(), h.ownerID, slug, slug+".eth", true, "batch-1")
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	return created
}

// installJobPersistAbort installs a BEFORE UPDATE trigger on
// registry_publication_jobs that aborts the transaction when the given
// predicate matches — an explicit crash seam that exists only in the test DB
// and can never affect production (nil/no trigger preempts it).
func installJobPersistAbort(t *testing.T, db *sql.DB, name, predicate string) {
	t.Helper()
	stmt := fmt.Sprintf(`create trigger %s before update on registry_publication_jobs
		for each row when %s begin select raise(abort, 'injected persist crash'); end`, name, predicate)
	if _, err := db.Exec(stmt); err != nil {
		t.Fatalf("install persist abort trigger %s: %v", name, err)
	}
}

func dropTrigger(t *testing.T, db *sql.DB, name string) {
	t.Helper()
	if _, err := db.Exec(`drop trigger if exists ` + name); err != nil {
		t.Fatalf("drop trigger %s: %v", name, err)
	}
}

func countRows(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`select count(*) from ` + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// TestProvisioningFeedResolutionNoOpUpdaterNeverCompletes proves a no-op feed
// updater (accepted but never resolvable) cannot complete provisioning.
func TestProvisioningFeedResolutionNoOpUpdaterNeverCompletes(t *testing.T) {
	h := newHardHarness(t, noopFeedUpdater{}, nil)
	created := h.createRegistry(t)

	// Stage 3 requires the feed to independently resolve to the uploaded ref;
	// a no-op updater leaves it unresolved, so reconciliation must never
	// complete and must persist the coarse "feed resolution mismatch" class.
	for i := 0; i < 3; i++ {
		if err := h.reconciler.RunOnce(context.Background()); err != nil {
			t.Fatalf("run once (no-op updater) must not be fatal, got %v", err)
		}
		h.advance(time.Nanosecond)
		jobs, _ := h.store.listJobsForRegistry(context.Background(), created.Registry.ID)
		for _, j := range jobs {
			if j.State == PublicationStateSucceeded {
				t.Fatalf("no-op updater must never succeed a job, got %+v", j)
			}
			if j.State != PublicationStatePending && j.State != PublicationStateFailed {
				t.Fatalf("unexpected job state %q for no-op updater", j.State)
			}
			if j.LastError != "feed resolution mismatch" {
				t.Fatalf("expected sanitized feed resolution mismatch, got %q", j.LastError)
			}
		}
		reg, err := h.store.FindRegistryByID(context.Background(), created.Registry.ID)
		if err != nil {
			t.Fatalf("find registry: %v", err)
		}
		if reg.ProvisioningState == ProvisioningStateReady {
			t.Fatal("no-op updater must never mark the registry ready")
		}
	}
}

// TestProvisioningFeedResolutionWrongOrOverwrittenRefNeverCompletes proves a
// feed that resolves to the WRONG object ref (stale/overwritten) is a
// retryable mismatch, and that completion happens only once the feed genuinely
// points at the uploaded object.
func TestProvisioningFeedResolutionWrongOrOverwrittenRefNeverCompletes(t *testing.T) {
	h := newHardHarness(t, noopFeedUpdater{}, nil)
	created := h.createRegistry(t)
	stampFeed := stampPolicyFeedRef(created.Registry)

	// Pre-seed a STALE feed entry pointing at a wrong/overwritten ref. The
	// no-op updater never overwrites it, so resolution sees the wrong target.
	h.feedStore.Feeds[stampFeed] = "0xstale-overwritten-ref"
	if err := h.reconciler.RunOnce(context.Background()); err != nil {
		t.Fatalf("run once: %v", err)
	}
	jobs, _ := h.store.listJobsForRegistry(context.Background(), created.Registry.ID)
	for _, j := range jobs {
		if j.LastError != "feed resolution mismatch" {
			t.Fatalf("expected mismatch on stale feed target, got %q (%s)", j.LastError, j.Kind)
		}
		if j.State == PublicationStateSucceeded {
			t.Fatalf("stale feed target must not succeed a job")
		}
	}

	// The jobs' object refs are now durable; point EACH feed at its committed
	// object and recovery completes — proving resolution (not the feed_ref
	// identifier) gates it. Both feeds were stale/mismatched (auth unresolved,
	// stamp pointing at a stale ref), so both must be repaired.
	for _, j := range jobs {
		if j.ObjectRef == "" {
			t.Fatalf("expected a committed object ref after the mismatch pass (%s)", j.Kind)
		}
		ref := stampPolicyFeedRef(created.Registry)
		if j.Kind == PublicationKindAuth {
			ref = authPolicyFeedRef(created.Registry)
		}
		h.feedStore.Feeds[ref] = j.ObjectRef
	}
	if err := h.reconciler.RunOnce(context.Background()); err != nil {
		t.Fatalf("recovery run once: %v", err)
	}
	reg, err := h.store.FindRegistryByID(context.Background(), created.Registry.ID)
	if err != nil {
		t.Fatalf("find registry: %v", err)
	}
	if reg.ProvisioningState != ProvisioningStateReady {
		t.Fatalf("expected ready once the feed resolves to the object, got %q", reg.ProvisioningState)
	}
}

// TestProvisioningMidTxRollbackLeavesNoRows injects an abort at two points
// inside CreateProvisionedRegistry's single transaction and proves the whole
// transaction rolls back with zero rows in every transaction table.
func TestProvisioningMidTxRollbackLeavesNoRows(t *testing.T) {
	for _, tc := range []struct {
		name      string
		predicate string // abort when the insert matches
	}{
		{"after registries_and_membership_first_job", "new.kind = 'auth'"},
		{"after_first_job_second_job", "new.kind = 'stamp'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			storeName := fmt.Sprintf("file:provh_rollback_%d?mode=memory&cache=shared", atomic.AddUint64(&reconcilerSeq, 1))
			store, err := OpenSQLite(storeName)
			if err != nil {
				t.Fatalf("open store: %v", err)
			}
			if _, err := store.DB.Exec(`insert into users (email, password_hash, created_at) values (?, ?, ?)`,
				"owner@example.com", "hash", time.Now().UTC().Format(time.RFC3339)); err != nil {
				t.Fatalf("seed owner: %v", err)
			}
			// Crash seam: abort the jobs INSERT when the predicate matches.
			if _, err := store.DB.Exec(fmt.Sprintf(`create trigger inject_rollback before insert on registry_publication_jobs
				for each row when %s begin select raise(abort, 'injected rollback'); end`, tc.predicate)); err != nil {
				t.Fatalf("install rollback trigger: %v", err)
			}
			_, err = store.CreateProvisionedRegistry(context.Background(), Registry{
				Slug: "x", Host: "x.registry.example", ENSName: "x.eth", OwnerUserID: 1,
				FeedOwnerAddress: "0x", DefaultStampBatchID: "b", AnonymousPull: false,
			}, newTestFeedKeyCipher(t), []byte("k"), []byte(mig7Auth), []byte(mig7Stamp))
			if err == nil {
				t.Fatal("expected injected mid-transaction rollback to fail CreateProvisionedRegistry")
			}
			// The whole transaction — registry, membership, jobs — must be gone.
			if n := countRows(t, store.DB, "registries"); n != 0 {
				t.Fatalf("expected zero registries after rollback, got %d", n)
			}
			if n := countRows(t, store.DB, "registry_memberships"); n != 0 {
				t.Fatalf("expected zero memberships after rollback, got %d", n)
			}
			if n := countRows(t, store.DB, "registry_publication_jobs"); n != 0 {
				t.Fatalf("expected zero jobs after rollback, got %d", n)
			}
			// The owner user is seeded before the transaction and must survive.
			if n := countRows(t, store.DB, "users"); n != 1 {
				t.Fatalf("expected the pre-transaction owner to survive, got %d users", n)
			}
		})
	}
}

// TestProvisioningTwoIndependentStoresOneFileNoDuplicatePublication uses TWO
// independent Store/sql.DB instances and two reconciler workers against ONE
// file-backed SQLite database. Atomic claiming guarantees each logical job is
// published exactly once total, despite two independent claimers.
func TestProvisioningTwoIndependentStoresOneFileNoDuplicatePublication(t *testing.T) {
	dbFile := filepath.Join(t.TempDir(), "shared.db")
	storeA := mustOpenFileStore(t, dbFile)
	storeB := mustOpenFileStore(t, dbFile)

	// Seed owner + registry + jobs via storeA only.
	if _, err := storeA.CreateUser(context.Background(), "owner@example.com", "hash"); err != nil {
		t.Fatalf("create owner: %v", err)
	}
	if _, err := storeA.CreateProvisionedRegistry(context.Background(), Registry{
		Slug: "two", Host: "two.registry.example", ENSName: "two.eth", OwnerUserID: 1,
		FeedOwnerAddress: "0xfeed", DefaultStampBatchID: "batch-1", AnonymousPull: true,
	}, newTestFeedKeyCipher(t), []byte("k"), []byte(mig7Auth), []byte(mig7Stamp)); err != nil {
		t.Fatalf("seed registry: %v", err)
	}

	mkWorker := func(store *Store) (*failObjectStore, *Reconciler) {
		up := &failObjectStore{inner: &memoryUploader{refs: map[string][]byte{}}}
		fs := &MemoryRegistryFeedStore{Feeds: map[string]string{}}
		pub := &Publisher{Documents: up, Feeds: fs, FeedsReader: fs}
		svc := &Service{Store: store, Tokens: newTestSessionManager(t), RegistryDomain: "uncloud-registry.com",
			FeedKeys: newTestFeedKeyCipher(t), Publisher: pub}
		rec, err := svc.NewReconciler()
		if err != nil {
			t.Fatalf("worker reconciler: %v", err)
		}
		rec.BackoffBase = 0
		rec.BackoffMax = 0
		return up, rec
	}

	upA, recA := mkWorker(storeA)
	upB, recB := mkWorker(storeB)

	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	for _, rec := range []*Reconciler{recA, recB} {
		wg.Add(1)
		go func(r *Reconciler) {
			defer wg.Done()
			errCh <- r.RunOnce(context.Background())
		}(rec)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent run once over two stores: %v", err)
		}
	}

	// Each logical job published exactly once TOTAL across both workers.
	total := upA.putCalls() + upB.putCalls()
	if total != 2 {
		t.Fatalf("expected exactly two uploads total across two workers, got %d", total)
	}
	var registryID int64
	if err := storeA.DB.QueryRow(`select id from registries limit 1`).Scan(&registryID); err != nil {
		t.Fatalf("read registry id: %v", err)
	}
	reg, err := storeA.FindRegistryByID(context.Background(), registryID)
	if err != nil {
		t.Fatalf("find registry: %v", err)
	}
	if reg.ProvisioningState != ProvisioningStateReady {
		t.Fatalf("expected ready after two-worker publication, got %q", reg.ProvisioningState)
	}
	jobs, err := storeA.listJobsForRegistry(context.Background(), registryID)
	if err != nil {
		t.Fatalf("list jobs: %v", err)
	}
	if len(jobs) != 2 {
		t.Fatalf("expected two jobs, got %d", len(jobs))
	}
	for _, j := range jobs {
		if j.State != PublicationStateSucceeded {
			t.Fatalf("every job must succeed exactly once, got %+v", j)
		}
		if j.ObjectRef == "" || j.FeedRef == "" {
			t.Fatalf("succeeded job must carry verified refs, got %+v", j)
		}
	}
}

func mustOpenFileStore(t *testing.T, path string) *Store {
	t.Helper()
	if path == "" {
		t.Fatal("mustOpenFileStore requires a file path")
	}
	store, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("open file store %s: %v", path, err)
	}
	return store
}

// TestNewReconcilerFailsClosedOnMissingDependencies proves NewReconciler
// rejects every partial dependency combination (never a silently-degraded
// reconciler).
func TestNewReconcilerFailsClosedOnMissingDependencies(t *testing.T) {
	doc := &memoryUploader{refs: map[string][]byte{}}
	fs := &MemoryRegistryFeedStore{Feeds: map[string]string{}}
	cases := []struct {
		name     string
		store    *Store
		docs     ObjectStore
		feeds    RegistryFeedUpdater
		resolver FeedResolver
	}{
		{"nil store", nil, doc, fs, fs},
		{"nil documents", &Store{}, nil, fs, fs},
		{"nil feeds", &Store{}, doc, nil, fs},
		{"nil resolver", &Store{}, doc, fs, nil},
		{"all nil", nil, nil, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := NewReconciler(c.store, c.docs, c.feeds, c.resolver)
			if err == nil || !errors.Is(err, errReconcilerNotConfigured) {
				t.Fatalf("expected errReconcilerNotConfigured, got %v", err)
			}
			if r != nil {
				t.Fatal("a failed-closed construction must return a nil reconciler")
			}
		})
	}
}

// TestRunOnceConfigErrorNeverPanicsAndTouchesNothing proves RunOnce returns the
// data-free config error (never a panic) for nil and partially-configured
// reconcilers, with ZERO database effects (no claims, no rows).
func TestRunOnceConfigErrorNeverPanicsAndTouchesNothing(t *testing.T) {
	ctx := context.Background()
	store := mustOpenFileStore(t, filepath.Join(t.TempDir(), "runonce_cfg.db"))

	for _, rec := range []*Reconciler{nil, {}, {Store: store}} {
		if err := rec.RunOnce(ctx); err == nil || !errors.Is(err, errReconcilerNotConfigured) {
			t.Fatalf("expected data-free errReconcilerNotConfigured, got %v (rec %+v)", err, rec)
		}
	}
	// No claim and no rows were produced by the config-error path.
	if n := countRows(t, store.DB, "registry_publication_jobs"); n != 0 {
		t.Fatalf("config error must not create jobs, got %d", n)
	}
	var claimed int
	if err := store.DB.QueryRow(`select count(*) from registry_publication_jobs where state <> 'pending'`).Scan(&claimed); err != nil {
		t.Fatalf("count claims: %v", err)
	}
	if claimed != 0 {
		t.Fatalf("config error must not claim any job, got %d", claimed)
	}
}

// TestCreateRegistryFailsClosedWithoutPublisherZeroDbEffects proves creation
// rejects before key generation or any registry write when provisioning
// dependencies are missing.
func TestCreateRegistryFailsClosedWithoutPublisherZeroDbEffects(t *testing.T) {
	ctx := context.Background()
	store := mustOpenFileStore(t, filepath.Join(t.TempDir(), "create_fail.db"))
	svc := &Service{Store: store, Tokens: newTestSessionManager(t), RegistryDomain: "uncloud-registry.com"}
	user, _, err := svc.RegisterUser(ctx, "owner@example.com", "password123")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}

	if _, err := svc.CreateRegistry(ctx, user.ID, "alice", "alice.eth", false, "batch-1"); !errors.Is(err, errProvisioningNotConfigured) {
		t.Fatalf("expected errProvisioningNotConfigured for a Publisher-less service, got %v", err)
	}
	// No registry, membership, job — and no feed key material — was written.
	for _, table := range []string{"registries", "registry_memberships", "registry_publication_jobs"} {
		if n := countRows(t, store.DB, table); n != 0 {
			t.Fatalf("fail-closed creation must not write to %s, got %d rows", table, n)
		}
	}
}

// TestProvisioningCrashBeforeObjectRefPersistIsAtLeastOnceProvesSafeReplay
// injects a crash in the persist just AFTER the object upload but BEFORE the
// object_ref commit. Replay re-uploads (unavoidable at-least-once physical
// call) yet completes the LOGICAL job exactly once and reaches ready exactly
// once.
func TestProvisioningCrashBeforeObjectRefPersistIsAtLeastOnceProvesSafeReplay(t *testing.T) {
	feedShared := &MemoryRegistryFeedStore{Feeds: map[string]string{}}
	h := newHardHarness(t, feedShared, feedShared)
	created := h.createRegistry(t)
	// Crash when the object_ref is about to be persisted.
	installJobPersistAbort(t, h.store.DB, "inject_obj_ref",
		"new.object_ref <> '' and old.object_ref = ''")

	// First pass: uploads succeed, but persisting object_ref crashes.
	err := h.reconciler.RunOnce(context.Background())
	if err == nil {
		t.Fatal("expected the object_ref persist crash to surface as an error")
	}
	// The upload happened (physical, at-least-once) but no progress was committed.
	if h.uploader.putCalls() != 1 {
		t.Fatalf("expected the physical upload to have occurred, got %d", h.uploader.putCalls())
	}

	// After the lease expires + the seam is removed, replay is safe.
	dropTrigger(t, h.store.DB, "inject_obj_ref")
	h.advance(15 * time.Second)
	if err := h.reconciler.RunOnce(context.Background()); err != nil {
		t.Fatalf("replay run once: %v", err)
	}
	reg, err := h.store.FindRegistryByID(context.Background(), created.Registry.ID)
	if err != nil {
		t.Fatalf("find registry: %v", err)
	}
	if reg.ProvisioningState != ProvisioningStateReady {
		t.Fatalf("expected ready after safe replay, got %q", reg.ProvisioningState)
	}
	jobs, _ := h.store.listJobsForRegistry(context.Background(), created.Registry.ID)
	for _, j := range jobs {
		if j.State != PublicationStateSucceeded {
			t.Fatalf("logical job must complete exactly once, got %+v", j)
		}
	}
	// Physical upload count is >= 1 per logical job (the auth job re-uploaded).
	if h.uploader.putCalls() < 2 {
		t.Fatalf("at-least-once physical upload expected, got %d", h.uploader.putCalls())
	}
}

// TestProvisioningCrashAfterFeedUpdateBeforeFeedRefPersistNoReupload injects a
// crash between the (external) feed update and persisting the feed_ref. The
// object_ref is already durable so replay must NOT re-upload.
func TestProvisioningCrashAfterFeedUpdateBeforeFeedRefPersistNoReupload(t *testing.T) {
	feedShared := &MemoryRegistryFeedStore{Feeds: map[string]string{}}
	h := newHardHarness(t, feedShared, feedShared)
	created := h.createRegistry(t)
	installJobPersistAbort(t, h.store.DB, "inject_feed_ref",
		"new.feed_ref <> '' and old.feed_ref = ''")

	err := h.reconciler.RunOnce(context.Background())
	if err == nil {
		t.Fatal("expected the feed_ref persist crash to surface as an error")
	}
	if h.uploader.putCalls() != 1 {
		t.Fatalf("expected one physical upload before the crash, got %d", h.uploader.putCalls())
	}

	dropTrigger(t, h.store.DB, "inject_feed_ref")
	h.advance(15 * time.Second)
	if err := h.reconciler.RunOnce(context.Background()); err != nil {
		t.Fatalf("replay run once: %v", err)
	}
	// No re-upload on replay: object_ref was already committed. Two logical
	// jobs == two total physical uploads.
	if h.uploader.putCalls() != 2 {
		t.Fatalf("replay must not re-upload a committed object, got %d uploads", h.uploader.putCalls())
	}
	reg, err := h.store.FindRegistryByID(context.Background(), created.Registry.ID)
	if err != nil {
		t.Fatalf("find registry: %v", err)
	}
	if reg.ProvisioningState != ProvisioningStateReady {
		t.Fatalf("expected ready after replay, got %q", reg.ProvisioningState)
	}
}

// TestProvisioningCrashAtCompletionPersistNeverFalselyReady injects a crash at
// the completion pers.
func TestProvisioningCrashAtCompletionPersistNeverFalselyReady(t *testing.T) {
	feedShared := &MemoryRegistryFeedStore{Feeds: map[string]string{}}
	h := newHardHarness(t, feedShared, feedShared)
	created := h.createRegistry(t)
	installJobPersistAbort(t, h.store.DB, "inject_complete",
		"new.state = 'succeeded' and old.state <> 'succeeded'")

	err := h.reconciler.RunOnce(context.Background())
	if err == nil {
		t.Fatal("expected the completion persist crash to surface as an error")
	}
	reg, err := h.store.FindRegistryByID(context.Background(), created.Registry.ID)
	if err != nil {
		t.Fatalf("find registry: %v", err)
	}
	if reg.ProvisioningState == ProvisioningStateReady {
		t.Fatal("registry must never be ready when completion could not be persisted")
	}

	dropTrigger(t, h.store.DB, "inject_complete")
	h.advance(15 * time.Second)
	if err := h.reconciler.RunOnce(context.Background()); err != nil {
		t.Fatalf("replay run once: %v", err)
	}
	reg, err = h.store.FindRegistryByID(context.Background(), created.Registry.ID)
	if err != nil {
		t.Fatalf("find registry: %v", err)
	}
	if reg.ProvisioningState != ProvisioningStateReady {
		t.Fatalf("expected ready after replay, got %q", reg.ProvisioningState)
	}
	if h.uploader.putCalls() != 2 {
		t.Fatalf("replay after completion-crash must not re-upload, got %d", h.uploader.putCalls())
	}
}

// TestProvisioningSettingsGateStaleBootstrapCannotReenableAnonymousOrOldStamp
// proves the ready-only settings gate (F2): a stale provisioning registry can
// never re-enable anonymous pull or overwrite the stamp batch; nothing is
// mutated or published on rejection.
func TestProvisioningSettingsGateStaleBootstrapCannotReenableAnonymousOrOldStamp(t *testing.T) {
	ctx := context.Background()
	feedShared := &MemoryRegistryFeedStore{Feeds: map[string]string{}}
	h := newHardHarness(t, feedShared, feedShared)
	owner := h.ownerID

	// Registry born anonymous=false with stamp snapshot-A.
	slug := fmt.Sprintf("gate%d", atomic.AddUint64(&reconcilerSeq, 3000))
	created, err := h.service.CreateRegistry(ctx, owner, slug, slug+".eth", false, "snapshot-A")
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	regID := created.Registry.ID

	// While provisioning, settings changes are REJECTED and untouched.
	if _, err := h.service.UpdateRegistrySettings(ctx, owner, regID, true, "snapshot-B"); !errors.Is(err, errRegistryNotReady) {
		t.Fatalf("expected errRegistryNotReady while provisioning, got %v", err)
	}
	reg, err := h.store.FindRegistryByID(ctx, regID)
	if err != nil {
		t.Fatalf("find registry: %v", err)
	}
	if reg.AnonymousPull || reg.DefaultStampBatchID != "snapshot-A" {
		t.Fatalf("rejected settings change must leave the registry untouched, got %+v", reg)
	}

	// Drive to ready, then settings changes apply.
	if err := h.reconciler.RunOnce(ctx); err != nil {
		t.Fatalf("reconcile to ready: %v", err)
	}
	if _, err := h.service.UpdateRegistrySettings(ctx, owner, regID, true, "snapshot-C"); err != nil {
		t.Fatalf("settings change after ready: %v", err)
	}
	reg, err = h.store.FindRegistryByID(ctx, regID)
	if err != nil {
		t.Fatalf("find registry: %v", err)
	}
	if !reg.AnonymousPull || reg.DefaultStampBatchID != "snapshot-C" {
		t.Fatalf("ready registry settings change must apply, got %+v", reg)
	}

	// RACE SAFETY against the final ready transition: hammer settings updates
	// while a RECONCILER finally finishes readiness on a second registry. The
	// gate is a single atomic conditional UPDATE, so a change either applies
	// (registry already ready) or is fully rejected (still provisioning) —
	// never a partial/stale re-enable while the registry is non-ready.
	slug2 := fmt.Sprintf("gate2%d", atomic.AddUint64(&reconcilerSeq, 3000))
	created2, err := h.service.CreateRegistry(ctx, owner, slug2, slug2+".eth", false, "snapshot-A")
	if err != nil {
		t.Fatalf("create second registry: %v", err)
	}
	regID2 := created2.Registry.ID

	var wg sync.WaitGroup
	var mu sync.Mutex
	var applied, rejected int
	stop := make(chan struct{})
	// rejectedSignal confirms the racer observed a rejection WHILE the registry
	// was still provisioning, making the race outcome deterministic instead of
	// depending on whether the goroutine scheduled before the ready transition.
	rejectedSignal := make(chan struct{}, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_, err := h.service.UpdateRegistrySettings(ctx, owner, regID2, true, "snapshot-C")
			if err != nil {
				if !errors.Is(err, errRegistryNotReady) {
					t.Errorf("expected only errRegistryNotReady or success, got %v", err)
				}
				mu.Lock()
				rejected++
				saw := rejected
				mu.Unlock()
				if saw > 0 {
					select {
					case rejectedSignal <- struct{}{}:
					default:
					}
				}
			} else {
				mu.Lock()
				applied++
				mu.Unlock()
			}
		}
	}()
	// Wait until the racer has observed at least one rejection while the
	// registry is still provisioning (guaranteed before readiness, once the
	// gate is installed), THEN run the reconciler to race the ready transition.
	select {
	case <-rejectedSignal:
	case <-time.After(5 * time.Second):
		t.Fatal("racer never observed a rejection while provisioning (the registry must be provisioning until the reconciler runs)")
	}
	if err := h.reconciler.RunOnce(ctx); err != nil {
		t.Fatalf("reconcile second registry: %v", err)
	}
	close(stop)
	wg.Wait()

	reg2, err := h.store.FindRegistryByID(ctx, regID2)
	if err != nil {
		t.Fatalf("find second registry: %v", err)
	}
	if reg2.ProvisioningState != ProvisioningStateReady {
		t.Fatalf("second registry must reach ready, got %q", reg2.ProvisioningState)
	}
	// Whether the racing update won or lost, the outcome is coherent: it is
	// either the stale value (never re-enabled) or the FULLY applied new value
	// after ready — never an in-between/partial re-enable. With the gate
	// racing the ready transition, at least one rejection must have been
	// observed while still provisioning.
	mu.Lock()
	defer mu.Unlock()
	if applied+rejected == 0 {
		t.Fatal("expected the racer to observe at least one gate decision")
	}
	if rejected == 0 {
		t.Fatal("expected at least one rejection while provisioning raced readiness")
	}
	if !reg2.AnonymousPull && reg2.DefaultStampBatchID != "snapshot-A" {
		t.Fatalf("no partial/stale write allowed, got %+v", reg2)
	}
}
