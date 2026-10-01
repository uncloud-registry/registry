package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"
)

// newProvisioningStore opens a fresh in-memory store with a unique shared-cache
// name so parallel store tests never collide.
var (
	// testAuthPayload / testStampPayload are structurally valid, kind-appropriate
	// policy documents in the exact production shape migration 8's hardened jobs
	// CHECK requires (auth: $.version==1, $.defaultAccess=='deny', $.defaultRepo
	// object with pull/push arrays, $.repos object; stamp: $.version==1,
	// $.defaultPolicy.batchID text, allowPushFor array, $.repos object).
	testAuthPayload  = []byte(`{"version":1,"defaultAccess":"deny","defaultRepo":{"pull":["anonymous","role:read","role:write"],"push":["role:write"]},"repos":{}}`)
	testStampPayload = []byte(`{"version":1,"defaultPolicy":{"batchID":"batch-1","allowPushFor":["role:write"]},"repos":{}}`)
)

func newProvisioningStore(t *testing.T) *Store {
	t.Helper()
	name := "file:provstore_" + t.Name() + "?mode=memory&cache=shared"
	store, err := OpenSQLite(name)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	return store
}

// seedProvisioningOwner creates an owner user for provisioning store tests.
func seedProvisioningOwner(t *testing.T, store *Store) User {
	t.Helper()
	owner, err := store.CreateUser(context.Background(), "prov-owner@example.com", "hash")
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	return owner
}

func newTestFeedKeyCipherForStore(t *testing.T) *FeedKeyCipher {
	t.Helper()
	return newTestFeedKeyCipher(t)
}

// TestCreateProvisionedRegistryIsAtomic proves registry+membership+jobs all
// commit together or all roll back together: a second creation attempt
// colliding on the unique slug rolls the whole transaction back, so no orphan
// job or membership is ever left behind (and an existing registry is untouched).
func TestCreateProvisionedRegistryIsAtomic(t *testing.T) {
	store := newProvisioningStore(t)
	owner := seedProvisioningOwner(t, store)
	ctx := context.Background()

	key := []byte("01234567890123456789012345678901")
	created, err := store.CreateProvisionedRegistry(ctx, Registry{
		Slug: "atomic", Host: "atomic.registry.test", ENSName: "atomic.eth",
		OwnerUserID: owner.ID, FeedOwnerAddress: "0xpair1", DefaultStampBatchID: "batch-b",
		AnonymousPull: true,
	}, newTestFeedKeyCipherForStore(t), key, []byte(testAuthPayload), []byte(testStampPayload))
	if err != nil {
		t.Fatalf("create provisioned registry: %v", err)
	}
	if created.ProvisioningState != ProvisioningStateProvisioning {
		t.Fatalf("expected provisioning state, got %q", created.ProvisioningState)
	}

	// A duplicate-slug attempt fails on the persistent unique constraint AFTER
	// the registry INSERT, proving a mid-transaction failure rolls back the
	// registry, membership, AND both jobs atomically.
	if _, err := store.CreateProvisionedRegistry(ctx, Registry{
		Slug: "atomic", Host: "atomic.registry.test", ENSName: "atomic2.eth",
		OwnerUserID: owner.ID, FeedOwnerAddress: "0xpair2", DefaultStampBatchID: "batch-b",
		AnonymousPull: true,
	}, newTestFeedKeyCipherForStore(t), key, []byte(testAuthPayload), []byte(testStampPayload)); err == nil {
		t.Fatal("expected duplicate-slug creation to fail")
	}

	// Exactly two jobs (auth, stamp) for the single surviving registry, one
	// owner membership, and no orphaned second registry.
	jobs, err := store.listJobsForRegistry(ctx, created.ID)
	if err != nil {
		t.Fatalf("list jobs: %v", err)
	}
	if len(jobs) != 2 {
		t.Fatalf("expected exactly 2 jobs, got %d", len(jobs))
	}
	kinds := map[string]bool{}
	for _, j := range jobs {
		kinds[j.Kind] = true
		if j.State != PublicationStatePending {
			t.Fatalf("expected job pending at creation, got %q", j.State)
		}
	}
	if !kinds[PublicationKindAuth] || !kinds[PublicationKindStamp] {
		t.Fatalf("expected auth and stamp jobs, got %v", kinds)
	}
	memberships, err := store.ListMembershipsForRegistry(ctx, created.ID)
	if err != nil {
		t.Fatalf("list memberships: %v", err)
	}
	if len(memberships) != 1 || memberships[0].Role != "owner" {
		t.Fatalf("expected exactly one owner membership, got %+v", memberships)
	}
	registries, err := store.ListRegistries(ctx)
	if err != nil {
		t.Fatalf("list registries: %v", err)
	}
	if len(registries) != 1 {
		t.Fatalf("expected exactly one registry after rollback, got %d", len(registries))
	}
}

func (s *Store) listJobsForRegistry(ctx context.Context, registryID int64) ([]PublicationJob, error) {
	rows, err := s.DB.QueryContext(ctx, `select `+publicationJobColumns+` from registry_publication_jobs where registry_id = ? order by kind asc`, registryID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PublicationJob
	for rows.Next() {
		var job PublicationJob
		if err := scanPublicationJob(rows, &job); err != nil {
			return nil, err
		}
		out = append(out, job)
	}
	return out, rows.Err()
}

// TestProvisioningStaleClaimOwnerShipAndGuards proves claiming is concurrency-
// safe and completion/failure updates are conditional on ownership: another
// worker's token can neither complete nor reset a job, and only a stale claim
// past its lease can be reclaimed.
func TestProvisioningStaleClaimOwnerShipAndGuards(t *testing.T) {
	store := newProvisioningStore(t)
	owner := seedProvisioningOwner(t, store)
	ctx := context.Background()
	reg, err := store.CreateProvisionedRegistry(ctx, Registry{
		Slug: "lease", Host: "lease.registry.test", ENSName: "lease.eth",
		OwnerUserID: owner.ID, FeedOwnerAddress: "0xlease", DefaultStampBatchID: "batch-l",
	}, newTestFeedKeyCipherForStore(t), []byte("01234567890123456789012345678901"),
		[]byte(testAuthPayload), []byte(testStampPayload))
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	now := time.Now().UTC()
	lease := 10 * time.Second

	jobs, token, err := store.ClaimStalePublicationJobs(ctx, now, lease, 2)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(jobs) != 2 {
		t.Fatalf("expected to claim 2 jobs, got %d", len(jobs))
	}
	job := jobs[0]

	// A stale worker holding a DIFFERENT token cannot write onto the claimed
	// job: complete, progress, and fail are all ownership-conditional.
	if err := store.CompletePublicationJob(ctx, job.ID, "stale-token", now); !errors.Is(err, errLostClaim) {
		t.Fatalf("expected lost-claim on stale complete, got %v", err)
	}
	if err := store.SetPublicationObjectRef(ctx, job.ID, "stale-token", "0xabc"); !errors.Is(err, errLostClaim) {
		t.Fatalf("expected lost-claim on stale object-ref, got %v", err)
	}
	if _, err := store.FailPublicationJob(ctx, job.ID, "stale-token", now, 8, time.Second, time.Minute, "x"); !errors.Is(err, errLostClaim) {
		t.Fatalf("expected lost-claim on stale fail, got %v", err)
	}

	// The job stays claimed by the real token (live lease): a second claim pass
	// before the lease expires sees nothing.
	again, _, err := store.ClaimStalePublicationJobs(ctx, now.Add(5*time.Second), lease, 2)
	if err != nil {
		t.Fatalf("second claim: %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("live lease must not be reclaimable, got %d jobs", len(again))
	}

	// The real token CAN complete it (and it then becomes ready since both jobs
	// must complete — complete only the first; the registry stays provisioning).
	// The completed job must satisfy the hardened succeeded coherence (verified
	// object + feed refs and a completion stamp), so persist the refs first.
	if err := store.SetPublicationObjectRef(ctx, job.ID, token, "0xobj"); err != nil {
		t.Fatalf("set object ref with real token: %v", err)
	}
	if err := store.SetPublicationFeedRef(ctx, job.ID, token, "feed://0xowner/aa"); err != nil {
		t.Fatalf("set feed ref with real token: %v", err)
	}
	if err := store.CompletePublicationJob(ctx, job.ID, token, now); err != nil {
		t.Fatalf("complete with real token: %v", err)
	}
	done, err := store.RegistryProvisioningJobsComplete(ctx, reg.ID)
	if err != nil {
		t.Fatalf("provisioning complete: %v", err)
	}
	if done {
		t.Fatal("one job must not satisfy readiness")
	}

	// After the lease expires, the completed job is terminal and not eligible
	// for reclaim; the still-claimed second job IS reclaimed by a new worker.
	reclaimed, newToken, err := store.ClaimStalePublicationJobs(ctx, now.Add(lease+time.Second), lease, 2)
	if err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	if len(reclaimed) != 1 {
		t.Fatalf("expected exactly one stale job to be reclaimed, got %d", len(reclaimed))
	}
	if reclaimed[0].ID == job.ID {
		t.Fatal("completed (terminal) job must not be reclaimed")
	}
	if newToken == "" {
		t.Fatal("expected a new worker token")
	}
}

// TestRegistryProvisioningStateGuard rejects any provisioning state outside the
// vocabulary at the schema boundary (direct-SQL gap closed by the trigger).
func TestRegistryProvisioningStateGuard(t *testing.T) {
	store := newProvisioningStore(t)
	owner := seedProvisioningOwner(t, store)
	ctx := context.Background()
	reg, err := store.CreateProvisionedRegistry(ctx, Registry{
		Slug: "guard", Host: "guard.registry.test", ENSName: "guard.eth",
		OwnerUserID: owner.ID, FeedOwnerAddress: "0xguard", DefaultStampBatchID: "batch-g",
	}, newTestFeedKeyCipherForStore(t), []byte("01234567890123456789012345678901"),
		[]byte(testAuthPayload), []byte(testStampPayload))
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	if _, err := store.DB.ExecContext(ctx, `update registries set provisioning_state = 'bogus' where id = ?`, reg.ID); err == nil {
		t.Fatal("expected invalid provisioning_state to be rejected by the schema guard trigger")
	}
	// A legitimate transition (provisioning → ready via guarded store method) works.
	if err := store.MarkRegistryReady(ctx, reg.ID); err != nil {
		t.Fatalf("mark ready: %v", err)
	}
}
