package staging

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/spec"
)

// ---------------------------------------------------------------------------
// Task 18 publication claim fence (schema v6): the durable, staging-side
// publication-owner claim that closes the cross-process publication-versus-unpin
// TOCTOU. The claim is a row transition finalized -> claimed keyed by the
// publication's stable operationID. A claimed row is invisible to the general
// publishable listing, is never selected by cleanup, is never expired, and is
// rejected by a generic Delete — exactly ONE operation may own it, and only
// that operation (or its exact retry) may consume it. Every test here uses two
// independent durable Store/Service instances sharing ONE staging SQLite DB,
// proving the fence holds across processes, with deterministic ordering and
// exact unpin counting via a fake unpinner.
// ---------------------------------------------------------------------------

// openSharedService opens ANOTHER independent durable service over the same
// directory (same staging SQLite file + spool) — modelling a second process
// sharing the staging DB. Startup reconciliation runs on open.
func openSharedService(t *testing.T, dir string) *service {
	t.Helper()
	svc, err := NewService(context.Background(), dir+"/spool", dir+"/staging.db")
	if err != nil {
		t.Fatalf("NewService on shared dir: %v", err)
	}
	t.Cleanup(func() { svc.Close() })
	return svc
}

// claimPubFinalize finalizes one blob on svc and returns its digest + ref.
func claimPubFinalize(t *testing.T, svc *service, repo, actor string) (digest, ref string) {
	t.Helper()
	s := mustCreate(t, svc, repo, actor)
	s = mustAppend(t, svc, s, "claim-fence-bytes")
	dg, beeRef, media, size := finalizeArgs(s)
	mustFinalize(t, svc, s, dg, beeRef, media, size)
	return dg, beeRef
}

// mustClaim returns the claimed descriptors and fails the test on error.
func mustClaim(t *testing.T, svc *service, repo, actor, op string, digests []string) {
	t.Helper()
	if _, err := svc.ClaimStagedForPublish(context.Background(), repo, actor, op, digests); err != nil {
		t.Fatalf("ClaimStagedForPublish(%s) = %v", op, err)
	}
}

// TestPubClaimCleanupWinsBeforeClaimFailsClosed proves the "cleanup won"
// ordering: a finalized blob is listed by the publication, then cleanup wins
// (claims and unpins/removes it) BEFORE the publication claims. The
// publication's claim then fails ErrClaimConflict with ZERO side effects —
// nothing is claimed, consumed, or resigned, and no further unpin occurs.
func TestPubClaimCleanupWinsBeforeClaimFailsClosed(t *testing.T) {
	dir := tempPrivate(t)
	pub := openSharedService(t, dir)
	clean := openSharedService(t, dir)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fixedClock(pub, now)
	fixedClock(clean, now)

	repo, actor := seedRepo, seedActor
	digest, ref := claimPubFinalize(t, pub, repo, actor)

	// Cleanup wins: the finalized blob is expired (eligible) and cleanup claims
	// + unpins + removes it fully.
	runAt := fixClockAhead(clean, now)
	unp := &fakeUnpinner{}
	c, err := NewCleanup(clean, unp, &fakeCommitted{})
	if err != nil {
		t.Fatalf("NewCleanup: %v", err)
	}
	res, err := c.RunOnce(context.Background(), runAt, 10)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if res.Unpinned != 1 || res.Removed != 1 {
		t.Fatalf("cleanup-wins counts = %+v, want unpinned=1 removed=1", res)
	}
	if unpins := unp.calls(); len(unpins) != 1 || unpins[0] != ref {
		t.Fatalf("cleanup unpin calls = %v, want exactly [%s]", unpins, ref)
	}

	// Publication's claim now fails closed: no finalized row remains and no
	// same-op claim exists, so the WHOLE claim errors and nothing is consumed.
	if _, err := pub.ClaimStagedForPublish(context.Background(), repo, actor, "op-pub", []string{digest}); !errors.Is(err, ErrClaimConflict) {
		t.Fatalf("claim after cleanup-wins = %v, want ErrClaimConflict", err)
	}
	if got := mustListStaged(t, pub, repo, actor); len(got) != 0 {
		t.Fatalf("post-cleanup-wins claim must leave zero publishable rows, got %+v", got)
	}
	if got, _ := pub.ClaimedDigests(context.Background(), repo, actor, "op-pub"); len(got) != 0 {
		t.Fatalf("post-cleanup-wins claim must not own any row, got %+v", got)
	}
	if unpins := unp.calls(); len(unpins) != 1 {
		t.Fatalf("publication must cause zero extra unpins, got %v", unpins)
	}
}

// TestPubClaimClaimWinsCleanupZeroUnpins proves the "publication claim won"
// ordering: the publication durably claims the finalized blob BEFORE cleanup
// runs; an independent cleanup instance then runs at an expiry where the blob
// WOULD be eligible, yet does ZERO unpins because the row is publication-owned.
// The publication then completes by consuming exactly its own claim.
func TestPubClaimClaimWinsCleanupZeroUnpins(t *testing.T) {
	dir := tempPrivate(t)
	pub := openSharedService(t, dir)
	clean := openSharedService(t, dir)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fixedClock(pub, now)

	repo, actor := seedRepo, seedActor
	digest, ref := claimPubFinalize(t, pub, repo, actor)

	// Publication claim wins FIRST (the blob is non-expired, so it claims).
	// Barrier: the publication is now paused after its durable claim, before
	// commit. Cleanup runs in an independent process here.
	mustClaim(t, pub, repo, actor, "op-pub", []string{digest})
	if got := mustListStaged(t, pub, repo, actor); len(got) != 0 {
		t.Fatalf("claimed row must be invisible to the publishable listing, got %+v", got)
	}

	// Cleanup at the same eligible expiry, from the OTHER instance.
	fixedClock(clean, now.Add(2*time.Hour))
	pinned := &fakeUnpinner{}
	c, err := NewCleanup(clean, pinned, &fakeCommitted{})
	if err != nil {
		t.Fatalf("NewCleanup: %v", err)
	}
	res, err := c.RunOnce(context.Background(), now.Add(2*time.Hour), 10)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if res.Unpinned != 0 {
		t.Fatalf("cleanup must unpin ZERO publication-owned rows, res=%+v", res)
	}
	if pins := pinned.calls(); len(pins) != 0 {
		t.Fatalf("cleanup must not unpin a claimed ref, got %v", pins)
	}

	// The claimed row survives cleanup untouched, and publication completes by
	// consuming exactly its own claim (without unpinning).
	if got := rawClaimedDigests(t, dir+"/staging.db", repo, actor); len(got) != 1 || got[0] != digest {
		t.Fatalf("claimed row must survive cleanup, got %v", got)
	}
	if err := pub.ConsumeStagedForPublish(context.Background(), repo, actor, "op-pub", []string{digest}); err != nil {
		t.Fatalf("ConsumeStagedForPublish: %v", err)
	}
	if got := mustListStaged(t, pub, repo, actor); len(got) != 0 {
		t.Fatalf("publishable rows after consume = %+v, want none", got)
	}
	if got := rawClaimedDigests(t, dir+"/staging.db", repo, actor); len(got) != 0 {
		t.Fatalf("claimed rows after consume = %v, want none", got)
	}
	_ = ref
	if pins := pinned.calls(); len(pins) != 0 {
		t.Fatalf("consume must never unpin, got %v", pins)
	}
}

// TestPubClaimRetrySameOperationReacquires proves crash/retry: the durable
// claim survives a new service instance's startup reconciliation (it is never
// stolen by startup/cleanup), a same-operation retry idempotently reacquires it
// instead of double-claiming, and the retry then consumes it to completion.
func TestPubClaimRetrySameOperationReacquires(t *testing.T) {
	dir := tempPrivate(t)
	pub1 := openSharedService(t, dir)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fixedClock(pub1, now)

	repo, actor := seedRepo, seedActor
	digest, _ := claimPubFinalize(t, pub1, repo, actor)
	mustClaim(t, pub1, repo, actor, "op-retry", []string{digest})

	// "Crash" and reopen: a NEW independent service instance runs startup
	// reconciliation against the same DB. The valid claim must be PRESERVED.
	pub2 := openSharedService(t, dir)
	owned, err := pub2.ClaimedDigests(context.Background(), repo, actor, "op-retry")
	if err != nil {
		t.Fatalf("ClaimedDigests after reopen: %v", err)
	}
	if _, ok := owned[digest]; !ok {
		t.Fatalf("startup lost the durable claim, owned=%v", owned)
	}

	// Same-operation retry reacquires idempotently (existing owned claim wins,
	// no double claim, no ErrClaimConflict) and reports the descriptor.
	got, err := pub2.ClaimStagedForPublish(context.Background(), repo, actor, "op-retry", []string{digest})
	if err != nil {
		t.Fatalf("retry reacquire = %v, want idempotent success", err)
	}
	if len(got) != 1 || got[0].Digest != digest {
		t.Fatalf("reacquire descriptors = %+v, want exactly the claimed blob", got)
	}
	if err := pub2.ConsumeStagedForPublish(context.Background(), repo, actor, "op-retry", []string{digest}); err != nil {
		t.Fatalf("retry consume: %v", err)
	}
	if got := mustListStaged(t, pub2, repo, actor); len(got) != 0 {
		t.Fatalf("after retry-consume publishable rows = %+v, want none", got)
	}
}

// TestPubClaimDistinctOperationCannotSteal proves a DIFFERENT operation cannot
// re-claim a row that operation A owns, cannot consume it, and does not clear
// A's claim — ownership is exclusive until A consumes.
func TestPubClaimDistinctOperationCannotSteal(t *testing.T) {
	dir := tempPrivate(t)
	pub := openSharedService(t, dir)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fixedClock(pub, now)

	repo, actor := seedRepo, seedActor
	digest, _ := claimPubFinalize(t, pub, repo, actor)
	mustClaim(t, pub, repo, actor, "op-a", []string{digest})

	// Operation B (a different logical publication) cannot steal it.
	if _, err := pub.ClaimStagedForPublish(context.Background(), repo, actor, "op-b", []string{digest}); !errors.Is(err, ErrClaimConflict) {
		t.Fatalf("foreign-operation claim = %v, want ErrClaimConflict", err)
	}
	// B's consume is a no-op that does NOT clear A's claim.
	if err := pub.ConsumeStagedForPublish(context.Background(), repo, actor, "op-b", []string{digest}); err != nil {
		t.Fatalf("foreign consume: %v", err)
	}
	ownedA, _ := pub.ClaimedDigests(context.Background(), repo, actor, "op-a")
	if _, ok := ownedA[digest]; !ok {
		t.Fatalf("foreign consume cleared operation A's claim, owned=%v", ownedA)
	}
	// A still owns it and completes.
	if err := pub.ConsumeStagedForPublish(context.Background(), repo, actor, "op-a", []string{digest}); err != nil {
		t.Fatalf("owner consume: %v", err)
	}
}

// TestPubClaimSuccessClearsExactOwnedRefsOnly proves consumption removes ONLY
// the rows claimed by the exact operation and referenced by the manifest:
// unrelated finalized rows remain publishable and a different operation's claim
// is untouched.
func TestPubClaimSuccessClearsExactOwnedRefsOnly(t *testing.T) {
	dir := tempPrivate(t)
	pub := openSharedService(t, dir)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fixedClock(pub, now)

	repo, actor := seedRepo, seedActor
	dA := finalizeDigestBlob(t, pub, repo, actor, "aa")
	dB := finalizeDigestBlob(t, pub, repo, actor, "bb")
	dUnrelated := finalizeDigestBlob(t, pub, repo, actor, "cc")

	mustClaim(t, pub, repo, actor, "op-a", []string{dA})
	mustClaim(t, pub, repo, actor, "op-b", []string{dB})

	// Consume op-a referencing dA (plus a bogus extra digest): only the exact
	// op-a claim for dA goes away. dB's claim (op-b) and the unrelated
	// finalized row are untouched.
	if err := pub.ConsumeStagedForPublish(context.Background(), repo, actor, "op-a", []string{dA, "sha256:0000000000000000000000000000000000000000000000000000000000000000"}); err != nil {
		t.Fatalf("consume: %v", err)
	}
	ownedA, _ := pub.ClaimedDigests(context.Background(), repo, actor, "op-a")
	if _, ok := ownedA[dA]; ok {
		t.Fatalf("op-a claim for dA not consumed, owned=%v", ownedA)
	}
	ownedB, _ := pub.ClaimedDigests(context.Background(), repo, actor, "op-b")
	if _, ok := ownedB[dB]; !ok {
		t.Fatalf("op-b claim must survive op-a consume, owned=%v", ownedB)
	}
	live := mustListStaged(t, pub, repo, actor)
	if len(live) != 1 || live[0].Digest != dUnrelated {
		t.Fatalf("unrelated finalized row must remain publishable, got %+v", live)
	}
}

// TestPubClaimGenericDeletingNeverClaimedNorUnpinned proves a generic `deleting`
// tombstone remains non-claimable (a publication referencing it fails closed)
// and non-eligible for cleanup (never unpinned), combined on the same row.
func TestPubClaimGenericDeletingNeverClaimedNorUnpinned(t *testing.T) {
	dir := tempPrivate(t)
	pub := openSharedService(t, dir)
	clean := openSharedService(t, dir)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	fixedClock(pub, now)

	repo, actor := seedRepo, seedActor
	digest, ref := claimPubFinalize(t, pub, repo, actor)

	// Simulate a generic Delete that crashed: tombstone to `deleting` (allowed
	// by the trigger) while still carrying its finalized bee_ref, removal never
	// ran.
	db, err := sql.Open("sqlite", dir+"/staging.db")
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	id := firstSessionID(t, db)
	if _, err := db.Exec(`update upload_sessions set state = 'deleting' where id = ?`, id); err != nil {
		db.Close()
		t.Fatalf("tombstone to deleting: %v", err)
	}
	db.Close()

	// Publication cannot claim a deleting row (fail closed, zero writes).
	if _, err := pub.ClaimStagedForPublish(context.Background(), repo, actor, "op-pub", []string{digest}); !errors.Is(err, ErrClaimConflict) {
		t.Fatalf("claim of deleting row = %v, want ErrClaimConflict", err)
	}
	// Cleanup never unpins the deleting-with-ref row (it is not even a batch
	// candidate).
	fixedClock(clean, now.Add(2*time.Hour))
	unp := &fakeUnpinner{}
	c, err := NewCleanup(clean, unp, &fakeCommitted{})
	if err != nil {
		t.Fatalf("NewCleanup: %v", err)
	}
	res, err := c.RunOnce(context.Background(), now.Add(2*time.Hour), 10)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if res.Unpinned != 0 || res.Removed != 0 {
		t.Fatalf("deleting-with-ref must not be cleaned, res=%+v", res)
	}
	if pins := unp.calls(); len(pins) != 0 {
		t.Fatalf("deleting-with-ref must never be unpinned, got %v", pins)
	}
	_ = ref
}

// TestMigrateV5ToV6 proves the frozen v5 predecessor migrates forward to the v6
// publication-claim surface, preserving every committed row/field exactly and
// staying idempotent across reopens.
func TestMigrateV5ToV6(t *testing.T) {
	gold := mustLoadTestManifest(t, schemaGoldenV5JSON)
	if gold.Version != 5 {
		t.Fatalf("v5 predecessor manifest must be frozen at version 5, got %d", gold.Version)
	}
	if gold.Version == latestSchemaVersion {
		t.Fatalf("v5 must not be the current (v%d) schema", latestSchemaVersion)
	}
	dbPath := fixtureFromGolden(t, gold, func(db *sql.DB) { seedFullLifecycle(t, db) })
	beforeSess := scanSessionsCleanup(t, migRaw(t, dbPath))
	if len(beforeSess) != 4 {
		t.Fatalf("pre-migration session count = %d, want 4", len(beforeSess))
	}

	db, err := migrateThenOpen(t, dbPath)
	if err != nil {
		t.Fatalf("migrate v5: %v", err)
	}
	db.Close()
	if v := versionOf(t, dbPath); v != latestSchemaVersion {
		t.Fatalf("version after migration = %d, want %d", v, latestSchemaVersion)
	}
	after := scanSessionsCleanup(t, migRaw(t, dbPath))
	if len(after) != len(beforeSess) {
		t.Fatalf("session count changed across v5 migration: %d -> %d", len(beforeSess), len(after))
	}
	if fmt.Sprint(migSessKeys(beforeSess)) != fmt.Sprint(migSessKeys(after)) {
		t.Fatalf("session rows not preserved exactly across v5 migration:\nbefore=%s\nafter=%s",
			fmt.Sprint(migSessKeys(beforeSess)), fmt.Sprint(migSessKeys(after)))
	}

	// Reopen is idempotent.
	db2, err := migrateThenOpen(t, dbPath)
	if err != nil {
		t.Fatalf("idempotent reopen: %v", err)
	}
	db2.Close()
	if v := versionOf(t, dbPath); v != latestSchemaVersion {
		t.Fatalf("version drifted on reopen = %d", v)
	}
}

// mustListStaged is a fail-on-error wrapper around the finalized-only listing.
func mustListStaged(t *testing.T, svc *service, repo, actor string) []spec.StagedBlob {
	t.Helper()
	out, err := svc.ListStagedBlobs(context.Background(), repo, actor)
	if err != nil {
		t.Fatalf("ListStagedBlobs: %v", err)
	}
	return out
}

// rawClaimedDigests returns the digests of all `claimed` (publication-owned)
// rows for the repo/actor, read directly from the durable DB by path — the
// introspection that lets fence tests observe surviving claims that are
// invisible to the finalized-only ListStagedBlobs listing.
func rawClaimedDigests(t *testing.T, dbPath, repo, actor string) []string {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw claimed: %v", err)
	}
	defer db.Close()
	rows, err := db.Query(
		`select b.digest from staged_blobs b join upload_sessions u on u.id = b.upload_id
		  where b.repo = ? and b.actor = ? and u.state = 'claimed' order by b.rowid`,
		repo, actor)
	if err != nil {
		t.Fatalf("query claimed: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			t.Fatalf("scan claimed: %v", err)
		}
		out = append(out, d)
	}
	return out
}

// finalizeDigestBlob finalizes ONE blob whose digest is the distinct explicit
// hex key (built as sha256:<64 x key>) — the fixture's shared finalizeArgs
// digest would collapse distinct blobs, so scenario tests needing multiple
// claimable digests use this.
func finalizeDigestBlob(t *testing.T, svc *service, repo, actor, key string) string {
	t.Helper()
	if len(key) != 2 {
		t.Fatalf("key must be 2 hex chars, got %q", key)
	}
	digest := "sha256:" + strings.Repeat(key, 32)
	s := mustCreate(t, svc, repo, actor)
	s = mustAppend(t, svc, s, "bytes-"+key)
	if err := svc.MarkFinalized(context.Background(), s.ID, s.Repo, s.Actor, testTok, digest, strings.Repeat("c", 64), "application/vnd.oci.image.layer.v1.tar+gzip", s.Offset); err != nil {
		t.Fatalf("MarkFinalized(%s): %v", digest, err)
	}
	return digest
}

// firstSessionID returns the first session id in the DB (raw helper).
func firstSessionID(t *testing.T, db *sql.DB) string {
	t.Helper()
	var id string
	if err := db.QueryRow(`select id from upload_sessions order by rowid limit 1`).Scan(&id); err != nil {
		t.Fatalf("first session id: %v", err)
	}
	return id
}
