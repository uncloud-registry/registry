package registry

// Task 18 round-2 correction: a verified publication whose production consume
// fails AFTER the claimed -> deleting transition commits (a real
// filesystem/quarantine cleanup fault) must leave a publication-OWNED deleting
// tombstone that keeps operation identity, so an exact retry can never return
// 201 while quota stays stranded. These tests drive the REAL handler over two
// independent durable staging services sharing one DB, faulting the PRODUCTION
// finishDeletion path (never a wrapper before mutation), and prove the owned
// tombstone is withheld on retry until cleanup succeeds, then resumed and
// removed, with zero new object/feed commits and quota demonstrably reusable.
// A distinct operation never clears it; a restart finishes it safely (not
// convert it to publishable).

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"testing"

	"github.com/uncloud-registry/registry/internal/staging"
)

// rawOwnedDeletingTombstones counts publication-owned deleting tombstones
// (state='deleting' with a non-null operation_id) across the DB — the durable
// post-transition residue an exact retry must resume and remove.
func rawOwnedDeletingTombstones(t *testing.T, dbPath, repo string) int {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open owned-deleting: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(
		`select count(*) from upload_sessions u where u.repo = ? and u.state = 'deleting' and u.operation_id is not null`,
		repo).Scan(&n); err != nil {
		t.Fatalf("count owned-deleting: %v", err)
	}
	return n
}

// TestHandlerPostTransitionFaultRetryRemovesOwnedTombstone proves the full
// round-2 invariant through the REAL handler: fault the PRODUCTION
// finishDeletion after the claimed -> deleting transition commits, then show
// that (a) the first exact retry WITHHOLDS 201 with a fixed data-free error
// while durable ownership + quota charge remain, (b) a distinct operation's
// consume never clears it, and (c) after the fault clears, the second exact
// retry resumes/removes the owned tombstone and returns 201 with ZERO new
// object/feed commits and quota demonstrably reusable.
func TestHandlerPostTransitionFaultRetryRemovesOwnedTombstone(t *testing.T) {
	h1, h2, svc1, svc2, docs, feeds, issuer, dbPath, url1, url2 := twoActorDurableWorld(t)
	committer := &generationCommitter{feeds: feeds, docs: docs}
	h1.Publisher.Commits = committer
	h2.Publisher.Commits = committer
	h1Objs := &countingObjectUploader{inner: h1.Publisher.Objects}
	h1.Publisher.Objects = h1Objs
	h2Objs := &countingObjectUploader{inner: h2.Publisher.Objects}
	h2.Publisher.Objects = h2Objs
	_ = url1
	_ = svc1

	// Alice stages the config blob the manifest will reference.
	configBytes := configFor("amd64")
	configDigest := stageBlobAs(t, url2, issuer, "user:alice", configBytes, "application/vnd.oci.image.config.v1+json")
	manifestBody := manifestFor(configDigest, len(configBytes))

	// Install the PRODUCTION finishDeletion fault on the service h2 uses. This
	// faults the real directory/file-sync inside finishDeletion — which runs
	// ONLY AFTER the claimed -> publication-owned-deleting transition commits.
	staging.FaultFinishDeletionForTest(svc2)

	// Alice publishes via h2: commit + verify succeed, the claimed->deleting
	// transition commits, then production finishDeletion faults -> 500. The row
	// is now a publication-owned deleting tombstone (operation identity kept).
	first := putManifestAs(t, url2, issuer, "user:alice", "latest", manifestBody)
	firstBody, _ := io.ReadAll(first.Body)
	first.Body.Close()
	if first.StatusCode != http.StatusInternalServerError {
		t.Fatalf("faulted finishDeletion must surface 500, got %d (%s)", first.StatusCode, firstBody)
	}
	if code, msg := decodeErrorPayload(t, firstBody); code != ErrorCodeInternal || msg != messageUnknown {
		t.Fatalf("faulted publish error surface = (%s, %q), want (UNKNOWN, internal error)", code, msg)
	}
	if n := rawOwnedDeletingTombstones(t, dbPath, "backend/api"); n != 1 {
		t.Fatalf("post-transition fault must leave exactly one owned deleting tombstone, got %d", n)
	}
	if n := rawClaimedRows(t, dbPath, "backend/api", "user:alice"); n != 0 {
		t.Fatalf("the claimed row must have transitioned to deleting, alice claimed rows = %d (want 0)", n)
	}
	feedRef := feeds.Feeds[repoStateFeed()]
	if feedRef == "" {
		t.Fatal("the faulted publication must still have advanced the feed (commit happened)")
	}
	commitsAfterFirst, _ := committer.count()
	putsAfterFirst := h2Objs.puts

	// FIRST exact retry by Bob (the SAME exact publication): the fault is still
	// on, so the fast-path consume resumes the owned tombstone and AGAIN fails
	// its finishDeletion -> the retry MUST withhold 201 (500, fixed data-free
	// message) and leave the durable ownership + quota charge intact.
	r1 := putManifestAs(t, url2, issuer, "user:bob", "latest", manifestBody)
	r1Body, _ := io.ReadAll(r1.Body)
	r1.Body.Close()
	if r1.StatusCode != http.StatusInternalServerError {
		t.Fatalf("first exact retry under lingering clean fault must withhold 201 with 500, got %d (%s)", r1.StatusCode, r1Body)
	}
	if code, msg := decodeErrorPayload(t, r1Body); code != ErrorCodeInternal || msg != messageUnknown {
		t.Fatalf("withheld retry error surface = (%s, %q), want (UNKNOWN, internal error)", code, msg)
	}
	if n := rawOwnedDeletingTombstones(t, dbPath, "backend/api"); n != 1 {
		t.Fatalf("withheld retry must retain the owned tombstone, got %d", n)
	}
	if feeds.Feeds[repoStateFeed()] != feedRef {
		t.Fatal("withheld retry must not advance the feed")
	}
	if c, _ := committer.count(); c != commitsAfterFirst {
		t.Fatalf("withheld retry committed again: %d commits (want %d)", c, commitsAfterFirst)
	}
	if h2Objs.puts != putsAfterFirst {
		t.Fatalf("withheld retry performed %d new object writes (want 0)", h2Objs.puts-putsAfterFirst)
	}

	// DISTINCT-OPERATION negative: a consume for a foreign operation must be a
	// pure no-op and must NEVER clear the owned tombstone.
	if err := svc2.ConsumeStagedForPublish(context.Background(), "backend/api", "user:bob", "foreign-op", []string{configDigest}); err != nil {
		t.Fatalf("foreign-operation consume errored: %v", err)
	}
	if n := rawOwnedDeletingTombstones(t, dbPath, "backend/api"); n != 1 {
		t.Fatalf("foreign-operation consume must not clear the owned tombstone, got %d", n)
	}

	// SECOND exact retry after the fault clears: the owned tombstone is resumed
	// and durably removed, and 201 is returned with ZERO new commits/writes.
	staging.ClearFinishDeletionFaultForTest(svc2)
	r2 := putManifestAs(t, url2, issuer, "user:bob", "latest", manifestBody)
	r2Body, _ := io.ReadAll(r2.Body)
	opID := r2.Header.Get(OperationIDHeader)
	r2.Body.Close()
	if r2.StatusCode != http.StatusCreated {
		t.Fatalf("exact retry must return verified 201, got %d (%s)", r2.StatusCode, r2Body)
	}
	if opID == "" {
		t.Fatal("verified 201 must carry the operation identity")
	}
	if n := rawOwnedDeletingTombstones(t, dbPath, "backend/api"); n != 0 {
		t.Fatalf("exact retry must remove the owned tombstone, %d owned-deleting rows remain", n)
	}
	if n := rawClaimedRows(t, dbPath, "backend/api", "user:alice"); n != 0 {
		t.Fatalf("quota must be fully released, alice claimed rows = %d (want 0)", n)
	}
	if feeds.Feeds[repoStateFeed()] != feedRef {
		t.Fatal("successful retry must not advance the feed")
	}
	if c, _ := committer.count(); c != commitsAfterFirst {
		t.Fatalf("successful retry committed again: %d commits (want %d)", c, commitsAfterFirst)
	}
	if h2Objs.puts != putsAfterFirst {
		t.Fatalf("successful retry performed %d new object writes (want 0)", h2Objs.puts-putsAfterFirst)
	}

	// QUOTA DEMONSTRABLY REUSABLE: a fresh independent publication with a new
	// digest (not the fast-path replay of the same manifest) must succeed.
	secondConfig := configFor("arm64")
	secondDigest := stageBlobAs(t, url2, issuer, "user:alice", secondConfig, "application/vnd.oci.image.config.v1+json")
	secondManifest := manifestFor(secondDigest, len(secondConfig))
	fresh := putManifestAs(t, url2, issuer, "user:alice", "next", secondManifest)
	freshBody, _ := io.ReadAll(fresh.Body)
	stage2 := fresh.StatusCode
	fresh.Body.Close()
	if stage2 != http.StatusCreated {
		t.Fatalf("fresh publication must reuse released quota with 201, got %d (%s)", stage2, freshBody)
	}
}

// TestHandlerRestartFinishesOwnedTombstoneNotRepublishable proves a process
// restart (a fresh durable staging service over the same DB) safely finishes
// a verified-publication-owned deleting tombstone via startup reconciliation —
// freeing quota — WITHOUT converting it back to a publishable (claimed) state.
func TestHandlerRestartFinishesOwnedTombstoneNotRepublishable(t *testing.T) {
	h1, h2, _, svc2, docs, feeds, issuer, dbPath, _, url2 := twoActorDurableWorld(t)
	committer := &generationCommitter{feeds: feeds, docs: docs}
	h1.Publisher.Commits = committer
	h2.Publisher.Commits = committer

	configBytes := configFor("amd64")
	configDigest := stageBlobAs(t, url2, issuer, "user:alice", configBytes, "application/vnd.oci.image.config.v1+json")
	manifestBody := manifestFor(configDigest, len(configBytes))

	staging.FaultFinishDeletionForTest(svc2)
	first := putManifestAs(t, url2, issuer, "user:alice", "latest", manifestBody)
	first.Body.Close()
	if first.StatusCode != http.StatusInternalServerError {
		t.Fatalf("faulted publish must surface 500, got %d", first.StatusCode)
	}
	if n := rawOwnedDeletingTombstones(t, dbPath, "backend/api"); n != 1 {
		t.Fatalf("post-transition fault must leave one owned tombstone, got %d", n)
	}

	// RESTART: a fresh durable service over the SAME DB. Startup reconciliation
	// runs over the owned deleting tombstone. (The prior handler stayed
	// untouched; h2 switches to the restarted service.)
	if err := svc2.ConsumeStagedForPublish(context.Background(), "backend/api", "user:bob", "not-the-publication-op", []string{configDigest}); err != nil {
		t.Fatalf("foreign-op consume errored: %v", err)
	}
	if n := rawOwnedDeletingTombstones(t, dbPath, "backend/api"); n != 1 {
		t.Fatalf("foreign-op consume must keep the owned tombstone before restart, got %d", n)
	}

	restarted := durableRestartService(t, dbPath)
	if n := rawOwnedDeletingTombstones(t, dbPath, "backend/api"); n != 0 {
		t.Fatalf("restart reconciliation must finish the owned tombstone, %d owned-deleting rows remain", n)
	}
	if n := rawClaimedRows(t, dbPath, "backend/api", "user:alice"); n != 0 {
		t.Fatalf("restart must not convert the owned tombstone back to publishable, alice claimed = %d", n)
	}

	// A subsequent exact retry (now via the restarted service) returns verified
	// 201 with nothing left stranded.
	h2.Staging = restarted
	r := putManifestAs(t, url2, issuer, "user:bob", "latest", manifestBody)
	rBody, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("post-restart exact retry must return 201, got %d (%s)", r.StatusCode, rBody)
	}
	if n := rawOwnedDeletingTombstones(t, dbPath, "backend/api"); n != 0 {
		t.Fatalf("post-restart retry must leave zero owned tombstones, got %d", n)
	}
}

// durableRestartService opens a fresh durable staging service over the same DB
// (a process restart), returning the new RegistryStore for handler wiring.
func durableRestartService(t *testing.T, dbPath string) staging.RegistryStore {
	t.Helper()
	spool := durableTempDir(t) + "/spool"
	s, err := staging.NewService(context.Background(), spool, dbPath)
	if err != nil {
		t.Fatalf("restart NewService over %s: %v", dbPath, err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
