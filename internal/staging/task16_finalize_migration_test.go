package staging

// Task16 repair — schema v3 -> v4 migration. v4 introduces the durable
// "finalizing" finalization-claim state (a fresh session state value, added to
// the state CHECK, coherence CHECK, and the state/blob triggers) so an upload
// winner can claim a session BEFORE any external object-store write. The v3
// predecessor carries no such state (two concurrent PUTs could both reach Bee);
// migrating preserves every committed row byte-for-byte and never invents a
// finalizing row.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestMigrateV3ToV4 proves the frozen v3 predecessor migrates to the v4
// surface, preserving every committed row/field exactly (no row can be born
// finalizing in v3; the CHECK and state trigger enforce it) and staying
// idempotent across reopens.
func TestMigrateV3ToV4(t *testing.T) {
	gold := mustLoadTestManifest(t, schemaGoldenV3JSON)
	if gold.Version != 3 {
		t.Fatalf("v3 predecessor manifest must be frozen at version 3, got %d", gold.Version)
	}
	dbPath := fixtureFromGolden(t, gold, func(db *sql.DB) { seedFullLifecycle(t, db) })
	beforeSess := scanSessionsCleanup(t, migRaw(t, dbPath))
	beforeBlob := migScanBlobs(t, migRaw(t, dbPath))
	if len(beforeSess) != 4 || len(beforeBlob) != 1 {
		t.Fatalf("pre-migration row counts sessions=%d blobs=%d", len(beforeSess), len(beforeBlob))
	}

	db, err := migrateThenOpen(t, dbPath)
	if err != nil {
		t.Fatalf("migrate v3: %v", err)
	}
	db.Close()

	if v := versionOf(t, dbPath); v != latestSchemaVersion {
		t.Fatalf("version after migration = %d, want %d", v, latestSchemaVersion)
	}
	after := scanSessionsCleanup(t, migRaw(t, dbPath))
	if len(after) != len(beforeSess) {
		t.Fatalf("session count changed across v3 migration: %d -> %d", len(beforeSess), len(after))
	}
	if fmt.Sprint(migSessKeys(beforeSess)) != fmt.Sprint(migSessKeys(after)) {
		t.Fatalf("session rows not preserved exactly across v3 migration:\nbefore=%s\nafter=%s",
			fmt.Sprint(migSessKeys(beforeSess)), fmt.Sprint(migSessKeys(after)))
	}
	blobs := migScanBlobs(t, migRaw(t, dbPath))
	if fmt.Sprint(migBlobKeys(blobs)) != fmt.Sprint(migBlobKeys(beforeBlob)) {
		t.Fatalf("staged blob not preserved byte-for-byte: %+v -> %+v", beforeBlob, blobs)
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

func TestMigrateV3AtomicRollbackAfterCopy(t *testing.T) {
	gold := mustLoadTestManifest(t, schemaGoldenV3JSON)
	dbPath := fixtureFromGolden(t, gold, func(db *sql.DB) { seedFullLifecycle(t, db) })
	beforeSess := scanSessionsCleanup(t, migRaw(t, dbPath))
	beforeBlob := migScanBlobs(t, migRaw(t, dbPath))

	migrationCopyFault = errors.New("injected copy fault")
	t.Cleanup(func() { migrationCopyFault = nil })
	if db, err := migrateThenOpen(t, dbPath); err == nil {
		db.Close()
		t.Fatal("copy fault must abort the v3 migration")
	}
	migrationCopyFault = nil

	// Byte-exact predecessor preserved: version stays 3, every row intact.
	if v := versionOf(t, dbPath); v != 3 {
		t.Fatalf("version after failed v3 migration = %d, want 3", v)
	}
	if tableExists(t, dbPath, "upload_sessions_copy") {
		t.Fatal("temporary rebuild table survived a rolled-back v3 migration")
	}
	afterSess := scanSessionsCleanup(t, migRaw(t, dbPath))
	if fmt.Sprint(migSessKeys(afterSess)) != fmt.Sprint(migSessKeys(beforeSess)) {
		t.Fatalf("session rows changed by a rolled-back v3 migration:\nbefore=%+v\nafter=%+v", beforeSess, afterSess)
	}
	afterBlob := migScanBlobs(t, migRaw(t, dbPath))
	if fmt.Sprint(migBlobKeys(afterBlob)) != fmt.Sprint(migBlobKeys(beforeBlob)) {
		t.Fatalf("blob rows changed by a rolled-back v3 migration: %+v -> %+v", beforeBlob, afterBlob)
	}

	// With the fault cleared the SAME database migrates cleanly to v4.
	db, err := migrateThenOpen(t, dbPath)
	if err != nil {
		t.Fatalf("reopen after fault cleared: %v", err)
	}
	db.Close()
	if v := versionOf(t, dbPath); v != latestSchemaVersion {
		t.Fatalf("post-fault migration version = %d, want %d", v, latestSchemaVersion)
	}
}

// TestMigrateV3ThenClaimFinalized asserts a migrated v4 database accepts a
// finalizing claim (the new state is live), and the claim is serialized (a
// second ClaimFinalize loses). The migration itself is performed by the
// PRODUCTION service open path: NewService over the v3 fixture migrates it to
// v4 before serving, exactly like production startup after an upgrade.
func TestMigrateV3ThenClaimFinalized(t *testing.T) {
	gold := mustLoadTestManifest(t, schemaGoldenV3JSON)
	dir := tempPrivate(t)
	spool := filepath.Join(dir, "spool")
	if err := os.Mkdir(spool, 0o700); err != nil {
		t.Fatalf("mkdir spool: %v", err)
	}
	dbPath := fixtureAt(t, gold, spool) // v3 fixture at dir/staging.db

	svc, err := NewService(context.Background(), spool, dbPath)
	if err != nil {
		t.Fatalf("NewService over v3 fixture (production migration): %v cause=%v", err, causeOf(err))
	}
	defer svc.Close()
	if v := versionOf(t, dbPath); v != latestSchemaVersion {
		t.Fatalf("version after service open = %d, want %d", v, latestSchemaVersion)
	}

	ctx := context.Background()
	s := mustCreate(t, svc, seedRepo, seedActor)
	s = mustAppend(t, svc, s, "payload")
	claimed, err := svc.ClaimFinalize(ctx, s.ID, s.Repo, s.Actor, s.Offset)
	if err != nil {
		t.Fatalf("claim after migration: %v", err)
	}
	if claimed.State != StateFinalizing {
		t.Fatalf("claimed state = %v, want finalizing", claimed.State)
	}
	if _, err := svc.ClaimFinalize(ctx, s.ID, s.Repo, s.Actor, s.Offset); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("second claim must lose, got %v", err)
	}
	if st, _ := svc.Status(ctx, s.ID, s.Repo, s.Actor); st.State != StateFinalizing {
		t.Fatalf("post-migration claim state wrong: %+v", st)
	}
}
