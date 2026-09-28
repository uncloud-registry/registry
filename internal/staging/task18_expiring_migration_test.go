package staging

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Task 18 correction: schema v4 -> v5 migration. v5 introduces the cleanup-
// owned `expiring` state value (added to the state CHECK, coherence CHECK, and
// the state-transition trigger) so a distinct durable tombstone proves cleanup
// ownership and a generic Delete/Expire `deleting` tombstone is never mis-read
// as cleanup-eligible. The v4 predecessor carries no such state; migrating
// preserves every committed row/field byte-for-byte and never invents an
// expiring row.
// ---------------------------------------------------------------------------

// TestMigrateV4ToV5 proves the frozen v4 predecessor migrates to the v5
// surface, preserving every committed row/field exactly and staying idempotent
// across reopens.
func TestMigrateV4ToV5(t *testing.T) {
	gold := mustLoadTestManifest(t, schemaGoldenV4JSON)
	if gold.Version != 4 {
		t.Fatalf("v4 predecessor manifest must be frozen at version 4, got %d", gold.Version)
	}
	if gold.Version == latestSchemaVersion {
		t.Fatalf("v4 must not be the current (v%d) schema", latestSchemaVersion)
	}
	dbPath := fixtureFromGolden(t, gold, func(db *sql.DB) { seedFullLifecycle(t, db) })
	beforeSess := scanSessionsCleanup(t, migRaw(t, dbPath))
	if len(beforeSess) != 4 {
		t.Fatalf("pre-migration session count = %d, want 4", len(beforeSess))
	}

	db, err := migrateThenOpen(t, dbPath)
	if err != nil {
		t.Fatalf("migrate v4: %v", err)
	}
	db.Close()
	if v := versionOf(t, dbPath); v != latestSchemaVersion {
		t.Fatalf("version after migration = %d, want %d", v, latestSchemaVersion)
	}
	after := scanSessionsCleanup(t, migRaw(t, dbPath))
	if len(after) != len(beforeSess) {
		t.Fatalf("session count changed across v4 migration: %d -> %d", len(beforeSess), len(after))
	}
	if fmt.Sprint(migSessKeys(beforeSess)) != fmt.Sprint(migSessKeys(after)) {
		t.Fatalf("session rows not preserved exactly across v4 migration:\nbefore=%s\nafter=%s",
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

// TestMigrateV4ThenExpiringIsLive proves the new expiring claim is actionable
// after a real production startup migration (NewService over an empty v4
// database), and that the expiring transition is enforced by the upgraded
// schema: a user Delete of an expiring claim fails closed, and the claim is
// never re-purposed back to a live state.
func TestMigrateV4ThenExpiringIsLive(t *testing.T) {
	gold := mustLoadTestManifest(t, schemaGoldenV4JSON)
	dir := tempPrivate(t)
	spool := filepath.Join(dir, "spool")
	if err := os.Mkdir(spool, 0o700); err != nil {
		t.Fatalf("mkdir spool: %v", err)
	}
	dbPath := filepath.Join(dir, "staging.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	for _, o := range gold.Objects {
		if _, err := db.Exec(o.SQL); err != nil {
			db.Close()
			t.Fatalf("fixture object %s: %v", o.Name, err)
		}
	}
	if _, err := db.Exec(`insert into staging_schema (version, applied_at) values (4, 1)`); err != nil {
		db.Close()
		t.Fatalf("version row: %v", err)
	}
	db.Close()

	svc, err := NewService(context.Background(), spool, dbPath)
	if err != nil {
		t.Fatalf("NewService over v4 fixture (production migration): %v cause=%v", err, causeOf(err))
	}
	defer svc.Close()
	if v := versionOf(t, dbPath); v != latestSchemaVersion {
		t.Fatalf("version after service open = %d, want %d", v, latestSchemaVersion)
	}

	ctx := context.Background()
	s := mustCreate(t, svc, seedRepo, seedActor)
	s = mustAppend(t, svc, s, "payload")
	dg, ref, media, size := finalizeArgs(s)
	mustFinalize(t, svc, s, dg, ref, media, size)
	var cand cleanupCandidate
	if err := svc.claimExpiring(ctx, s.ID, &cand); err != nil {
		t.Fatalf("claimExpiring on migrated v5: %v", err)
	}
	if !cand.expiring || cand.beeRef != ref {
		t.Fatalf("expiring claim on migrated v5 = %+v, want beeRef %q", cand, ref)
	}
	if st, _ := svc.Status(ctx, s.ID, s.Repo, s.Actor); st.State != StateExpiring {
		t.Fatalf("claimed state = %v, want expiring", st.State)
	}
	if err := svc.Delete(ctx, s.ID, s.Repo, s.Actor); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Delete of expiring claim = %v, want ErrInvalidState", err)
	}
	db2, _ := sql.Open("sqlite", dbPath)
	defer db2.Close()
	if _, err := db2.Exec(`update upload_sessions set state = 'finalized' where id = ?`, s.ID); err == nil {
		t.Fatal("expiring claim must not be re-purposed back to finalized")
	}
}