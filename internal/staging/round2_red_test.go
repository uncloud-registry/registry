package staging

// Round 2 RED probe: behavioral checks for the eight review areas, run
// against the pre-fix code to capture RED evidence before implementation.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// RED 1: concurrent Expire over the same expired row must sum to exactly 1.
func TestRound2REDExpireBarrierSumIsOne(t *testing.T) {
	dir := tempPrivate(t)
	spoolDir := filepath.Join(dir, "spool")
	dbPath := filepath.Join(dir, "staging.db")
	svcA, err := NewService(context.Background(), spoolDir, dbPath)
	if err != nil {
		t.Fatalf("A: %v", err)
	}
	defer svcA.Close()
	svcB, err := NewService(context.Background(), spoolDir, dbPath)
	if err != nil {
		t.Fatalf("B: %v", err)
	}
	defer svcB.Close()

	ctx := context.Background()
	now := time.Now().UTC()
	fixedClock(svcA, now.Add(-10*time.Minute))
	s, err := svcA.Create(ctx, "backend/api", "user:alice", time.Minute)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	future := now.Add(time.Hour)

	// Both instances SELECT the same expired row before either tombstones.
	idsA, err := svcA.expiredIDs(ctx, future.UnixNano(), 10)
	if err != nil || len(idsA) != 1 || idsA[0] != s.ID {
		t.Fatalf("A selected %v err=%v", idsA, err)
	}
	idsB, err := svcB.expiredIDs(ctx, future.UnixNano(), 10)
	if err != nil || len(idsB) != 1 || idsB[0] != s.ID {
		t.Fatalf("B selected %v err=%v", idsB, err)
	}

	var wg sync.WaitGroup
	counts := make([]int, 2)
	var errs [2]error
	for i, svc := range []*service{svcA, svcB} {
		wg.Add(1)
		go func(i int, svc *service) {
			defer wg.Done()
			counts[i], errs[i] = svc.Expire(ctx, future, 10)
		}(i, svc)
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil {
		t.Fatalf("expire errors: %v %v", errs[0], errs[1])
	}
	if counts[0]+counts[1] != 1 {
		t.Fatalf("aggregate expire count = %d, want exactly 1 (row deleted once)", counts[0]+counts[1])
	}
	if _, err := svcA.Status(ctx, s.ID, s.Repo, s.Actor); !errors.Is(err, ErrNotFound) {
		t.Fatalf("row survived: %v", err)
	}
}

// RED 2: creating recovery must refuse an attacker-planted empty file.
func TestRound2REDAttackerPlantedEmptyFileNotAdopted(t *testing.T) {
	dir := tempPrivate(t)
	spoolDir := filepath.Join(dir, "spool")
	dbPath := filepath.Join(dir, "staging.db")
	seed, err := NewService(context.Background(), spoolDir, dbPath)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	seed.Close()

	id := strings.Repeat("d", 64)
	created := time.Now().Add(-time.Hour).UTC()
	db, err := sqlOpenForTest(dbPath)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at, create_token) values (?, 'backend/api', 'user:alice', 'creating', 0, ?, ?, ?)`,
		id, created.UnixNano(), created.Add(time.Hour).UnixNano(), strings.Repeat("1", 64)); err != nil {
		t.Fatalf("seed creating row: %v", err)
	}
	db.Close()
	// Attacker plants an EMPTY canonical file (no token lobe).
	planted := filepath.Join(spoolDir, id)
	if err := os.WriteFile(planted, nil, 0o600); err != nil {
		t.Fatalf("plant: %v", err)
	}

	svc, err := NewService(context.Background(), spoolDir, dbPath)
	if err == nil {
		svc.Close()
		t.Fatal("startup adopted an unattributable empty file as a live session")
	}
	if !errors.Is(err, ErrDependency) {
		t.Fatalf("startup error: %v, want ErrDependency", err)
	}
	// The file must be untouched.
	fi, err := os.Lstat(planted)
	if err != nil || fi.Size() != 0 {
		t.Fatalf("attacker file was modified/removed: %v size=%v", err, fi.Size())
	}
}

// RED 3: Delete on a wrong-owner session must be idempotent nil, identical to
// deleting a truly absent id.
func TestRound2REDDeleteAbsentEqualsWrongOwner(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	missing := strings.Repeat("c", 64)

	absentErr := svc.Delete(ctx, missing, "backend/api", "user:alice")
	wrongOwnerErr := svc.Delete(ctx, s.ID, "other/app", "user:alice")
	if absentErr != wrongOwnerErr {
		t.Fatalf("absent=%v wrongOwner=%v, want identical nil", absentErr, wrongOwnerErr)
	}
	if absentErr != nil {
		t.Fatalf("idempotent delete of absent row must be nil, got %v", absentErr)
	}
	if st, err := svc.Status(ctx, s.ID, s.Repo, s.Actor); err != nil || st.State != StateActive {
		t.Fatalf("wrong-owner delete damaged the session: %+v %v", st, err)
	}
}

// RED 4: spool file mode must be exact 0600 even when the file drifts.
func TestRound2REDModeDriftRepair(t *testing.T) {
	dir := tempPrivate(t)
	rootPath := filepath.Join(dir, "spool")
	sp, err := newSpool(context.Background(), rootPath)
	if err != nil {
		t.Fatalf("newSpool: %v", err)
	}
	defer sp.Close()
	id := validTestID()
	f, err := sp.create(id)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	f.Close()
	if err := os.Chmod(filepath.Join(rootPath, id), 0o644); err != nil {
		t.Fatalf("chmod 0644: %v", err)
	}
	r, err := sp.openForRead(id, 0)
	if err != nil {
		t.Fatalf("openForRead on drifted mode: %v", err)
	}
	r.Close()
	fi, err := os.Lstat(filepath.Join(rootPath, id))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode after open = %v, want 0600", fi.Mode().Perm())
	}
}

// RED 6: intermediate symlink with existing descendants must be rejected.
func TestRound2REDIntermediateSymlinkWithDescendants(t *testing.T) {
	dir := tempPrivate(t)
	real := filepath.Join(dir, "real")
	if err := os.MkdirAll(filepath.Join(real, "nested", "spool"), 0o700); err != nil {
		t.Fatalf("mkdir real: %v", err)
	}
	if err := os.WriteFile(filepath.Join(real, "nested", "spool", "keep"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if sp, err := newSpool(context.Background(), filepath.Join(link, "nested", "spool")); err == nil {
		sp.Close()
		t.Fatal("newSpool followed an intermediate symlink with existing descendants")
	}
	if _, err := os.Lstat(filepath.Join(real, "nested", "spool", "keep")); err != nil {
		t.Fatalf("target was modified: %v", err)
	}
}
