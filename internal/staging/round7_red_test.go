package staging

// Round 7 RED probes: deterministic barriers demonstrating the FINAL
// window of the check-then-name filesystem cleanup that repair 4 replaces.
// Every service mutation that can rename/delete a spool entry is serialized
// with BEGIN IMMEDIATE, and deletion is performed by atomically quarantining
// the CURRENT occupant, authenticating it against the durable/observed
// identity, and unlinking the private quarantine name under the same lock.
// These probes run against HEAD (where the direct name-removal windows still
// exist) to capture RED evidence; they pass once the atomic quarantine
// protocol lands. No deliberately failing tests are committed.

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRound7REDTokenSwapAtCleanupWindowPreserved proves the post-activation
// token sidecar is NEVER unlinked by its mutable managed name: a foreign file
// swapped into <id>.tok between the committed activation and the sidecar
// removal must be preserved exactly, and the committed session returned
// truthfully. RED on HEAD: the pre-fix Phase R unlinks <id>.tok by name with
// no final identity re-check, deleting the swapped-in foreign file.
func TestRound7REDTokenSwapAtCleanupWindowPreserved(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()

	var sid string
	svc.postActivateHook = func() {
		entries, err := os.ReadDir(filepath.Join(dir, "spool"))
		if err != nil {
			t.Fatal(err)
		}
		for _, en := range entries {
			if strings.HasSuffix(en.Name(), ".tok") {
				sid = strings.TrimSuffix(en.Name(), ".tok")
				break
			}
		}
		if sid == "" {
			t.Fatal("no token file at the post-activation hook")
		}
		// Replace the real sidecar with a foreign file of the same lobe size.
		tokPath := filepath.Join(dir, "spool", sid+".tok")
		aside := filepath.Join(dir, "spool", "_saved.tok")
		if err := os.Rename(tokPath, aside); err != nil {
			t.Fatal(err)
		}
		foreign := make([]byte, creatingTokenLen)
		for i := range foreign {
			foreign[i] = 'X'
		}
		if err := os.WriteFile(tokPath, foreign, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	s, err := svc.Create(ctx, "backend/api", "user:alice", time.Hour)
	if err != nil {
		t.Fatalf("RED: a committed activation must be returned truthfully even when sidecar cleanup sees a swapped file: %v", err)
	}
	if sid == "" || s.ID != sid {
		t.Fatalf("RED: session id mismatch sid=%q session=%q", sid, s.ID)
	}

	// The swapped-in foreign sidecar must SURVIVE with its exact bytes.
	got, rerr := os.ReadFile(filepath.Join(dir, "spool", sid+".tok"))
	if rerr != nil {
		t.Fatalf("RED: sidecar cleanup removed/renamed the swapped foreign file: %v", rerr)
	}
	if len(got) != creatingTokenLen {
		t.Fatalf("RED: foreign sidecar length changed: %d", len(got))
	}
	for _, b := range got {
		if b != 'X' {
			t.Fatal("RED: foreign sidecar content mutated")
		}
	}

	// The committed session is still live and its payload usable.
	st, err := svc.Status(ctx, s.ID, s.Repo, s.Actor)
	if err != nil || st.State != StateActive {
		t.Fatalf("RED: committed session not live: %v state=%s", err, st.State)
	}
}

// TestRound7REDCanonicalSwapAtQuarantineBoundaryPreserved proves the commanda
// payload file is NEVER deleted by its mutable managed name during Delete:
// a foreign file swapped into <id> at the pre-rename boundary must be
// preserved non-clobberingly and the deletion must retain the tombstone and
// fail closed. RED on HEAD: the pre-fix removeFiles unlinks <id> by name with
// only a SameFile check immediately before, and there is no hook at all, so
// the barrier is ignored and Delete removes the real file.
func TestRound7REDCanonicalSwapAtQuarantineBoundaryPreserved(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "doomed")

	canonPath := filepath.Join(dir, "spool", s.ID)
	saved := filepath.Join(dir, "spool", "_saved")
	swapped := false

	svc.quarantineBarrier = func(phase, name string) {
		if phase != "pre-rename" || name != s.ID {
			return
		}
		if swapped {
			return
		}
		swapped = true
		if err := os.Rename(canonPath, saved); err != nil {
			t.Fatal(err)
		}
		// Foreign payload of the EXACT committed size (offset) to defeat
		// size-based provenance.
		if err := os.WriteFile(canonPath, []byte("capital-f"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	err := svc.Delete(ctx, s.ID, s.Repo, s.Actor)
	if err == nil || !errors.Is(err, ErrDependency) {
		svc.quarantineBarrier = nil
		t.Fatalf("RED: Delete must fail closed (preserve the foreign occupant + retain tombstone), got %v", err)
	}
	svc.quarantineBarrier = nil
	if !swapped {
		t.Fatal("RED: quarantine barrier never fired")
	}

	// The foreign occupant is preserved (non-clobbering restore) at <id>.
	got, rerr := os.ReadFile(canonPath)
	if rerr != nil || string(got) != "capital-f" {
		t.Fatalf("RED: foreign occupant lost: %q err=%v", got, rerr)
	}
	// The real file (moved aside by the test) is untouched.
	savedBytes, serr := os.ReadFile(saved)
	if serr != nil || string(savedBytes) != "doomed" {
		t.Fatalf("RED: real payload damaged: %q err=%v", savedBytes, serr)
	}
	stateOfRow(t, filepath.Join(dir, "staging.db"), s.ID, "deleting")
}

// TestRound7REDCanonicalSwapAtFinalUnlinkPreserved proves the quarantine
// name is re-authenticated immediately before the final unlink (the final
// replacement window): a foreign file swapped into the quarantine right
// before unlink is detected and preserved. RED on HEAD: there is no barrier
// and the payload is removed by name.
func TestRound7REDCanonicalSwapAtFinalUnlinkPreserved(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "doomed")

	qPath := filepath.Join(dir, "spool", quarantineNameFor(s.ID))
	saved := filepath.Join(dir, "spool", "_saved2")
	swapped := false

	svc.quarantineBarrier = func(phase, name string) {
		if phase != "pre-unlink" || name != quarantineNameFor(s.ID) {
			return
		}
		if swapped {
			return
		}
		swapped = true
		// Swap what the quarantine name now denotes, exactly as the final
		// identity re-check must catch.
		if err := os.Rename(qPath, saved); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(qPath, []byte("evil-bytes-here"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	err := svc.Delete(ctx, s.ID, s.Repo, s.Actor)
	if err == nil || !errors.Is(err, ErrDependency) {
		svc.quarantineBarrier = nil
		t.Fatalf("RED: final-window swap must be detected and fail closed, got %v", err)
	}
	svc.quarantineBarrier = nil
	if !swapped {
		t.Fatal("RED: final-unlink barrier never fired")
	}
	// The swapped-in occupant is detected and NEVER unlinked: the quarantine
	// protocol restores it non-clobberingly to the (now free) managed name.
	if got, rerr := os.ReadFile(filepath.Join(dir, "spool", s.ID)); rerr != nil || string(got) != "evil-bytes-here" {
		t.Fatalf("RED: swapped-in occupant was unlinked or mutated: %q err=%v", got, rerr)
	}
	// The quarantine name is drained by the restore; the real payload the test
	// moved aside is untouched.
	if _, rerr := os.Lstat(qPath); !os.IsNotExist(rerr) {
		t.Fatalf("RED: quarantine name not drained by restore: err=%v", rerr)
	}
	savedBytes, serr := os.ReadFile(saved)
	if serr != nil || string(savedBytes) != "doomed" {
		t.Fatalf("RED: real payload damaged: %q err=%v", savedBytes, serr)
	}
	stateOfRow(t, filepath.Join(dir, "staging.db"), s.ID, "deleting")
}

// TestRound7REDQuarantineDestinationCollisionFailsClosed proves a rename
// into quarantine NEVER clobbers an occupied quarantine destination (POSIX
// rename would replace it): the foreign destination and the real payload are
// both preserved and the deletion fails closed. RED on HEAD: the direct
// removeFiles has no quarantine destination, so Delete succeeds and removes
// the real payload.
func TestRound7REDQuarantineDestinationCollisionFailsClosed(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "doomed")

	qPath := filepath.Join(dir, "spool", quarantineNameFor(s.ID))
	if err := os.WriteFile(qPath, []byte("occupied-dest"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := svc.Delete(ctx, s.ID, s.Repo, s.Actor)
	if err == nil || !errors.Is(err, ErrDependency) {
		t.Fatalf("RED: occupied quarantine destination must fail closed (never clobber), got %v", err)
	}
	// Both the real payload and the occupied destination survive.
	if got, rerr := os.ReadFile(qPath); rerr != nil || string(got) != "occupied-dest" {
		t.Fatalf("RED: occupied quarantine destination was clobbered: %q err=%v", got, rerr)
	}
	if got, rerr := os.ReadFile(filepath.Join(dir, "spool", s.ID)); rerr != nil || string(got) != "doomed" {
		t.Fatalf("RED: real payload damaged by collision: %q err=%v", got, rerr)
	}
	stateOfRow(t, filepath.Join(dir, "staging.db"), s.ID, "deleting")
}

// stateOfRow asserts the current state column of an upload_sessions row.
func stateOfRow(t *testing.T, dbPath, id, want string) {
	t.Helper()
	db, err := sqlOpenForTest(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	var state sql.NullString
	if err := db.QueryRow(`select state from upload_sessions where id = ?`, id).Scan(&state); err != nil {
		t.Fatalf("query state for %s: %v", id, err)
	}
	if !state.Valid || state.String != want {
		t.Fatalf("state of row %s = %q, want %q", id, state.String, want)
	}
}
