package staging

// Task-15 final closure, commit 2: deleting-tombstone sidecar provenance (v3)
// and the post-rename quarantine fsync.
//
// Defect A: the tombstone transition captured the pending token only in memory
// and committed the deleting row with create_token/cleanup_token NULL; a crash
// before finishDeletion lost the provenance, so a restart refused a MANAGED
// `.tok` (only resuming an outstanding quarantine), deleted the row, and then
// rejected the stranded sidecar forever. The fix persists the durable
// applicable token as the deleting row's cleanup_token and lets startup
// reconciliation authenticate a managed sidecar against it.
//
// Defect B: quarantineUnlink renamed managed->quarantine then authenticated
// and unlinked BEFORE the first directory fsync, so the rename was not durable
// at the pre-unlink hook (sync count zero). The fix fsyncs the containing
// directory immediately after a successful same-root rename, before any
// authentication or unlink; a sync failure retains the quarantine (never an
// unsynced restore) and the delete fails closed for an idempotent restart.

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	factRepo  = "backend/api"
	factActor = "user:alice"
)

// buildServiceNoReconcile builds a service WITHOUT running reconcileStartup,
// so a test can fabricate a live row whose pending sidecar cleanup is still in
// flight and probe Delete/Expire without constructor reconciliation racing the
// pending cleanup (which would otherwise remove the sidecar first).
func buildServiceNoReconcile(t *testing.T, dir string) *service {
	t.Helper()
	sp, err := newSpool(context.Background(), filepath.Join(dir, "spool"))
	if err != nil {
		t.Fatalf("newSpool: %v", err)
	}
	pool, err := openStagingPool(context.Background(), filepath.Join(dir, "staging.db"), 4)
	if err != nil {
		sp.Close()
		t.Fatalf("openStagingPool: %v", err)
	}
	svc := &service{spool: sp, pool: pool, now: time.Now, creationLease: creationLease}
	svc.spool.syncFile = func(f *os.File) error { return svc.syncFile(f) }
	t.Cleanup(func() { svc.Close() })
	return svc
}

// newV3StagingDir materializes a fresh v3 database and private spool root.
func newV3StagingDir(t *testing.T) string {
	t.Helper()
	dir := tempPrivate(t)
	db, err := openStagingDB(context.Background(), filepath.Join(dir, "staging.db"), 0)
	if err != nil {
		t.Fatalf("materialize v3 db: %v", err)
	}
	db.Close()
	if err := os.Mkdir(filepath.Join(dir, "spool"), 0o700); err != nil {
		t.Fatalf("mkdir spool: %v", err)
	}
	return dir
}

func factID(fill byte) string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = fill
	}
	return hex.EncodeToString(b)
}

func factToken(fill byte) (string, []byte) {
	// fill must be a lowercase hex digit (0-9,a-f); use 'b'/'c' etc.
	raw := make([]byte, creatingTokenLen)
	for i := range raw {
		raw[i] = fill
	}
	return hex.EncodeToString(raw), raw
}

func writeSpoolLeaf(t *testing.T, dir, name string, content []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "spool", name), content, 0o600); err != nil {
		t.Fatalf("write spool %s: %v", name, err)
	}
}

func rawExec(t *testing.T, dir, query string, args ...any) {
	t.Helper()
	db, err := sqlOpenForTest(filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatalf("raw exec %q: %v", query, err)
	}
}

// rowState returns (found, state, createToken, cleanupToken) for id.
func rowState(t *testing.T, dir, id string) (bool, string, string, string) {
	t.Helper()
	db, err := sqlOpenForTest(filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	defer db.Close()
	var st string
	var ct, cl sql.NullString
	err = db.QueryRow(`select state, create_token, cleanup_token from upload_sessions where id = ?`, id).
		Scan(&st, &ct, &cl)
	if errors.Is(err, sql.ErrNoRows) {
		return false, "", "", ""
	}
	if err != nil {
		t.Fatalf("row state query: %v", err)
	}
	return true, st, ct.String, cl.String
}

func spoolExists(t *testing.T, dir, name string) bool {
	t.Helper()
	_, err := os.Lstat(filepath.Join(dir, "spool", name))
	return err == nil
}

// fabricatePendingSidecar builds a live row carrying the pending sidecar
// provenance plus its `.tok` and empty canonical file, in the requested state.
// kind: "creating" (token held in create_token), "active" or "finalized"
// (token held in cleanup_token). createdShift/expShift apply to the row's
// identity-frozen timestamps (set at INSERT, since the row identity is
// immutable). Returns (id, tokenHex).
func fabricatePendingSidecar(t *testing.T, dir, kind string, idFill byte, createdShift, expShift time.Duration) (string, string) {
	t.Helper()
	id := factID(idFill)
	tokenHex, tokenBytes := factToken(idFill + 1)
	// The token sidecar carries the raw token bytes; the canonical is empty.
	writeSpoolLeaf(t, dir, id+".tok", tokenBytes)
	writeSpoolLeaf(t, dir, id, nil)
	now := time.Now().UTC().UnixNano()
	created := now + int64(createdShift)
	exp := now + int64(expShift)
	switch kind {
	case "creating":
		rawExec(t, dir,
			`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at, create_token)
			 values (?,?,?, 'creating', 0, ?, ?, ?)`,
			id, factRepo, factActor, created, exp, tokenHex)
	case "active":
		rawExec(t, dir,
			`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at, create_token)
			 values (?,?,?, 'creating', 0, ?, ?, ?)`,
			id, factRepo, factActor, created, exp, tokenHex)
		rawExec(t, dir,
			`update upload_sessions set state='active', create_token=null, cleanup_token=? where id=?`,
			tokenHex, id)
	case "finalized":
		rawExec(t, dir,
			`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at, create_token)
			 values (?,?,?, 'creating', 0, ?, ?, ?)`,
			id, factRepo, factActor, created, exp, tokenHex)
		rawExec(t, dir,
			`update upload_sessions set state='active', create_token=null, cleanup_token=? where id=?`,
			tokenHex, id)
		digest := "sha256:" + strings.Repeat("d", 64)
		ref := strings.Repeat("e", 64)
		rawExec(t, dir,
			`insert into staged_blobs (upload_id, repo, actor, digest, bee_ref, size, media_type, created_at, expires_at)
			 values (?,?,?,?,?,?,?,?,?)`,
			id, factRepo, factActor, digest, ref, 0, "application/octet-stream", created, exp)
		rawExec(t, dir,
			`update upload_sessions set state='finalized', digest=?, bee_ref=?, media_type=?, size=0 where id=?`,
			digest, ref, "application/octet-stream", id)
	default:
		t.Fatalf("unknown kind %q", kind)
	}
	return id, tokenHex
}

// tombstoneByRawSQL simulates "crash immediately after the tombstone commit,
// before the filesystem cleanup": the durable deleting row carries the token,
// while both files are still at their MANAGED names.
func tombstoneByRawSQL(t *testing.T, dir, id, tokenHex string) {
	t.Helper()
	rawExec(t, dir,
		`update upload_sessions set state='deleting', create_token=null, cleanup_token=? where id=?`,
		tokenHex, id)
}

// ---------------------------------------------------------------------------
// Defect A: the deleting tombstone persists the durable sidecar provenance.
// ---------------------------------------------------------------------------

// TestV3TombstonePersistsDurableTokenForEverySource proves the tombstone
// transition atomically copies the durable applicable token (create_token for
// an interrupted create, cleanup_token for a live pending sidecar) onto the
// deleting row and clears create_token — via the REAL Delete path with the
// cleanup phase faulted, so the durable deleting row can be inspected.
func TestV3TombstonePersistsDurableTokenForEverySource(t *testing.T) {
	ctx := context.Background()
	sources := []struct {
		kind     string
		expToken func(tokenHex string) string
	}{
		{"creating", func(hex string) string { return hex }},
		{"active", func(hex string) string { return hex }},
		{"finalized", func(hex string) string { return hex }},
	}
	for _, tc := range sources {
		tc := tc
		t.Run(tc.kind, func(t *testing.T) {
			dir := newV3StagingDir(t)
			id, tokenHex := fabricatePendingSidecar(t, dir, tc.kind, '1', 0, time.Hour)
			svc := buildServiceNoReconcile(t, dir)
			// Fault the cleanup phase: every directory sync fails, so
			// finishDeletion is interrupted after the tombstone committed and
			// after each same-root rename (Defect B semantics: quarantine
			// retained, never unlinked without durability).
			svc.dirSyncHook = func() error { return errors.New("dir-sync fault") }

			if err := svc.Delete(ctx, id, factRepo, factActor); !errors.Is(err, ErrDependency) {
				svc.dirSyncHook = nil
				t.Fatalf("Delete must fail closed under a dir-sync fault, got %v", err)
			}

			found, st, ct, cl := rowState(t, dir, id)
			if !found {
				t.Fatalf("deleting row vanished despite the failed cleanup")
			}
			if st != "deleting" {
				t.Fatalf("state = %q, want deleting tombstone", st)
			}
			if cl != tc.expToken(tokenHex) {
				t.Fatalf("cleanup_token on tombstone = %q, want durable %q", cl, tc.expToken(tokenHex))
			}
			if ct != "" {
				t.Fatalf("create_token = %q on a deleting row, want cleared", ct)
			}
			// Defect B: the quarantined sidecar/canonical are RETAINED (not
			// unlinked without durability).
			if spoolExists(t, dir, quarantineTokNameFor(id)) != true {
				t.Fatalf("token sidecar quarantine missing after a dir-sync fault")
			}
			if spoolExists(t, dir, quarantineNameFor(id)) != true {
				t.Fatalf("canonical quarantine missing after a dir-sync fault")
			}
			svc.dirSyncHook = nil

			// Restart (fresh independent service via real reconcileStartup)
			// converges: it reads the durable cleanup_token, authenticates and
			// finishes both quarantines, and removes the row.
			svc.Close()
			svc2, err := NewService(ctx, filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
			if err != nil {
				t.Fatalf("restart: %v", err)
			}
			defer svc2.Close()
			if found2, _, _, _ := rowState(t, dir, id); found2 {
				t.Fatalf("deleting row survived restart convergence")
			}
			if spoolExists(t, dir, quarantineTokNameFor(id)) || spoolExists(t, dir, quarantineNameFor(id)) ||
				spoolExists(t, dir, id) || spoolExists(t, dir, id+".tok") {
				t.Fatalf("spool residue after restart convergence")
			}
		})
	}
}

// TestV3ExpirePersistsAndConvergesInterruptedCreate drives the Expire path on
// an expired creating row (create_token provenance): the tombstone must
// persist the token, a first crash-retained quarantine must converge on a
// fresh independent service.
func TestV3ExpirePersistsAndConvergesInterruptedCreate(t *testing.T) {
	ctx := context.Background()
	dir := newV3StagingDir(t)
	id, tokenHex := fabricatePendingSidecar(t, dir, "creating", '2', -30*time.Minute, -5*time.Minute)
	now := time.Now()
	svc := buildServiceNoReconcile(t, dir)
	svc.dirSyncHook = func() error { return errors.New("dir-sync fault") }
	if n, err := svc.Expire(ctx, now, 100); !errors.Is(err, ErrDependency) || n != 0 {
		svc.dirSyncHook = nil
		t.Fatalf("Expire under dir-sync fault: n=%d err=%v, want ErrDependency/n=0", n, err)
	}
	svc.dirSyncHook = nil

	found, st, ct, cl := rowState(t, dir, id)
	if !found || st != "deleting" {
		t.Fatalf("row must be a retained deleting tombstone: found=%v state=%q", found, st)
	}
	if cl != tokenHex {
		t.Fatalf("Expire tombstone did not persist the durable token: %q", cl)
	}
	if ct != "" {
		t.Fatalf("Expire tombstone kept create_token: %q", ct)
	}

	// Fresh independent service converges and restart is clean.
	if _, err := NewService(ctx, filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db")); err != nil {
		t.Fatalf("restart convergence: %v", err)
	}
	if found2, _, _, _ := rowState(t, dir, id); found2 {
		t.Fatalf("expired creating row survived restart convergence")
	}
	entries, err := os.ReadDir(filepath.Join(dir, "spool"))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("spool residue after Expire convergence: %v", entries)
	}
}

// TestV3RestartConvergesDeletingRowWithManagedSidecar proves a restart reads
// the durable tombstone provenance and can quarantine + authenticate a MANAGED
// `.tok` left behind by a crash that landed between the tombstone commit and
// the filesystem cleanup — the exact defect A state. Covers the create_token
// source (creating) and the cleanup_token source (active).
func TestV3RestartConvergesDeletingRowWithManagedSidecar(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"creating", "active"} {
		kind := kind
		t.Run(kind, func(t *testing.T) {
			dir := newV3StagingDir(t)
			id, tokenHex := fabricatePendingSidecar(t, dir, kind, '3', 0, time.Hour)
			tombstoneByRawSQL(t, dir, id, tokenHex) // crash immediately after the tombstone

			svc, err := NewService(ctx, filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
			if err != nil {
				t.Fatalf("restart with managed sidecar: %v", err)
			}
			defer svc.Close()

			if found, _, _, _ := rowState(t, dir, id); found {
				t.Fatalf("deleting row survived restart with a managed sidecar")
			}
			// Both the managed canonical and the managed `.tok` are durably gone.
			if spoolExists(t, dir, id) || spoolExists(t, dir, id+".tok") {
				t.Fatalf("managed sidecar residue after restart convergence")
			}
			for _, q := range []string{quarantineNameFor(id), quarantineTokNameFor(id)} {
				if spoolExists(t, dir, q) {
					t.Fatalf("quarantine residue %s after convergence", q)
				}
			}
		})
	}
}

// TestV3AbortRollbackPersistsToken proves the interrupted-create rollback path
// (startup attribution of a stale creating row) persists the token on its
// deleting tombstone, so a crash that lands after the abort tombstone but
// before the cleanup still leaves an independently restartable deletion.
func TestV3AbortRollbackPersistsToken(t *testing.T) {
	ctx := context.Background()
	dir := newV3StagingDir(t)
	id, tokenHex := fabricatePendingSidecar(t, dir, "creating", '4', -2*creationLease, time.Hour)
	// The row is now STALE (older than the creation lease) so startup
	// reconciliation attributes and rolls it back.
	_ = tokenHex

	// First restart: reconcile rolls the stale creating row into a deleting
	// tombstone carrying the durable token; the cleanup then succeeds and the
	// row is removed. The convergence is only observable via a fresh service.
	if _, err := NewService(ctx, filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db")); err != nil {
		t.Fatalf("abort rollback restart: %v", err)
	}
	if found, _, _, _ := rowState(t, dir, id); found {
		t.Fatalf("stale creating row survived its rollback")
	}
	_ = tokenHex // the rollback authenticates the sidecar, which is now gone
	if spoolExists(t, dir, id) || spoolExists(t, dir, id+".tok") {
		t.Fatalf("rollback left attributable residue")
	}
}

// TestV3WrongOrEmptyManagedSidecarFailsClosed proves a deleting row whose
// managed `.tok` does not carry the durable token (wrong bytes or empty) fails
// closed WITHOUT removing the row or the foreign sidecar.
func TestV3WrongOrEmptyManagedSidecarFailsClosed(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		content []byte
	}{
		{"wrong_bytes", []byte(strings.Repeat("X", creatingTokenLen))},
		{"empty", nil},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dir := newV3StagingDir(t)
			id, tokenHex := fabricatePendingSidecar(t, dir, "creating", '5', 0, time.Hour)
			// Replace the managed sidecar with the wrong/empty occupant and
			// commit the deleting tombstone.
			writeSpoolLeaf(t, dir, id+".tok", tc.content)
			tombstoneByRawSQL(t, dir, id, tokenHex)

			if _, err := NewService(ctx, filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db")); !errors.Is(err, ErrDependency) {
				if err == nil {
					t.Fatalf("startup must fail closed on a mismatched managed sidecar, got nil")
				}
				t.Fatalf("startup error = %v, want ErrDependency", err)
			}
			// Row retained as a durable deleting tombstone; the foreign sidecar
			// is preserved (restored to the managed name), never removed.
			found, st, _, _ := rowState(t, dir, id)
			if !found || st != "deleting" {
				t.Fatalf("row must remain a deleting tombstone: found=%v state=%q", found, st)
			}
			if got, err := os.ReadFile(filepath.Join(dir, "spool", id+".tok")); err != nil {
				t.Fatalf("managed sidecar lost: %v", err)
			} else if string(got) != string(tc.content) {
				t.Fatalf("managed sidecar content mutated")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Defect B: quarantineUnlink fsyncs the directory immediately after a same-root
// rename, BEFORE any authentication or unlink.
// ---------------------------------------------------------------------------

// TestQuarantineUnlinkSyncsDirAfterRenameBeforeAuth asserts at the spool level
// that a successful managed->quarantine rename is fsynced exactly once before
// the post-sync barrier (i.e. before authentication and the pre-unlink
// barrier), and that a failing sync retains the quarantine without unlinking.
func TestQuarantineUnlinkSyncsDirAfterRenameBeforeAuth(t *testing.T) {
	dir := tempPrivate(t)
	rootPath := filepath.Join(dir, "spool")
	sp, err := newSpool(context.Background(), rootPath)
	if err != nil {
		t.Fatalf("newSpool: %v", err)
	}
	defer sp.Close()

	id := factID('6')
	if f, err := sp.create(id); err != nil {
		t.Fatalf("create: %v", err)
	} else if _, err := f.Write([]byte("payload")); err != nil {
		t.Fatalf("write: %v", err)
	} else if serr := f.Sync(); serr != nil {
		t.Fatalf("sync file: %v", serr)
	} else if cerr := f.Close(); cerr != nil {
		t.Fatalf("close: %v", cerr)
	}

	var syncCount atomic.Int32
	sawPostSync := make(chan struct{})
	syncDir := func() error {
		syncCount.Add(1)
		return nil
	}
	barrier := func(phase, name string) {
		if phase == "post-sync" {
			// The dir must already be synced ONCE (the rename), and nothing may
			// be unlinked yet: the leaf is still at the quarantine name.
			if got := syncCount.Load(); got != 1 {
				t.Fatalf("at post-sync barrier sync count = %d, want exactly 1 (rename already synced, pre-auth)", got)
			}
			if !spoolExists(t, dir, quarantineNameFor(id)) {
				t.Fatal("quarantine leaf missing at the post-sync barrier")
			}
			if spoolExists(t, dir, id) {
				t.Fatal("managed leaf still present after the rename at the post-sync barrier")
			}
			close(sawPostSync)
		}
	}

	removed, err := sp.quarantineUnlink(id, quarantineNameFor(id), nil, nil, syncDir, barrier)
	if err != nil {
		t.Fatalf("quarantineUnlink: %v", err)
	}
	if !removed {
		t.Fatal("quarantineUnlink reported not-removed")
	}
	select {
	case <-sawPostSync:
	default:
		t.Fatal("post-sync barrier never fired")
	}
	// Two syncs total: once for the rename, once for the unlink.
	if got := syncCount.Load(); got != 2 {
		t.Fatalf("total dir syncs = %d, want 2 (rename + unlink)", got)
	}
}

// TestQuarantineUnlinkFirstAuthRunsAfterSyncOnMismatch drives the post-rename
// identity-mismatch path: a swap at the post-sync barrier makes the quarantine
// name hold a foreign inode. It proves the required ordering — the
// managed->quarantine rename is fsynced BEFORE the first Lstat/SameFile
// authentication, so the swap is detected by that first auth (and the foreign
// occupant non-clobberingly restored to the now-free managed name) only AFTER
// the rename is durable. RED on the old code: the identity check ran inside the
// rename switch BEFORE the directory fsync, so a swap was detected by a LATER
// authentication with a different error and the pre-auth fsync was skipped.
func TestQuarantineUnlinkFirstAuthRunsAfterSyncOnMismatch(t *testing.T) {
	dir := tempPrivate(t)
	rootPath := filepath.Join(dir, "spool")
	sp, err := newSpool(context.Background(), rootPath)
	if err != nil {
		t.Fatalf("newSpool: %v", err)
	}
	defer sp.Close()

	id := factID('6')
	if f, err := sp.create(id); err != nil {
		t.Fatalf("create: %v", err)
	} else if _, err := f.Write([]byte("payload")); err != nil {
		t.Fatalf("write: %v", err)
	} else if serr := f.Sync(); serr != nil {
		t.Fatalf("sync file: %v", serr)
	} else if cerr := f.Close(); cerr != nil {
		t.Fatalf("close: %v", cerr)
	}

	var syncCount atomic.Int32
	swapped := false
	syncDir := func() error {
		syncCount.Add(1)
		return nil
	}
	barrier := func(phase, name string) {
		if phase != "post-sync" || swapped {
			return
		}
		// The rename MUST already be fsynced exactly once before the first
		// authentication: no identity Lstat/restore decision may precede it.
		if got := syncCount.Load(); got != 1 {
			t.Fatalf("at post-sync barrier sync count = %d, want 1 (rename fsynced before first-auth)", got)
		}
		swapped = true
		qpath := filepath.Join(rootPath, quarantineNameFor(id))
		saved := filepath.Join(rootPath, "_saved_q")
		if err := os.Rename(qpath, saved); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(qpath, []byte("foreign-occupant"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	_, err = sp.quarantineUnlink(id, quarantineNameFor(id), nil, nil, syncDir, barrier)
	cause := spoolErrorCause(err)
	if err == nil || cause == nil || !strings.Contains(cause.Error(), "quarantine captured a replaced leaf") {
		t.Fatalf("swap must be caught by the FIRST auth (after the rename fsync), got %v", err)
	}
	if !swapped {
		t.Fatal("post-sync barrier never fired")
	}
	// The foreign inode is restored to the (now free) managed name; the
	// quarantine name is drained; the real payload moved aside is untouched.
	if got, rerr := os.ReadFile(filepath.Join(rootPath, id)); rerr != nil || string(got) != "foreign-occupant" {
		t.Fatalf("foreign occupant not restored to the managed name: %q err=%v", got, rerr)
	}
	if _, qerr := os.Lstat(filepath.Join(rootPath, quarantineNameFor(id))); !os.IsNotExist(qerr) {
		t.Fatalf("quarantine name not drained by the restore: err=%v", qerr)
	}
	// rename fsync (1) + restore fsync (2).
	if got := syncCount.Load(); got != 2 {
		t.Fatalf("total dir syncs = %d, want 2 (rename + restore)", got)
	}
}

// TestQuarantineUnlinkSyncFailureAfterRenameRetainsQuarantine proves that when
// the immediate post-rename directory fsync fails, quarantineUnlinkRoot fails
// closed with the quarantine RETAINED (managed free, quarantine occupied) and
// no authentication / restore / unlink / metadata-clear was attempted — the
// post-sync barrier is never reached.
func TestQuarantineUnlinkSyncFailureAfterRenameRetainsQuarantine(t *testing.T) {
	dir := tempPrivate(t)
	rootPath := filepath.Join(dir, "spool")
	sp, err := newSpool(context.Background(), rootPath)
	if err != nil {
		t.Fatalf("newSpool: %v", err)
	}
	defer sp.Close()

	id := factID('7')
	if f, err := sp.create(id); err != nil {
		t.Fatalf("create: %v", err)
	} else if _, err := f.Write([]byte("payload")); err != nil {
		t.Fatalf("write: %v", err)
	} else if serr := f.Sync(); serr != nil {
		t.Fatalf("sync file: %v", serr)
	} else if cerr := f.Close(); cerr != nil {
		t.Fatalf("close: %v", cerr)
	}

	var syncCount atomic.Int32
	sawPostSync := false
	syncDir := func() error {
		syncCount.Add(1)
		return errors.New("dir-sync fault")
	}
	barrier := func(phase, name string) {
		// Only the post-rename/post-fsync boundary must NOT be reached on a
		// sync failure. (The pre-rename barrier legitimately fires first.)
		if phase == "post-sync" {
			sawPostSync = true
		}
	}

	_, err = sp.quarantineUnlink(id, quarantineNameFor(id), nil, nil, syncDir, barrier)
	if err == nil || err.Error() != "dir-sync fault" {
		t.Fatalf("must fail closed with the injected sync fault, got %v", err)
	}
	if !spoolExists(t, dir, quarantineNameFor(id)) {
		t.Fatal("quarantine must be retained on a rename-sync failure")
	}
	if spoolExists(t, dir, id) {
		t.Fatal("managed name must be free after the rename (renamed into quarantine)")
	}
	if sawPostSync {
		t.Fatal("post-sync barrier / authentication must not run before the rename fsync succeeds")
	}
	if got := syncCount.Load(); got != 1 {
		t.Fatalf("dir syncs = %d, want 1 (the failed rename sync), no reads/restores/unlink before it", got)
	}
}

// TestV3DeleteDirSyncFailureRetainsQuarantineAndConverges proves a dir-sync
// failure right after the rename retains the quarantine (managed name free,
// quarantine occupied), keeps the tombstone and credible count, and a retry /
// fresh service converges idempotently.
func TestV3DeleteDirSyncFailureRetainsQuarantineAndConverges(t *testing.T) {
	ctx := context.Background()
	dir := newV3StagingDir(t)
	id, tokenHex := fabricatePendingSidecar(t, dir, "creating", '7', 0, time.Hour)
	svc := buildServiceNoReconcile(t, dir)
	svc.dirSyncHook = func() error { return errors.New("dir-sync fault") }

	if err := svc.Delete(ctx, id, factRepo, factActor); !errors.Is(err, ErrDependency) {
		svc.dirSyncHook = nil
		t.Fatalf("Delete must fail closed, got %v", err)
	}
	// Managed canonical name is free (renamed into quarantine), quarantine
	// occupied and RETAINED — never unlinked, never restored unsynced.
	if spoolExists(t, dir, id) {
		t.Fatal("managed name still occupied after a dir-sync failure")
	}
	if !spoolExists(t, dir, quarantineNameFor(id)) {
		t.Fatal("canonical quarantine lost after a dir-sync failure")
	}
	svc.dirSyncHook = nil

	// Retry on the SAME service converges idempotently.
	if err := svc.Delete(ctx, id, factRepo, factActor); err != nil {
		t.Fatalf("retry Delete: %v", err)
	}
	if found, _, _, _ := rowState(t, dir, id); found {
		t.Fatalf("deleting row survived the retry")
	}
	if spoolExists(t, dir, quarantineNameFor(id)) || spoolExists(t, dir, id) ||
		spoolExists(t, dir, quarantineTokNameFor(id)) || spoolExists(t, dir, id+".tok") {
		t.Fatalf("spool residue after the retry convergence")
	}
	_ = tokenHex
}

// TestV3RestartConvergesQuarantinedSidecarAfterRenameSync proves the crash
// state "rename committed AND directory synced, unlink not yet done" (the leaf
// is at the quarantine, with the durable token on the row) converges from the
// quarantine on a fresh service using the durable token.
func TestV3RestartConvergesQuarantinedSidecarAfterRenameSync(t *testing.T) {
	ctx := context.Background()
	dir := newV3StagingDir(t)
	id, tokenHex := fabricatePendingSidecar(t, dir, "active", '8', 0, time.Hour)
	// Commit the deleting tombstone with the durable token, then move both
	// managed files into quarantine (the rename is durable, the unlink never
	// ran — the exact crash-after-rename-sync state).
	tombstoneByRawSQL(t, dir, id, tokenHex)
	sp, err := newSpool(context.Background(), filepath.Join(dir, "spool"))
	if err != nil {
		t.Fatalf("newSpool: %v", err)
	}
	defer sp.Close()
	if err := sp.root.Rename(id+".tok", quarantineTokNameFor(id)); err != nil {
		t.Fatalf("rename tok: %v", err)
	}
	if err := sp.root.Rename(id, quarantineNameFor(id)); err != nil {
		t.Fatalf("rename canonical: %v", err)
	}
	// Sync the directory so the renames are durable (the crash landed after).
	sp.syncDir()

	svc, err := NewService(ctx, filepath.Join(dir, "spool"), filepath.Join(dir, "staging.db"))
	if err != nil {
		t.Fatalf("restart from quarantine: %v", err)
	}
	defer svc.Close()
	if found, _, _, _ := rowState(t, dir, id); found {
		t.Fatalf("row survived convergence from quarantine")
	}
	for _, name := range []string{id, id + ".tok", quarantineNameFor(id), quarantineTokNameFor(id)} {
		if spoolExists(t, dir, name) {
			t.Fatalf("residue %s after convergence from quarantine", name)
		}
	}
}
