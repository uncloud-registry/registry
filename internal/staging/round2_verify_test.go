package staging

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Creating recovery: attacker-planted / wrong-token files and live leases.
// ---------------------------------------------------------------------------

// TestRound2RestartRejectsWrongTokenFile proves a stale creating row whose
// file carries foreign bytes fails closed WITHOUT touching the file: an
// attacker cannot make the service delete a file it cannot attribute.
func TestRound2RestartRejectsWrongTokenFile(t *testing.T) {
	dir := tempPrivate(t)
	spoolDir := filepath.Join(dir, "spool")
	dbPath := filepath.Join(dir, "staging.db")

	token := strings.Repeat("ab", 32) // 64 lowercase hex
	id := strings.Repeat("11", 32)
	created := time.Now().Add(-time.Hour).UnixNano()
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	fixture, err := newStagingDBAt(dbPath)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if _, err := fixture.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at, create_token) values (?, 'backend/api', 'user:alice', 'creating', 0, ?, ?, ?)`, id, created, created+int64(time.Hour), token); err != nil {
		fixture.Close()
		t.Fatalf("seed: %v", err)
	}
	fixture.Close()
	// Plant a file with DIFFERENT bytes than the row's token.
	if err := os.WriteFile(filepath.Join(spoolDir, id), make([]byte, 32), 0o600); err != nil {
		t.Fatalf("plant: %v", err)
	}
	svc, err := NewService(context.Background(), spoolDir, dbPath)
	if err == nil {
		svc.Close()
		t.Fatal("service adopted a creating file with foreign bytes")
	}
	if !errors.Is(err, ErrDependency) {
		t.Fatalf("expected ErrDependency, got %v", err)
	}
	// The file is untouched.
	got, rerr := os.ReadFile(filepath.Join(spoolDir, id))
	if rerr != nil {
		t.Fatalf("planted file vanished: %v", rerr)
	}
	if len(got) != 32 {
		t.Fatalf("planted file content changed: %d bytes", len(got))
	}
}

// TestRound2RestartLeavesLiveCreatingAlone proves a LIVE creating lease is
// never touched at startup — with or without its token file — and the
// service remains fully usable.
func TestRound2RestartLeavesLiveCreatingAlone(t *testing.T) {
	dir := tempPrivate(t)
	spoolDir := filepath.Join(dir, "spool")
	dbPath := filepath.Join(dir, "staging.db")

	token := strings.Repeat("cd", 32)
	id := strings.Repeat("22", 32)
	created := time.Now().Add(-time.Second).UnixNano() // fresh lease
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	seed := func(tok, state string) {
		fixture, err := newStagingDBAt(dbPath)
		if err != nil {
			t.Fatalf("fixture: %v", err)
		}
		if _, err := fixture.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at, create_token) values (?, 'backend/api', 'user:alice', ?, 0, ?, ?, ?)`, id, state, created, created+int64(time.Hour), tok); err != nil {
			fixture.Close()
			t.Fatalf("seed: %v", err)
		}
		fixture.Close()
	}
	// Case 1: live lease, no file.
	seed(token, "creating")
	svc, err := NewService(context.Background(), spoolDir, dbPath)
	if err != nil {
		t.Fatalf("startup with live lease: %v", err)
	}
	assertRowState(t, dbPath, id, "creating")
	// Case 2: live lease WITH its token file must also be left alone.
	tokenBytes, _ := hex.DecodeString(token)
	if err := os.WriteFile(filepath.Join(spoolDir, id), tokenBytes, 0o600); err != nil {
		t.Fatalf("plant token file: %v", err)
	}
	if _, err := NewService(context.Background(), spoolDir, dbPath); err != nil {
		t.Fatalf("startup with live lease and token file: %v", err)
	}
	assertRowState(t, dbPath, id, "creating")
	got, rerr := os.ReadFile(filepath.Join(spoolDir, id))
	if rerr != nil || len(got) != 32 {
		t.Fatalf("live lease token file was touched: %v", rerr)
	}
	svc.Close()
	// Case 3: the service still creates fine alongside the live lease.
	svc2, err := NewService(context.Background(), spoolDir, dbPath)
	if err != nil {
		t.Fatalf("second startup: %v", err)
	}
	if s2, err := svc2.Create(context.Background(), "backend/api", "user:alice", time.Hour); err != nil {
		t.Fatalf("create alongside live lease: %v", err)
	} else if s2.State != StateActive {
		t.Fatalf("unexpected state %s", s2.State)
	}
	svc2.Close()
}

// TestRound2RestartRollsBackStaleTokenFile proves a stale creating row whose
// file carries exactly its token is rolled back: row AND file removed.
func TestRound2RestartRollsBackStaleTokenFile(t *testing.T) {
	dir := tempPrivate(t)
	spoolDir := filepath.Join(dir, "spool")
	dbPath := filepath.Join(dir, "staging.db")

	token := strings.Repeat("ef", 32)
	id := strings.Repeat("33", 32)
	created := time.Now().Add(-time.Hour).UnixNano()
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	fixture, err := newStagingDBAt(dbPath)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if _, err := fixture.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at, create_token) values (?, 'backend/api', 'user:alice', 'creating', 0, ?, ?, ?)`, id, created, created+int64(time.Hour), token); err != nil {
		fixture.Close()
		t.Fatalf("seed: %v", err)
	}
	fixture.Close()
	tokenBytes, _ := hex.DecodeString(token)
	// New-protocol residue: empty canonical payload file + attribution
	// token file carrying exactly the row token.
	if err := os.WriteFile(filepath.Join(spoolDir, id), nil, 0o600); err != nil {
		t.Fatalf("plant canonical: %v", err)
	}
	if err := os.WriteFile(filepath.Join(spoolDir, id+".tok"), tokenBytes, 0o600); err != nil {
		t.Fatalf("plant token file: %v", err)
	}
	svc, err := NewService(context.Background(), spoolDir, dbPath)
	if err != nil {
		t.Fatalf("startup must roll back the stale token file: %v", err)
	}
	svc.Close()
	assertRowState(t, dbPath, id, "")
	for _, name := range []string{id, id + ".tok"} {
		if _, err := os.Lstat(filepath.Join(spoolDir, name)); !os.IsNotExist(err) {
			t.Fatalf("stale file %s not removed: %v", name, err)
		}
	}
}

func assertRowState(t *testing.T, dbPath, id, want string) {
	t.Helper()
	db, err := sqlOpenForTest(dbPath)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	defer db.Close()
	var state string
	err = db.QueryRow(`select state from upload_sessions where id = ?`, id).Scan(&state)
	if want == "" {
		if err == nil {
			t.Fatalf("row %s still exists in state %s", id, state)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("query: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if state != want {
		t.Fatalf("state = %s, want %s", state, want)
	}
}

// ---------------------------------------------------------------------------
// Durable truncation: failed appends never leak tails; sync failures
// propagate; acknowledged data never reappears.
// ---------------------------------------------------------------------------

// TestRound2AppendSyncFailurePropagates proves the rollback truncate is
// itself synced on the ordinary (non-panic) path, and a FAILED restore fsync
// means the tail's durability is UNCERTAIN: the live service is atomically
// poisoned (never left usable), the file stays exactly at the committed
// offset, and a FRESH service reconciles so a later append succeeds.
func TestRound2AppendSyncFailurePropagates(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "abc")

	boom := errors.New("fsync boom")
	svc.fsyncHook = func() error { return boom }
	_, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, 3, strings.NewReader("def"), 100)
	if err == nil || !errors.Is(err, ErrDependency) {
		t.Fatalf("append with failing fsync: %v", err)
	}
	// The file is exactly at the committed offset despite the failed sync.
	got, rerr := os.ReadFile(filepath.Join(dir, "spool", s.ID))
	if rerr != nil {
		t.Fatalf("read: %v", rerr)
	}
	if string(got) != "abc" {
		t.Fatalf("tail leaked after failed append: %q", got)
	}
	// The RESTORE fsync also faulted (the same hook fired during the tail
	// truncation), so the truncation's durability cannot be confirmed: the
	// pool is atomically poisoned and the live service fails closed fixed.
	if poisoned, _, _ := snapPool(svc.pool); !poisoned {
		t.Fatal("pool not poisoned after a failed restore fsync on an ordinary error path")
	}
	if _, err := svc.Append(ctx, s.ID, s.Repo, s.Actor, 3, strings.NewReader("def"), 100); !errors.Is(err, ErrDependency) {
		t.Fatalf("poisoned service still accepts an append: %v", err)
	}

	// Recovery: a FRESH service reconciles and a later append succeeds.
	svc.Close()
	svc2 := newTestServiceOn(t, dir)
	if st, err := svc2.Status(ctx, s.ID, s.Repo, s.Actor); err != nil || st.Offset != int64(len("abc")) {
		t.Fatalf("fresh status after fsync-fault poison: offset=%d err=%v", st.Offset, err)
	}
	s = mustAppend(t, svc2, s, "def")
	r, _, err := svc2.Open(ctx, s.ID, s.Repo, s.Actor)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	all, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(all) != "abcdef" {
		t.Fatalf("read %q, want abcdef", all)
	}
}

// TestRound2TailTruncationDurable proves an overlong tail is truncated AND
// synced on access, and once acknowledged the committed bytes can never be
// confused with uncommitted ones (the on-disk file shrinks to the offset).
func TestRound2TailTruncationDurable(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "committed")

	// Crash-style residue: garbage AFTER the committed bytes.
	cur, _ := os.ReadFile(filepath.Join(dir, "spool", s.ID))
	if err := os.WriteFile(filepath.Join(dir, "spool", s.ID), append(cur, []byte("GARBAGE-TAIL")...), 0o600); err != nil {
		t.Fatalf("plant tail: %v", err)
	}
	r, got, err := svc.Open(ctx, s.ID, s.Repo, s.Actor)
	if err != nil {
		t.Fatalf("open with tail: %v", err)
	}
	all, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(all) != "committed" {
		t.Fatalf("tail leaked: %q", all)
	}
	if got.Offset != 9 {
		t.Fatalf("offset %d, want 9", got.Offset)
	}
	// The tail is durably gone on disk.
	fi, err := os.Lstat(filepath.Join(dir, "spool", s.ID))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Size() != 9 {
		t.Fatalf("on-disk size %d, want 9 (tail not truncated durably)", fi.Size())
	}
}

// ---------------------------------------------------------------------------
// Context authority matrices.
// ---------------------------------------------------------------------------

func TestRound2ContextCancellationMatrix(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "data")
	dig := "sha256:" + strings.Repeat("a", 64)
	ref := strings.Repeat("b", 64)

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	dead, deadCancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer deadCancel()

	ops := []struct {
		name string
		run  func(ctx context.Context) error
	}{
		{"Status", func(c context.Context) error {
			_, err := svc.Status(c, s.ID, s.Repo, s.Actor)
			return err
		}},
		{"ListFinalized", func(c context.Context) error {
			_, err := svc.ListFinalized(c, s.Repo, s.Actor)
			return err
		}},
		{"Delete", func(c context.Context) error {
			return svc.Delete(c, s.ID, s.Repo, s.Actor)
		}},
		{"Append", func(c context.Context) error {
			_, err := svc.Append(c, s.ID, s.Repo, s.Actor, s.Offset, strings.NewReader("x"), 5)
			return err
		}},
		{"MarkFinalized", func(c context.Context) error {
			return svc.MarkFinalized(c, s.ID, s.Repo, s.Actor, dig, ref, "application/octet-stream", s.Offset)
		}},
		{"Open", func(c context.Context) error {
			rc, _, err := svc.Open(c, s.ID, s.Repo, s.Actor)
			if rc != nil {
				rc.Close()
			}
			return err
		}},
		{"Expire", func(c context.Context) error {
			_, err := svc.Expire(c, time.Now(), 10)
			return err
		}},
		{"Create", func(c context.Context) error {
			_, err := svc.Create(c, "backend/api", "user:alice", time.Hour)
			return err
		}},
	}
	for _, op := range ops {
		for _, err := range []error{nil, dead.Err()} {
			cc, want := canceled, context.Canceled
			if err != nil {
				// deadline variant
				cc = dead
				want = context.DeadlineExceeded
			}
			e := op.run(cc)
			if !errors.Is(e, want) {
				t.Fatalf("%s(%v): got %v, want exact %v", op.name, want, e, want)
			}
			if errors.Is(e, ErrDependency) || errors.Is(e, ErrNotFound) {
				t.Fatalf("%s(%v): wrapped a domain sentinel: %v", op.name, want, e)
			}
		}
	}
	// NewService itself refuses a dead context with the exact error.
	if _, err := NewService(canceled, filepath.Join(t.TempDir(), "spool"), filepath.Join(t.TempDir(), "db")); !errors.Is(err, context.Canceled) {
		t.Fatalf("NewService(canceled): %v", err)
	}
}

// TestRound2ConstructorErrorsAreDataFree proves fail-closed constructor
// errors never leak paths or row data.
func TestRound2ConstructorErrorsAreDataFree(t *testing.T) {
	dir := tempPrivate(t)
	spoolDir := filepath.Join(dir, "spool")
	dbPath := filepath.Join(dir, "staging.db")

	// A mismatched row/file pair: the active row commits offset 10 but the
	// planted file holds only three bytes — alignment must fail closed, and
	// the message must not contain the spool path or the session id.
	id := strings.Repeat("ab", 32)
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	fixture, err := newStagingDBAt(dbPath)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if _, err := fixture.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'active', 0, ?, ?)`, id, time.Now().UnixNano(), time.Now().Add(time.Hour).UnixNano()); err != nil {
		fixture.Close()
		t.Fatalf("seed: %v", err)
	}
	// Commit a nonzero offset through an update (a born-active insert must
	// carry offset 0); the file then cannot possibly match it.
	if _, err := fixture.Exec(`update upload_sessions set offset = 10 where id = ?`, id); err != nil {
		fixture.Close()
		t.Fatalf("bump offset: %v", err)
	}
	fixture.Close()
	if err := os.WriteFile(filepath.Join(spoolDir, id), []byte("short"), 0o600); err != nil {
		t.Fatalf("plant: %v", err)
	}
	svc, err := NewService(context.Background(), spoolDir, dbPath)
	if err == nil {
		svc.Close()
		t.Fatal("startup accepted an active row with a short file")
	}
	if !errors.Is(err, ErrDependency) {
		t.Fatalf("expected ErrDependency, got %v", err)
	}
	msg := err.Error()
	if strings.Contains(msg, spoolDir) || strings.Contains(msg, filepath.Base(spoolDir)) || strings.Contains(msg, id) || strings.Contains(msg, dbPath) {
		t.Fatalf("constructor error leaks path or data: %s", msg)
	}
	// The file is untouched.
	if got, rerr := os.ReadFile(filepath.Join(spoolDir, id)); rerr != nil || string(got) != "short" {
		t.Fatalf("planted file touched: %v", rerr)
	}
}

// newStagingDBAt opens a fresh migrated staging database at an explicit path.
func newStagingDBAt(dbPath string) (*sql.DB, error) {
	return openStagingDB(context.Background(), dbPath, 0)
}

// ---------------------------------------------------------------------------
// Schema golden parity (both directions).
// ---------------------------------------------------------------------------

// deriveFromDDL computes the manifest a generator WOULD produce from the
// migration constants: object bodies from the DDL, physical expectations
// from the frozen golden (the columns/indexes/FKs are the independently
// authored part and can only come from the golden itself).
func deriveFromDDL() *schemaManifest {
	m := &schemaManifest{Version: latestSchemaVersion}
	all := append([]string{versionTableDDL}, schemaDDL...)
	for _, ddl := range all {
		typ, name, tbl, err := parseDDLHead(ddl)
		if err != nil {
			return nil
		}
		norm, err := normalizeSQL(ddl)
		if err != nil {
			return nil
		}
		m.Objects = append(m.Objects, schemaObject{Typ: typ, Name: name, Tbl: tbl, SQL: norm})
	}
	m.Columns = schemaGold.Columns
	m.Indexes = schemaGold.Indexes
	m.ForeignKeys = schemaGold.ForeignKeys
	return m
}

// TestSchemaGoldenParityDDL proves the frozen golden matches the migration
// DDL exactly, and that a DDL-only drift (or golden-only drift) is detected
// as a parity failure.
func TestSchemaGoldenParityDDL(t *testing.T) {
	derived := deriveFromDDL()
	if derived == nil || !reflect.DeepEqual(derived, schemaGold) {
		t.Fatal("golden manifest drifted from the migration DDL constants")
	}
	// DDL-solo change: mutate the derived object set and prove parity fails.
	mut := deriveFromDDL()
	mut.Objects[1].SQL += " -- nudge"
	if reflect.DeepEqual(mut, schemaGold) {
		t.Fatal("parity cannot detect a DDL-only change")
	}
	// Golden-solo change: flip a frozen object in a COPY and prove parity
	// fails. The object slice must be cloned: mutating a shared backing
	// array would corrupt the package-level golden.
	flipped := *schemaGold
	flipped.Objects = append([]schemaObject(nil), schemaGold.Objects...)
	flipped.Objects[1].SQL += " -- nudge"
	if reflect.DeepEqual(&flipped, derived) {
		t.Fatal("parity cannot detect a golden-only change")
	}
}

// TestSchemaGoldenManifestIsFrozen proves the committed golden file yields a
// valid manifest and that the runtime verifier (which depends on it) is not
// tautological: the golden object count and names are independently
// documented.
func TestSchemaGoldenManifestIsFrozen(t *testing.T) {
	if len(schemaGold.Objects) != 1+len(schemaDDL) {
		t.Fatalf("golden object count %d != DDL count %d", len(schemaGold.Objects), len(schemaDDL))
	}
	for _, want := range []string{"upload_sessions", "staged_blobs", versionTable,
		"trg_session_insert", "trg_session_state", "trg_session_metadata", "trg_session_identity",
		"trg_session_token", "trg_session_delete", "trg_blob_insert", "trg_blob_update", "trg_blob_delete"} {
		found := false
		for _, o := range schemaGold.Objects {
			if o.Name == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("golden missing frozen object %s", want)
		}
	}
}

// ---------------------------------------------------------------------------
// Rejected databases leave no journal sidecars and no byte changes.
// ---------------------------------------------------------------------------

// TestSchemaRejectedDBLeavesNoSidecars proves a schema-rejected database is
// byte-identical before/after AND produces no -wal/-shm/-journal files.
func TestSchemaRejectedDBLeavesNoSidecars(t *testing.T) {
	dir := tempPrivate(t)
	dbPath := filepath.Join(dir, "fixture.db")

	// Build from golden but tamper with the version row only: object
	// verification would pass, version verification must reject.
	fixture, err := newStagingDBAt(dbPath)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if _, err := fixture.Exec(`update staging_schema set version = 99`); err != nil {
		fixture.Close()
		t.Fatalf("tamper: %v", err)
	}
	fixture.Close()
	before := hashFile(t, dbPath)
	if db, err := openStagingDB(context.Background(), dbPath, 0); err == nil {
		db.Close()
		t.Fatal("tampered version accepted")
	}
	assertRejectedDBClean(t, dbPath, before)
}

// ---------------------------------------------------------------------------
// File-URI percent-decoding and path anchoring.
// ---------------------------------------------------------------------------

func TestBasePathOfDecoding(t *testing.T) {
	cases := []struct {
		dsn  string
		want string
		ok   bool
	}{
		{"/tmp/x.db", "/tmp/x.db", true},
		{"file:/tmp/x.db", "/tmp/x.db", true},
		{"file:///tmp/x.db", "/tmp/x.db", true},
		{"file:/tmp/sp ace.db", "/tmp/sp ace.db", true},
		{"file:/tmp/sp%20ace.db", "/tmp/sp ace.db", true},
		{"file:/tmp/caf%C3%A9.db", "/tmp/café.db", true},
		{"file:/tmp/x.db?mode=ro", "/tmp/x.db", true},
		{"file://relative", "", false},
		{"file://host/x.db", "", false},
		{"file:/tmp/a%2Fb.db", "", false}, // escaped separator: ambiguous
		{"file:/tmp/a%5Cb.db", "", false},
		{"file:/tmp/%2e%2e/db.db", "", false}, // escaped dot-dot
		{"file:/tmp/a%00b.db", "", false},
		{"file:/tmp/x.db?mode=ro&cache=shared&_pragma=journal_mode(WAL)", "/tmp/x.db", true},
	}
	for _, tc := range cases {
		got, err := basePathOf(tc.dsn)
		if tc.ok {
			if err != nil || got != tc.want {
				t.Fatalf("basePathOf(%q) = %q, %v; want %q", tc.dsn, got, err, tc.want)
			}
			continue
		}
		if err == nil {
			t.Fatalf("basePathOf(%q) accepted as %q", tc.dsn, got)
		}
	}
}

// TestRound2OpenStagingDBFileURI proves file: URIs with percent-encoded
// names open the SAME database as the raw path.
func TestRound2OpenStagingDBFileURI(t *testing.T) {
	dir := tempPrivate(t)
	raw := filepath.Join(dir, "sp ace.db")
	uri := "file:" + strings.ReplaceAll(raw, " ", "%20")
	db1, err := openStagingDB(context.Background(), raw, 0)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	if _, err := db1.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at) values (?, 'backend/api', 'user:alice', 'active', 0, 1000, 2000)`, strings.Repeat("7", 64)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	db1.Close()
	db2, err := openStagingDB(context.Background(), uri, 0)
	if err != nil {
		t.Fatalf("uri open: %v", err)
	}
	var n int
	if err := db2.QueryRow(`select count(*) from upload_sessions`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	db2.Close()
	if n != 1 {
		t.Fatalf("URI and raw path opened different files (%d rows)", n)
	}
}

// TestRound2PoolSurvivesParentAndBasenameSwaps proves the pinned connection
// pool never reopens the (swapped) path: after the database is renamed and a
// fresh database is planted at the old path, the service keeps operating on
// the ORIGINAL inode and the swapped file stays untouched.
func TestRound2PoolSurvivesParentAndBasenameSwaps(t *testing.T) {
	svc, dir := newTestService(t)
	ctx := context.Background()
	s := mustCreate(t, svc, "backend/api", "user:alice")
	s = mustAppend(t, svc, s, "payload")
	dbPath := filepath.Join(dir, "staging.db")

	// Basename swap: rename the DB (and its WAL sidecars, which SQLite
	// path-resolves per connection) away and plant a NON-database blob at
	// the old path. The pinned pool never reopens the path, so the service
	// keeps operating on the ORIGINAL inode and the blob stays untouched.
	moved := dbPath + ".moved"
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if err := os.Rename(dbPath+suffix, moved+suffix); err == nil {
			// renamed
		} else if !os.IsNotExist(err) {
			t.Fatalf("rename %s: %v", suffix, err)
		}
	}
	blob := make([]byte, 4096)
	if err := os.WriteFile(dbPath, blob, 0o600); err != nil {
		t.Fatalf("plant blob: %v", err)
	}

	// The service still sees the ORIGINAL database through pinned conns.
	st, err := svc.Status(ctx, s.ID, s.Repo, s.Actor)
	if err != nil {
		t.Fatalf("status after basename swap: %v", err)
	}
	if st.Offset != 7 {
		t.Fatalf("status offset %d, want 7", st.Offset)
	}
	// Writes land in the ORIGINAL (moved) file, never the swapped blob.
	s = mustAppend(t, svc, s, "more")
	if got := readDBTail(t, moved, s.ID); got != 11 {
		t.Fatalf("original db offset %d, want 11", got)
	}
	swapped, rerr := os.ReadFile(dbPath)
	if rerr != nil || !reflect.DeepEqual(swapped, blob) {
		t.Fatalf("swapped path was touched: %v", rerr)
	}

	// Parent swap: rename the containing directory (everything moves
	// together); operations keep pinning the moved original. A blob planted
	// at the original path afterwards is never opened.
	dirMoved := dir + ".moved"
	if err := os.Rename(dir, dirMoved); err != nil {
		t.Fatalf("rename dir: %v", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir dir: %v", err)
	}
	if err := os.WriteFile(dbPath, blob, 0o600); err != nil {
		t.Fatalf("plant blob2: %v", err)
	}
	if st, err := svc.Status(ctx, s.ID, s.Repo, s.Actor); err != nil || st.Offset != 11 {
		t.Fatalf("status after parent swap: %v (offset %d)", err, st.Offset)
	}
	s = mustAppend(t, svc, s, "!")
	// The service keeps operating on the moved original (SQLite resolves
	// journal sidecars per-connection from the originally opened path, so a
	// FRESH reader of the moved path legitimately sees WAL state it cannot
	// follow — the service's own pinned handles are authoritative).
	if st, err := svc.Status(ctx, s.ID, s.Repo, s.Actor); err != nil || st.Offset != 12 {
		t.Fatalf("status after parent-swap append: %v (offset %d)", err, st.Offset)
	}
	swapped2, rerr := os.ReadFile(dbPath)
	if rerr != nil || !reflect.DeepEqual(swapped2, blob) {
		t.Fatalf("swapped path after parent swap was touched: %v", rerr)
	}
}

func readDBTail(t *testing.T, dbPath, id string) int64 {
	t.Helper()
	db := sqlOpenMust(t, dbPath)
	defer db.Close()
	var off int64
	if err := db.QueryRow(`select offset from upload_sessions where id = ?`, id).Scan(&off); err != nil {
		t.Fatalf("read offset: %v", err)
	}
	return off
}

func sqlOpenMust(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	return db
}
