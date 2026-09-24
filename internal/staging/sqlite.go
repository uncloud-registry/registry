package staging

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	sqlite "modernc.org/sqlite"
)

// latestSchemaVersion is the only schema version this subsystem knows. A
// pre-existing database whose version table records anything else — or that
// carries unknown tables — is rejected, never adopted or guessed at.
const latestSchemaVersion = 1

// busytimeoutMS is the busy-timeout installed on every pooled connection
// when the caller did not configure one.
const busytimeoutMS = 5000

// migrationFault is a test-only injection point that fails the version-1
// migration after its DDL and before the version row is recorded, proving
// the whole migration rolls back atomically.
var migrationFault error

// schemaDDL is the ordered DDL for the staging schema (version 1).
//
// Storage classes are pinned with typeof() checks; timestamps are signed
// Unix nanoseconds (INTEGER only, never REAL/text/BLOB); expiry is strictly
// after creation; state coherence (active carries no finalize metadata and a
// finalized row carries all of it with size == offset) is enforced by CHECK
// plus the triggers below, which cover transitions CHECK cannot see. The
// integer fields are declared WITHOUT a type name (BLOB affinity) so SQLite
// never coerces REAL or numeric TEXT into INTEGER storage before the CHECK
// sees it — the typeof() checks below then provably accept only genuine
// INTEGER storage-class values.
var schemaDDL = []string{
	`create table upload_sessions (
		id         text primary key,
		repo       text not null,
		actor      text not null,
		state      text not null,
		offset     not null,
		created_at not null,
		expires_at not null,
		digest     text,
		bee_ref    text,
		media_type text,
		size,
		check (typeof(id) = 'text' and length(id) = 64 and id = lower(id) and id not glob '*[^0-9a-f]*'),
		check (typeof(repo) = 'text' and length(repo) between 1 and 200 and repo = lower(repo) and repo not glob '*[^a-z0-9._/-]*' and repo not glob '*/' and repo not glob '*//*' and repo not glob '*..*'),
		check (typeof(actor) = 'text' and length(actor) between 1 and 200 and actor not glob '*[^a-zA-Z0-9:_@.+-]*'),
		check (state in ('active','finalized','deleting')),
		check (typeof(offset) = 'integer' and offset >= 0),
		check (typeof(created_at) = 'integer' and typeof(expires_at) = 'integer' and expires_at > created_at),
		check (
			(state = 'active' and digest is null and bee_ref is null and media_type is null and size is null)
			or (state = 'finalized' and digest is not null and bee_ref is not null and media_type is not null
				and size is not null and typeof(size) = 'integer' and size = offset
				and typeof(digest) = 'text' and length(digest) = 71 and digest = lower(digest)
				and digest glob 'sha256:[0-9a-f]*'
				and typeof(bee_ref) = 'text' and length(bee_ref) = 64 and bee_ref = lower(bee_ref)
				and bee_ref not glob '*[^0-9a-f]*'
				and typeof(media_type) = 'text' and length(media_type) between 1 and 200
				and media_type not glob '*[^a-z0-9.+/_-]*')
			or (state = 'deleting')
		)
	)`,
	`create table staged_blobs (
		upload_id  text primary key references upload_sessions(id) on delete cascade,
		repo       text not null,
		actor      text not null,
		digest     text not null,
		bee_ref    text not null,
		size       not null,
		media_type text not null,
		created_at not null,
		expires_at not null,
		check (typeof(upload_id) = 'text' and length(upload_id) = 64 and upload_id = lower(upload_id) and upload_id not glob '*[^0-9a-f]*'),
		check (typeof(repo) = 'text' and length(repo) between 1 and 200 and repo = lower(repo) and repo not glob '*[^a-z0-9._/-]*' and repo not glob '*/' and repo not glob '*//*' and repo not glob '*..*'),
		check (typeof(actor) = 'text' and length(actor) between 1 and 200 and actor not glob '*[^a-zA-Z0-9:_@.+-]*'),
		check (typeof(digest) = 'text' and length(digest) = 71 and digest = lower(digest) and digest glob 'sha256:[0-9a-f]*'),
		check (typeof(bee_ref) = 'text' and length(bee_ref) = 64 and bee_ref = lower(bee_ref) and bee_ref not glob '*[^0-9a-f]*'),
		check (typeof(size) = 'integer' and size >= 0),
		check (typeof(media_type) = 'text' and length(media_type) between 1 and 200 and media_type not glob '*[^a-z0-9.+/_-]*'),
		check (typeof(created_at) = 'integer' and typeof(expires_at) = 'integer' and expires_at > created_at)
	)`,
	`create index idx_staged_blobs_owner on staged_blobs(repo, actor, created_at, upload_id)`,
	`create index idx_sessions_owner on upload_sessions(repo, actor)`,
	`create index idx_sessions_expiry on upload_sessions(expires_at)`,
	// A session may only be born active at offset 0 with no finalize metadata.
	`create trigger trg_session_insert before insert on upload_sessions begin
		select case when not (new.state = 'active' and new.offset = 0
			and new.digest is null and new.bee_ref is null and new.media_type is null and new.size is null)
			then raise(abort, 'session insert must be active') end;
	end`,
	// State transitions: nothing may return to active; finalize requires a
	// fully matching staged blob (identity, metadata, timing) and size ==
	// offset; the deleting tombstone is terminal.
	`create trigger trg_session_state before update of state on upload_sessions begin
		select case
			when new.state = 'active' and new.state <> old.state then raise(abort, 'cannot return to active')
			when new.state = 'finalized' and not (
				select exists(select 1 from staged_blobs b where b.upload_id = new.id
					and b.repo = new.repo and b.actor = new.actor and b.created_at = new.created_at
					and b.expires_at = new.expires_at and b.digest = new.digest and b.bee_ref = new.bee_ref
					and b.media_type = new.media_type and b.size = new.size)
				and new.digest is not null and new.bee_ref is not null
				and new.media_type is not null and new.size is not null and new.size = new.offset)
				then raise(abort, 'finalize requires matching staged blob')
			when new.state = 'deleting' and old.state = 'deleting' then raise(abort, 'already deleting')
			else null end;
	end`,
	// Finalize metadata columns are immutable once set and may only be SET
	// (never cleared) as part of a finalize whose staged blob matches.
	`create trigger trg_session_metadata before update of digest, bee_ref, media_type, size on upload_sessions begin
		select case
			when old.digest is not null then raise(abort, 'finalized metadata immutable')
			when new.digest is null or new.bee_ref is null or new.media_type is null or new.size is null
				then raise(abort, 'cannot clear finalize metadata')
			when not (select exists(select 1 from staged_blobs b where b.upload_id = new.id
					and b.repo = new.repo and b.actor = new.actor and b.created_at = new.created_at
					and b.expires_at = new.expires_at and b.digest = new.digest and b.bee_ref = new.bee_ref
					and b.media_type = new.media_type and b.size = new.size))
				then raise(abort, 'metadata must match staged blob')
			else null end;
	end`,
	// Session identity (id, repo, actor, timestamps) is immutable.
	`create trigger trg_session_identity before update of id, repo, actor, created_at, expires_at on upload_sessions begin
		select case when old.id <> new.id or old.repo <> new.repo or old.actor <> new.actor
			or old.created_at <> new.created_at or old.expires_at <> new.expires_at
			then raise(abort, 'session identity immutable') else null end;
	end`,
	// Rows may only be removed through the deleting tombstone.
	`create trigger trg_session_delete before delete on upload_sessions begin
		select case when old.state <> 'deleting' then raise(abort, 'delete only via deleting state') else null end;
	end`,
	// A staged blob must join an ACTIVE session and copy its identity and
	// timing exactly; one blob per session (PK).
	`create trigger trg_blob_insert before insert on staged_blobs begin
		select case when not (
			(select state from upload_sessions where id = new.upload_id) = 'active'
			and (select repo from upload_sessions where id = new.upload_id) = new.repo
			and (select actor from upload_sessions where id = new.upload_id) = new.actor
			and (select created_at from upload_sessions where id = new.upload_id) = new.created_at
			and (select expires_at from upload_sessions where id = new.upload_id) = new.expires_at)
			then raise(abort, 'staged blob must match active session') end;
	end`,
	// Staged blobs are immutable once written.
	`create trigger trg_blob_update before update on staged_blobs begin
		select raise(abort, 'staged blob immutable');
	end`,
	// A staged blob may only be removed once its session is tombstoned (or
	// being cascaded away by that deletion).
	`create trigger trg_blob_delete before delete on staged_blobs begin
		select case when (select state from upload_sessions where id = old.upload_id) not in ('deleting')
			then raise(abort, 'cannot delete staged blob of live session') else null end;
	end`,
}

// sessionTable, blobTable are the required physical tables for schema
// verification.
const (
	sessionTable = "upload_sessions"
	blobTable    = "staged_blobs"
	versionTable = "staging_schema"
)

// openStagingDB opens (creating if needed) the dedicated staging database and
// applies/verifies the schema. maxOpen sets the pool cap (0 keeps the driver
// default; NewService always passes a finite pool size). The schema decision
// (fresh / known version / foreign) is made on a pragma-free INSPECTION
// connection FIRST, so a database we reject is never opened in a way that
// could mutate it — its bytes stay untouched.
func openStagingDB(ctx context.Context, dbPath string, maxOpen int) (*sql.DB, error) {
	if err := preparePrivateDirParent(dbPath); err != nil {
		return nil, err
	}
	tables, version, hasVersion, err := inspectStagingSchema(ctx, dbPath)
	if err != nil {
		return nil, typed(ErrDependency, err)
	}
	fresh := len(tables) == 0 && !hasVersion
	if !fresh && (!hasVersion || version != latestSchemaVersion) {
		return nil, typed(ErrDependency, fmt.Errorf(
			"staging database %q is not a supported upload-staging schema (tables=%v, version=%v); refusing to touch it",
			basePathOf(dbPath), tables, version))
	}
	db, err := sql.Open("sqlite", normalizeDSN(dbPath))
	if err != nil {
		return nil, typed(ErrDependency, err)
	}
	closeOnErr := true
	defer func() {
		if closeOnErr {
			db.Close()
		}
	}()
	if maxOpen > 0 {
		db.SetMaxOpenConns(maxOpen)
		db.SetMaxIdleConns(maxOpen)
	}
	if fresh {
		if err := createFreshSchema(ctx, db); err != nil {
			return nil, err
		}
	} else if err := verifyStagingSchema(ctx, db); err != nil {
		return nil, typed(ErrDependency, err)
	}
	// The database file itself must be private.
	if err := chmodPrivate(dbPath); err != nil {
		return nil, err
	}
	closeOnErr = false
	return db, nil
}

// basePathOf returns the on-disk path portion of a DSN (stripping any file:
// scheme and query parameters) for diagnostics.
func basePathOf(dsn string) string {
	p := dsn
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	p = strings.TrimPrefix(p, "file:")
	return p
}

// preparePrivateDirParent ensures the parent directory of the database file
// exists with private 0700 permissions (no group/other access), rejecting
// symlink parents.
func preparePrivateDirParent(dbPath string) error {
	dir := dbPath
	if i := strings.IndexByte(dbPath, '?'); i > 0 {
		dir = dbPath[:i]
	}
	if strings.HasPrefix(dir, "file:") {
		// file: URI — strip the scheme; relative file: URIs keep the path.
		dir = strings.TrimPrefix(dir, "file:")
		if i := strings.IndexByte(dir, '?'); i > 0 {
			dir = dir[:i]
		}
	}
	if dir == "" || dir == ":memory:" || dir == "memory:" {
		return nil
	}
	parent := dir
	if i := strings.LastIndexByte(dir, '/'); i > 0 {
		parent = dir[:i]
		if parent == "" || parent == "." {
			return nil
		}
	}
	if err := preparePrivateDir(parent); err != nil {
		return err
	}
	return nil
}

// chmodPrivate verifies the database file has no group/other access and
// tightens it to 0600 when needed.
func chmodPrivate(dbPath string) error {
	fi, err := os.Lstat(dbPath)
	if err != nil {
		return typed(ErrDependency, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return typed(ErrDependency, errors.New("database path is a symbolic link"))
	}
	if fi.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(dbPath, 0o600); err != nil {
			return typed(ErrDependency, err)
		}
	}
	return nil
}

// normalizeDSN rewrites a modernc SQLite DSN so that EVERY pooled connection
// inherits: foreign_keys=ON, a bounded busy timeout (unless the caller
// configured one), WAL journal mode, and synchronous=FULL. Conflicting
// pragmas are removed; unrelated query parameters are preserved. Durability
// therefore never relies on driver defaults.
func normalizeDSN(dsn string) string {
	base, query := dsn, ""
	if i := strings.Index(dsn, "?"); i >= 0 {
		base, query = dsn[:i], dsn[i+1:]
	}
	var kept []string
	hasBusy := false
	if query != "" {
		for _, param := range strings.Split(query, "&") {
			if param == "" {
				continue
			}
			lower := strings.ToLower(param)
			skip := false
			for _, conflict := range []string{
				"_pragma=foreign_keys(", "_pragma=journal_mode(", "_pragma=synchronous(",
			} {
				if strings.HasPrefix(lower, conflict) {
					skip = true
					break
				}
			}
			if skip {
				continue
			}
			if strings.HasPrefix(lower, "_pragma=busy_timeout(") {
				hasBusy = true
			}
			kept = append(kept, param)
		}
	}
	kept = append(kept,
		"_pragma=foreign_keys(1)",
		"_pragma=journal_mode(WAL)",
		"_pragma=synchronous(FULL)",
	)
	if !hasBusy {
		kept = append(kept, fmt.Sprintf("_pragma=busy_timeout(%d)", busytimeoutMS))
	}
	return base + "?" + strings.Join(kept, "&")
}

// inspectStagingSchema decides fresh / known / foreign by examining an
// existing database on a pragma-free connection: no journal_mode or
// synchronous pragmas run on it, so pure reads leave the file byte-identical
// even when the schema is later rejected.
func inspectStagingSchema(ctx context.Context, dbPath string) ([]string, int64, bool, error) {
	db, err := sql.Open("sqlite", stripMutationPragmas(dbPath))
	if err != nil {
		return nil, 0, false, err
	}
	defer db.Close()
	tables, err := userTables(db)
	if err != nil {
		return nil, 0, false, err
	}
	version, hasVersion, err := currentVersion(db)
	if err != nil {
		return nil, 0, false, err
	}
	return tables, version, hasVersion, nil
}

// stripMutationPragmas removes journal_mode/synchronous pragmas from a DSN so
// an inspection connection can read a database without ever persisting a
// change to its journal mode (which is a file write).
func stripMutationPragmas(dsn string) string {
	if !strings.Contains(dsn, "?") {
		return dsn
	}
	base, query := dsn, ""
	if i := strings.Index(dsn, "?"); i >= 0 {
		base, query = dsn[:i], dsn[i+1:]
	}
	var kept []string
	for _, param := range strings.Split(query, "&") {
		if param == "" {
			continue
		}
		lower := strings.ToLower(param)
		if strings.HasPrefix(lower, "_pragma=journal_mode(") || strings.HasPrefix(lower, "_pragma=synchronous(") {
			continue
		}
		kept = append(kept, param)
	}
	if len(kept) == 0 {
		return base
	}
	return base + "?" + strings.Join(kept, "&")
}

func userTables(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`select name from sqlite_master where type = 'table' and name not like 'sqlite_%' order by name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}

func currentVersion(db *sql.DB) (int64, bool, error) {
	rows, err := db.Query(`select version from staging_schema`)
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return 0, false, nil
		}
		return 0, false, err
	}
	defer rows.Close()
	var versions []int64
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return 0, false, err
		}
		versions = append(versions, v)
	}
	if len(versions) == 0 {
		return 0, false, nil
	}
	if len(versions) != 1 {
		return 0, false, errors.New("staging_schema has multiple version rows")
	}
	return versions[0], true, nil
}

// createFreshSchema runs the version-1 DDL and records the version row inside
// one transaction; any failure (including the test-injected fault) rolls the
// whole migration back.
func createFreshSchema(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return typed(ErrDependency, err)
	}
	rollback := true
	defer func() {
		if rollback {
			_ = tx.Rollback()
		}
	}()
	now := timeNowNanos()
	// The version table is the first object so a partially created database
	// can never be re-adopted as fresh.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(
		`create table %s (version integer primary key, applied_at integer not null)`, versionTable)); err != nil {
		return typed(ErrDependency, err)
	}
	for _, stmt := range schemaDDL {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return typed(ErrDependency, err)
		}
	}
	if migrationFault != nil {
		return typed(ErrDependency, migrationFault)
	}
	if err := verifySchemaOnTx(ctx, tx); err != nil {
		return typed(ErrDependency, err)
	}
	if err := verifySchemaObjects(ctx, tx); err != nil {
		return typed(ErrDependency, err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(
		`insert into %s (version, applied_at) values (?, ?)`, versionTable), latestSchemaVersion, now); err != nil {
		return typed(ErrDependency, err)
	}
	if err := tx.Commit(); err != nil {
		return typed(ErrDependency, err)
	}
	rollback = false
	return nil
}

func timeNowNanos() int64 {
	return time.Now().UTC().UnixNano()
}

// verifyStagingSchema validates the FULL physical shape of an existing
// database: the exact table set, column names and storage classes, the
// physical foreign key, required indexes and triggers, and the version row.
func verifyStagingSchema(ctx context.Context, db *sql.DB) error {
	return verifySchemaOnTx(ctx, &txAdapter{db: db})
}

type schemaChecker interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type txAdapter struct{ db *sql.DB }

func (a *txAdapter) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return a.db.QueryContext(ctx, query, args...)
}

func (a *txAdapter) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return a.db.QueryRowContext(ctx, query, args...)
}

func verifySchemaOnTx(ctx context.Context, db schemaChecker) error {
	// Exact table set.
	rows, err := db.QueryContext(ctx, `select name from sqlite_master where type = 'table' and name not like 'sqlite_%' order by name`)
	if err != nil {
		return err
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		tables = append(tables, n)
	}
	rows.Close()
	expected := []string{versionTable, sessionTable, blobTable}
	sort.Strings(expected)
	sort.Strings(tables)
	if len(tables) != len(expected) {
		return errors.New("staging schema has an unexpected table set")
	}
	for i := range tables {
		if tables[i] != expected[i] {
			return errors.New("staging schema has an unexpected table set")
		}
	}

	for _, table := range []string{versionTable, sessionTable, blobTable} {
		if err := verifyTableShape(ctx, db, table); err != nil {
			return err
		}
	}

	// Physical FK on staged_blobs.
	fkRows, err := db.QueryContext(ctx, `pragma foreign_key_list(staged_blobs)`)
	if err != nil {
		return err
	}
	found := false
	for fkRows.Next() {
		var id, seq int
		var t, from, to, onUpdate, onDelete, match string
		if err := fkRows.Scan(&id, &seq, &t, &from, &to, &onUpdate, &onDelete, &match); err != nil {
			fkRows.Close()
			return err
		}
		if t == sessionTable && from == "upload_id" && to == "id" && onDelete == "CASCADE" {
			found = true
		}
	}
	fkRows.Close()
	if !found {
		return errors.New("staging schema lacks the staged-blob foreign key")
	}

	// Integrity: no orphan rows.
	checkRows, err := db.QueryContext(ctx, `pragma foreign_key_check`)
	if err != nil {
		return err
	}
	for checkRows.Next() {
		checkRows.Close()
		return errors.New("staging schema has foreign-key violations")
	}
	checkRows.Close()
	if err := verifySchemaObjects(ctx, db); err != nil {
		return err
	}
	return nil
}

func verifyTableShape(ctx context.Context, db schemaChecker, table string) error {
	rows, err := db.QueryContext(ctx, fmt.Sprintf(`pragma table_info(%s)`, table))
	if err != nil {
		return err
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return err
		}
		cols[fmt.Sprintf("%s:%s", name, strings.ToLower(typ))] = true
	}
	want := map[string][]string{
		versionTable: {"version:integer", "applied_at:integer"},
		sessionTable: {
			"id:text", "repo:text", "actor:text", "state:text",
			"offset:", "created_at:", "expires_at:",
			"digest:text", "bee_ref:text", "media_type:text", "size:",
		},
		blobTable: {
			"upload_id:text", "repo:text", "actor:text", "digest:text",
			"bee_ref:text", "size:", "media_type:text",
			"created_at:", "expires_at:",
		},
	}
	for _, key := range want[table] {
		if !cols[key] {
			return fmt.Errorf("staging schema table %s lacks column %s", table, key)
		}
	}
	return nil
}

// verifySchemaObjects verifies the db-global trigger/index set of the staging
// schema.
func verifySchemaObjects(ctx context.Context, db schemaChecker) error {
	for _, obj := range []string{
		"trg_session_insert", "trg_session_state", "trg_session_metadata",
		"trg_session_identity", "trg_session_delete", "trg_blob_insert",
		"trg_blob_update", "trg_blob_delete",
		"idx_staged_blobs_owner", "idx_sessions_owner", "idx_sessions_expiry",
	} {
		var n int
		if err := db.QueryRowContext(ctx, `select count(*) from sqlite_master where name = ? and type in ('trigger','index')`, obj).Scan(&n); err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("staging schema lacks object %s", obj)
		}
	}
	return nil
}

// isBusyLocked reports whether err is a SQLite BUSY or LOCKED result code
// (the retryable contention classes for BEGIN IMMEDIATE serialization).
func isBusyLocked(err error) bool {
	if err == nil {
		return false
	}
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() {
		case 5, 6: // SQLITE_BUSY, SQLITE_LOCKED
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "database is locked") || strings.Contains(msg, "database table is locked") || strings.Contains(msg, "sqlite_busy")
}

// busyWait waits with backoff until ctx is done.
func busyWait(ctx context.Context, attempt int) error {
	d := time.Duration(1<<uint(min(attempt, 6))) * time.Millisecond
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
