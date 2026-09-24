package staging

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	sqlite "modernc.org/sqlite"
)

// latestSchemaVersion is the only schema version this subsystem knows. A
// pre-existing database whose version table records anything else — or that
// carries unknown objects — is rejected, never adopted or guessed at.
const latestSchemaVersion = 1

// busytimeoutMS is the busy-timeout installed on every pooled connection
// when the caller did not configure one.
const busytimeoutMS = 5000

// migrationFault is a test-only injection point that fails the version-1
// migration after its DDL and before the version row is recorded, proving
// the whole migration rolls back atomically.
var migrationFault error

// versionTableDDL is the exact DDL of the version bookkeeping table. It is
// part of the verified schema surface like every other object.
const versionTableDDL = `create table staging_schema (version integer primary key, applied_at integer not null)`

// schemaDDL is the ordered DDL for the staging schema (version 1).
//
// Storage classes are pinned with typeof() checks; timestamps are signed
// Unix nanoseconds (INTEGER only, never REAL/text/BLOB); expiry is strictly
// after creation; state coherence (active and creating carry no finalize
// metadata, a finalized row carries all of it with size == offset) is
// enforced by CHECK plus the triggers below, which cover transitions CHECK
// cannot see. The integer fields are declared WITHOUT a type name (BLOB
// affinity) so SQLite never coerces REAL or numeric TEXT into INTEGER
// storage before the CHECK sees it — the typeof() checks below then provably
// accept only genuine INTEGER storage-class values.
//
// Grammar notes (mirroring the Go validators byte-for-byte):
//   - digest is exactly "sha256:" + 64 lowercase hex: the prefix is compared
//     literally and the tail must be all-lowercase hex — the GLOB-suffix
//     loophole ('sha256:[0-9a-f]*') is gone.
//   - repo rejects leading/dot/hyphen/underscore segment starts (and empty
//     segments) via ('/' || repo) — first character included.
//   - actor rejects '+' and requires an alphanumeric first character.
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
		check (typeof(id) = 'text' and length(hex(id)) = 128 and id = lower(id) and id not glob '*[^0-9a-f]*' and instr(hex(id), '00') = 0),
		check (typeof(repo) = 'text' and length(hex(repo)) between 2 and 400 and instr(hex(repo), '00') = 0 and repo = lower(repo) and repo not glob '*[^a-z0-9._/-]*' and repo not glob '/**' and repo not glob '*/' and repo not glob '*//*' and repo not glob '*..*' and ('/' || repo) not glob '*[/][._-]*'),
		check (typeof(actor) = 'text' and length(hex(actor)) between 2 and 400 and instr(hex(actor), '00') = 0 and actor not glob '*[^a-zA-Z0-9:_@.-]*' and actor not glob '[+._:@-]*'),
		check (state in ('active','creating','finalized','deleting')),
		check (typeof(offset) = 'integer' and offset >= 0),
		check (typeof(created_at) = 'integer' and typeof(expires_at) = 'integer' and expires_at > created_at),
		check (
			(state = 'active' and digest is null and bee_ref is null and media_type is null and size is null)
			or (state = 'creating' and digest is null and bee_ref is null and media_type is null and size is null and offset = 0)
			or (state = 'finalized' and digest is not null and bee_ref is not null and media_type is not null
				and size is not null and typeof(size) = 'integer' and size = offset
				and typeof(digest) = 'text' and length(hex(digest)) = 142 and instr(hex(digest), '00') = 0
				and digest = lower(digest) and substr(digest, 1, 7) = 'sha256:' and substr(digest, 8) not glob '*[^0-9a-f]*'
				and typeof(bee_ref) = 'text' and length(hex(bee_ref)) = 128 and instr(hex(bee_ref), '00') = 0
				and bee_ref = lower(bee_ref) and bee_ref not glob '*[^0-9a-f]*'
				and typeof(media_type) = 'text' and length(hex(media_type)) between 2 and 400
				and instr(hex(media_type), '00') = 0 and media_type not glob '*[^a-z0-9.+/_-]*')
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
		check (typeof(upload_id) = 'text' and length(hex(upload_id)) = 128 and upload_id = lower(upload_id) and upload_id not glob '*[^0-9a-f]*' and instr(hex(upload_id), '00') = 0),
		check (typeof(repo) = 'text' and length(hex(repo)) between 2 and 400 and instr(hex(repo), '00') = 0 and repo = lower(repo) and repo not glob '*[^a-z0-9._/-]*' and repo not glob '/**' and repo not glob '*/' and repo not glob '*//*' and repo not glob '*..*' and ('/' || repo) not glob '*[/][._-]*'),
		check (typeof(actor) = 'text' and length(hex(actor)) between 2 and 400 and instr(hex(actor), '00') = 0 and actor not glob '*[^a-zA-Z0-9:_@.-]*' and actor not glob '[+._:@-]*'),
		check (typeof(digest) = 'text' and length(hex(digest)) = 142 and instr(hex(digest), '00') = 0 and digest = lower(digest) and substr(digest, 1, 7) = 'sha256:' and substr(digest, 8) not glob '*[^0-9a-f]*'),
		check (typeof(bee_ref) = 'text' and length(hex(bee_ref)) = 128 and instr(hex(bee_ref), '00') = 0 and bee_ref = lower(bee_ref) and bee_ref not glob '*[^0-9a-f]*'),
		check (typeof(size) = 'integer' and size >= 0),
		check (typeof(media_type) = 'text' and length(hex(media_type)) between 2 and 400 and instr(hex(media_type), '00') = 0 and media_type not glob '*[^a-z0-9.+/_-]*'),
		check (typeof(created_at) = 'integer' and typeof(expires_at) = 'integer' and expires_at > created_at)
	)`,
	`create index idx_staged_blobs_owner on staged_blobs(repo, actor, created_at, upload_id)`,
	`create index idx_sessions_owner on upload_sessions(repo, actor)`,
	`create index idx_sessions_expiry on upload_sessions(expires_at)`,
	// A session may only be born active (offset 0, no finalize metadata) or
	// creating (offset 0, no metadata): the durable-creation pre-state.
	`create trigger trg_session_insert before insert on upload_sessions begin
		select case when not (
			(new.state = 'active' and new.offset = 0
				and new.digest is null and new.bee_ref is null and new.media_type is null and new.size is null)
			or (new.state = 'creating' and new.offset = 0
				and new.digest is null and new.bee_ref is null and new.media_type is null and new.size is null))
			then raise(abort, 'session insert must be active or creating') end;
	end`,
	// State transitions: active may only be ENTERED from creating; nothing
	// may re-enter creating; finalize requires a fully matching staged blob
	// (identity, metadata, timing) and size == offset; the deleting tombstone
	// is terminal.
	`create trigger trg_session_state before update of state on upload_sessions begin
		select case
			when new.state = 'active' and old.state <> 'creating' and new.state <> old.state then raise(abort, 'cannot return to active')
			when new.state = 'creating' and new.state <> old.state then raise(abort, 'cannot enter creating')
			when new.state = 'finalized' and not (
				select exists(select 1 from staged_blobs b where b.upload_id = new.id
					and b.repo = new.repo and b.actor = new.actor and b.created_at = new.created_at
					and b.expires_at = new.expires_at and b.digest = new.digest and b.bee_ref = new.bee_ref
					and b.media_type = new.media_type and b.size = new.size)
				and new.digest is not null and new.bee_ref is not null
				and new.media_type is not null and new.size is not null and new.size = new.offset)
				then raise(abort, 'finalize requires matching staged blob')
			when new.state = 'deleting' and old.state = 'deleting' then raise(abort, 'already deleting')
			when old.state = 'deleting' and new.state <> 'deleting' then raise(abort, 'deleting is terminal')
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

// schemaObject is the exact expected sqlite_master surface of one object:
// type, name, table, and the SQL-aware normalized body.
type schemaObject struct {
	typ  string
	name string
	tbl  string
	sql  string
}

// expectedSchema is built once from the subsystem's own DDL: the version
// table plus every schemaDDL statement. Verification compares against this,
// so any drift between the DDL used to migrate and the DDL expected on
// reopen is impossible.
var expectedSchema = mustSchemaObjects()

func mustSchemaObjects() []schemaObject {
	all := append([]string{versionTableDDL}, schemaDDL...)
	objs := make([]schemaObject, 0, len(all))
	for _, ddl := range all {
		typ, name, tbl, err := parseDDLHead(ddl)
		if err != nil {
			panic(fmt.Sprintf("staging schema DDL is not parseable: %v", err))
		}
		norm, err := normalizeSQL(ddl)
		if err != nil {
			panic(fmt.Sprintf("staging schema DDL is not normalizable: %v", err))
		}
		objs = append(objs, schemaObject{typ: typ, name: name, tbl: tbl, sql: norm})
	}
	return objs
}

// parseDDLHead derives (type, name, tbl_name) from the leading tokens of a
// CREATE statement. The full-statement identity comes from normalizeSQL.
func parseDDLHead(ddl string) (typ, name, tbl string, err error) {
	f := strings.Fields(ddl)
	if len(f) < 3 || !strings.EqualFold(f[0], "create") {
		return "", "", "", errors.New("cannot parse schema DDL head")
	}
	typ = strings.ToLower(f[1])
	switch typ {
	case "table":
		if len(f) < 3 {
			return "", "", "", errors.New("table DDL lacks a name")
		}
		name = f[2]
		tbl = name
	case "index":
		if len(f) < 5 || !strings.EqualFold(f[3], "on") {
			return "", "", "", errors.New("index DDL is malformed")
		}
		name = f[2]
		tbl = f[4]
		if i := strings.IndexByte(tbl, '('); i >= 0 {
			tbl = tbl[:i]
		}
	case "trigger":
		if len(f) < 5 {
			return "", "", "", errors.New("trigger DDL is malformed")
		}
		name = f[2]
		for i := 3; i+1 < len(f); i++ {
			if strings.EqualFold(f[i], "on") {
				tbl = f[i+1]
				break
			}
		}
		if tbl == "" {
			return "", "", "", errors.New("trigger DDL lacks a table")
		}
	default:
		return "", "", "", fmt.Errorf("unexpected schema DDL type %q", typ)
	}
	return typ, name, tbl, nil
}

// normalizeSQL canonicalizes schema DDL for byte-exact comparison while
// preserving quoted content byte-for-byte: characters outside quotes are
// lowercased, whitespace collapses, and comments or unterminated quotes are
// rejected outright — a lookalike that re-quotes a body, changes a literal,
// or hides a weakening inside a comment cannot pass. A trailing semicolon
// (which SQLite strips when storing object text) is trimmed.
func normalizeSQL(sqlText string) (string, error) {
	var b strings.Builder
	var last byte = ' '
	i, n := 0, len(sqlText)
	for i < n {
		c := sqlText[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			j := i
			for j < n && (sqlText[j] == ' ' || sqlText[j] == '\t' || sqlText[j] == '\r' || sqlText[j] == '\n') {
				j++
			}
			if b.Len() > 0 && last != ' ' {
				b.WriteByte(' ')
			}
			i = j
		case c == '\'':
			j := i + 1
			for {
				if j >= n {
					return "", errors.New("unterminated string literal in schema object")
				}
				if sqlText[j] == '\'' {
					if j+1 < n && sqlText[j+1] == '\'' {
						j += 2
						continue
					}
					break
				}
				j++
			}
			b.WriteString(sqlText[i : j+1])
			last = '\''
			i = j + 1
		case c == '"':
			j := i + 1
			for {
				if j >= n {
					return "", errors.New("unterminated quoted identifier in schema object")
				}
				if sqlText[j] == '"' {
					if j+1 < n && sqlText[j+1] == '"' {
						j += 2
						continue
					}
					break
				}
				j++
			}
			b.WriteString(sqlText[i : j+1])
			last = '"'
			i = j + 1
		case c == '`':
			return "", errors.New("backtick quoting in schema object")
		case c == '-' && i+1 < n && sqlText[i+1] == '-':
			return "", errors.New("comment in schema object")
		case c == '/' && i+1 < n && sqlText[i+1] == '*':
			return "", errors.New("comment in schema object")
		default:
			b.WriteByte(lowerASCII(c))
			last = c
			i++
		}
	}
	out := strings.TrimSuffix(strings.TrimSpace(b.String()), ";")
	return strings.TrimSpace(out), nil
}

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

// openStagingDB opens (creating if needed) the dedicated staging database
// and applies/verifies the schema. maxOpen sets the pool cap (0 keeps the
// driver default; NewService always passes a finite pool size).
//
// Filesystem anchoring: the database parent is resolved descriptor-relatively
// (symlink-rejecting chain, repaired to exactly 0700 — never touching the
// bare "." parent of a bare name), the database file is verified to be a
// regular non-symlink file BEFORE any mutation-capable connection opens, and
// its identity is re-verified through the anchored descriptor after open
// (os.SameFile against the captured expectation). The schema decision
// (empty / current / foreign) is made on a mode=ro, mutation-pragma-free
// inspection connection FIRST, so a database we reject is never opened in a
// way that could write to it — its bytes stay untouched.
func openStagingDB(ctx context.Context, dbPath string, maxOpen int) (*sql.DB, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	base := basePathOf(dbPath)
	if base == "" || strings.Contains(base, ":memory:") {
		// Pure in-memory target: always fresh, no filesystem involvement.
		db, err := sql.Open("sqlite", normalizeDSN(dbPath))
		if err != nil {
			return nil, typed(ErrDependency, err)
		}
		if maxOpen > 0 {
			db.SetMaxOpenConns(maxOpen)
			db.SetMaxIdleConns(maxOpen)
		}
		if err := createFreshSchema(ctx, db); err != nil {
			db.Close()
			return nil, err
		}
		return db, nil
	}

	parentRoot, dbName, preFi, absent, err := prepareDBTarget(ctx, dbPath)
	if err != nil {
		return nil, err
	}
	defer parentRoot.Close()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if absent {
		// We create the file ourselves through the anchored descriptor
		// (O_EXCL, no symlink following) so SQLite never opens a foreign
		// target that merely appeared at the path.
		created, err := createDBFile(parentRoot, dbName)
		if err != nil {
			return nil, err
		}
		preFi = created
	}

	state, err := inspectSchemaState(ctx, dbPath)
	if err != nil {
		return nil, err
	}
	if state == schemaReject {
		return nil, typed(ErrDependency, errors.New("staging database is not a supported upload-staging schema"))
	}

	// Only after the schema is fully verified may the database file be
	// touched by a mutation-capable connection; the private mode is exact
	// 0600 first (through a descriptor, never via a path).
	if err := repairDBFileMode(parentRoot, dbName, preFi); err != nil {
		return nil, err
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
	if state == schemaEmpty {
		if err := createFreshSchema(ctx, db); err != nil {
			return nil, err
		}
	}
	// Post-open identity: the opened database is still exactly the file we
	// verified — regular, non-symlink, 0600, same inode.
	if err := verifyDBIdentity(parentRoot, dbName, preFi); err != nil {
		return nil, err
	}
	if err := syncRootDir(parentRoot); err != nil {
		return nil, typed(ErrDependency, err)
	}
	closeOnErr = false
	return db, nil
}

// basePathOf returns the on-disk path portion of a DSN (stripping any file:
// scheme and query parameters).
func basePathOf(dsn string) string {
	p := dsn
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	p = strings.TrimPrefix(p, "file:")
	return p
}

// prepareDBTarget splits dbPath into its parent anchor and basename,
// resolves the parent through the private directory chain (the bare "."
// parent of a bare database name is neither created nor mode-repaired), and
// captures the database file's identity — or its absence — for later
// descriptor-relative verification, creation, and post-open identity checks.
// A symlink or non-regular database path is rejected BEFORE any SQLite
// connection exists.
func prepareDBTarget(ctx context.Context, dbPath string) (root *os.Root, dbName string, preFi os.FileInfo, absent bool, err error) {
	if err := ctx.Err(); err != nil {
		return nil, "", nil, false, err
	}
	base := basePathOf(dbPath)
	if base == "" {
		return nil, "", nil, false, typed(ErrDependency, errors.New("empty database path"))
	}
	parent := filepath.Dir(base)
	dbName = filepath.Base(base)
	enforce := parent != "."
	parentRoot, err := openPrivateDirChain(parent, enforce)
	if err != nil {
		return nil, "", nil, false, err
	}
	fi, lerr := parentRoot.Lstat(dbName)
	switch {
	case lerr == nil:
		if fi.Mode()&os.ModeSymlink != 0 {
			parentRoot.Close()
			return nil, "", nil, false, typed(ErrDependency, errors.New("database path is a symbolic link"))
		}
		if !fi.Mode().IsRegular() {
			parentRoot.Close()
			return nil, "", nil, false, typed(ErrDependency, errors.New("database path is not a regular file"))
		}
		return parentRoot, dbName, fi, false, nil
	case os.IsNotExist(lerr):
		return parentRoot, dbName, nil, true, nil
	default:
		parentRoot.Close()
		return nil, "", nil, false, typed(ErrDependency, lerr)
	}
}

// createDBFile creates the database file through the anchored descriptor
// with O_EXCL 0600 and fsyncs the containing directory so the entry is
// durable before SQLite opens it.
func createDBFile(parentRoot *os.Root, dbName string) (os.FileInfo, error) {
	f, err := parentRoot.OpenFile(dbName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, typed(ErrDependency, errors.New("cannot create database file"))
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		_ = parentRoot.Remove(dbName)
		return nil, typed(ErrDependency, err)
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0o077 != 0 {
		f.Close()
		_ = parentRoot.Remove(dbName)
		return nil, typed(ErrDependency, errors.New("database file is not a private regular file"))
	}
	if err := f.Close(); err != nil {
		return nil, typed(ErrDependency, err)
	}
	return st, nil
}

// repairDBFileMode verifies through the anchored descriptor that the
// database file is a real regular non-symlink file with the exact identity
// captured before inspection, and makes its mode exactly 0600. It runs only
// AFTER the schema is fully verified and BEFORE the mutation-capable
// connection opens.
func repairDBFileMode(parentRoot *os.Root, dbName string, preFi os.FileInfo) error {
	f, err := parentRoot.OpenFile(dbName, os.O_RDONLY, 0)
	if err != nil {
		return typed(ErrDependency, errors.New("cannot open database file"))
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return typed(ErrDependency, err)
	}
	if !st.Mode().IsRegular() || (preFi != nil && !os.SameFile(st, preFi)) {
		f.Close()
		return typed(ErrDependency, errors.New("database file changed before open"))
	}
	if p := st.Mode().Perm(); p != 0o600 {
		if err := f.Chmod(0o600); err != nil {
			f.Close()
			return typed(ErrDependency, errors.New("cannot make database file private"))
		}
	}
	f.Close()
	fi, err := parentRoot.Lstat(dbName)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		return typed(ErrDependency, errors.New("database file is not a private regular file"))
	}
	return nil
}

// verifyDBIdentity confirms through the anchored descriptor that the
// database file is still a regular non-symlink 0600 file and — when an
// expectation was captured — the very same inode that was inspected.
func verifyDBIdentity(parentRoot *os.Root, dbName string, preFi os.FileInfo) error {
	fi, err := parentRoot.Lstat(dbName)
	if err != nil {
		return typed(ErrDependency, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		return typed(ErrDependency, errors.New("database file is not a private regular file"))
	}
	if preFi != nil && !os.SameFile(preFi, fi) {
		return typed(ErrDependency, errors.New("database file changed during open"))
	}
	return nil
}

// syncRootDir fsyncs the parent directory of the database file so a fresh
// creation and its migration are durably linked.
func syncRootDir(root *os.Root) error {
	f, err := root.Open(".")
	if err != nil {
		return typed(ErrDependency, err)
	}
	err = f.Sync()
	f.Close()
	if err != nil {
		return typed(ErrDependency, err)
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

type schemaState int

const (
	schemaReject schemaState = iota
	schemaEmpty
	schemaCurrent
)

// inspectSchemaState examines an existing database on a read-only,
// mutation-pragma-free connection and returns:
//
//	schemaEmpty   — no tables and no version row: an empty file, migratable;
//	schemaCurrent — every expected object exists with the EXACT expected SQL
//	                body, physical column/index/FK shape, and version row;
//	schemaReject  — anything else (foreign schema, lookalike bodies, unknown
//	                objects, mutated fixtures…).
//
// Because the connection is mode=ro, a rejected database is never written.
func inspectSchemaState(ctx context.Context, dbPath string) (schemaState, error) {
	db, err := sql.Open("sqlite", inspectionDSN(dbPath))
	if err != nil {
		return schemaReject, typed(ErrDependency, err)
	}
	defer db.Close()
	tables, err := userTables(ctx, db)
	if err != nil {
		return schemaReject, typed(ErrDependency, err)
	}
	version, hasVersion, err := currentVersion(ctx, db)
	if err != nil {
		return schemaReject, typed(ErrDependency, err)
	}
	if len(tables) == 0 && !hasVersion {
		return schemaEmpty, nil
	}
	if !hasVersion || version != latestSchemaVersion {
		return schemaReject, typed(ErrDependency, fmt.Errorf(
			"staging database is not a supported upload-staging schema (tables=%v, version=%v)",
			tables, version))
	}
	if err := verifySchemaFully(ctx, &txAdapter{db: db}); err != nil {
		return schemaReject, typed(ErrDependency, err)
	}
	if err := verifyVersionRow(ctx, &txAdapter{db: db}); err != nil {
		return schemaReject, typed(ErrDependency, err)
	}
	return schemaCurrent, nil
}

// inspectionDSN builds a read-only, mutation-pragma-free DSN for the
// pre-open examination connection. mode=ro removes every write capability
// (journal replay, header fixups, sidecars); mutation pragmas and any
// caller-supplied mode are stripped so ro always wins.
func inspectionDSN(dsn string) string {
	if !strings.Contains(dsn, "?") {
		return dsn + "?mode=ro"
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
		if strings.HasPrefix(lower, "_pragma=journal_mode(") ||
			strings.HasPrefix(lower, "_pragma=synchronous(") ||
			strings.HasPrefix(lower, "mode=") {
			continue
		}
		kept = append(kept, param)
	}
	kept = append(kept, "_pragma=foreign_keys(1)", "mode=ro")
	return base + "?" + strings.Join(kept, "&")
}

func userTables(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, `select name from sqlite_master where type = 'table' and name not like 'sqlite_%' order by name`)
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

func currentVersion(ctx context.Context, db *sql.DB) (int64, bool, error) {
	rows, err := db.QueryContext(ctx, `select version from staging_schema`)
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
// whole migration back. The schema verifies itself inside the transaction
// before the version row is recorded.
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
	if _, err := tx.ExecContext(ctx, versionTableDDL); err != nil {
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
	if err := verifySchemaFully(ctx, tx); err != nil {
		return typed(ErrDependency, err)
	}
	if _, err := tx.ExecContext(ctx,
		`insert into staging_schema (version, applied_at) values (?, ?)`, latestSchemaVersion, now); err != nil {
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

// verifySchemaFully validates the complete expected sqlite_schema surface:
// the exact object set with SQL-aware normalized bodies, the exact physical
// column shapes (table_xinfo incl. hidden columns), the exact index columns
// (index_xinfo), the exact single foreign key row, FK integrity (no orphan
// rows), and the absence of temporary objects.
func verifySchemaFully(ctx context.Context, db schemaChecker) error {
	if err := verifySchemaObjects(ctx, db); err != nil {
		return err
	}
	for _, table := range []string{versionTable, sessionTable, blobTable} {
		if err := verifyColumnShapes(ctx, db, table); err != nil {
			return err
		}
	}
	for _, idx := range []string{"idx_staged_blobs_owner", "idx_sessions_owner", "idx_sessions_expiry"} {
		if err := verifyIndexShape(ctx, db, idx); err != nil {
			return err
		}
	}
	if err := verifyForeignKeys(ctx, db); err != nil {
		return err
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
	var temp int
	if err := db.QueryRowContext(ctx, `select count(*) from sqlite_temp_master where type in ('table','trigger','index','view')`).Scan(&temp); err != nil {
		return err
	}
	if temp != 0 {
		return errors.New("staging schema must not create temporary objects")
	}
	return nil
}

// verifySchemaObjects proves the object set is EXACTLY the expected one and
// every object's stored body normalizes to the expected SQL: a lookalike
// that shares a name but relaxes a check, changes a trigger body, reorders
// index columns, or carries different quoted content is rejected.
func verifySchemaObjects(ctx context.Context, db schemaChecker) error {
	var total int
	if err := db.QueryRowContext(ctx,
		`select count(*) from sqlite_master where type in ('table','index','trigger','view') and name not like 'sqlite_%'`).
		Scan(&total); err != nil {
		return err
	}
	if total != len(expectedSchema) {
		return fmt.Errorf("staging schema has %d objects, want %d", total, len(expectedSchema))
	}
	for i := range expectedSchema {
		want := &expectedSchema[i]
		var typ, tbl, sqlText string
		err := db.QueryRowContext(ctx,
			`select type, tbl_name, sql from sqlite_master where name = ? and type in ('table','index','trigger','view')`,
			want.name).Scan(&typ, &tbl, &sqlText)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("staging schema lacks object %s", want.name)
		}
		if err != nil {
			return err
		}
		if typ != want.typ || tbl != want.tbl {
			return fmt.Errorf("staging schema object %s does not match its expected type/table", want.name)
		}
		norm, err := normalizeSQL(sqlText)
		if err != nil {
			return err
		}
		if norm != want.sql {
			return fmt.Errorf("staging schema object %s body differs from the expected schema", want.name)
		}
	}
	return nil
}

type columnShape struct {
	name    string
	typ     string
	notnull bool
	pk      bool
}

var expectedColumnShapes = map[string][]columnShape{
	versionTable: {
		{name: "version", typ: "integer", pk: true},
		{name: "applied_at", typ: "integer", notnull: true},
	},
	sessionTable: {
		{name: "id", typ: "text", pk: true},
		{name: "repo", typ: "text", notnull: true},
		{name: "actor", typ: "text", notnull: true},
		{name: "state", typ: "text", notnull: true},
		{name: "offset", typ: "", notnull: true},
		{name: "created_at", typ: "", notnull: true},
		{name: "expires_at", typ: "", notnull: true},
		{name: "digest", typ: "text"},
		{name: "bee_ref", typ: "text"},
		{name: "media_type", typ: "text"},
		{name: "size", typ: ""},
	},
	blobTable: {
		{name: "upload_id", typ: "text", pk: true},
		{name: "repo", typ: "text", notnull: true},
		{name: "actor", typ: "text", notnull: true},
		{name: "digest", typ: "text", notnull: true},
		{name: "bee_ref", typ: "text", notnull: true},
		{name: "size", typ: "", notnull: true},
		{name: "media_type", typ: "text", notnull: true},
		{name: "created_at", typ: "", notnull: true},
		{name: "expires_at", typ: "", notnull: true},
	},
}

// verifyColumnShapes proves table_xinfo (incl. hidden columns) matches the
// expected columns EXACTLY — same count, names, storage classes, NOT NULL
// flags, PK flags, and no hidden columns.
func verifyColumnShapes(ctx context.Context, db schemaChecker, table string) error {
	rows, err := db.QueryContext(ctx, fmt.Sprintf(`pragma table_xinfo(%s)`, table))
	if err != nil {
		return err
	}
	var got []columnShape
	for rows.Next() {
		var cid, notnull, pk, hidden int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk, &hidden); err != nil {
			rows.Close()
			return err
		}
		got = append(got, columnShape{name: name, typ: strings.ToLower(typ), notnull: notnull == 1, pk: pk == 1})
		if hidden != 0 {
			rows.Close()
			return fmt.Errorf("staging schema table %s has an unexpected hidden column", table)
		}
	}
	rows.Close()
	want := expectedColumnShapes[table]
	if len(got) != len(want) {
		return fmt.Errorf("staging schema table %s has %d columns, want %d", table, len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			return fmt.Errorf("staging schema table %s column %d mismatch: got %+v, want %+v", table, i, got[i], want[i])
		}
	}
	return nil
}

var expectedIndexCols = map[string][]string{
	"idx_staged_blobs_owner": {"repo", "actor", "created_at", "upload_id"},
	"idx_sessions_owner":     {"repo", "actor"},
	"idx_sessions_expiry":    {"expires_at"},
}

// verifyIndexShape proves index_xinfo matches the expected ordered columns
// with no descending columns. The implicit table-rowid auxiliary row that
// SQLite appends to indexes of rowid tables (NULL name, key=0) is expected
// and not part of the declared column list.
func verifyIndexShape(ctx context.Context, db schemaChecker, idx string) error {
	rows, err := db.QueryContext(ctx, fmt.Sprintf(`pragma index_xinfo(%s)`, idx))
	if err != nil {
		return err
	}
	var cols []string
	for rows.Next() {
		var seqno, cid, desc, key int
		var name sql.NullString
		var coll string
		if err := rows.Scan(&seqno, &cid, &name, &desc, &coll, &key); err != nil {
			rows.Close()
			return err
		}
		if desc != 0 {
			rows.Close()
			return fmt.Errorf("staging schema index %s has a descending column", idx)
		}
		if !name.Valid {
			continue // implicit rowid auxiliary entry
		}
		cols = append(cols, name.String)
	}
	rows.Close()
	want := expectedIndexCols[idx]
	if len(cols) != len(want) {
		return fmt.Errorf("staging schema index %s has %d columns, want %d", idx, len(cols), len(want))
	}
	for i := range want {
		if cols[i] != want[i] {
			return fmt.Errorf("staging schema index %s column %d = %q, want %q", idx, i, cols[i], want[i])
		}
	}
	return nil
}

// verifyForeignKeys proves the staged_blobs FK is EXACTLY the single
// expected row: upload_id -> upload_sessions(id), ON DELETE CASCADE, NO
// ACTION update, NONE match.
func verifyForeignKeys(ctx context.Context, db schemaChecker) error {
	rows, err := db.QueryContext(ctx, `pragma foreign_key_list(staged_blobs)`)
	if err != nil {
		return err
	}
	count := 0
	for rows.Next() {
		var id, seq int
		var t, from, to, onUpdate, onDelete, match string
		if err := rows.Scan(&id, &seq, &t, &from, &to, &onUpdate, &onDelete, &match); err != nil {
			rows.Close()
			return err
		}
		count++
		if count > 1 {
			rows.Close()
			return errors.New("staging schema has more than one foreign key on staged_blobs")
		}
		if t != sessionTable || from != "upload_id" || to != "id" ||
			onDelete != "CASCADE" || onUpdate != "NO ACTION" || match != "NONE" || id != 0 || seq != 0 {
			rows.Close()
			return errors.New("staging schema staged_blobs foreign key differs from the expected one")
		}
	}
	rows.Close()
	if count != 1 {
		return errors.New("staging schema lacks the expected staged_blobs foreign key")
	}
	return nil
}

// verifyVersionRow proves the version row is exactly one row with the latest
// version and an INTEGER applied_at (never text/numeric-coerced).
func verifyVersionRow(ctx context.Context, db schemaChecker) error {
	rows, err := db.QueryContext(ctx, `select version, typeof(applied_at), applied_at from staging_schema`)
	if err != nil {
		return err
	}
	count := 0
	for rows.Next() {
		var v int64
		var typ string
		var applied int64
		if err := rows.Scan(&v, &typ, &applied); err != nil {
			rows.Close()
			return err
		}
		count++
		if count > 1 {
			rows.Close()
			return errors.New("staging_schema has multiple version rows")
		}
		if v != latestSchemaVersion || typ != "integer" {
			rows.Close()
			return errors.New("staging_schema version row differs from the expected one")
		}
	}
	rows.Close()
	if count != 1 {
		return errors.New("staging_schema has no version row")
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
