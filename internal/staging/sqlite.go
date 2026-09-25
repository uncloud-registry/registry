package staging

import (
	"context"
	"database/sql"
	"database/sql/driver"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	sqlite "modernc.org/sqlite"
)

// latestSchemaVersion is the current staging schema version. The migration
// path accepts exactly two committed v1 predecessor shapes (the exact
// pre-cleanup-token v1 and the exact cleanup-token-v1 compatibility shape),
// an exact v2 predecessor, and a fresh empty file — every shape is recognized
// ONLY by its exact frozen object surface plus version, never guessed at. A
// pre-existing database that matches none of them is rejected, never adopted.
//
// v4 is the current schema. It carries one forward change over v3: the durable
// finalization claim state `finalizing`, which an upload winner commits BEFORE
// any external object-store write so concurrent or retried finalizes serialize
// to a single Bee write. A finalizing row freezes its exact staged snapshot
// (offset == the hashed size), rejects appends, fails delete/expire closed,
// and is never listed for publication; it is retained fail-closed across
// restarts until an explicit reconciliation path settles it. v3 never had such
// a frozen pre-write claim, so two concurrent PUTs could both reach Bee.
const latestSchemaVersion = 4

// busytimeoutMS is the busy-timeout installed on every pooled connection
// when the caller did not configure one.
const busytimeoutMS = 5000

// migrationFault is a test-only injection point that fails the fresh v2
// creation after its DDL and before the version row is recorded, proving
// the whole creation rolls back atomically.
var migrationFault error

// migrationCopyFault and migrationVersionFault are test-only injection
// points for the atomic predecessor->v2 migration: the first fails the
// migration right after the pre-cleanup row copy (mid-rebuild), the second
// immediately before the version record is written. Both prove rollback
// restores the exact predecessor schema, rows, and version.
var (
	migrationCopyFault    error
	migrationVersionFault error
)

// reconcileSnapshotHook is a test-only injection point (nil in production):
// it fires after the Phase A row snapshot in startup reconciliation, so a
// test can interleave a concurrently-activating creator exactly at the
// stale-snapshot race window.
var reconcileSnapshotHook func()

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
		create_token text,
		cleanup_token text,
		finalize_token text,
		digest     text,
		bee_ref    text,
		media_type text,
		size,
		check (typeof(id) = 'text' and length(hex(id)) = 128 and id = lower(id) and id not glob '*[^0-9a-f]*' and instr(hex(id), '00') = 0),
		check (typeof(repo) = 'text' and length(hex(repo)) between 2 and 400 and instr(hex(repo), '00') = 0 and repo = lower(repo) and repo not glob '*[^a-z0-9._/-]*' and repo not glob '/**' and repo not glob '*/' and repo not glob '*//*' and repo not glob '*..*' and ('/' || repo) not glob '*[/][._-]*'),
		check (typeof(actor) = 'text' and length(hex(actor)) between 2 and 400 and instr(hex(actor), '00') = 0 and actor not glob '*[^a-zA-Z0-9:_@.-]*' and actor not glob '[+._:@-]*'),
		check (state in ('active','creating','finalizing','finalized','deleting')),
		check (typeof(offset) = 'integer' and offset >= 0),
		check (typeof(created_at) = 'integer' and typeof(expires_at) = 'integer' and expires_at > created_at),
		check (cleanup_token is null or (typeof(cleanup_token) = 'text' and length(hex(cleanup_token)) = 128 and cleanup_token = lower(cleanup_token) and cleanup_token not glob '*[^0-9a-f]*' and instr(hex(cleanup_token), '00') = 0)),
		check (finalize_token is null or (typeof(finalize_token) = 'text' and length(hex(finalize_token)) = 128 and finalize_token = lower(finalize_token) and finalize_token not glob '*[^0-9a-f]*' and instr(hex(finalize_token), '00') = 0)),
		check (
			(state = 'active' and digest is null and bee_ref is null and media_type is null and size is null and create_token is null and finalize_token is null)
			or (state = 'finalizing' and digest is null and bee_ref is null and media_type is null and size is null and create_token is null
				and typeof(finalize_token) = 'text' and length(hex(finalize_token)) = 128
				and finalize_token = lower(finalize_token)
				and finalize_token not glob '*[^0-9a-f]*' and instr(hex(finalize_token), '00') = 0)
			or (state = 'creating' and digest is null and bee_ref is null and media_type is null and size is null and offset = 0
				and typeof(create_token) = 'text' and length(hex(create_token)) = 128 and create_token = lower(create_token)
				and create_token not glob '*[^0-9a-f]*' and instr(hex(create_token), '00') = 0 and cleanup_token is null and finalize_token is null)
			or (state = 'finalized' and digest is not null and bee_ref is not null and media_type is not null
				and size is not null and typeof(size) = 'integer' and size = offset
				and typeof(digest) = 'text' and length(hex(digest)) = 142 and instr(hex(digest), '00') = 0
				and digest = lower(digest) and substr(digest, 1, 7) = 'sha256:' and substr(digest, 8) not glob '*[^0-9a-f]*'
				and typeof(bee_ref) = 'text' and length(hex(bee_ref)) = 128 and instr(hex(bee_ref), '00') = 0
				and bee_ref = lower(bee_ref) and bee_ref not glob '*[^0-9a-f]*'
				and typeof(media_type) = 'text' and length(hex(media_type)) between 2 and 400
				and instr(hex(media_type), '00') = 0 and media_type not glob '*[^a-z0-9.+/_-]*'
				and create_token is null and finalize_token is null)
			or (state = 'deleting' and create_token is null and finalize_token is null
				and (cleanup_token is null
					or (typeof(cleanup_token) = 'text' and length(hex(cleanup_token)) = 128
						and cleanup_token = lower(cleanup_token)
						and cleanup_token not glob '*[^0-9a-f]*' and instr(hex(cleanup_token), '00') = 0)))
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
	// Neither birth state may carry the post-activation cleanup token.
	`create trigger trg_session_insert before insert on upload_sessions begin
		select case when not (
			(new.state = 'active' and new.offset = 0
				and new.digest is null and new.bee_ref is null and new.media_type is null and new.size is null
				and new.cleanup_token is null and new.finalize_token is null)
			or (new.state = 'creating' and new.offset = 0
				and new.digest is null and new.bee_ref is null and new.media_type is null and new.size is null
				and new.cleanup_token is null and new.finalize_token is null))
			then raise(abort, 'session insert must be active or creating') end;
	end`,
	// State transitions: active may only be ENTERED from creating; nothing
	// may re-enter creating; finalize requires a fully matching staged blob
	// (identity, metadata, timing) and size == offset; the deleting tombstone
	// is terminal.
	`create trigger trg_session_state before update of state on upload_sessions begin
		select case
			when new.state = 'active' and new.state <> old.state and old.state not in ('creating','finalizing') then raise(abort, 'cannot return to active')
			when new.state = 'creating' and new.state <> old.state then raise(abort, 'cannot enter creating')
			when new.state = 'finalizing' and new.state <> old.state and old.state <> 'active' then raise(abort, 'finalizing requires active')
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
	// The unforgeable per-create token is immutable once set, may never be
	// set after INSERT, and may only be CLEARED while the row is still in
	// the creating phase (activation and rollback both clear it; a live
	// row's token can never be rewritten, which is what guarantees an
	// attacker-planted file can never be attributed to a creating row).
	`create trigger trg_session_token before update of create_token on upload_sessions begin
		select case
			when old.create_token is not null and new.create_token is not null then raise(abort, 'create token immutable')
			when old.create_token is null and new.create_token is not null then raise(abort, 'cannot set create token after insert')
			when old.create_token is not null and new.create_token is null and old.state <> 'creating' then raise(abort, 'create token cannot be cleared outside creating')
			else null end;
	end`,
	// The finalize token is the unforgeable claim identity handed ONLY to the
	// single upload winner at ClaimFinalize. It may be SET exactly once, and
	// only as part of the active -> finalizing claim transition; it may be
	// CLEARED only by the owner from finalizing: on completion (-> finalized,
	// presented as the win identity) or on a CONCLUSIVELY pre-side-effect
	// release (-> active). It is never surfaced by any read path (Status/Open/
	// list), so a foreign instance cannot use or release a claim it never won.
	`create trigger trg_session_finalize before update of finalize_token on upload_sessions begin
		select case
			when old.finalize_token is not null and new.finalize_token is not null and old.finalize_token <> new.finalize_token then raise(abort, 'finalize token immutable')
			when new.finalize_token is not null and old.finalize_token is null and not (old.state = 'active' and new.state = 'finalizing') then raise(abort, 'finalize token may only be set at the claim')
			when old.finalize_token is not null and new.finalize_token is null and old.state not in ('finalizing','finalized') then raise(abort, 'finalize token may only be cleared from finalizing')
			else null end;
	end`,
	// The cleanup token is the durable sidecar provenance. It may be SET at
	// activation (the creating row's create token atomically becomes the
	// cleanup token) or at the deleting transition (an interrupted create's
	// create token, or an already-present cleanup token, becomes the tombstone's
	// authenticating provenance while create_token is cleared). It is immutable
	// while set, and may only be CLEARED from a live row — the Go side clears it
	// only after the sidecar removal and directory fsync, or at startup
	// reconciliation after verifying the sidecar is gone or carries exactly
	// that token.
	`create trigger trg_session_cleanup before update of cleanup_token on upload_sessions begin
		select case
			when old.cleanup_token is not null and new.cleanup_token is not null and old.cleanup_token <> new.cleanup_token then raise(abort, 'cleanup token immutable')
			when new.cleanup_token is not null and old.cleanup_token is null and new.state = 'active'
				and not (old.state = 'creating' and old.create_token is not null
					and old.create_token = new.cleanup_token and new.create_token is null)
				then raise(abort, 'cleanup token may only be set at activation')
			when new.cleanup_token is not null and old.cleanup_token is null and new.state = 'deleting'
				and not (old.state = 'creating' and old.create_token is not null
					and old.create_token = new.cleanup_token and new.create_token is null)
				then raise(abort, 'cleanup token may only be set at activation or delete transition')
			when old.cleanup_token is not null and new.cleanup_token is null and old.state not in ('active','finalized')
				then raise(abort, 'cleanup token may only be cleared from a live row')
			else null end;
	end`,
	// Rows may only be removed through the deleting tombstone.
	`create trigger trg_session_delete before delete on upload_sessions begin
		select case when old.state <> 'deleting' then raise(abort, 'delete only via deleting state') else null end;
	end`,
	// A staged blob must join an ACTIVE session and copy its identity and
	// timing exactly; one blob per session (PK).
	`create trigger trg_blob_insert before insert on staged_blobs begin
		select case when not (
			(select state from upload_sessions where id = new.upload_id) in ('active','finalizing')
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
	Typ  string `json:"type"`
	Name string `json:"name"`
	Tbl  string `json:"tbl"`
	SQL  string `json:"sql"`
}

// goldenColumn is one expected physical column of a table.
type goldenColumn struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	NotNull bool   `json:"notnull"`
	PK      bool   `json:"pk"`
}

// goldenFK is one expected foreign-key declaration row.
type goldenFK struct {
	Table    string `json:"table"`
	From     string `json:"from"`
	To       string `json:"to"`
	RefTable string `json:"ref_table"`
	OnUpdate string `json:"on_update"`
	OnDelete string `json:"on_delete"`
	Match    string `json:"match"`
}

// schemaManifest is the FROZEN, independently authored expectation for the
// staging schema. It is deliberately NOT derived from the migration DDL:
// verification compares a real database against this manifest, and a parity
// test compares the DDL constants against it, so a unilateral change to
// either the creation DDL or this golden fails one of the checks. Mutated
// adversarial fixtures are also built from these bodies, never from the DDL.
type schemaManifest struct {
	Version     int                       `json:"version"`
	Objects     []schemaObject            `json:"objects"`
	Columns     map[string][]goldenColumn `json:"columns"`
	Indexes     map[string][]string       `json:"indexes"`
	ForeignKeys []goldenFK                `json:"foreign_keys"`
}

// The three independently frozen schema manifests. The target v2 golden is
// kept independent of the creation DDL (a parity test binds them), and each
// predecessor shape — the exact pre-cleanup-token v1 and the exact
// cleanup-token-v1 compatibility shape — has its own frozen manifest so a
// single "v1" name can never ambiguously cover two different committed
// green-task states.
//
//go:embed schema_golden_v1_precleanup.json
var schemaGoldenV1PreJSON []byte

//go:embed schema_golden_v1_cleanup.json
var schemaGoldenV1CleanupJSON []byte

//go:embed schema_golden_v2.json
var schemaGoldenV2JSON []byte

//go:embed schema_golden_v3.json
var schemaGoldenV3JSON []byte

//go:embed schema_golden_v4.json
var schemaGoldenV4JSON []byte

// schemaGold is the current (v4) manifest.
var schemaGold = mustLoadSchemaGolden(schemaGoldenV4JSON)

// schemaGoldV3 is the exact frozen v3 predecessor manifest (the previously
// committed "current" shape before v4), retained for migration detection and
// parity. It is never renamed or called v4.
var schemaGoldV3 = mustLoadSchemaGolden(schemaGoldenV3JSON)

// schemaGoldV2 is the exact frozen v2 predecessor manifest (the previously
// committed "current" shape before v3), retained for migration detection and
// parity. It is never renamed or called v3.
var schemaGoldV2 = mustLoadSchemaGolden(schemaGoldenV2JSON)

// schemaGoldV1Pre is the exact pre-cleanup-token v1 predecessor manifest.
var schemaGoldV1Pre = mustLoadSchemaGolden(schemaGoldenV1PreJSON)

// schemaGoldV1Cleanup is the exact cleanup-token-v1 compatibility predecessor
// manifest (same object surface as v2; frozen at version 1).
var schemaGoldV1Cleanup = mustLoadSchemaGolden(schemaGoldenV1CleanupJSON)

// mustLoadSchemaGolden parses a committed schema manifest and sanity-checks
// its structure. It deliberately does NOT panic on a version mismatch with
// latestSchemaVersion: each manifest records its own frozen version (1, 2, or
// 3), and package init must remain alive for upgrade-after-recovery even when a
// manifest's recorded version differs from the current one. Only a manifest
// that cannot even be parsed or carries no objects is a packaging defect.
func mustLoadSchemaGolden(data []byte) *schemaManifest {
	var m schemaManifest
	if err := json.Unmarshal(data, &m); err != nil {
		panic(fmt.Sprintf("staging schema golden is not parseable: %v", err))
	}
	if len(m.Objects) == 0 || m.Version < 1 || m.Version > latestSchemaVersion {
		panic(fmt.Sprintf("staging schema golden version/objects mismatch: %d/%d", m.Version, len(m.Objects)))
	}
	return &m
}

// manifestColumnShapes maps a manifest's frozen column descriptions into the
// runtime columnShape list used by table_xinfo verification.
func manifestColumnShapes(gold *schemaManifest) map[string][]columnShape {
	out := make(map[string][]columnShape, len(gold.Columns))
	for table, cols := range gold.Columns {
		shapes := make([]columnShape, 0, len(cols))
		for _, c := range cols {
			shapes = append(shapes, columnShape{name: c.Name, typ: c.Type, notnull: c.NotNull, pk: c.PK})
		}
		out[table] = shapes
	}
	return out
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

// Test-only fault-injection / observation hooks for the pool constructor
// (nil in production).
var (
	// poolPinHook fires once, after the database is fully verified and just
	// before the retained connection set is acquired. A path swap made here
	// must be caught by the per-connection identity verification.
	poolPinHook func()
	// poolVerifyHook fires after each retained connection is checked out and
	// verified, with the zero-based index. Tests assert that ALL N physical
	// connections are held simultaneously (database/sql InUse == i+1), so a
	// verification that reuses one idle connection is caught.
	poolVerifyHook func(i int)
)

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
	db, _, _, _, _, err := openStagingDBAnchored(ctx, dbPath, maxOpen)
	return db, err
}

// openStagingDBAnchored is openStagingDB plus the retained anchoring
// resources: the descriptor-relative parent root, the database basename, and
// the pre-open file identity, so a caller that pins connections (the pool)
// can identity-verify each one against the exact file that was verified. The
// returned parent root is NOT closed here; the caller owns it. On any error
// the database and the parent root are closed.
func openStagingDBAnchored(ctx context.Context, dbPath string, maxOpen int) (*sql.DB, *os.Root, string, os.FileInfo, schemaState, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, "", nil, schemaReject, err
	}
	base, err := basePathOf(dbPath)
	if err != nil {
		return nil, nil, "", nil, schemaReject, typed(ErrDependency, err)
	}
	if base == "" || strings.Contains(base, ":memory:") {
		// Pure in-memory target: always fresh, no filesystem involvement.
		db, err := sql.Open("sqlite", normalizeDSN(dbPath))
		if err != nil {
			return nil, nil, "", nil, schemaReject, typed(ErrDependency, err)
		}
		if maxOpen > 0 {
			db.SetMaxOpenConns(maxOpen)
			db.SetMaxIdleConns(maxOpen)
		}
		state := schemaEmpty
		if err := createFreshSchema(ctx, db); err != nil {
			db.Close()
			return nil, nil, "", nil, schemaReject, err
		}
		state = schemaCurrent
		return db, nil, "", nil, state, nil
	}

	parentRoot, dbName, preFi, absent, err := prepareDBTarget(ctx, dbPath)
	if err != nil {
		return nil, nil, "", nil, schemaReject, err
	}
	fail := func(e error) (*sql.DB, *os.Root, string, os.FileInfo, schemaState, error) {
		parentRoot.Close()
		return nil, nil, "", nil, schemaReject, e
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}

	if absent {
		// We create the file ourselves through the anchored descriptor
		// (O_EXCL, no symlink following, exact 0600 immediately) so SQLite
		// never opens a foreign target that merely appeared at the path.
		created, cerr := createDBFile(parentRoot, dbName)
		if cerr != nil {
			return fail(cerr)
		}
		preFi = created
	}

	state, err := inspectSchemaState(ctx, dbPath)
	if err != nil {
		return fail(err)
	}
	if state == schemaReject {
		return fail(typed(ErrDependency, errors.New("staging database is not a supported upload-staging schema")))
	}

	// Only after the schema is fully verified may the database file be
	// touched by a mutation-capable connection; the private mode is exact
	// 0600 first (through a descriptor, never via a path).
	if err := repairDBFileMode(parentRoot, dbName, preFi); err != nil {
		return fail(err)
	}

	db, err := sql.Open("sqlite", normalizeDSN(dbPath))
	if err != nil {
		return fail(typed(ErrDependency, err))
	}
	closeOnErr := true
	defer func() {
		if closeOnErr {
			db.Close()
		}
	}()
	if maxOpen > 0 {
		// Bound the pool to exactly the permitted number of connections and
		// keep every one of them alive forever (no idle/lifetime expiry), so
		// the covering check below is exhaustive for the pool lifetime and a
		// later swapped path can never be quietly reopened.
		db.SetMaxOpenConns(maxOpen)
		db.SetMaxIdleConns(maxOpen)
		db.SetConnMaxIdleTime(0)
		db.SetConnMaxLifetime(0)
	}
	switch state {
	case schemaEmpty:
		if err := createFreshSchema(ctx, db); err != nil {
			return fail(err)
		}
	case schemaMigrateV1Pre, schemaMigrateV1Cleanup, schemaMigrateV2, schemaMigrateV3:
		if err := migrateSchema(ctx, db, state); err != nil {
			return fail(err)
		}
	}
	// Post-open identity: the opened database is still exactly the file we
	// verified — regular, non-symlink, 0600, same inode.
	if err := verifyDBIdentity(parentRoot, dbName, preFi); err != nil {
		return fail(err)
	}
	if err := syncRootDir(parentRoot); err != nil {
		return fail(typed(ErrDependency, err))
	}
	closeOnErr = false
	return db, parentRoot, dbName, preFi, state, nil
}

// verifyAndPinAllConns acquires ALL n permitted connections simultaneously
// (so database/sql can never hand back one idle connection repeatedly),
// verifies each physical connection against the anchored database inode and
// the required pragma settings while every handle is held, and returns the
// verified handles for installation into the retained pool. A path swap
// between the final identity check and any single connection's open is
// caught per-connection; the constructor fails closed and every already
// acquired handle is closed.
func verifyAndPinAllConns(ctx context.Context, db *sql.DB, n int, parentRoot *os.Root, dbName string, preFi os.FileInfo) ([]*sql.Conn, error) {
	// No idle reuse: every pinned handle is checked out fresh and held.
	db.SetMaxIdleConns(0)
	conns := make([]*sql.Conn, 0, n)
	for i := 0; i < n; i++ {
		if err := ctx.Err(); err != nil {
			closeRetainedConns(conns)
			return nil, err
		}
		conn, err := db.Conn(ctx)
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				err = cerr
			}
			closeRetainedConns(conns)
			return nil, typed(ErrDependency, err)
		}
		if poolVerifyHook != nil {
			poolVerifyHook(i)
		}
		if err := verifyConnIdentity(ctx, conn, parentRoot, dbName, preFi); err != nil {
			_ = conn.Close()
			closeRetainedConns(conns)
			return nil, err
		}
		conns = append(conns, conn)
	}
	return conns, nil
}

func closeRetainedConns(conns []*sql.Conn) {
	for _, c := range conns {
		_ = c.Close()
	}
}

// verifyConnIdentity proves a live connection is on exactly the verified
// database inode with the exact pragma settings the service depends on.
func verifyConnIdentity(ctx context.Context, conn *sql.Conn, parentRoot *os.Root, dbName string, preFi os.FileInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	rows, err := conn.QueryContext(ctx, `pragma database_list`)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		return typed(ErrDependency, err)
	}
	var main string
	for rows.Next() {
		var seq int
		var name, path string
		if err := rows.Scan(&seq, &name, &path); err != nil {
			rows.Close()
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			return typed(ErrDependency, err)
		}
		if name == "main" {
			main = path
		}
	}
	rows.Close()
	if parentRoot != nil {
		cur, err := parentRoot.Lstat(dbName)
		if err != nil || preFi == nil || !os.SameFile(cur, preFi) {
			return typed(ErrDependency, errors.New("database file changed before pool pinning"))
		}
		if main != "" {
			// The path this connection actually opened must resolve to the
			// exact verified inode. If it cannot be stat'd at all (path
			// swapped away), fail closed — never assume.
			sfi, serr := os.Stat(main)
			if serr != nil {
				return typed(ErrDependency, errors.New("pool connection cannot be matched to the database file"))
			}
			if !os.SameFile(sfi, cur) {
				return typed(ErrDependency, errors.New("pool connection opened a different database file"))
			}
		}
	}
	var fk int
	if err := conn.QueryRowContext(ctx, `pragma foreign_keys`).Scan(&fk); err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		return typed(ErrDependency, err)
	}
	if fk != 1 {
		return typed(ErrDependency, errors.New("pool connection has foreign_keys disabled"))
	}
	var jm string
	if err := conn.QueryRowContext(ctx, `pragma journal_mode`).Scan(&jm); err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		return typed(ErrDependency, err)
	}
	if jm != "wal" {
		return typed(ErrDependency, errors.New("pool connection is not in wal journal mode"))
	}
	var syncMode int
	if err := conn.QueryRowContext(ctx, `pragma synchronous`).Scan(&syncMode); err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		return typed(ErrDependency, err)
	}
	if syncMode != 2 {
		return typed(ErrDependency, errors.New("pool connection is not in synchronous=FULL mode"))
	}
	return nil
}

// dbPool is a retained, pinned connection pool: every *sql.Conn available to
// the service was physically opened and identity-verified against the
// anchored database file at construction and stays checked out of
// database/sql for the pool lifetime, so no later path-based connection can
// be opened behind the service's back.
//
// Concurrency contract:
//   - acquire never holds the pool mutex while waiting for a handle; it
//     selects on the available-handle channel, the caller's context, and the
//     pool-closed signal. A canceled waiter under full exhaustion returns
//     the exact context error promptly while another goroutine can still
//     release.
//   - release hands the handle back, or — if the pool is already closing —
//     closes it itself, so Close never races a send on a closed channel (the
//     channel is never closed) and a handle released after Close is never
//     leaked.
//   - close LINEARIZES shutdown so EVERY concurrent or later Close joins one
//     single completion. Exactly one caller atomically transitions the pool
//     open→closing and becomes the shutdown owner: it waits until every
//     reservation and borrowed handle is returned or canceled (it never holds
//     the mutex while waiting on the cond, the channel, or while closing
//     handles), drains and closes the exact retained set of idle handles, and
//     closes the underlying *sql.DB exactly once. Every other Close — racing
//     or repeated, even after completion — waits on the same never-replaced
//     `done` channel, so no Close can observe shutdown as finished before the
//     underlying close completes. Acquires after Close return a fixed
//     closed-pool error; a reservation or borrow that outlived Close's
//     mark is either received/returned through this one linearization or
//     canceled, and is always accounted exactly once.
type dbPool struct {
	db       *sql.DB
	ch       chan *sql.Conn // buffered (size N); NEVER closed
	closing  chan struct{}  // closed once by the shutdown owner
	done     chan struct{}  // closed exactly once when shutdown fully completes; never replaced
	poisonCh chan struct{}  // closed once when the pool is quarantined (poisoned)
	mu       sync.Mutex
	cond     *sync.Cond
	closed   bool
	poisoned bool
	borrowed int
	// shutdownStarted is set under mu by the single task that owns the drain
	// (the caller that transitioned open→closing); every other Close joins it.
	shutdownStarted bool
	// closedConns counts handles the pool itself closed (retire, drain, or a
	// release after closing/poisoning) — test-observable, so a broken handle
	// can be proven closed exactly once.
	closedConns int

	// closeHook is a test-only observation barrier fired by the shutdown owner
	// at named boundaries ("marked", "drained", "dbclose", "done"); nil in
	// production.
	closeHook func(phase string)
}

// newDBPool builds a pool over db with size retained handles already in the
// channel.
func newDBPool(db *sql.DB, size int) *dbPool {
	p := &dbPool{
		db:       db,
		ch:       make(chan *sql.Conn, size),
		closing:  make(chan struct{}),
		done:     make(chan struct{}),
		poisonCh: make(chan struct{}),
	}
	p.cond = sync.NewCond(&p.mu)
	return p
}

var errPoolClosed = errors.New("staging database pool is closed")

// errPoolPoisoned is the fixed data-free error every acquire returns once the
// pool is poisoned; it unwraps to ErrDependency, so callers and tests match
// it with errors.Is(err, ErrDependency).
var errPoolPoisoned = typed(ErrDependency, errors.New("staging database pool poisoned"))

// openStagingPool opens and verifies the staging database exactly like
// openStagingDB (with the connection count bounded and every physical
// connection held simultaneously, identity-verified against the anchored
// database file and pragma set, then installed into the retained pool), so
// the exact full retained set is verified. Callers hold one connection at a
// time via acquire.
func openStagingPool(ctx context.Context, dbPath string, size int) (*dbPool, error) {
	if size <= 0 {
		size = 4
	}
	base, err := basePathOf(dbPath)
	if err != nil {
		return nil, typed(ErrDependency, err)
	}
	if base == "" || strings.Contains(base, ":memory:") {
		// A memory database cannot share multiple physical connections;
		// pin exactly one.
		size = 1
	}
	db, parentRoot, dbName, preFi, _, err := openStagingDBAnchored(ctx, dbPath, size)
	if err != nil {
		return nil, err
	}
	defer parentRoot.Close()
	if poolPinHook != nil {
		poolPinHook()
	}
	conns, err := verifyAndPinAllConns(ctx, db, size, parentRoot, dbName, preFi)
	if err != nil {
		db.Close()
		return nil, err
	}
	p := newDBPool(db, size)
	for _, c := range conns {
		p.ch <- c
	}
	return p, nil
}

// acquire returns a retained handle, serializing acceptance against close
// WITHOUT holding the mutex while waiting. It reserves the borrow BEFORE
// receiving: if close has already marked the pool closed the reservation is
// refused outright, and once a reservation exists close() waits for it, so
// a successfully received handle is always already accounted (a received
// handle whose pool is closing is returned, never dropped on the floor).
// A canceled waiter under full exhaustion releases its reservation and
// returns the exact context error while another goroutine can still
// release.
func (p *dbPool) acquire(ctx context.Context) (*sql.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	if p.poisoned {
		p.mu.Unlock()
		return nil, errPoolPoisoned
	}
	if p.closed {
		p.mu.Unlock()
		return nil, errPoolClosed
	}
	p.borrowed++ // reservation: Close can no longer complete past this point
	p.mu.Unlock()
	select {
	case c := <-p.ch:
		// A poison that landed after the reservation must not hand out a
		// handle: quarantine is atomic, so the received handle is closed
		// here instead of borrowed (accounted exactly once either way).
		p.mu.Lock()
		if p.poisoned {
			if p.borrowed > 0 {
				p.borrowed--
			}
			p.closedConns++
			p.cond.Broadcast()
			p.mu.Unlock()
			_ = c.Close()
			if cerr := ctx.Err(); cerr != nil {
				return nil, cerr
			}
			return nil, errPoolPoisoned
		}
		p.mu.Unlock()
		return c, nil
	case <-ctx.Done():
		p.releaseReservation()
		return nil, ctx.Err()
	case <-p.closing:
		p.releaseReservation()
		// When the caller's own cancellation fired alongside Close, the
		// exact context sentinel is the more precise answer and MUST win.
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		// A poisoned pool is quarantined even when a Close lands on the same
		// wake: the fixed dependency error stays the poison answer.
		p.mu.Lock()
		poisoned := p.poisoned
		p.mu.Unlock()
		if poisoned {
			return nil, errPoolPoisoned
		}
		return nil, errPoolClosed
	case <-p.poisonCh:
		p.releaseReservation()
		// The caller's own cancellation, when it fired, is authoritative.
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		return nil, errPoolPoisoned
	}
}

// releaseReservation undoes an unconsumed acquire reservation: close() may
// only finish once no reservation or borrow remains.
func (p *dbPool) releaseReservation() {
	p.mu.Lock()
	if p.borrowed > 0 {
		p.borrowed--
	}
	p.cond.Broadcast()
	p.mu.Unlock()
}

// release hands the handle back. Returning the handle to the channel and
// decrementing the borrow happen in ONE critical section, so close() can
// only observe an idle pool (borrowed == 0) once every returned handle is
// back in the channel and can drain the exact retained set. After close or
// poison the handle is closed here instead (never sent, so there can never
// be a send on a closed channel — the channel is never closed — and never
// leaked).
func (p *dbPool) release(c *sql.Conn) {
	p.mu.Lock()
	if p.borrowed > 0 {
		p.borrowed--
	}
	if p.closed || p.poisoned {
		p.closedConns++
		p.cond.Broadcast()
		p.mu.Unlock()
		_ = c.Close()
		return
	}
	// Capacity == retained count and this handle was borrowed, so the send
	// cannot block: len(ch) < cap(ch) holds under the lock.
	p.ch <- c
	p.cond.Broadcast()
	p.mu.Unlock()
}

// poison atomically quarantines the pool: no acquire — blocked or fresh —
// succeeds from here on (each fails with the fixed dependency error while
// the caller's own context error stays authoritative), every handle released
// into the pool afterwards is closed instead of reused, and a later close()
// still drains and joins the single shutdown completion. It is idempotent.
func (p *dbPool) poison() {
	p.mu.Lock()
	if !p.poisoned {
		p.poisoned = true
		close(p.poisonCh)
	}
	p.cond.Broadcast()
	p.mu.Unlock()
}

// retire permanently removes a broken retained connection from the pool: the
// handle is closed (never returned to the channel) and — best-effort — the
// PHYSICAL connection is closed too, so any transaction or SQLite write lock
// it still carries is released instead of lingering in the sql.DB pool.
// Retiring without poisoning shrinks the retained capacity, so callers
// retire only when they poison the pool. The handle is closed by the pool
// exactly once.
func (p *dbPool) retire(c *sql.Conn) {
	if c == nil {
		return
	}
	p.mu.Lock()
	if p.borrowed > 0 {
		p.borrowed--
	}
	p.closedConns++
	p.cond.Broadcast()
	p.mu.Unlock()
	// The Raw close makes the *sql.Conn permanently broken: the database/sql
	// pool will discard it instead of reusing it when Conn.Close is called.
	_ = c.Raw(func(dc any) error {
		if d, ok := dc.(driver.Conn); ok {
			return d.Close()
		}
		return nil
	})
	_ = c.Close()
}

// close linearizes staging-pool shutdown so every concurrent or later Close
// JOINS one shared completion. Exactly one caller atomically transitions the
// pool open→closing and becomes the shutdown owner: it waits until every
// reservation and borrowed handle is returned or canceled (never holding the
// mutex while waiting on the cond or the channel or while closing handles),
// drains and closes the exact retained set of idle handles, closes the
// underlying *sql.DB exactly once, and then closes the never-replaced `done`
// channel. Every other Close — racing it or arriving later, even after
// completion — waits on that same `done` channel, so no Close can observe
// shutdown finished before the underlying database close completes. This
// repairs the prior defect where a second concurrent Close saw `closed` and
// returned immediately, before shutdown had finished. Acquires after close
// return a fixed closed-pool error; a handle released during closing is
// closed by the owner protocol and decremented once.
func (p *dbPool) close() {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		close(p.closing)
	}
	var owner bool
	if !p.shutdownStarted {
		// This caller transitioned open→closing (or is the first to claim
		// the drain) and performs the shutdown; every other Close joins it.
		p.shutdownStarted = true
		owner = true
	}
	if !owner {
		// A concurrent or later Close joins the SAME completion and never
		// returns early. We do not hold the mutex while waiting.
		p.mu.Unlock()
		<-p.done
		return
	}

	if p.closeHook != nil {
		p.closeHook("marked")
	}
	// Wait for every reservation and borrow to be returned or canceled.
	// The len of p.ch plus borrowed is an invariant of size, so once
	// borrowed reaches zero the channel holds exactly the idle retained set.
	for p.borrowed > 0 {
		p.cond.Wait()
	}
	p.mu.Unlock()

	if p.closeHook != nil {
		p.closeHook("drained")
	}
	// The channel is frozen once `closed` is set: release() closes rather
	// than re-sends during closing, and no post-close acquire can receive, so
	// draining here lands exactly the retained idle handles and closes each.
	var drained []*sql.Conn
	for {
		select {
		case c := <-p.ch:
			drained = append(drained, c)
		default:
			goto drainFinished
		}
	}
drainFinished:
	p.mu.Lock()
	p.closedConns += len(drained)
	p.mu.Unlock()
	for _, c := range drained {
		_ = c.Close()
	}
	if p.closeHook != nil {
		p.closeHook("dbclose")
	}
	_ = p.db.Close()
	if p.closeHook != nil {
		p.closeHook("done")
	}
	// Publish completion: every joined Close unblocks on the SAME channel.
	close(p.done)
}

// basePathOf returns the on-disk path portion of a DSN, stripping any file:
// scheme, decoding percent-escapes, and rejecting ambiguous or unsupported
// URI forms so the filesystem target we anchor is exactly the target SQLite
// opens.
func basePathOf(dsn string) (string, error) {
	p := dsn
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	switch {
	case strings.HasPrefix(p, "file://"):
		// Only the absolute file:/// form (empty authority) is supported.
		// file://host/... is ambiguous across SQLite revisions and rejected.
		if !strings.HasPrefix(p, "file:///") {
			return "", errors.New("unsupported file URI authority")
		}
		p = p[len("file://"):]
	case strings.HasPrefix(p, "file:"):
		p = p[len("file:"):]
	}
	if strings.Contains(p, "%") {
		// Escapes that would alter the COMPONENT STRUCTURE of the target
		// (separators inside an escape, dot-dot, NUL) are ambiguous against
		// SQLite's own decoding rules: reject them fail-closed. Plain
		// escapes like %20 never change which filesystem object the raw
		// path denotes, so they decode.
		lower := strings.ToLower(p)
		for _, forbidden := range []string{"%2f", "%5c", "%2e", "%00"} {
			if strings.Contains(lower, forbidden) {
				return "", errors.New("ambiguous percent-escape in database path")
			}
		}
		dec, err := url.PathUnescape(p)
		if err != nil {
			return "", errors.New("malformed percent-escape in database path")
		}
		p = dec
	}
	if strings.ContainsRune(p, 0) {
		return "", errors.New("database path contains a NUL byte")
	}
	return p, nil
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
	base, berr := basePathOf(dbPath)
	if berr != nil {
		return nil, "", nil, false, typed(ErrDependency, berr)
	}
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
// with O_EXCL and forces its mode to EXACTLY 0600 by fchmod'ing the OPENED
// descriptor immediately (a restrictive process umask can never leave it
// looser, and the descriptor is the only handle used — never a path), then
// verifies the exact mode AND the directory-entry identity by descriptor
// before any schema inspection happens. Any failure removes the freshly
// created file so no mode-000 residue survives.
func createDBFile(parentRoot *os.Root, dbName string) (os.FileInfo, error) {
	f, err := parentRoot.OpenFile(dbName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, typed(ErrDependency, errors.New("cannot create database file"))
	}
	fail := func(e error) (os.FileInfo, error) {
		// Clean up ONLY the inode this call created: the residue is removed
		// through the atomic authenticated quarantine protocol
		// (rename -> authenticate against the created descriptor identity ->
		// unlink + directory fsync), so a foreign replacement swapped in after
		// creation is NEVER removed and the parent directory is fsynced after
		// every rename/unlink — never a check-then-name unlink on the mutable
		// database name.
		if ascLeafSwapHook != nil {
			ascLeafSwapHook("db", dbName)
		}
		st, serr := f.Stat()
		_ = f.Close()
		if serr == nil {
			_ = quarantineCreated(parentRoot, dbName, st, func() error { return syncRootDir(parentRoot) }, nil)
		}
		return nil, e
	}
	// fchmod the opened descriptor to exactly 0600 immediately, before any
	// further check: the file is private from its first byte.
	if err := f.Chmod(0o600); err != nil {
		return fail(typed(ErrDependency, err))
	}
	st, err := f.Stat()
	if err != nil {
		return fail(typed(ErrDependency, err))
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 {
		return fail(typed(ErrDependency, errors.New("database file is not a private regular file")))
	}
	// The directory entry must be the very inode we just created (no swap,
	// no symlink) — verified through the anchored descriptor.
	lst, lerr := parentRoot.Lstat(dbName)
	if lerr != nil || lst.Mode()&os.ModeSymlink != 0 || !lst.Mode().IsRegular() || !os.SameFile(st, lst) {
		return fail(typed(ErrDependency, errors.New("database file changed during creation")))
	}
	if err := f.Close(); err != nil {
		return fail(typed(ErrDependency, err))
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
	schemaMigrateV1Pre
	schemaMigrateV1Cleanup
	schemaMigrateV2
	schemaMigrateV3
)

// inspectSchemaState examines an existing database on a read-only,
// mutation-pragma-free connection and returns:
//
//	schemaEmpty           — no tables and no version row: an empty file,
//	                        created fresh;
//	schemaCurrent         — the exact current (v2) object surface and version;
//	schemaMigrateV1Pre    — the exact pre-cleanup-token v1 predecessor (frozen
//	                        committed shape), ready for an atomic rebuild to v2;
//	schemaMigrateV1Cleanup— the exact cleanup-token-v1 compatibility
//	                        predecessor, ready for exact-validation plus version
//	                        advancement to v2;
//	schemaReject          — anything else (foreign schema, lookalike bodies,
//	                        unknown objects, ambiguous/mutated fixtures…).
//
// Every recognized shape is accepted ONLY when it fully verifies against its
// own frozen manifest (objects, columns, indexes, FKs, and version row) — a
// malformed lookalike never reaches migration. Because the connection is
// mode=ro, a rejected database is never written.
func inspectSchemaState(ctx context.Context, dbPath string) (schemaState, error) {
	db, err := sql.Open("sqlite", inspectionDSN(dbPath))
	if err != nil {
		return schemaReject, depErr(err, ctx)
	}
	defer db.Close()
	tables, err := userTables(ctx, db)
	if err != nil {
		return schemaReject, depErr(err, ctx)
	}
	version, hasVersion, err := currentVersion(ctx, db)
	if err != nil {
		return schemaReject, depErr(err, ctx)
	}
	if len(tables) == 0 && !hasVersion {
		return schemaEmpty, nil
	}
	if !hasVersion {
		return schemaReject, depErr(errors.New(
			"staging database is not a supported upload-staging schema"), ctx)
	}
	adapter := &txAdapter{db: db}
	// The version value selects WHICH frozen shapes are admissible; the shape
	// itself must verify byte/structure-exactly against that manifest. The two
	// v1 predecessors record version 1 (the cleanup_token presence on the same
	// frozen surface distinguishes them); v2 and v3 each have their own frozen
	// manifest. Malformed or ambiguous combinations reject.
	switch version {
	case latestSchemaVersion:
		if err := verifyAgainst(ctx, adapter, schemaGold, latestSchemaVersion); err == nil {
			return schemaCurrent, nil
		}
	case 3:
		if err := verifyAgainst(ctx, adapter, schemaGoldV3, 3); err == nil {
			return schemaMigrateV3, nil
		}
	case 2:
		if err := verifyAgainst(ctx, adapter, schemaGoldV2, 2); err == nil {
			return schemaMigrateV2, nil
		}
	case 1:
		if err := verifyAgainst(ctx, adapter, schemaGoldV1Pre, 1); err == nil {
			return schemaMigrateV1Pre, nil
		}
		if err := verifyAgainst(ctx, adapter, schemaGoldV1Cleanup, 1); err == nil {
			return schemaMigrateV1Cleanup, nil
		}
	}
	return schemaReject, depErr(errors.New(
		"staging database is not a supported upload-staging schema"), ctx)
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
		return nil, ctxOr(err, ctx)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, ctxOr(err, ctx)
		}
		names = append(names, n)
	}
	return names, ctxOr(rows.Err(), ctx)
}

func currentVersion(ctx context.Context, db *sql.DB) (int64, bool, error) {
	rows, err := db.QueryContext(ctx, `select version from staging_schema`)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return 0, false, cerr
		}
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
			return 0, false, ctxOr(err, ctx)
		}
		versions = append(versions, v)
	}
	if err := rows.Err(); err != nil {
		return 0, false, ctxOr(err, ctx)
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
		return depErr(err, ctx)
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
		return depErr(err, ctx)
	}
	for _, stmt := range schemaDDL {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return depErr(err, ctx)
		}
	}
	if migrationFault != nil {
		return depErr(migrationFault, ctx)
	}
	if err := verifySchemaFully(ctx, tx, schemaGold); err != nil {
		return depErr(err, ctx)
	}
	if _, err := tx.ExecContext(ctx,
		`insert into staging_schema (version, applied_at) values (?, ?)`, latestSchemaVersion, now); err != nil {
		return depErr(err, ctx)
	}
	if err := tx.Commit(); err != nil {
		return depErr(err, ctx)
	}
	rollback = false
	return nil
}

// migrateSchema atomically upgrades one of the exact predecessor shapes to the
// current schema on a pinned connection under a serialized BEGIN IMMEDIATE
// write transaction:
//
//   - an EXACT pre-cleanup-token v1 database rebuilds upload_sessions (adding
//     the cleanup_token column, its CHECK, the tightened coherence CHECK, and
//     de novo session triggers) preserving every existing row/field exactly —
//     the newly added column is NULL everywhere, never inventing provenance;
//   - an EXACT cleanup-token-v1 database (whose object surface equals v2)
//     rebuilds upload_sessions to the current shape preserving every row/field;
//   - an EXACT v2 database rebuilds upload_sessions to v3 preserving every
//     row/field exactly, including any cleanup_token (deleting rows with NULL
//     stay NULL, so an ambiguous old sidecar is never adopted);
//   - the full current object/column/index/FK surface AND every migrated row
//     validate before the version record is written, and only after that is
//     the row committed.
//
// The rebuild is performed with foreign_keys temporarily OFF (SQLite's
// documented table-rewrite procedure, since dropping the parent while the
// child FK references it is illegal with enforcement on) and re-enables it and
// runs PRAGMA foreign_key_check before commit; every failure rolls back to the
// byte-exact predecessor.
func migrateSchema(ctx context.Context, db *sql.DB, from schemaState) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return depErr(err, ctx)
	}
	defer conn.Close()
	exec := func(q string, args ...any) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if _, err := conn.ExecContext(ctx, q, args...); err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			return err
		}
		return nil
	}
	// The connection inherits foreign_keys=ON from the DSN; take it OFF only
	// for the atomic rebuild and restore it on the way out.
	if err := exec(`PRAGMA foreign_keys=OFF`); err != nil {
		return depErr(err, ctx)
	}
	if err := exec(`BEGIN IMMEDIATE`); err != nil {
		_, _ = conn.ExecContext(context.Background(), `PRAGMA foreign_keys=ON`)
		return depErr(err, ctx)
	}
	rollback := true
	defer func() {
		if rollback {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		}
		_, _ = conn.ExecContext(context.Background(), `PRAGMA foreign_keys=ON`)
	}()
	// Preflight inside the transaction, before ANY DDL: the exact predecessor
	// must still verify byte/structure-identically (a TOCTOU swap after the
	// read-only inspection cannot slip an unvetted shape into a mutation).
	switch from {
	case schemaMigrateV1Pre:
		if err := verifyAgainst(ctx, conn, schemaGoldV1Pre, 1); err != nil {
			return depErr(err, ctx)
		}
		// v1-pre copies the reconstructed cleanup_token as NULL everywhere.
		if err := rebuildUploadSessions(ctx, conn, exec, false); err != nil {
			return depErr(err, ctx)
		}
	case schemaMigrateV1Cleanup:
		if err := verifyAgainst(ctx, conn, schemaGoldV1Cleanup, 1); err != nil {
			return depErr(err, ctx)
		}
		// The cleanup-token-v1 surface equals v2, but the current surface (v3)
		// differs (the deleting-tombstone provenance change), so this shape
		// also rebuilds upload_sessions to v3, carrying rows and any
		// cleanup_token exactly across.
		if err := rebuildUploadSessions(ctx, conn, exec, true); err != nil {
			return depErr(err, ctx)
		}
	case schemaMigrateV2:
		if err := verifyAgainst(ctx, conn, schemaGoldV2, 2); err != nil {
			return depErr(err, ctx)
		}
		// Exact v2 -> v4: rebuild upload_sessions carrying every row/field
		// across, including any cleanup_token (NULL deleting rows stay NULL).
		if err := rebuildUploadSessions(ctx, conn, exec, true); err != nil {
			return depErr(err, ctx)
		}
	case schemaMigrateV3:
		if err := verifyAgainst(ctx, conn, schemaGoldV3, 3); err != nil {
			return depErr(err, ctx)
		}
		// Exact v3 -> v4: the finalizing claim state. Rebuild upload_sessions
		// carrying every row/field across exactly (no active/finalized row can
		// be born finalizing; the CHECK and state trigger enforce it), so no
		// existing row is ever altered or re-derived.
		if err := rebuildUploadSessions(ctx, conn, exec, true); err != nil {
			return depErr(err, ctx)
		}
	default:
		return depErr(errors.New("staging migration does not recognize the source schema"), ctx)
	}
	// The full current surface must hold on this live write connection, and
	// every migrated row must satisfy it (the rebuild's copy goes through the
	// new table's CHECKs; the cleanup path's rows already satisfied v3).
	if err := verifySchemaFully(ctx, conn, schemaGold); err != nil {
		return depErr(err, ctx)
	}
	if err := ctx.Err(); err != nil {
		return depErr(ctx.Err(), ctx)
	}
	now := timeNowNanos()
	if migrationVersionFault != nil {
		return depErr(migrationVersionFault, ctx)
	}
	if err := exec(`update staging_schema set version = ?, applied_at = ?`, latestSchemaVersion, now); err != nil {
		return depErr(err, ctx)
	}
	if err := exec(`COMMIT`); err != nil {
		return depErr(err, ctx)
	}
	rollback = false
	return nil
}

// rebuildUploadSessions rewrites the previous-major upload_sessions table into
// the exact current (v3) shape. The new table is created directly under its
// FINAL name from schemaDDL[0] — never via ALTER TABLE ... RENAME, which makes
// SQLite store a double-quoted table name that would break the byte-exact
// golden fingerprint. Rows are moved field-by-field (explicit column lists,
// never INSERT ... SELECT *). preserveCleanup selects whether the source
// already carries a cleanup_token column that must be carried over exactly
// (v2), or whether the reconstructed column is synthesized NULL everywhere
// (v1-pre, which never had it; provenance is never invented). The full current
// indexes/triggers are recreated. The scratch copy table is dropped before
// verification so the live object set is exactly the current one.
func rebuildUploadSessions(ctx context.Context, conn *sql.Conn, exec func(q string, args ...any) error, preserveCleanup bool) error {
	cleanupExpr := "NULL"
	if preserveCleanup {
		cleanupExpr = "cleanup_token"
	}
	copyDDL := strings.Replace(schemaDDL[0], "upload_sessions", "upload_sessions_copy", 1)
	if err := exec(copyDDL); err != nil {
		return err
	}
	if err := exec(`insert into upload_sessions_copy
		( id, repo, actor, state, offset, created_at, expires_at, create_token, cleanup_token, digest, bee_ref, media_type, size )
		select id, repo, actor, state, offset, created_at, expires_at, create_token, ` + cleanupExpr + `,
		       digest, bee_ref, media_type, size from upload_sessions`); err != nil {
		return err
	}
	// Test-only fault injection: fail immediately after the row copy (mid-
	// rebuild) and prove the whole transaction rolls back the predecessor.
	if migrationCopyFault != nil {
		return migrationCopyFault
	}
	// Drop every trigger/index that references upload_sessions BEFORE dropping
	// the table (otherwise SQLite reparses them against the missing table). The
	// pre-cleanup v1 source predates the cleanup trigger, so it is dropped only
	// when the source carried it (v2); the final table is rebuilt with the
	// full current trigger set regardless.
	trigs := []string{"trg_blob_insert", "trg_blob_update", "trg_blob_delete",
		"trg_session_insert", "trg_session_state", "trg_session_metadata",
		"trg_session_identity", "trg_session_token", "trg_session_delete"}
	if preserveCleanup {
		trigs = append(trigs, "trg_session_cleanup")
	}
	for _, trig := range trigs {
		if err := exec(`drop trigger ` + trig); err != nil {
			return err
		}
	}
	for _, idx := range []string{"idx_sessions_owner", "idx_sessions_expiry"} {
		if err := exec(`drop index ` + idx); err != nil {
			return err
		}
	}
	if err := exec(`drop table upload_sessions`); err != nil {
		return err
	}
	// Recreate the current upload_sessions table under its final name, then
	// move the preserved rows back.
	if err := exec(schemaDDL[0]); err != nil {
		return err
	}
	if err := exec(`insert into upload_sessions
		( id, repo, actor, state, offset, created_at, expires_at, create_token, cleanup_token, digest, bee_ref, media_type, size )
		select id, repo, actor, state, offset, created_at, expires_at, create_token, ` + cleanupExpr + `,
		       digest, bee_ref, media_type, size from upload_sessions_copy`); err != nil {
		return err
	}
	if err := exec(`drop table upload_sessions_copy`); err != nil {
		return err
	}
	// Recreate the two session indexes (schemaDDL[3], schemaDDL[4]), then
	// every remaining session and staged-blob trigger (schemaDDL[5..end]) so
	// the rebuilt table carries the ENTIRE current trigger set — including the
	// finalizing-claim trigger (trg_session_finalize) that the v1/v2/v3
	// predecessors never had.
	for _, idx := range []int{3, 4} {
		if err := exec(schemaDDL[idx]); err != nil {
			return err
		}
	}
	for i := 5; i < len(schemaDDL); i++ {
		if err := exec(schemaDDL[i]); err != nil {
			return err
		}
	}
	return ctx.Err()
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

// verifySchemaFully validates the complete expected sqlite_schema surface
// against a specific frozen manifest: the exact object set with SQL-aware
// normalized bodies, the exact physical column shapes (table_xinfo incl.
// hidden columns), the exact index columns (index_xinfo), the exact foreign
// key rows, FK integrity (no orphan rows), and the absence of temporary
// objects.
func verifySchemaFully(ctx context.Context, db schemaChecker, gold *schemaManifest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	shapes := manifestColumnShapes(gold)
	if err := verifySchemaObjects(ctx, db, gold); err != nil {
		return err
	}
	for table := range gold.Columns {
		if err := verifyColumnShapes(ctx, db, table, shapes[table]); err != nil {
			return err
		}
	}
	for idx := range gold.Indexes {
		if err := verifyIndexShape(ctx, db, idx, gold.Indexes[idx]); err != nil {
			return err
		}
	}
	if err := verifyForeignKeys(ctx, db, gold.ForeignKeys); err != nil {
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
	return ctx.Err()
}

// verifyAgainst proves a database matches a specific frozen manifest exactly:
// full object/column/index/FK surface plus the exact single version row.
func verifyAgainst(ctx context.Context, db schemaChecker, gold *schemaManifest, expectedVersion int) error {
	if err := verifySchemaFully(ctx, db, gold); err != nil {
		return err
	}
	if err := verifyVersionRow(ctx, db, expectedVersion); err != nil {
		return err
	}
	return ctx.Err()
}

// verifySchemaObjects proves the object set is EXACTLY the expected one and
// every object's stored body normalizes to the expected SQL: a lookalike
// that shares a name but relaxes a check, changes a trigger body, reorders
// index columns, or carries different quoted content is rejected.
func verifySchemaObjects(ctx context.Context, db schemaChecker, gold *schemaManifest) error {
	expected := gold.Objects
	var total int
	if err := db.QueryRowContext(ctx,
		`select count(*) from sqlite_master where type in ('table','index','trigger','view') and name not like 'sqlite_%'`).
		Scan(&total); err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		return err
	}
	if total != len(expected) {
		return fmt.Errorf("staging schema has %d objects, want %d", total, len(expected))
	}
	for i := range expected {
		want := &expected[i]
		var typ, tbl, sqlText string
		err := db.QueryRowContext(ctx,
			`select type, tbl_name, sql from sqlite_master where name = ? and type in ('table','index','trigger','view')`,
			want.Name).Scan(&typ, &tbl, &sqlText)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("staging schema lacks object %s", want.Name)
		}
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			return err
		}
		if typ != want.Typ || tbl != want.Tbl {
			return fmt.Errorf("staging schema object %s does not match its expected type/table", want.Name)
		}
		norm, err := normalizeSQL(sqlText)
		if err != nil {
			return err
		}
		if norm != want.SQL {
			return fmt.Errorf("staging schema object %s body differs from the expected schema", want.Name)
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

// verifyColumnShapes proves table_xinfo (incl. hidden columns) matches the
// expected columns EXACTLY — same count, names, storage classes, NOT NULL
// flags, PK flags, and no hidden columns.
func verifyColumnShapes(ctx context.Context, db schemaChecker, table string, want []columnShape) error {
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

// verifyIndexShape proves index_xinfo matches the expected ordered columns
// with no descending columns. The implicit table-rowid auxiliary row that
// SQLite appends to indexes of rowid tables (NULL name, key=0) is expected
// and not part of the declared column list.
func verifyIndexShape(ctx context.Context, db schemaChecker, idx string, want []string) error {
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

// verifyForeignKeys proves every declared foreign key matches the frozen
// golden expectation EXACTLY (table, columns, actions, flags) and that no
// additional foreign keys exist.
func verifyForeignKeys(ctx context.Context, db schemaChecker, expected []goldenFK) error {
	for _, want := range expected {
		rows, err := db.QueryContext(ctx, fmt.Sprintf(`pragma foreign_key_list(%s)`, want.Table))
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
				return fmt.Errorf("staging schema has more than one foreign key on %s", want.Table)
			}
			if t != want.RefTable || from != want.From || to != want.To ||
				onDelete != want.OnDelete || onUpdate != want.OnUpdate || match != want.Match || id != 0 || seq != 0 {
				rows.Close()
				return fmt.Errorf("staging schema foreign key on %s differs from the expected one", want.Table)
			}
		}
		rows.Close()
		if count != 1 {
			return fmt.Errorf("staging schema lacks the expected foreign key on %s", want.Table)
		}
	}
	return nil
}

// verifyVersionRow proves the version row is exactly one row with the
// expected version and an INTEGER applied_at (never text/numeric-coerced).
func verifyVersionRow(ctx context.Context, db schemaChecker, expectedVersion int) error {
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
		if int(v) != expectedVersion || typ != "integer" {
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
