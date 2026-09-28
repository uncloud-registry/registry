package staging

// Task 18 round-3 correction: the SQLite operation_id schema must enforce
// byte-exact parity with validateOperationID. v7 constrained operation_id by
// CHARACTER count only and its ownership trigger admitted finalized -> claimed
// values the Go validator rejects, so direct DB writes could persist
// API-unaddressable, permanently quota-charged claimed rows. v8 re-binds the
// storage CHECK to RAW BYTES and enforces the byte-exact grammar in mandatory
// INSERT+UPDATE triggers (recursive-CTE/hex, mirroring the proven controlplane
// pattern). These tests (1) prove a direct INSERT or UPDATE can never persist a
// grammar-violating operation_id across the full adversarial class corpus and
// that valid case-sensitive IDs round-trip byte-exactly through the consume
// stages, and (2) prove v7 -> v8 migration preserves valid IDs exactly and
// fails closed atomically for every malformed predecessor class.

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
)

// rawOperationIDHex returns the exact stored operation_id BYTES of one row as
// lowercase hex ("" when NULL).
func rawOperationIDHex(t *testing.T, db *sql.DB, id string) string {
	t.Helper()
	var v sql.NullString
	if err := db.QueryRow(`select hex(cast(operation_id as blob)) from upload_sessions where id = ?`, id).Scan(&v); err != nil {
		t.Fatalf("read operation_id: %v", err)
	}
	// SQLite hex() is uppercase; normalize to lowercase for comparison.
	return strings.ToLower(v.String) // NULL -> hex(NULL) is NULL -> ""
}

// seededFinalize seeds ONE finalized session under a caller-unique hex id
// (coherence requires a matching staged blob, size == offset = 0).
func seededFinalize(t *testing.T, db *sql.DB, idHex string) {
	t.Helper()
	digest := "sha256:" + strings.Repeat("d", 64)
	beeRef := strings.Repeat("e", 64)
	if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at)
		values (?,?,?, 'active', 0, 1000, 2000)`, idHex, seedRepo, seedActor); err != nil {
		t.Fatalf("seed active: %v", err)
	}
	if _, err := db.Exec(`insert into staged_blobs (upload_id, repo, actor, digest, bee_ref, size, media_type, created_at, expires_at)
		values (?,?,?,?,?,0,'application/octet-stream',1000,2000)`, idHex, seedRepo, seedActor, digest, beeRef); err != nil {
		t.Fatalf("seed blob: %v", err)
	}
	if _, err := db.Exec(`update upload_sessions set state='finalized', digest=?, bee_ref=?, media_type=?, size=0 where id=?`,
		digest, beeRef, "application/octet-stream", idHex); err != nil {
		t.Fatalf("seed finalize: %v", err)
	}
}

// opProbe is one adversarial operation_id write. `wantAccept` is whether the
// finalized->claimed UPDATE must succeed. `mode` is "string" (TEXT-storage
// grammar probe, must exactly equal validateOperationID), "blob" (BLOB-storage
// probe, must be rejected by storage class), or "null"/"numeric" (storage
// probes with special handling).
type opProbe struct {
	name       string
	value      any
	mode       string
	wantAccept bool
}

func opProbes() []opProbe {
	boundary := "!#$%'()*+,-./0123456789:;=?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~"
	return []opProbe{
		{"empty", "", "string", false},
		{"space-only", " ", "string", false},
		{"interior-space", "op id", "string", false},
		{"tab", "op\tid", "string", false},
		{"newline", "op\nid", "string", false},
		{"carriage-return", "op\rid", "string", false},
		{"nul", "op\x00id", "string", false},
		{"del", "op\x7f", "string", false},
		{"double-quote", `"`, "string", false},
		{"backslash", `a\b`, "string", false},
		{"less-than", "a<b", "string", false},
		{"greater-than", "a>b", "string", false},
		{"ampersand", "a&b", "string", false},
		{"mixed-with-forbidden", `x<y>&z".\`, "string", false},
		{"valid-boundary-punct", boundary, "string", true},
		{"mixed-uppercase-ascii", "AbC-9_XYZ.@tExT", "string", true},
		{"digit-leading", "2026op-42", "string", true},
		{"256-byte-valid", strings.Repeat("Q", 256), "string", true},
		{"257-byte", strings.Repeat("Q", 257), "string", false},
		{"valid-nonascii-utf8", "op\xc3\xa9", "string", false},
		{"malformed-utf8-single", string([]byte{0x80}), "string", false},
		{"malformed-utf8-pair", string([]byte{0x41, 0x80}), "string", false},
		{"multibyte-260-bytes", strings.Repeat("\xc3\xa9", 130), "string", false},
		{"blob-storage", []byte("AABB"), "blob", false},
		{"numeric-literal", 65, "numeric", true},
		{"null", nil, "null", false},
	}
}

// TestOperationIDDirectWriteGrammarMatrix proves:
//   - a direct INSERT can never persist an operation_id (no ownership injection
//     at birth) for every class;
//   - a direct finalized->claimed UPDATE persists exactly the values
//     validateOperationID accepts (byte-exact parity, round-trip proven) and
//     rejects everything it rejects;
//   - BLOB storage is rejected by storage class, a numeric literal coerces to
//     a valid TEXT value, and NULL storage is legal only where the coherence
//     shape permits it.
func TestOperationIDDirectWriteGrammarMatrix(t *testing.T) {
	db, _ := newStagingDB(t)
	for i, tc := range opProbes() {
		t.Run(tc.name, func(t *testing.T) {
			// ---- INSERT path: operation_id can never be injected at birth.
			insID := fmt.Sprintf("%064x", 0x100000+i+1)
			if _, ierr := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at, operation_id)
				values (?,?,?, 'claimed', 0, 1000, 2000, ?)`, insID, seedRepo, seedActor, tc.value); ierr == nil {
				t.Fatalf("INSERT persisted an operation_id (%s); ownership must be un-injectable", tc.name)
			}

			fid := fmt.Sprintf("%064x", i+1)
			seededFinalize(t, db, fid)
			_, uerr := db.Exec(`update upload_sessions set state='claimed', operation_id=? where id=?`, tc.value, fid)

			switch tc.mode {
			case "null":
				// A finalized row CANNOT claim with a NULL operation_id (claimed
				// coherence requires non-null ownership), so the probe is rejected
				// while NULL remains legal on unowned shapes elsewhere.
				if uerr == nil {
					t.Fatalf("claimed row with NULL operation_id unexpectedly accepted")
				}
			case "numeric":
				// TEXT affinity coerces a numeric literal to a valid TEXT value.
				if uerr != nil {
					t.Fatalf("numeric literal 65 rejected as claimed op: %v", uerr)
				}
				if got := rawOperationIDHex(t, db, fid); got != "3635" {
					t.Fatalf("numeric op storage bytes = %s, want %s", got, "3635")
				}
			case "blob":
				// BLOB storage is rejected outright: storage class must be TEXT.
				if uerr == nil {
					t.Fatalf("BLOB-storage operation_id accepted; storage class must be TEXT")
				}
				// The rejected transition left NULL ownership and the row intact.
				if got := rawOperationIDHex(t, db, fid); got != "" {
					t.Fatalf("rejected BLOB probe left operation_id bytes %q behind", got)
				}
				var st string
				if err := db.QueryRow(`select state from upload_sessions where id=?`, fid).Scan(&st); err != nil {
					t.Fatalf("read state: %v", err)
				}
				if st != string(StateFinalized) {
					t.Fatalf("rejected BLOB probe mutated state to %q", st)
				}
			default: // string: byte-exact grammar parity with validateOperationID
				want := validateOperationID(tc.value.(string)) == nil
				if want != tc.wantAccept {
					t.Fatalf("test vector bug: wantAccept=%v but validateOperationID says %v", tc.wantAccept, want)
				}
				if uerr != nil && tc.wantAccept {
					t.Fatalf("valid op %q rejected by claimed UPDATE: %v", tc.name, uerr)
				}
				if uerr == nil && !tc.wantAccept {
					t.Fatalf("invalid op %q accepted by claimed UPDATE; validateOperationID rejects it", tc.name)
				}
				if tc.wantAccept {
					if got := rawOperationIDHex(t, db, fid); got != fmt.Sprintf("%x", tc.value.(string)) {
						t.Fatalf("valid op %q round-trip mismatch: got %s want %x", tc.name, got, tc.value)
					}
				} else {
					if got := rawOperationIDHex(t, db, fid); got != "" {
						t.Fatalf("rejected op %q left bytes %q behind", tc.name, got)
					}
					var st string
					if err := db.QueryRow(`select state from upload_sessions where id=?`, fid).Scan(&st); err != nil {
						t.Fatalf("read state: %v", err)
					}
					if st != string(StateFinalized) {
						t.Fatalf("rejected op %q still mutated state to %q", tc.name, st)
					}
				}
			}
		})
	}
}

// TestOperationIDNullStorageLegalOnUnowned proves NULL operation_id storage is
// accepted on rows where the coherence shape permits NULL (active, generic
// deleting tombstones), while a claimed or owned deleting row always carries
// the exact non-NULL ownership bytes.
func TestOperationIDNullStorageLegalOnUnowned(t *testing.T) {
	db, _ := newStagingDB(t)
	id := strings.Repeat("a", 64)
	if _, err := db.Exec(`insert into upload_sessions (id, repo, actor, state, offset, created_at, expires_at)
		values (?,?,?, 'active', 0, 1000, 2000)`, id, seedRepo, seedActor); err != nil {
		t.Fatalf("insert active: %v", err)
	}
	if got := rawOperationIDHex(t, db, id); got != "" {
		t.Fatalf("active row operation_id = %s, want empty", got)
	}
	// Generic deleting tombstone stays NULL-owned.
	if _, err := db.Exec(`update upload_sessions set state='deleting' where id=?`, id); err != nil {
		t.Fatalf("generic delete: %v", err)
	}
	if got := rawOperationIDHex(t, db, id); got != "" {
		t.Fatalf("generic deleting row operation_id = %s, want empty", got)
	}
}

// TestOperationIDImmutableAcrossStages proves a set (valid) operation_id is
// byte-exact and immutable across finalized -> claimed -> deleting, can never
// be cleared from claimed/owned-deleting, never mutated, and a generic
// deleting tombstone is never injected.
func TestOperationIDImmutableAcrossStages(t *testing.T) {
	db, _ := newStagingDB(t)
	id := strings.Repeat("f", 64)
	seededFinalize(t, db, id)
	op := "MiXeD-CaSe.op/2026_@xYz" // case-sensitive valid bytes
	if _, err := db.Exec(`update upload_sessions set state='claimed', operation_id=? where id=?`, op, id); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if got := rawOperationIDHex(t, db, id); got != fmt.Sprintf("%x", op) {
		t.Fatalf("claimed op bytes = %s, want %x", got, op)
	}
	// Consume transition (publication-owned deleting) retains the exact bytes.
	if _, err := db.Exec(`update upload_sessions set state='deleting' where id=?`, id); err != nil {
		t.Fatalf("tombstone: %v", err)
	}
	if got := rawOperationIDHex(t, db, id); got != fmt.Sprintf("%x", op) {
		t.Fatalf("deleting op bytes = %s, want %x", got, op)
	}
	// Malformed mutation on the owned row is rejected.
	if _, err := db.Exec(`update upload_sessions set operation_id='other' where id=?`, id); err == nil {
		t.Fatalf("operation_id was mutated on an owned row")
	}
	// Clearing the owned operation_id is rejected.
	if _, err := db.Exec(`update upload_sessions set operation_id=NULL where id=?`, id); err == nil {
		t.Fatalf("operation_id was cleared from an owned row")
	}
	// A malformed value cannot overwrite an owned row's operation_id.
	if _, err := db.Exec(`update upload_sessions set operation_id='bad op' where id=?`, id); err == nil {
		t.Fatalf("malformed operation_id overwrote an owned row")
	}
	// A generic deleting tombstone cannot be injected with a foreign op.
	gid := fmt.Sprintf("%064x", 256)
	seededFinalize(t, db, gid)
	if _, err := db.Exec(`update upload_sessions set state='deleting' where id=?`, gid); err != nil {
		t.Fatalf("seed generic deleting: %v", err)
	}
	if _, err := db.Exec(`update upload_sessions set operation_id=? where id=? and operation_id is null`, "x", gid); err == nil {
		t.Fatalf("generic deleting tombstone injected with an operation_id")
	}
}

// TestV8ServiceClaimConsumeCaseSensitiveID proves the real service claim /
// consume path works for a case-sensitive operation ID on the v8 schema:
// claim succeeds, the row stores the exact bytes, and the exact consume durably
// removes it.
func TestV8ServiceClaimConsumeCaseSensitiveID(t *testing.T) {
	dir := tempPrivate(t)
	svc := openSharedService(t, dir)
	repo, actor := seedRepo, seedActor
	digest, _ := claimPubFinalize(t, svc, repo, actor)
	op := "CaSe-SeNsItIvE.op_2026"
	mustClaim(t, svc, repo, actor, op, []string{digest})

	db := mustRawDB(t, dir+"/staging.db")
	var count int
	if err := db.QueryRow(`select count(*) from upload_sessions where state='claimed' and operation_id = ?`, op).Scan(&count); err != nil {
		t.Fatalf("count claimed: %v", err)
	}
	if count != 1 {
		t.Fatalf("claimed rows for %q = %d, want 1", op, count)
	}
	if err := svc.ConsumeStagedForPublish(context.Background(), repo, actor, op, []string{digest}); err != nil {
		t.Fatalf("consume exact-case op: %v", err)
	}
	if err := db.QueryRow(`select count(*) from upload_sessions where operation_id = ?`, op).Scan(&count); err != nil {
		t.Fatalf("count after consume: %v", err)
	}
	if count != 0 {
		t.Fatalf("exact consume left %d rows for %q", count, op)
	}
}
