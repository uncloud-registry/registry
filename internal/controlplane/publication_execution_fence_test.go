package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// Round 6B / Important 2 acceptance proof: migration 17's writer fence (see
// publication_execution_fence.go). Every test here builds its predecessor
// schema via the REAL migration chain (applyMigrationsThrough) and drives
// history through the REAL Store methods, never a hand-authored lookalike
// row, and uses a unique t.TempDir()-backed file per database so repeated
// `-count=N` runs never alias a prior run's rows.

// openRawFileTestDBAt opens a raw file-backed SQLite handle at an EXPLICIT
// path (unlike openRawFileTestDB, which always mints its own fresh path), so
// a test can hold multiple independent *sql.DB handles open against the SAME
// physical file - the exact "already-running process with an open handle"
// and "independent second connection" shapes these tests exist to prove.
func openRawFileTestDBAt(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open raw file-backed sqlite at %s: %v", path, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// canonicalFenceTopic returns a canonical full-feed wire-form topic
// (feed://<40 hex owner>/<64 hex>) distinct per input byte, so a fence
// assertion can reserve several feed_signer_operations rows on the SAME
// registry without colliding on the feed_signer_active_repo_claim partial
// unique index (one 'processing' row per (registry_id, topic)).
func canonicalFenceTopic(b byte) string {
	return "feed://" + testFeedOwner + "/" + refHex(b)
}

// feedSignerRowSnapshot captures every column of one feed_signer_operations
// row so a refused migration's "byte-for-byte untouched" guarantee can be
// checked on every field/result/token/timestamp, not merely a row count.
type feedSignerRowSnapshot struct {
	OperationID string
	RegistryID  int64
	Topic       string
	RequestHash []byte
	State       string
	ResultJSON  sql.NullString
	ClaimToken  sql.NullString
	LeaseUntil  sql.NullInt64
	Attempts    int64
	CreatedAt   int64
	UpdatedAt   int64
}

func snapshotFeedSignerRows(t *testing.T, db *sql.DB) []feedSignerRowSnapshot {
	t.Helper()
	rows, err := db.Query(`select operation_id, registry_id, topic, request_hash, state, result_json,
		claim_token, lease_until, attempts, created_at, updated_at
		from feed_signer_operations order by operation_id`)
	if err != nil {
		t.Fatalf("snapshot feed_signer_operations: %v", err)
	}
	defer rows.Close()
	var out []feedSignerRowSnapshot
	for rows.Next() {
		var s feedSignerRowSnapshot
		if err := rows.Scan(&s.OperationID, &s.RegistryID, &s.Topic, &s.RequestHash, &s.State, &s.ResultJSON,
			&s.ClaimToken, &s.LeaseUntil, &s.Attempts, &s.CreatedAt, &s.UpdatedAt); err != nil {
			t.Fatalf("scan feed_signer_operations row: %v", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate feed_signer_operations: %v", err)
	}
	return out
}

// legacyRowSnapshot captures every column of one feed_signer_operations_legacy
// quarantine row.
type legacyRowSnapshot struct {
	OperationID string
	RequestHash []byte
	State       string
	ResultJSON  sql.NullString
	CreatedAt   int64
	UpdatedAt   int64
}

func snapshotLegacyRows(t *testing.T, db *sql.DB) []legacyRowSnapshot {
	t.Helper()
	rows, err := db.Query(`select operation_id, request_hash, state, result_json, created_at, updated_at
		from feed_signer_operations_legacy order by operation_id`)
	if err != nil {
		t.Fatalf("snapshot feed_signer_operations_legacy: %v", err)
	}
	defer rows.Close()
	var out []legacyRowSnapshot
	for rows.Next() {
		var s legacyRowSnapshot
		if err := rows.Scan(&s.OperationID, &s.RequestHash, &s.State, &s.ResultJSON, &s.CreatedAt, &s.UpdatedAt); err != nil {
			t.Fatalf("scan feed_signer_operations_legacy row: %v", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate feed_signer_operations_legacy: %v", err)
	}
	return out
}

// publicationExecutionRowSnapshot captures every column of one
// publication_states row.
type publicationExecutionRowSnapshot struct {
	OperationID string
	RegistryID  int64
	State       string
	AttemptID   string
	CreatedAt   int64
	UpdatedAt   int64
}

func snapshotPublicationExecutionRows(t *testing.T, db *sql.DB) []publicationExecutionRowSnapshot {
	t.Helper()
	rows, err := db.Query(`select operation_id, registry_id, state, attempt_id, created_at, updated_at
		from publication_states order by operation_id`)
	if err != nil {
		t.Fatalf("snapshot publication_states: %v", err)
	}
	defer rows.Close()
	var out []publicationExecutionRowSnapshot
	for rows.Next() {
		var s publicationExecutionRowSnapshot
		if err := rows.Scan(&s.OperationID, &s.RegistryID, &s.State, &s.AttemptID, &s.CreatedAt, &s.UpdatedAt); err != nil {
			t.Fatalf("scan publication_states row: %v", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate publication_states: %v", err)
	}
	return out
}

// assertNeverV17WithUntrackedOperation is the round-6B combined invariant:
// the database must never simultaneously be at schema version 17 AND carry a
// feed_signer_operations row with no coherent matching publication_states
// row (the exact untracked-writer gap migration 17 exists to close).
func assertNeverV17WithUntrackedOperation(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	version, err := CurrentSchemaVersion(ctx, db)
	if err != nil {
		t.Fatalf("current schema version: %v", err)
	}
	if version != 17 {
		return
	}
	var untracked int
	if err := db.QueryRowContext(ctx, `select count(*) from feed_signer_operations fs
		where not exists (
			select 1 from publication_states ps
			where ps.registry_id = fs.registry_id and ps.attempt_id = fs.operation_id
			  and ps.state in ('active','replaceable','succeeded')
		)`).Scan(&untracked); err != nil {
		t.Fatalf("count untracked feed_signer_operations: %v", err)
	}
	if untracked != 0 {
		t.Fatalf("observed schema version 17 together with %d untracked feed_signer_operations row(s)", untracked)
	}
}

// TestMigration17FencesAlreadyOpenV16Writer is the round-6B reviewer failure
// sequence: a process holding an ALREADY-OPEN handle to a v16 database (built
// before migration 17 ever ran) keeps calling the UNCHANGED
// Store.ReserveFeedSignerOperation after an independent second handle upgrades
// the SAME physical file to version 17. Without the fence trigger this insert
// would silently create untracked history; with it, the write is rejected at
// the SQLite boundary.
func TestMigration17FencesAlreadyOpenV16Writer(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "fence_open_writer.sqlite")

	dbA := openRawFileTestDBAt(t, path)
	if err := applyMigrationsThrough(ctx, dbA, 16); err != nil {
		t.Fatalf("apply exact v16 predecessor: %v", err)
	}
	storeA := &Store{DB: dbA}
	reg, topic := seedFeedSignerRegistry(t, storeA)

	dbB := openRawFileTestDBAt(t, path)
	if err := applyMigrationsThrough(ctx, dbB, 17); err != nil {
		t.Fatalf("apply migration 17 via independent handle: %v", err)
	}
	if v, err := CurrentSchemaVersion(ctx, dbB); err != nil || v != 17 {
		t.Fatalf("independent handle must observe version 17, got %d (err %v)", v, err)
	}

	reqHash := feedSignerTestHash("already-open-v16-writer")
	if _, err := storeA.ReserveFeedSignerOperation(ctx, "op-already-open-v16-writer", reg.ID, topic, reqHash); err == nil {
		t.Fatal("an already-open pre-fence handle's unfenced insert must be rejected by the SQLite trigger")
	}

	var opRows, pubRows int
	if err := dbA.QueryRowContext(ctx, `select count(*) from feed_signer_operations`).Scan(&opRows); err != nil {
		t.Fatalf("count feed_signer_operations: %v", err)
	}
	if opRows != 0 {
		t.Fatalf("rejected insert must not create a row, got %d", opRows)
	}
	if err := dbA.QueryRowContext(ctx, `select count(*) from publication_states`).Scan(&pubRows); err != nil {
		t.Fatalf("count publication_states: %v", err)
	}
	if pubRows != 0 {
		t.Fatalf("no publication execution row was ever reserved, got %d", pubRows)
	}
	if v, err := CurrentSchemaVersion(ctx, dbA); err != nil || v != 17 {
		t.Fatalf("the already-open handle must observe the SAME committed version 17, got %d (err %v)", v, err)
	}
	if sqliteObjectCount(t, dbA, "trigger", "feed_signer_operations_publication_fence_ins") != 1 ||
		sqliteObjectCount(t, dbA, "trigger", "feed_signer_operations_publication_fence_upd") != 1 {
		t.Fatal("both fence triggers must be physically present")
	}
}

// TestMigration17SerializesOldInsertAgainstUpgrade exercises both legal
// orderings between an old-writer insert and the migration-17 upgrade over
// the SAME physical file, driven from two independent raw handles: whichever
// commits first determines the outcome, and the two outcomes are mutually
// exclusive - the database is never left at version 17 with an untracked row.
func TestMigration17SerializesOldInsertAgainstUpgrade(t *testing.T) {
	ctx := context.Background()

	t.Run("old insert commits first migration refuses", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "serialize_insert_first.sqlite")
		dbA := openRawFileTestDBAt(t, path)
		if err := applyMigrationsThrough(ctx, dbA, 16); err != nil {
			t.Fatalf("apply exact v16 predecessor: %v", err)
		}
		storeA := &Store{DB: dbA}
		reg, topic := seedFeedSignerRegistry(t, storeA)

		reqHash := feedSignerTestHash("serialize-insert-first")
		if _, err := storeA.ReserveFeedSignerOperation(ctx, "op-insert-first", reg.ID, topic, reqHash); err != nil {
			t.Fatalf("old writer insert must commit uncontended pre-fence: %v", err)
		}

		dbB := openRawFileTestDBAt(t, path)
		if err := applyMigrationsThrough(ctx, dbB, 17); err == nil || !errors.Is(err, errFeedSignerFenceHistoryUnsafe) {
			t.Fatalf("migration must refuse the now-committed untracked row, got %v", err)
		}
		if v, err := CurrentSchemaVersion(ctx, dbB); err != nil || v != 16 {
			t.Fatalf("refused migration must leave version 16, got %d (err %v)", v, err)
		}
		var n int
		if err := dbA.QueryRowContext(ctx, `select count(*) from feed_signer_operations where operation_id = 'op-insert-first'`).Scan(&n); err != nil || n != 1 {
			t.Fatalf("the committed old-writer row must survive the refused migration, got %d (err %v)", n, err)
		}
		if sqliteObjectCount(t, dbA, "trigger", "feed_signer_operations_publication_fence_ins") != 0 ||
			sqliteObjectCount(t, dbA, "trigger", "feed_signer_operations_publication_fence_upd") != 0 {
			t.Fatal("refused migration must not install either fence trigger")
		}
		assertNeverV17WithUntrackedOperation(t, ctx, dbA)
	})

	t.Run("migration commits first old insert fails", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "serialize_migration_first.sqlite")
		dbA := openRawFileTestDBAt(t, path)
		if err := applyMigrationsThrough(ctx, dbA, 16); err != nil {
			t.Fatalf("apply exact v16 predecessor: %v", err)
		}
		storeA := &Store{DB: dbA}
		reg, topic := seedFeedSignerRegistry(t, storeA)

		dbB := openRawFileTestDBAt(t, path)
		if err := applyMigrationsThrough(ctx, dbB, 17); err != nil {
			t.Fatalf("migration over empty history must succeed: %v", err)
		}
		if v, err := CurrentSchemaVersion(ctx, dbB); err != nil || v != 17 {
			t.Fatalf("expected version 17, got %d (err %v)", v, err)
		}

		reqHash := feedSignerTestHash("serialize-migration-first")
		if _, err := storeA.ReserveFeedSignerOperation(ctx, "op-migration-first", reg.ID, topic, reqHash); err == nil {
			t.Fatal("the old writer's insert must be rejected once the fence is already committed")
		}
		var n int
		if err := dbA.QueryRowContext(ctx, `select count(*) from feed_signer_operations where operation_id = 'op-migration-first'`).Scan(&n); err != nil || n != 0 {
			t.Fatalf("rejected insert must not create a row, got %d (err %v)", n, err)
		}
		if v, err := CurrentSchemaVersion(ctx, dbA); err != nil || v != 17 {
			t.Fatalf("expected version 17, got %d (err %v)", v, err)
		}
		assertNeverV17WithUntrackedOperation(t, ctx, dbA)
	})
}

// TestMigration17RejectsUntrackedHistoryAndPreservesPredecessor proves the
// round-6B fail-closed upgrade policy: an exact v16 database whose
// feed_signer_operations (in ANY state) or feed_signer_operations_legacy
// carries a row not provably tracked by a coherent publication_states row
// refuses migration 17 atomically. Version stays 16, neither fence trigger
// is installed, and every seeded row is preserved byte-for-byte (every
// field, result, token, and timestamp - not merely a row count).
func TestMigration17RejectsUntrackedHistoryAndPreservesPredecessor(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name string
		seed func(t *testing.T, db *sql.DB)
	}{
		{
			name: "untracked pending",
			seed: func(t *testing.T, db *sql.DB) {
				store := &Store{DB: db}
				reg, topic := seedFeedSignerRegistry(t, store)
				hash := feedSignerTestHash("untracked-pending")
				if _, err := store.ReserveFeedSignerOperation(ctx, "op-untracked-pending", reg.ID, topic, hash); err != nil {
					t.Fatalf("seed pending: %v", err)
				}
			},
		},
		{
			name: "untracked processing",
			seed: func(t *testing.T, db *sql.DB) {
				store := &Store{DB: db}
				reg, topic := seedFeedSignerRegistry(t, store)
				hash := feedSignerTestHash("untracked-processing")
				if _, err := store.ReserveFeedSignerOperation(ctx, "op-untracked-processing", reg.ID, topic, hash); err != nil {
					t.Fatalf("seed reserve: %v", err)
				}
				won, err := store.ClaimFeedSignerOperation(ctx, "op-untracked-processing", hash, testClaimToken(t), time.Now().UTC().Add(time.Minute))
				if err != nil || !won {
					t.Fatalf("seed claim: won=%v err=%v", won, err)
				}
			},
		},
		{
			name: "untracked succeeded",
			seed: func(t *testing.T, db *sql.DB) {
				store := &Store{DB: db}
				reg, topic := seedFeedSignerRegistry(t, store)
				hash := feedSignerTestHash("untracked-succeeded")
				if _, err := store.ReserveFeedSignerOperation(ctx, "op-untracked-succeeded", reg.ID, topic, hash); err != nil {
					t.Fatalf("seed reserve: %v", err)
				}
				token := testClaimToken(t)
				won, err := store.ClaimFeedSignerOperation(ctx, "op-untracked-succeeded", hash, token, time.Now().UTC().Add(time.Minute))
				if err != nil || !won {
					t.Fatalf("seed claim: won=%v err=%v", won, err)
				}
				result := []byte(`{"operationID":"op-untracked-succeeded","feed":"` + topic + `","reference":"` + refHex('d') + `"}`)
				if err := store.CompleteFeedSignerOperation(ctx, "op-untracked-succeeded", hash, token, result); err != nil {
					t.Fatalf("seed complete: %v", err)
				}
			},
		},
		{
			name: "legacy quarantine row",
			seed: func(t *testing.T, db *sql.DB) {
				nowNs := timeToNanos(time.Now().UTC())
				h := feedSignerTestHash("legacy-quarantine-fence")
				if _, err := db.ExecContext(ctx, `insert into feed_signer_operations_legacy
					(operation_id, request_hash, state, result_json, created_at, updated_at)
					values (?, ?, 'pending', null, ?, ?)`, "op-legacy-quarantine-fence", h[:], nowNs, nowNs); err != nil {
					t.Fatalf("seed legacy quarantine row: %v", err)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "untracked_history.sqlite")
			db := openRawFileTestDBAt(t, path)
			if err := applyMigrationsThrough(ctx, db, 16); err != nil {
				t.Fatalf("apply exact v16 predecessor: %v", err)
			}
			tc.seed(t, db)

			beforeOps := snapshotFeedSignerRows(t, db)
			beforeLegacy := snapshotLegacyRows(t, db)

			if err := ApplyMigrations(ctx, db); err == nil || !errors.Is(err, errFeedSignerFenceHistoryUnsafe) {
				t.Fatalf("migration 17 must refuse %q, got %v", tc.name, err)
			}
			if v, err := CurrentSchemaVersion(ctx, db); err != nil || v != 16 {
				t.Fatalf("refused migration must leave version 16 current, got %d (err %v)", v, err)
			}
			if sqliteObjectCount(t, db, "trigger", "feed_signer_operations_publication_fence_ins") != 0 ||
				sqliteObjectCount(t, db, "trigger", "feed_signer_operations_publication_fence_upd") != 0 {
				t.Fatal("refused migration must not install either fence trigger")
			}
			var migRows int
			if err := db.QueryRowContext(ctx, `select count(*) from schema_migrations where version = 17`).Scan(&migRows); err != nil {
				t.Fatal(err)
			}
			if migRows != 0 {
				t.Fatalf("refused migration must not record a version-17 row, got %d", migRows)
			}

			afterOps := snapshotFeedSignerRows(t, db)
			afterLegacy := snapshotLegacyRows(t, db)
			if !reflect.DeepEqual(beforeOps, afterOps) {
				t.Fatalf("feed_signer_operations rows must be byte-for-byte unchanged:\nbefore %+v\nafter  %+v", beforeOps, afterOps)
			}
			if !reflect.DeepEqual(beforeLegacy, afterLegacy) {
				t.Fatalf("feed_signer_operations_legacy rows must be byte-for-byte unchanged:\nbefore %+v\nafter  %+v", beforeLegacy, afterLegacy)
			}
		})
	}
}

// assertMigration17FenceEnforced runs the shared post-v17 behavioral proof
// against an already-migrated database: a matching active insert+claim
// succeeds; an insert with no (or a mismatched) active publication_states row
// fails; a STALE attempt left behind by ReplacePublicationExecutionAttempt
// can never reclaim (checked via a SECOND, independent Store handle, so the
// proof is not an artifact of one process's in-memory state); and release,
// combined completion, and idempotent replay remain valid (never gated).
// label disambiguates identities across repeated calls against different
// predecessor fixtures.
func assertMigration17FenceEnforced(t *testing.T, storeA, storeB *Store, reg Registry, label string) {
	t.Helper()
	ctx := context.Background()

	// 1. A matching active insert+claim succeeds.
	matchAttempt := "attempt-" + label + "-match"
	matchPub := "pub-" + label + "-match"
	if _, err := storeA.ReservePublicationExecution(ctx, matchPub, reg.ID, matchAttempt); err != nil {
		t.Fatalf("reserve matching publication execution: %v", err)
	}
	matchHash := feedSignerTestHash(matchPub)
	if _, err := storeA.ReserveFeedSignerOperation(ctx, matchAttempt, reg.ID, canonicalFenceTopic('m'), matchHash); err != nil {
		t.Fatalf("insert with a matching active publication execution row must succeed: %v", err)
	}
	if won, err := storeA.ClaimFeedSignerOperation(ctx, matchAttempt, matchHash, testClaimToken(t), time.Now().UTC().Add(time.Minute)); err != nil || !won {
		t.Fatalf("claim with a matching active publication execution row must succeed: won=%v err=%v", won, err)
	}

	// 2a. An insert with NO publication_states row at all fails.
	missingAttempt := "attempt-" + label + "-missing"
	missingHash := feedSignerTestHash(missingAttempt)
	if _, err := storeA.ReserveFeedSignerOperation(ctx, missingAttempt, reg.ID, canonicalFenceTopic('n'), missingHash); err == nil {
		t.Fatal("insert with no matching active publication execution row must fail")
	}
	var missingRows int
	if err := storeA.DB.QueryRowContext(ctx, `select count(*) from feed_signer_operations where operation_id = ?`, missingAttempt).Scan(&missingRows); err != nil {
		t.Fatal(err)
	}
	if missingRows != 0 {
		t.Fatalf("rejected insert must not create a row, got %d", missingRows)
	}

	// 2b. An insert under an attempt id that is NOT the currently-active one
	// for this registry (a mismatch, as opposed to a total absence) also fails.
	otherActiveAttempt := "attempt-" + label + "-other-active"
	if _, err := storeA.ReservePublicationExecution(ctx, "pub-"+label+"-mismatch", reg.ID, otherActiveAttempt); err != nil {
		t.Fatalf("reserve unrelated active publication execution: %v", err)
	}
	mismatchAttempt := "attempt-" + label + "-mismatch"
	mismatchHash := feedSignerTestHash(mismatchAttempt)
	if _, err := storeA.ReserveFeedSignerOperation(ctx, mismatchAttempt, reg.ID, canonicalFenceTopic('x'), mismatchHash); err == nil {
		t.Fatal("insert under a non-active attempt id must fail even when a DIFFERENT attempt is active")
	}

	// 3. A stale attempt superseded by ReplacePublicationExecutionAttempt can
	// never reclaim - checked from a SECOND, independent Store handle on the
	// same physical file, proving the fence is enforced at the database
	// boundary, not merely inside one process's Store instance.
	staleOldAttempt := "attempt-" + label + "-stale-old"
	staleNewAttempt := "attempt-" + label + "-stale-new"
	stalePub := "pub-" + label + "-stale"
	if _, err := storeA.ReservePublicationExecution(ctx, stalePub, reg.ID, staleOldAttempt); err != nil {
		t.Fatalf("reserve stale publication execution: %v", err)
	}
	staleHash := feedSignerTestHash(stalePub)
	if _, err := storeA.ReserveFeedSignerOperation(ctx, staleOldAttempt, reg.ID, canonicalFenceTopic('s'), staleHash); err != nil {
		t.Fatalf("seed stale attempt's feed signer row: %v", err)
	}
	if applied, err := storeA.MarkPublicationExecutionReplaceable(ctx, stalePub, staleOldAttempt); err != nil || !applied {
		t.Fatalf("mark replaceable: applied=%v err=%v", applied, err)
	}
	if won, _, err := storeA.ReplacePublicationExecutionAttempt(ctx, stalePub, reg.ID, staleOldAttempt, staleNewAttempt); err != nil || !won {
		t.Fatalf("replace attempt: won=%v err=%v", won, err)
	}
	if won, err := storeB.ClaimFeedSignerOperation(ctx, staleOldAttempt, staleHash, testClaimToken(t), time.Now().UTC().Add(time.Minute)); err == nil && won {
		t.Fatal("a stale (superseded) attempt must never reclaim, but the independent handle's claim succeeded")
	}

	// 4. Release, combined completion, and idempotent replay remain valid -
	// none of these transitions are gated by the fence.
	lifeAttempt := "attempt-" + label + "-lifecycle"
	lifePub := "pub-" + label + "-lifecycle"
	lifeTopic := canonicalFenceTopic('e')
	if _, err := storeA.ReservePublicationExecution(ctx, lifePub, reg.ID, lifeAttempt); err != nil {
		t.Fatalf("reserve lifecycle publication execution: %v", err)
	}
	lifeHash := feedSignerTestHash(lifePub)
	if _, err := storeA.ReserveFeedSignerOperation(ctx, lifeAttempt, reg.ID, lifeTopic, lifeHash); err != nil {
		t.Fatalf("seed lifecycle feed signer row: %v", err)
	}
	firstToken := testClaimToken(t)
	if won, err := storeA.ClaimFeedSignerOperation(ctx, lifeAttempt, lifeHash, firstToken, time.Now().UTC().Add(time.Minute)); err != nil || !won {
		t.Fatalf("lifecycle first claim: won=%v err=%v", won, err)
	}
	if err := storeA.ReleaseFeedSignerOperation(ctx, lifeAttempt, firstToken); err != nil {
		t.Fatalf("release must remain valid post-fence: %v", err)
	}
	secondToken := testClaimToken(t)
	if won, err := storeA.ClaimFeedSignerOperation(ctx, lifeAttempt, lifeHash, secondToken, time.Now().UTC().Add(time.Minute)); err != nil || !won {
		t.Fatalf("re-claim after release must remain valid post-fence: won=%v err=%v", won, err)
	}
	result := []byte(`{"operationID":"` + lifeAttempt + `","feed":"` + lifeTopic + `","reference":"` + refHex('a') + `"}`)
	if err := storeA.CompleteFeedSignerOperationAndTerminatePublication(ctx, lifeAttempt, lifeHash, secondToken, result, lifePub, reg.ID, lifeAttempt); err != nil {
		t.Fatalf("combined completion must remain valid post-fence: %v", err)
	}
	if err := storeA.CompleteFeedSignerOperationAndTerminatePublication(ctx, lifeAttempt, lifeHash, secondToken, result, lifePub, reg.ID, lifeAttempt); err != nil {
		t.Fatalf("idempotent replay of the combined completion must not error: %v", err)
	}
}

// TestMigration17AcceptsCoherentHistoryAndEnforcesFence proves the accept
// path: an exact v16 database whose feed-signer history is fully coherent
// with publication_states (covering every state pairing the fence's history
// check treats as safe - active/pending, active/processing,
// replaceable/pending, and succeeded/succeeded) upgrades to 17 cleanly,
// preserving every existing row exactly, and the fence then behaves
// correctly going forward.
func TestMigration17AcceptsCoherentHistoryAndEnforcesFence(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name string
		seed func(t *testing.T, store *Store, reg Registry, topic string)
	}{
		{
			name: "active_pending",
			seed: func(t *testing.T, store *Store, reg Registry, topic string) {
				const attempt, pub = "attempt-coherent-active-pending", "pub-coherent-active-pending"
				if _, err := store.ReservePublicationExecution(ctx, pub, reg.ID, attempt); err != nil {
					t.Fatalf("reserve publication execution: %v", err)
				}
				hash := feedSignerTestHash(pub)
				if _, err := store.ReserveFeedSignerOperation(ctx, attempt, reg.ID, topic, hash); err != nil {
					t.Fatalf("reserve feed signer operation: %v", err)
				}
			},
		},
		{
			name: "active_processing",
			seed: func(t *testing.T, store *Store, reg Registry, topic string) {
				const attempt, pub = "attempt-coherent-active-processing", "pub-coherent-active-processing"
				if _, err := store.ReservePublicationExecution(ctx, pub, reg.ID, attempt); err != nil {
					t.Fatalf("reserve publication execution: %v", err)
				}
				hash := feedSignerTestHash(pub)
				if _, err := store.ReserveFeedSignerOperation(ctx, attempt, reg.ID, topic, hash); err != nil {
					t.Fatalf("reserve feed signer operation: %v", err)
				}
				won, err := store.ClaimFeedSignerOperation(ctx, attempt, hash, testClaimToken(t), time.Now().UTC().Add(time.Minute))
				if err != nil || !won {
					t.Fatalf("claim: won=%v err=%v", won, err)
				}
			},
		},
		{
			name: "replaceable_pending",
			seed: func(t *testing.T, store *Store, reg Registry, topic string) {
				const attempt, pub = "attempt-coherent-replaceable-pending", "pub-coherent-replaceable-pending"
				if _, err := store.ReservePublicationExecution(ctx, pub, reg.ID, attempt); err != nil {
					t.Fatalf("reserve publication execution: %v", err)
				}
				hash := feedSignerTestHash(pub)
				if _, err := store.ReserveFeedSignerOperation(ctx, attempt, reg.ID, topic, hash); err != nil {
					t.Fatalf("reserve feed signer operation: %v", err)
				}
				applied, err := store.MarkPublicationExecutionReplaceable(ctx, pub, attempt)
				if err != nil || !applied {
					t.Fatalf("mark replaceable: applied=%v err=%v", applied, err)
				}
			},
		},
		{
			name: "succeeded_succeeded",
			seed: func(t *testing.T, store *Store, reg Registry, topic string) {
				const attempt, pub = "attempt-coherent-succeeded", "pub-coherent-succeeded"
				if _, err := store.ReservePublicationExecution(ctx, pub, reg.ID, attempt); err != nil {
					t.Fatalf("reserve publication execution: %v", err)
				}
				hash := feedSignerTestHash(pub)
				if _, err := store.ReserveFeedSignerOperation(ctx, attempt, reg.ID, topic, hash); err != nil {
					t.Fatalf("reserve feed signer operation: %v", err)
				}
				token := testClaimToken(t)
				won, err := store.ClaimFeedSignerOperation(ctx, attempt, hash, token, time.Now().UTC().Add(time.Minute))
				if err != nil || !won {
					t.Fatalf("claim: won=%v err=%v", won, err)
				}
				result := []byte(`{"operationID":"` + attempt + `","feed":"` + topic + `","reference":"` + refHex('f') + `"}`)
				if err := store.CompleteFeedSignerOperationAndTerminatePublication(ctx, attempt, hash, token, result, pub, reg.ID, attempt); err != nil {
					t.Fatalf("combined completion: %v", err)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "coherent_"+tc.name+".sqlite")
			dbA := openRawFileTestDBAt(t, path)
			if err := applyMigrationsThrough(ctx, dbA, 16); err != nil {
				t.Fatalf("apply exact v16 predecessor: %v", err)
			}
			storeA := &Store{DB: dbA}
			reg, topic := seedFeedSignerRegistry(t, storeA)
			tc.seed(t, storeA, reg, topic)

			beforeOps := snapshotFeedSignerRows(t, dbA)
			beforeExec := snapshotPublicationExecutionRows(t, dbA)

			if err := ApplyMigrations(ctx, dbA); err != nil {
				t.Fatalf("coherent pre-v17 history must upgrade cleanly, got %v", err)
			}
			if v, err := CurrentSchemaVersion(ctx, dbA); err != nil || v != 17 {
				t.Fatalf("expected version 17, got %d (err %v)", v, err)
			}
			if sqliteObjectCount(t, dbA, "trigger", "feed_signer_operations_publication_fence_ins") != 1 ||
				sqliteObjectCount(t, dbA, "trigger", "feed_signer_operations_publication_fence_upd") != 1 {
				t.Fatal("migration must install both fence triggers")
			}

			afterOps := snapshotFeedSignerRows(t, dbA)
			afterExec := snapshotPublicationExecutionRows(t, dbA)
			if !reflect.DeepEqual(beforeOps, afterOps) {
				t.Fatalf("feed_signer_operations rows must be untouched:\nbefore %+v\nafter  %+v", beforeOps, afterOps)
			}
			if !reflect.DeepEqual(beforeExec, afterExec) {
				t.Fatalf("publication_states rows must be untouched:\nbefore %+v\nafter  %+v", beforeExec, afterExec)
			}

			dbB := openRawFileTestDBAt(t, path)
			storeB := &Store{DB: dbB}
			assertMigration17FenceEnforced(t, storeA, storeB, reg, tc.name)
		})
	}
}

// TestMigration17RejectsMalformedPredecessorAndIsIdempotent proves migration
// 17 validates the exact committed migration-16 objects (the
// publication_states table and both its identity triggers) before installing
// any DDL or recording any version - a stamped-but-weakened predecessor fails
// closed, atomically, leaving version 16 current - and that a fresh database
// converges on version 17 with each fence trigger installed EXACTLY once
// however many times ApplyMigrations is invoked.
func TestMigration17RejectsMalformedPredecessorAndIsIdempotent(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name   string
		mutate func(t *testing.T, db *sql.DB)
	}{
		{
			name: "missing publication state insert identity trigger",
			mutate: func(t *testing.T, db *sql.DB) {
				if _, err := db.Exec(`drop trigger publication_state_operation_id_ins`); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing publication state update identity trigger",
			mutate: func(t *testing.T, db *sql.DB) {
				if _, err := db.Exec(`drop trigger publication_state_operation_id_upd`); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "weakened publication_states table lookalike",
			mutate: func(t *testing.T, db *sql.DB) {
				for _, name := range []string{"publication_state_operation_id_ins", "publication_state_operation_id_upd"} {
					if _, err := db.Exec(`drop trigger ` + name); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := db.Exec(`drop table publication_states`); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`create table publication_states (operation_id text primary key, registry_id integer, state text, attempt_id text, created_at integer, updated_at integer)`); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "malformed_predecessor.sqlite")
			db := openRawFileTestDBAt(t, path)
			if err := applyMigrationsThrough(ctx, db, 16); err != nil {
				t.Fatalf("apply exact v16 predecessor: %v", err)
			}
			tc.mutate(t, db)

			var opsBefore, execBefore int
			if err := db.QueryRowContext(ctx, `select count(*) from feed_signer_operations`).Scan(&opsBefore); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRowContext(ctx, `select count(*) from publication_states`).Scan(&execBefore); err != nil {
				t.Fatal(err)
			}

			if err := ApplyMigrations(ctx, db); err == nil || !errors.Is(err, errFeedSignerFencePredecessorMalformed) {
				t.Fatalf("migration 17 must reject a malformed predecessor (%s), got %v", tc.name, err)
			}
			if v, err := CurrentSchemaVersion(ctx, db); err != nil || v != 16 {
				t.Fatalf("failed migration must leave version 16 current, got %d (err %v)", v, err)
			}
			if sqliteObjectCount(t, db, "trigger", "feed_signer_operations_publication_fence_ins") != 0 ||
				sqliteObjectCount(t, db, "trigger", "feed_signer_operations_publication_fence_upd") != 0 {
				t.Fatal("failed predecessor validation must not leave a fence trigger installed")
			}

			var opsAfter, execAfter int
			if err := db.QueryRowContext(ctx, `select count(*) from feed_signer_operations`).Scan(&opsAfter); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRowContext(ctx, `select count(*) from publication_states`).Scan(&execAfter); err != nil {
				t.Fatal(err)
			}
			if opsBefore != opsAfter || execBefore != execAfter {
				t.Fatalf("failed migration must not change row counts: feed_signer_operations %d->%d, publication_states %d->%d",
					opsBefore, opsAfter, execBefore, execAfter)
			}
		})
	}

	t.Run("fresh apply twice installs each fence trigger exactly once", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "idempotent_fresh.sqlite")
		db := openRawFileTestDBAt(t, path)
		if err := ApplyMigrations(ctx, db); err != nil {
			t.Fatalf("first apply: %v", err)
		}
		if err := ApplyMigrations(ctx, db); err != nil {
			t.Fatalf("second apply must be a no-op: %v", err)
		}
		if v, err := CurrentSchemaVersion(ctx, db); err != nil || v != 17 {
			t.Fatalf("expected version 17, got %d (err %v)", v, err)
		}
		if sqliteObjectCount(t, db, "trigger", "feed_signer_operations_publication_fence_ins") != 1 ||
			sqliteObjectCount(t, db, "trigger", "feed_signer_operations_publication_fence_upd") != 1 {
			t.Fatal("each fence trigger must be installed exactly once")
		}
		var migRows int
		if err := db.QueryRowContext(ctx, `select count(*) from schema_migrations where version = 17`).Scan(&migRows); err != nil {
			t.Fatal(err)
		}
		if migRows != 1 {
			t.Fatalf("migration 17 must be recorded exactly once, got %d", migRows)
		}
	})
}
