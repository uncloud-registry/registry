package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/publish"
)

// Round 5 / Important 2: migration 16's round-4 fail-closed check
// (validatePublicationStateHistorySafe) only refused a pre-v16
// feed_signer_operations row in state 'succeeded'. But a 'pending' or
// 'processing' row (including one an expired/released lease has reset back
// to pending) and a feed_signer_operations_legacy quarantine row (in EITHER
// legacy state) are exactly the same class of unrecoverable history: v15 has
// no record of the STABLE PublicationID any of them belong to, so serving
// v16 over them leaves a live pre-v16 attempt (or a legacy row
// AdoptLegacyFeedSignerOperation can still promote to active AFTER the
// upgrade) with no publication_states coordination at all. This file proves
// the broadened rule: ANY row in feed_signer_operations, in ANY state, and
// ANY row in feed_signer_operations_legacy, in ANY state, refuses migration
// 16 atomically — and that the refusal is backed by an exact-shape
// predecessor validation of those two tables (not merely their row counts).

// TestMigration16RefusesAnyPreV16FeedSignerHistory is the round-5 /
// Important 2 acceptance proof: every feed-signer history state that v15 can
// produce — via the real Store methods the pre-v16 signer used, never a
// hand-authored row — blocks migration 16 atomically. Version stays 15,
// publication_states is never created, and the seeded row is byte-for-byte
// untouched.
func TestMigration16RefusesAnyPreV16FeedSignerHistory(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name string
		seed func(t *testing.T, db *sql.DB)
	}{
		{
			name: "active pending",
			seed: func(t *testing.T, db *sql.DB) {
				store := &Store{DB: db}
				reg, topic := seedFeedSignerRegistry(t, store)
				req := publish.FeedCommitRequest{
					OperationID: "op-active-pending", RegistryID: reg.ID, Owner: "0x" + testFeedOwner,
					Topic: topic, Reference: refHex('a'), BatchID: "batch-1", ExpectedGeneration: 0,
				}
				reqHash := NormalizeFeedCommitHash(req)
				if _, err := store.ReserveFeedSignerOperation(ctx, req.OperationID, reg.ID, topic, reqHash); err != nil {
					t.Fatalf("reserve pending: %v", err)
				}
			},
		},
		{
			name: "active processing",
			seed: func(t *testing.T, db *sql.DB) {
				store := &Store{DB: db}
				reg, topic := seedFeedSignerRegistry(t, store)
				req := publish.FeedCommitRequest{
					OperationID: "op-active-processing", RegistryID: reg.ID, Owner: "0x" + testFeedOwner,
					Topic: topic, Reference: refHex('b'), BatchID: "batch-1", ExpectedGeneration: 0,
				}
				reqHash := NormalizeFeedCommitHash(req)
				if _, err := store.ReserveFeedSignerOperation(ctx, req.OperationID, reg.ID, topic, reqHash); err != nil {
					t.Fatalf("reserve: %v", err)
				}
				won, err := store.ClaimFeedSignerOperation(ctx, req.OperationID, reqHash, testClaimToken(t), time.Now().UTC().Add(time.Minute))
				if err != nil || !won {
					t.Fatalf("claim: won=%v err=%v", won, err)
				}
			},
		},
		{
			name: "expired processing released back to pending",
			seed: func(t *testing.T, db *sql.DB) {
				store := &Store{DB: db}
				reg, topic := seedFeedSignerRegistry(t, store)
				req := publish.FeedCommitRequest{
					OperationID: "op-released-pending", RegistryID: reg.ID, Owner: "0x" + testFeedOwner,
					Topic: topic, Reference: refHex('c'), BatchID: "batch-1", ExpectedGeneration: 0,
				}
				reqHash := NormalizeFeedCommitHash(req)
				if _, err := store.ReserveFeedSignerOperation(ctx, req.OperationID, reg.ID, topic, reqHash); err != nil {
					t.Fatalf("reserve: %v", err)
				}
				token := testClaimToken(t)
				won, err := store.ClaimFeedSignerOperation(ctx, req.OperationID, reqHash, token, time.Now().UTC().Add(time.Minute))
				if err != nil || !won {
					t.Fatalf("claim: won=%v err=%v", won, err)
				}
				if err := store.ReleaseFeedSignerOperation(ctx, req.OperationID, token); err != nil {
					t.Fatalf("release: %v", err)
				}
				op, err := store.GetFeedSignerOperation(ctx, req.OperationID)
				if err != nil || op.State != FeedSignerOpPending {
					t.Fatalf("sanity: row must be released back to pending, got %+v err %v", op, err)
				}
			},
		},
		{
			name: "succeeded",
			seed: func(t *testing.T, db *sql.DB) {
				store := &Store{DB: db}
				reg, topic := seedFeedSignerRegistry(t, store)
				req := publish.FeedCommitRequest{
					OperationID: "op-succeeded", RegistryID: reg.ID, Owner: "0x" + testFeedOwner,
					Topic: topic, Reference: refHex('d'), BatchID: "batch-1", ExpectedGeneration: 0,
				}
				reqHash := NormalizeFeedCommitHash(req)
				if _, err := store.ReserveFeedSignerOperation(ctx, req.OperationID, reg.ID, topic, reqHash); err != nil {
					t.Fatalf("reserve: %v", err)
				}
				token := testClaimToken(t)
				won, err := store.ClaimFeedSignerOperation(ctx, req.OperationID, reqHash, token, time.Now().UTC().Add(time.Minute))
				if err != nil || !won {
					t.Fatalf("claim: won=%v err=%v", won, err)
				}
				result := publish.FeedCommitResult{OperationID: req.OperationID, Feed: publish.CanonicalTopic(topic), Reference: publish.CanonicalReference(refHex('d'))}
				if err := store.CompleteFeedSignerOperation(ctx, req.OperationID, reqHash, token, publish.CanonicalFeedCommitResultJSON(result)); err != nil {
					t.Fatalf("complete: %v", err)
				}
			},
		},
		{
			name: "legacy quarantine pending",
			seed: func(t *testing.T, db *sql.DB) {
				nowNs := timeToNanos(time.Now().UTC())
				h := feedSignerTestHash("legacy-pending")
				if _, err := db.ExecContext(ctx, `insert into feed_signer_operations_legacy
					(operation_id, request_hash, state, result_json, created_at, updated_at)
					values (?, ?, 'pending', null, ?, ?)`, "op-legacy-pending", h[:], nowNs, nowNs); err != nil {
					t.Fatalf("seed legacy pending: %v", err)
				}
			},
		},
		{
			name: "legacy quarantine succeeded",
			seed: func(t *testing.T, db *sql.DB) {
				nowNs := timeToNanos(time.Now().UTC())
				h := feedSignerTestHash("legacy-succeeded")
				result := `{"operationID":"op-legacy-succeeded","feed":"` + strings.Repeat("f", 112) + `","reference":"` + strings.Repeat("a", 64) + `"}`
				if _, err := db.ExecContext(ctx, `insert into feed_signer_operations_legacy
					(operation_id, request_hash, state, result_json, created_at, updated_at)
					values (?, ?, 'succeeded', ?, ?, ?)`, "op-legacy-succeeded", h[:], result, nowNs, nowNs); err != nil {
					t.Fatalf("seed legacy succeeded: %v", err)
				}
			},
		},
		{
			name: "adopted legacy row now active pending",
			seed: func(t *testing.T, db *sql.DB) {
				store := &Store{DB: db}
				reg, topic := seedFeedSignerRegistry(t, store)
				h := feedSignerTestHash("legacy-to-adopt")
				nowNs := timeToNanos(time.Now().UTC())
				if _, err := db.ExecContext(ctx, `insert into feed_signer_operations_legacy
					(operation_id, request_hash, state, result_json, created_at, updated_at)
					values (?, ?, 'pending', null, ?, ?)`, "op-to-adopt", h[:], nowNs, nowNs); err != nil {
					t.Fatalf("seed legacy quarantine row: %v", err)
				}
				adopted, err := store.AdoptLegacyFeedSignerOperation(ctx, "op-to-adopt", reg.ID, topic, refHex('e'), h, nil)
				if err != nil || !adopted {
					t.Fatalf("adopt: adopted=%v err=%v", adopted, err)
				}
				// Sanity: quarantine is now empty, but the ACTIVE table carries
				// the promoted pending row — the case this test targets.
				if n, err := store.LegacyOperationCount(ctx); err != nil || n != 0 {
					t.Fatalf("quarantine must be empty after adoption, got %d err %v", n, err)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := openRawFileTestDB(t)
			if err := applyMigrationsThrough(ctx, db, 15); err != nil {
				t.Fatalf("apply exact predecessor: %v", err)
			}
			tc.seed(t, db)

			var beforeActive, beforeLegacy int
			if err := db.QueryRowContext(ctx, `select count(*) from feed_signer_operations`).Scan(&beforeActive); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRowContext(ctx, `select count(*) from feed_signer_operations_legacy`).Scan(&beforeLegacy); err != nil {
				t.Fatal(err)
			}

			if err := ApplyMigrations(ctx, db); err == nil || !errors.Is(err, errPublicationStateHistoryUnsafe) {
				t.Fatalf("migration 16 must refuse %q, got %v", tc.name, err)
			}
			if v, err := CurrentSchemaVersion(ctx, db); err != nil || v != 15 {
				t.Fatalf("refused migration must leave version 15 current, got %d (err %v)", v, err)
			}
			if sqliteObjectCount(t, db, "table", "publication_states") != 0 {
				t.Fatal("refused migration must not create publication_states")
			}
			var migRows int
			if err := db.QueryRowContext(ctx, `select count(*) from schema_migrations`).Scan(&migRows); err != nil {
				t.Fatal(err)
			}
			if migRows != 15 {
				t.Fatalf("refused migration must not record a migration row, got %d", migRows)
			}

			var afterActive, afterLegacy int
			if err := db.QueryRowContext(ctx, `select count(*) from feed_signer_operations`).Scan(&afterActive); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRowContext(ctx, `select count(*) from feed_signer_operations_legacy`).Scan(&afterLegacy); err != nil {
				t.Fatal(err)
			}
			if afterActive != beforeActive || afterLegacy != beforeLegacy {
				t.Fatalf("refused migration must leave row counts untouched: active %d->%d legacy %d->%d",
					beforeActive, afterActive, beforeLegacy, afterLegacy)
			}
		})
	}
}

// TestMigration16RefusalIsRepeatable proves a refused upgrade stays refused,
// deterministically, across repeated ApplyMigrations calls: it never
// half-applies, never records a partial migration row, and never flips to
// success merely because it was tried before.
func TestMigration16RefusalIsRepeatable(t *testing.T) {
	ctx := context.Background()
	db := openRawFileTestDB(t)
	if err := applyMigrationsThrough(ctx, db, 15); err != nil {
		t.Fatalf("apply through 15: %v", err)
	}
	store := &Store{DB: db}
	reg, topic := seedFeedSignerRegistry(t, store)
	req := publish.FeedCommitRequest{
		OperationID: "op-repeat-pending", RegistryID: reg.ID, Owner: "0x" + testFeedOwner,
		Topic: topic, Reference: refHex('a'), BatchID: "batch-1", ExpectedGeneration: 0,
	}
	reqHash := NormalizeFeedCommitHash(req)
	if _, err := store.ReserveFeedSignerOperation(ctx, req.OperationID, reg.ID, topic, reqHash); err != nil {
		t.Fatalf("reserve: %v", err)
	}

	for i := 0; i < 3; i++ {
		if err := ApplyMigrations(ctx, db); err == nil || !errors.Is(err, errPublicationStateHistoryUnsafe) {
			t.Fatalf("attempt %d: expected repeated refusal, got %v", i, err)
		}
		if v, err := CurrentSchemaVersion(ctx, db); err != nil || v != 15 {
			t.Fatalf("attempt %d: expected version 15, got %d (err %v)", i, v, err)
		}
	}
}

// TestMigration16RejectsMalformedFeedSignerPredecessor proves migration 16
// validates the EXACT migration 9-14 feed_signer_operations /
// feed_signer_operations_legacy schema (table, active-repo-claim index,
// operation-id identity triggers, canonical-result triggers) before
// installing any new object — mirroring TestMigration16RejectsMalformedV15Predecessor
// for publication_bindings. A stamped-but-weakened or missing predecessor
// object must fail closed and atomically: version 15 remains current and
// publication_states is not created, even over an otherwise-empty history.
func TestMigration16RejectsMalformedFeedSignerPredecessor(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, db *sql.DB)
	}{
		{
			name: "missing feed signer operation-id identity trigger",
			mutate: func(t *testing.T, db *sql.DB) {
				if _, err := db.Exec(`drop trigger feed_signer_operation_id_ins`); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing feed signer result-integrity trigger",
			mutate: func(t *testing.T, db *sql.DB) {
				if _, err := db.Exec(`drop trigger feed_signer_result_integrity_upd`); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing active-repo-claim index",
			mutate: func(t *testing.T, db *sql.DB) {
				if _, err := db.Exec(`drop index feed_signer_active_repo_claim`); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "weakened feed_signer_operations table lookalike",
			mutate: func(t *testing.T, db *sql.DB) {
				for _, name := range []string{
					"feed_signer_operation_id_ins", "feed_signer_operation_id_upd",
					"feed_signer_result_integrity_ins", "feed_signer_result_integrity_upd",
				} {
					if _, err := db.Exec(`drop trigger ` + name); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := db.Exec(`drop index feed_signer_active_repo_claim`); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`drop table feed_signer_operations`); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`create table feed_signer_operations (operation_id text primary key, registry_id integer, topic text, request_hash blob, state text, result_json text, claim_token text, lease_until integer, attempts integer, created_at integer, updated_at integer)`); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing feed_signer_operations_legacy table",
			mutate: func(t *testing.T, db *sql.DB) {
				if _, err := db.Exec(`drop table feed_signer_operations_legacy`); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "weakened feed_signer_operations_legacy table lookalike",
			mutate: func(t *testing.T, db *sql.DB) {
				if _, err := db.Exec(`drop table feed_signer_operations_legacy`); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`create table feed_signer_operations_legacy (operation_id text primary key, request_hash blob, state text, result_json text, created_at integer, updated_at integer)`); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			db := openRawFileTestDB(t)
			if err := applyMigrationsThrough(ctx, db, 15); err != nil {
				t.Fatalf("apply exact predecessor: %v", err)
			}
			tc.mutate(t, db)

			if err := ApplyMigrations(ctx, db); err == nil || !errors.Is(err, errPublicationStatePredecessorMalformed) {
				t.Fatalf("migration 16 must reject a malformed feed-signer predecessor (%s), got %v", tc.name, err)
			}
			if v, err := CurrentSchemaVersion(ctx, db); err != nil || v != 15 {
				t.Fatalf("failed migration must leave version 15 current, got %d (err %v)", v, err)
			}
			if sqliteObjectCount(t, db, "table", "publication_states") != 0 {
				t.Fatal("failed predecessor validation must not leave publication_states installed")
			}
			if sqliteObjectCount(t, db, "trigger", "publication_state_operation_id_ins") != 0 ||
				sqliteObjectCount(t, db, "trigger", "publication_state_operation_id_upd") != 0 {
				t.Fatal("failed predecessor validation must not leave publication-state triggers installed")
			}
		})
	}
}
