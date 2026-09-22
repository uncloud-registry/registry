package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"testing"
)

func TestMigration9CreatesFeedSignerOperationStore(t *testing.T) {
	store := newProvisioningStore(t)
	var found int
	err := store.DB.QueryRow("select count(*) from sqlite_master where type='table' and name='feed_signer_operations'").Scan(&found)
	if err != nil {
		t.Fatalf("query schema: %v", err)
	}
	if found != 1 {
		t.Fatalf("expected migration 9 table feed_signer_operations to exist, found %d", found)
	}
}

func TestFeedSignerOperationStoreLifecycle(t *testing.T) {
	store := newProvisioningStore(t)
	ctx := context.Background()
	var hash [32]byte
	for i := range hash {
		hash[i] = byte(i)
	}

	op, created, err := store.ReserveFeedSignerOperation(ctx, "op-1", hash)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if !created {
		t.Fatal("expected first reserve to create the operation")
	}
	if op.State != FeedSignerOpPending {
		t.Fatalf("expected pending, got %q", op.State)
	}

	// Second reserve of the SAME ID+hash returns created=false (no new row).
	_, created, err = store.ReserveFeedSignerOperation(ctx, "op-1", hash)
	if err != nil {
		t.Fatalf("reserve again: %v", err)
	}
	if created {
		t.Fatal("expected second reserve not to re-insert")
	}

	// Complete transitions it to succeeded with the stored result.
	result := `{"operationID":"op-1","feed":"feed://abc/0123","reference":"` + hashString() + `"}`
	if err := store.CompleteFeedSignerOperation(ctx, "op-1", hash, []byte(result)); err != nil {
		t.Fatalf("complete: %v", err)
	}

	got, err := store.GetFeedSignerOperation(ctx, "op-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.State != FeedSignerOpSucceeded || got.RequestHash != hash || string(got.ResultJSON) != result {
		t.Fatalf("unexpected stored op: state=%q hash=%x result=%s", got.State, got.RequestHash, got.ResultJSON)
	}

	// Completing again with the SAME hash is an idempotent no-op (a concurrent
	// identical completer must not error).
	if err := store.CompleteFeedSignerOperation(ctx, "op-1", hash, []byte(result)); err != nil {
		t.Fatalf("expected idempotent re-complete to succeed, got %v", err)
	}
	// Completing a non-pending op with a DIFFERENT hash is rejected.
	var otherHash [32]byte
	otherHash[0] = 0xff
	if err := store.CompleteFeedSignerOperation(ctx, "op-1", otherHash, []byte(result)); err == nil {
		t.Fatal("expected completing a non-pending op with a different hash to fail")
	}
}

func TestFeedSignerStoreUnknownOperationReturnsNoRows(t *testing.T) {
	store := newProvisioningStore(t)
	_, err := store.GetFeedSignerOperation(context.Background(), "missing")
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected ErrNoRows, got %v", err)
	}
}

func hashString() string {
	out := ""
	for i := 0; i < 64; i++ {
		out += "a"
	}
	return out
}
