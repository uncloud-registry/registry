package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/spec"
)

// validBindingReq is a structurally valid preflight request against the
// seeded feed-signer test registry (testFeedOwner).
func validBindingReq(regID int64, opID string) publish.OperationBindingRequest {
	return publish.OperationBindingRequest{
		OperationID:    opID,
		RegistryID:     regID,
		Owner:          testFeedOwner,
		Repo:           "myrepo",
		Tag:            "latest",
		ManifestDigest: "sha256:" + strings.Repeat("ab", 32),
	}
}

func seedBindingRegistry(t *testing.T, store *Store) (Registry, string) {
	t.Helper()
	return seedFeedSignerRegistry(t, store)
}

// TestNormalizePublicationBindingHashDeterministicAndDomainSeparated proves
// the binding hash is a pure function of the five typed fields: identical
// fields always derive the identical hash, and changing ANY ONE field
// (registry, owner, repo, tag, manifest digest) always derives a different
// hash — so two requests that differ in any payload dimension can never
// collide on one binding. Owner spellings that normalize identically
// (0x-prefix, case) bind identically.
func TestNormalizePublicationBindingHashDeterministicAndDomainSeparated(t *testing.T) {
	base := NormalizePublicationBindingHash(7, "0xABabABabABabABabABabABabABabABabABabABab", "myrepo", "latest", "sha256:"+strings.Repeat("cd", 32))
	if again := NormalizePublicationBindingHash(7, "0xABabABabABabABabABabABabABabABabABabABab", "myrepo", "latest", "sha256:"+strings.Repeat("cd", 32)); again != base {
		t.Fatal("identical fields must derive the identical binding hash")
	}
	if normalized := NormalizePublicationBindingHash(7, "abababababababababababababababababababab", "myrepo", "latest", "sha256:"+strings.Repeat("cd", 32)); normalized != base {
		t.Fatal("equivalent owner spellings must derive the identical binding hash")
	}
	cases := map[string]func() [32]byte{
		"registry": func() [32]byte {
			return NormalizePublicationBindingHash(8, "abababababababababababababababababababab", "myrepo", "latest", "sha256:"+strings.Repeat("cd", 32))
		},
		"owner": func() [32]byte {
			return NormalizePublicationBindingHash(7, "abababababababababababababababababababac", "myrepo", "latest", "sha256:"+strings.Repeat("cd", 32))
		},
		"repo": func() [32]byte {
			return NormalizePublicationBindingHash(7, "abababababababababababababababababababab", "otherrepo", "latest", "sha256:"+strings.Repeat("cd", 32))
		},
		"tag": func() [32]byte {
			return NormalizePublicationBindingHash(7, "abababababababababababababababababababab", "myrepo", "v2", "sha256:"+strings.Repeat("cd", 32))
		},
		"digest": func() [32]byte {
			return NormalizePublicationBindingHash(7, "abababababababababababababababababababab", "myrepo", "latest", "sha256:"+strings.Repeat("ce", 32))
		},
		"domain": func() [32]byte { // an empty-field hash must differ from a populated one
			return NormalizePublicationBindingHash(7, "", "", "", "")
		},
	}
	for name, h := range cases {
		if h() == base {
			t.Fatalf("%s change must derive a different binding hash", name)
		}
	}
}

// TestReservePublicationBindingFreshIdenticalChanged pins the atomic reserve
// semantics on the real store: fresh binds, identical re-binds stay green,
// and a different payload leaves the ORIGINAL row untouched (the caller's
// conflict decision), with exactly one row ever existing per key.
func TestReservePublicationBindingFreshIdenticalChanged(t *testing.T) {
	store := newProvisioningStore(t)
	reg, _ := seedBindingRegistry(t, store)
	ctx := context.Background()

	hashA := NormalizePublicationBindingHash(reg.ID, testFeedOwner, "myrepo", "latest", "sha256:"+strings.Repeat("ab", 32))
	hashB := NormalizePublicationBindingHash(reg.ID, testFeedOwner, "myrepo", "latest", "sha256:"+strings.Repeat("cd", 32))

	got, err := store.ReservePublicationBinding(ctx, "op-bind-fresh-0001", reg.ID, hashA)
	if err != nil {
		t.Fatalf("fresh reserve: %v", err)
	}
	if got.BindingHash != hashA {
		t.Fatal("fresh reserve must return the inserted binding hash")
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Fatal("fresh reserve must stamp created/updated times")
	}
	if got.RegistryID != reg.ID || got.OperationID != "op-bind-fresh-0001" {
		t.Fatalf("fresh reserve must scope the row to the registry, got registry %d", got.RegistryID)
	}

	// Identical re-bind: green, same row, unchanged hash.
	got2, err := store.ReservePublicationBinding(ctx, "op-bind-fresh-0001", reg.ID, hashA)
	if err != nil {
		t.Fatalf("identical re-reserve: %v", err)
	}
	if got2.BindingHash != hashA {
		t.Fatal("identical re-reserve must keep the original binding")
	}

	// Changed payload: the row keeps the ORIGINAL hash (insert-or-ignore). The
	// caller (PublicationBinder) turns the mismatch into the hard conflict.
	got3, err := store.ReservePublicationBinding(ctx, "op-bind-fresh-0001", reg.ID, hashB)
	if err != nil {
		t.Fatalf("changed re-reserve: %v", err)
	}
	if got3.BindingHash != hashA {
		t.Fatal("a changed payload must NEVER overwrite the original binding")
	}

	var rows int
	if err := store.DB.QueryRowContext(ctx, `select count(*) from publication_bindings`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("exactly one binding row must ever exist per key, got %d", rows)
	}
}

// TestReservePublicationBindingConcurrentDifferentHashesSingleWinner drives
// many concurrent changed contenders at ONE operation key across TWO store
// instances over ONE database: exactly one binding wins (all contenders read
// the very same row), no duplicate rows, no errors — so a conflicting request
// can never sneak past preflight into object writes.
func TestReservePublicationBindingConcurrentDifferentHashesSingleWinner(t *testing.T) {
	const dsn = "file:bindconcurrent_binding?mode=memory&cache=shared"
	storeA, errA := OpenSQLite(dsn)
	if errA != nil {
		t.Fatal(errA)
	}
	defer storeA.DB.Close()
	storeB, errB := OpenSQLite(dsn)
	if errB != nil {
		t.Fatal(errB)
	}
	defer storeB.DB.Close()
	reg, _ := seedBindingRegistry(t, storeA)
	ctx := context.Background()

	const opID = "op-bind-concurrent-single-winner"
	const contenders = 12
	hashes := make([][32]byte, contenders)
	for i := range hashes {
		hashes[i] = NormalizePublicationBindingHash(reg.ID, testFeedOwner, "myrepo", "latest", "sha256:"+strings.Repeat(string(rune('a'+i)), 64))
	}

	var wg sync.WaitGroup
	results := make([][32]byte, contenders)
	errs := make([]error, contenders)
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var store *Store
			if i%2 == 0 {
				store = storeA
			} else {
				store = storeB
			}
			b, err := store.ReservePublicationBinding(ctx, opID, reg.ID, hashes[i])
			results[i] = b.BindingHash
			errs[i] = err
		}(i)
	}
	wg.Wait()
	for i := range errs {
		if errs[i] != nil {
			t.Fatalf("contender %d: %v", i, errs[i])
		}
	}
	winner := results[0]
	for i := 1; i < contenders; i++ {
		if results[i] != winner {
			t.Fatalf("contenders must all read the SAME winning binding; contender %d diverged", i)
		}
	}
	var rows int
	if err := storeA.DB.QueryRowContext(ctx, `select count(*) from publication_bindings`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("exactly one binding row must win, got %d", rows)
	}
}

// TestPublicationBindingTableConstraints pins the DB-level guards: the FK to
// registries, the registry_id > 0 check, the exact 32-byte blob check, and —
// via the dedicated identity triggers — the same byte-exact operation-ID
// grammar migration 14 installed on feed_signer_operations, so a direct-SQL
// write can never store a grammar-violating operation key (quote characters,
// invalid UTF-8, empty, or oversized).
func TestPublicationBindingTableConstraints(t *testing.T) {
	db := openRawNamedTestDB(t, "binding_constraints")
	ctx := context.Background()
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatal(err)
	}
	store := &Store{DB: db}
	reg, _ := seedBindingRegistry(t, store)
	now := timeToNanos(time.Now().UTC())
	hash := NormalizePublicationBindingHash(reg.ID, testFeedOwner, "myrepo", "latest", "sha256:"+strings.Repeat("ab", 32))

	insert := func(opID string, registryID int64, h []byte) error {
		_, err := db.ExecContext(ctx, `insert into publication_bindings
			(operation_id, registry_id, binding_hash, created_at, updated_at)
			values (?, ?, ?, ?, ?)`, opID, registryID, h, now, now)
		return err
	}

	// Baseline: a fully valid row inserts.
	if err := insert("op-bind-ok", reg.ID, hash[:]); err != nil {
		t.Fatalf("valid row must insert: %v", err)
	}
	if err := db.QueryRowContext(ctx, `select registry_id from publication_bindings where operation_id = 'op-bind-ok'`).Scan(&reg.ID); err != nil {
		t.Fatal(err)
	}

	badCases := []struct {
		name string
		run  func() error
	}{
		{"unknown registry FK", func() error { return insert("op-bind-badfk", 999999, hash[:]) }},
		{"non-positive registry id", func() error { return insert("op-bind-badreg", 0, hash[:]) }},
		{"short hash", func() error { return insert("op-bind-shorthash", reg.ID, hash[:31]) }},
		{"empty operation id", func() error { return insert("", reg.ID, hash[:]) }},
		{"oversized operation id", func() error { return insert(strings.Repeat("x", 129), reg.ID, hash[:]) }},
		{"double-quote operation id", func() error { return insert(`op-bind"quote`, reg.ID, hash[:]) }},
		{"ampersand operation id", func() error { return insert("op&bind", reg.ID, hash[:]) }},
		{"less-than operation id", func() error { return insert("op<bind", reg.ID, hash[:]) }},
		{"backslash operation id", func() error { return insert(`op\bind`, reg.ID, hash[:]) }},
		{"invalid utf8 operation id", func() error { return insert("op-bind-\xff", reg.ID, hash[:]) }},
	}
	for _, tc := range badCases {
		if err := tc.run(); err == nil {
			t.Fatalf("%s must be rejected by the schema", tc.name)
		}
	}
	var rows int
	if err := db.QueryRowContext(ctx, `select count(*) from publication_bindings`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("only the single valid row may exist, got %d", rows)
	}
}

// TestMigration15FreshUpgradeAndRollback covers startup compatibility and
// atomicity: a fresh database converges to version 15 with the table and its
// identity triggers; a version-14 database upgrades with its feed-signer
// state intact; and a migration-15 statement failure (pre-existing
// wrong-schema table) rolls the whole transaction back — version stays 14,
// no migration row is recorded, and the incompatible table is untouched.
func TestMigration15FreshUpgradeAndRollback(t *testing.T) {
	ctx := context.Background()

	// Fresh database converges to 15 with table + triggers.
	fresh := openRawNamedTestDB(t, "migration15_fresh")
	if err := ApplyMigrations(ctx, fresh); err != nil {
		t.Fatalf("fresh apply: %v", err)
	}
	if v, _ := CurrentSchemaVersion(ctx, fresh); v != 15 {
		t.Fatalf("fresh db must reach version 15, got %d", v)
	}
	if sqliteObjectCount(t, fresh, "table", "publication_bindings") != 1 {
		t.Fatal("migration 15 must create publication_bindings on a fresh database")
	}
	if sqliteObjectCount(t, fresh, "trigger", "publication_binding_operation_id_ins") != 1 ||
		sqliteObjectCount(t, fresh, "trigger", "publication_binding_operation_id_upd") != 1 {
		t.Fatal("migration 15 must install the publication binding identity triggers")
	}

	// Version-14 database upgrades with its feed-signer state intact.
	upg := openRawNamedTestDB(t, "migration15_upgrade")
	if err := applyMigrationsThrough(ctx, upg, 14); err != nil {
		t.Fatalf("apply through 14: %v", err)
	}
	upgStore := &Store{DB: upg}
	reg, _ := seedBindingRegistry(t, upgStore)
	sh := []byte("01234567890123456789012345678901") // exactly 32 bytes
	now := timeToNanos(time.Now().UTC())
	if _, err := upg.ExecContext(ctx, `insert into feed_signer_operations
		(operation_id, registry_id, topic, request_hash, state, result_json,
		 claim_token, lease_until, attempts, created_at, updated_at)
		values ('op-before-15', ?, 'topic:one', ?, 'pending', null, null, null, 0, ?, ?)`,
		reg.ID, sh[:], now, now); err != nil {
		t.Fatalf("seed pre-15 operation: %v", err)
	}
	if err := ApplyMigrations(ctx, upg); err != nil {
		t.Fatalf("upgrade to 15: %v", err)
	}
	if v, _ := CurrentSchemaVersion(ctx, upg); v != 15 {
		t.Fatalf("upgraded db must reach version 15, got %d", v)
	}
	if sqliteObjectCount(t, upg, "table", "publication_bindings") != 1 {
		t.Fatal("migration 15 must create publication_bindings on upgrade")
	}
	var kept string
	if err := upg.QueryRowContext(ctx, `select operation_id from feed_signer_operations where operation_id = 'op-before-15'`).Scan(&kept); err != nil || kept != "op-before-15" {
		t.Fatalf("pre-15 feed-signer state must be untouched, got %q err %v", kept, err)
	}

	// Rollback: a wrong-schema pre-existing table fails migration 15
	// atomically — version stays 14, no migration row, table untouched.
	rb := openRawNamedTestDB(t, "migration15_rollback")
	if err := applyMigrationsThrough(ctx, rb, 14); err != nil {
		t.Fatalf("apply through 14: %v", err)
	}
	if _, err := rb.ExecContext(ctx, `create table publication_bindings (operation_id text primary key, unrelated_col integer)`); err != nil {
		t.Fatalf("seed wrong-schema table: %v", err)
	}
	if err := ApplyMigrations(ctx, rb); err == nil {
		t.Fatal("migration 15 must fail against a wrong-schema pre-existing table")
	}
	if v, _ := CurrentSchemaVersion(ctx, rb); v != 14 {
		t.Fatalf("failed migration 15 must leave version at 14, got %d", v)
	}
	var migRows int
	if err := rb.QueryRowContext(ctx, `select count(*) from schema_migrations`).Scan(&migRows); err != nil {
		t.Fatal(err)
	}
	if migRows != 14 {
		t.Fatalf("failed migration 15 must not record a migration row, got %d", migRows)
	}
	cols := tableColumnsOf(t, rb, "publication_bindings")
	if !cols["operation_id"] || !cols["unrelated_col"] || len(cols) != 2 {
		t.Fatalf("the incompatible table must be untouched by the failed migration, got %v", cols)
	}
}

// TestPublicationBinderBind covers the service mapping: fresh and identical
// binds pass; a reused key with a changed repo/tag/digest conflicts BEFORE
// any durable mutation; a changed owner or unknown registry yields
// registry-not-found; a provisioning registry is not ready; a nil store or a
// shape-invalid request never touches the database.
func TestPublicationBinderBind(t *testing.T) {
	store := newProvisioningStore(t)
	reg, _ := seedBindingRegistry(t, store)
	binder := &PublicationBinder{Store: store}
	ctx := context.Background()

	base := validBindingReq(reg.ID, "op-bind-svc-0001")

	if err := binder.Bind(ctx, base); err != nil {
		t.Fatalf("fresh bind must pass: %v", err)
	}
	if err := binder.Bind(ctx, base); err != nil {
		t.Fatalf("identical bind must pass: %v", err)
	}

	changed := map[string]func() publish.OperationBindingRequest{
		"repo": func() publish.OperationBindingRequest { r := base; r.Repo = "otherrepo"; return r },
		"tag":  func() publish.OperationBindingRequest { r := base; r.Tag = "v2"; return r },
		"digest": func() publish.OperationBindingRequest {
			r := base
			r.ManifestDigest = "sha256:" + strings.Repeat("cd", 32)
			return r
		},
	}
	for name, mutate := range changed {
		if err := binder.Bind(ctx, mutate()); !errors.Is(err, errFeedSignerConflict) {
			t.Fatalf("changed %s must conflict, got %v", name, err)
		}
	}

	// Changed owner is a registry-unknown (owner proof runs BEFORE any write).
	ownerReq := base
	ownerReq.Owner = "0x1111111111111111111111111111111111111111"
	if err := binder.Bind(ctx, ownerReq); !errors.Is(err, errFeedSignerRegistryNotFound) {
		t.Fatalf("changed owner must be registry-not-found, got %v", err)
	}
	// Unknown registry.
	unknownReq := base
	unknownReq.RegistryID = 999999
	if err := binder.Bind(ctx, unknownReq); !errors.Is(err, errFeedSignerRegistryNotFound) {
		t.Fatalf("unknown registry must be registry-not-found, got %v", err)
	}

	// Provisioning (not-ready) registry → not-ready.
	// NOTE: newProvisioningStore derives its shared-memory name from t.Name(),
	// so a SECOND store in the same test must use an explicit distinct name
	// (shared-memory databases persist for the life of the test process).
	provisioning := newProvisioningStoreNamed(t, "TestPublicationBinderBind_notready_"+t.Name())
	owner := seedProvisioningOwner(t, provisioning)
	notReady, err := provisioning.CreateProvisionedRegistry(ctx, Registry{
		Slug: "notready", Host: "notready.registry.test", ENSName: "notready.eth",
		OwnerUserID: owner.ID, FeedOwnerAddress: "0x2222222222222222222222222222222222222222",
		DefaultStampBatchID: "batch-n", AnonymousPull: true,
	}, newTestFeedKeyCipherForStore(t), []byte("01234567890123456789012345678901"),
		[]byte(testAuthPayload), []byte(testStampPayload))
	if err != nil {
		t.Fatalf("create provisioning registry: %v", err)
	}
	nrReq := validBindingReq(notReady.ID, "op-bind-notready")
	if err := (&PublicationBinder{Store: provisioning}).Bind(ctx, nrReq); !errors.Is(err, errFeedSignerNotReady) {
		t.Fatalf("provisioning registry must be not-ready, got %v", err)
	}

	// Nil store → backend. Shape-invalid requests → malformed, no DB touch.
	var typedNil *Store
	if err := (&PublicationBinder{Store: typedNil}).Bind(ctx, base); !errors.Is(err, errFeedSignerBackend) {
		t.Fatalf("typed-nil store must be backend, got %v", err)
	}
	if err := (&PublicationBinder{}).Bind(ctx, base); !errors.Is(err, errFeedSignerBackend) {
		t.Fatalf("nil store must be backend, got %v", err)
	}
	bad := base
	bad.ManifestDigest = "not-a-digest"
	if err := binder.Bind(ctx, bad); !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("bad digest must be malformed, got %v", err)
	}
	oversized := base
	oversized.OperationID = strings.Repeat("x", 129)
	if err := binder.Bind(ctx, oversized); !errors.Is(err, errFeedSignerMalformed) {
		t.Fatalf("oversized key must be malformed, got %v", err)
	}
	var bindingRows int
	if err := store.DB.QueryRowContext(ctx, `select count(*) from publication_bindings`).Scan(&bindingRows); err != nil {
		t.Fatal(err)
	}
	if bindingRows != 1 {
		t.Fatalf("only the fresh binding row may exist, got %d", bindingRows)
	}
}

// TestInternalOperationBindingEndpoint drives the internal preflight route
// over real HTTP: auth, routing, strict bounded JSON, not-ready/unknown
// registries, the fresh/identical/conflict decision, and the coarse generic
// bodies.
func TestInternalOperationBindingEndpoint(t *testing.T) {
	store := newProvisioningStore(t)
	reg, _ := seedBindingRegistry(t, store)
	binder := &PublicationBinder{Store: store}
	srv, err := NewInternalFeedServer(&FeedSigner{}, binder, []byte(testInternalSecret), nil)
	if err != nil {
		t.Fatal(err)
	}
	path := publish.InternalOperationBindingPath
	post := func(secret, body string) *httptest.ResponseRecorder {
		t.Helper()
		return postFeedUpdate(t, srv, path, secret, body)
	}
	validBody := func() string { b, _ := jsonMarshal(validBindingReq(reg.ID, "op-bind-http-0001")); return string(b) }

	// Auth: missing / wrong / duplicate / blank all 401.
	if rec := post("", validBody()); rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing credential: got %d want 401", rec.Code)
	}
	if rec := post("wrong-secret", validBody()); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong credential: got %d want 401", rec.Code)
	}
	dup := httptest.NewRequest(http.MethodPost, path, strings.NewReader(validBody()))
	dup.Header.Add(publish.InternalAuthHeader, testInternalSecret)
	dup.Header.Add(publish.InternalAuthHeader, testInternalSecret)
	dupRec := httptest.NewRecorder()
	srv.ServeHTTP(dupRec, dup)
	if dupRec.Code != http.StatusUnauthorized {
		t.Fatalf("duplicate credential: got %d want 401", dupRec.Code)
	}
	if rec := post("   ", validBody()); rec.Code != http.StatusUnauthorized {
		t.Fatalf("blank credential: got %d want 401", rec.Code)
	}

	// Routing: wrong path 404, wrong method 405.
	if rec := post(testInternalSecret, validBody()); rec.Code != http.StatusOK {
		t.Fatalf("happy path sanity: got %d want 200", rec.Code)
	}
	if rec := postFeedUpdate(t, srv, "/other", testInternalSecret, validBody()); rec.Code != http.StatusNotFound {
		t.Fatalf("wrong path: got %d want 404", rec.Code)
	}
	getReq := httptest.NewRequest(http.MethodGet, path, nil)
	getReq.Header.Set(publish.InternalAuthHeader, testInternalSecret)
	getRec := httptest.NewRecorder()
	srv.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET on route: got %d want 405", getRec.Code)
	}

	// Strict JSON: malformed, duplicate, unknown, trailing, oversized → 400.
	for name, body := range map[string]string{
		"not json":        `not json`,
		"duplicate field": `{"operationID":"a","operationID":"b"}`,
		"unknown field":   `{"registryID":1,"unknown":true}`,
		"trailing data":   `{"operationID":"a"} trailing`,
	} {
		if rec := post(testInternalSecret, body); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: got %d want 400", name, rec.Code)
		}
	}
	big := `{"operationID":"` + strings.Repeat("x", 66000) + `"}`
	if rec := post(testInternalSecret, big); rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body: got %d want 400", rec.Code)
	}

	// Unknown registry → 404 with the generic registry-not-found body.
	unknown := validBindingReq(999999, "op-bind-http-9999")
	ub, _ := jsonMarshal(unknown)
	if rec := post(testInternalSecret, string(ub)); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown registry: got %d want 404", rec.Code)
	}

	// Fresh → 200 reserved; identical reuse → 200; changed payload → 409.
	first := post(testInternalSecret, validBody())
	if first.Code != http.StatusOK || strings.TrimSpace(first.Body.String()) != `{"status":"reserved"}` {
		t.Fatalf("fresh bind: got %d %q", first.Code, first.Body.String())
	}
	if rec := post(testInternalSecret, validBody()); rec.Code != http.StatusOK {
		t.Fatalf("identical reuse: got %d want 200", rec.Code)
	}
	changedReq := validBindingReq(reg.ID, "op-bind-http-0001")
	changedReq.Tag = "v2"
	cb, _ := jsonMarshal(changedReq)
	rec := post(testInternalSecret, string(cb))
	if rec.Code != http.StatusConflict {
		t.Fatalf("changed payload: got %d want 409", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "operation conflict") {
		t.Fatalf("409 body must be the generic conflict body, got %q", rec.Body.String())
	}

	// Nil store backing the binder → 503 generic.
	emptyBinderSrv, err := NewInternalFeedServer(&FeedSigner{}, &PublicationBinder{}, []byte(testInternalSecret), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec := postFeedUpdate(t, emptyBinderSrv, path, testInternalSecret, validBody()); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil-store binder: got %d want 503", rec.Code)
	}
}

// TestControlPlaneOperationBinderAgainstRealInternalServer closes the loop:
// the data-plane binder client against the REAL internal server over HTTP —
// fresh reserve passes, the identical retry passes, a changed payload is the
// client-side ErrCommitConflict, and a wrong secret never reaches the store.
func TestControlPlaneOperationBinderAgainstRealInternalServer(t *testing.T) {
	store := newProvisioningStore(t)
	reg, _ := seedBindingRegistry(t, store)
	srv, err := NewInternalFeedServer(&FeedSigner{}, &PublicationBinder{Store: store}, []byte(testInternalSecret), nil)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	client := &publish.ControlPlaneOperationBinder{
		BaseURL:    ts.URL,
		Secret:     []byte(testInternalSecret),
		HTTPClient: ts.Client(),
	}
	ctx := context.Background()
	req := validBindingReq(reg.ID, "op-bind-e2e-0001")

	if err := client.Bind(ctx, req); err != nil {
		t.Fatalf("fresh e2e bind: %v", err)
	}
	if err := client.Bind(ctx, req); err != nil {
		t.Fatalf("identical e2e re-bind: %v", err)
	}
	changed := req
	changed.Tag = "release"
	if err := client.Bind(ctx, changed); !errors.Is(err, publish.ErrCommitConflict) {
		t.Fatalf("changed e2e payload must be ErrCommitConflict, got %v", err)
	}

	// Wrong credential on the client: the server 401s; the client collapses it
	// to the backend class and the control-plane row is untouched by it.
	wrong := &publish.ControlPlaneOperationBinder{BaseURL: ts.URL, Secret: []byte("wrong-secret"), HTTPClient: ts.Client()}
	if err := wrong.Bind(ctx, req); err == nil {
		t.Fatal("wrong secret must fail")
	}
	var rows int
	if err := store.DB.QueryRowContext(ctx, `select count(*) from publication_bindings`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("exactly one e2e binding row, got %d", rows)
	}

	// Owner normalization flows through: the seeded registry's address IS
	// testFeedOwner, so an equivalent spelled owner must bind identically.
	spelled := req
	spelled.Owner = spec.NormalizeOwner(testFeedOwner)
	if err := client.Bind(ctx, spelled); err != nil {
		t.Fatalf("normalized owner spelling must bind identically: %v", err)
	}
}

func jsonMarshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

// newProvisioningStoreNamed opens a provisioning store over a DISTINCT
// shared-memory database name. newProvisioningStore derives its name from
// t.Name(), so it can only be used once per test in a process (shared-memory
// databases persist for the life of the test binary); tests that need two
// isolated stores in one test must use this.
func newProvisioningStoreNamed(t *testing.T, name string) *Store {
	t.Helper()
	store, err := OpenSQLite("file:provstore_" + name + "?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	return store
}

// openRawNamedTestDB opens an ISOLATED in-memory SQLite database (unique
// shared-memory name, FK pragma on every pooled connection). The package's
// openRawTestDB helper uses ONE fixed shared-memory name for all opens in the
// test binary, so migration scenarios that each need their own pristine
// database must use this instead.
func openRawNamedTestDB(t *testing.T, name string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+name+"?"+"mode=memory&cache=shared&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
