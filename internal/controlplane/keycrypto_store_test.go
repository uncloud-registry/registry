package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

// testFeedKeyPlaintext is a deterministic 64-hex-char signing key used to
// detect plaintext at rest. Constructed by concatenation so this source never
// contains a single run that scans as key material.
func testFeedKeyPlaintext() string {
	return strings.Repeat("a1b2", 16)
}

func newStoreService(t *testing.T, db *sql.DB) *Service {
	t.Helper()
	return &Service{
		Store:          &Store{DB: db},
		Tokens:         newTestSessionManager(t),
		RegistryDomain: "uncloud-registry.com",
		FeedKeys:       newTestFeedKeyCipher(t),
	}
}

// dumpRegistryRow concatenates every column value of one registries row as
// text so a test can assert the plaintext key never appears anywhere in the
// persisted row.
func dumpRegistryRow(t *testing.T, db *sql.DB, id int64) string {
	t.Helper()
	rows, err := db.Query(`select * from registries where id = ?`, id)
	if err != nil {
		t.Fatalf("dump row: %v", err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatalf("row columns: %v", err)
	}
	if !rows.Next() {
		t.Fatal("expected a registry row")
	}
	raw := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range raw {
		ptrs[i] = &raw[i]
	}
	if err := rows.Scan(ptrs...); err != nil {
		t.Fatalf("scan row: %v", err)
	}
	var buf strings.Builder
	for _, v := range raw {
		switch x := v.(type) {
		case []byte:
			buf.Write(x)
		case string:
			buf.WriteString(x)
		case int64:
			buf.WriteString(strconv.FormatInt(x, 10))
		case nil:
			buf.WriteString("<nil>")
		}
	}
	return buf.String()
}

// TestStoreRegistryPersistsEncryptedKeyAtRest pins the core at-rest boundary:
// after Service.CreateRegistry the database holds ciphertext+nonce+version in
// binary/integer columns, the legacy plaintext column is empty, and the
// plaintext key material never appears anywhere in the row.
func TestStoreRegistryPersistsEncryptedKeyAtRest(t *testing.T) {
	t.Parallel()
	store, err := OpenSQLite("file:keycrypto_atrest?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	ctx := context.Background()
	cipher := newTestFeedKeyCipher(t)
	plaintext := testFeedKeyPlaintext()

	owner, err := store.CreateUser(ctx, "alice@example.com", "hash")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	created, err := store.CreateRegistry(ctx, Registry{
		Slug: "alice", Host: "alice.uncloud-registry.com", ENSName: "alice.eth",
		OwnerUserID: owner.ID, FeedOwnerAddress: "0xfeed0001", DefaultStampBatchID: "batch-1",
		AnonymousPull: false,
	}, cipher, plaintext)
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	if !created.FeedKeySet {
		t.Fatal("created registry must carry an encrypted feed key")
	}
	if created.FeedKey.KeyVersion != cipher.CurrentVersion() {
		t.Fatalf("expected version %d, got %d", cipher.CurrentVersion(), created.FeedKey.KeyVersion)
	}
	if len(created.FeedKey.Ciphertext) == 0 || len(created.FeedKey.Nonce) == 0 {
		t.Fatal("ciphertext and nonce must be persisted")
	}

	// Raw database scan: binary/integer columns, no plaintext.
	var legacy string
	var ciphertext, nonce []byte
	var version sql.NullInt64
	if err := store.DB.QueryRowContext(ctx, `select encrypted_feed_private_key, feed_key_ciphertext, feed_key_nonce, feed_key_version from registries where id = ?`, created.ID).
		Scan(&legacy, &ciphertext, &nonce, &version); err != nil {
		t.Fatalf("scan row: %v", err)
	}
	if legacy != "" {
		t.Fatalf("legacy plaintext column must be empty, got %q", legacy)
	}
	if len(ciphertext) == 0 || len(nonce) == 0 || !version.Valid {
		t.Fatal("encrypted key columns must be populated")
	}
	if version.Int64 != int64(cipher.CurrentVersion()) {
		t.Fatalf("expected stored version %d, got %d", cipher.CurrentVersion(), version.Int64)
	}

	// Absence of plaintext across the whole row dump (all columns, both text
	// and decoded blob bytes).
	dump := dumpRegistryRow(t, store.DB, created.ID)
	if strings.Contains(dump, plaintext) {
		t.Fatalf("plaintext feed key found in database row: %s", dump)
	}

	// Decryption with the row's own context returns exactly the plaintext.
	got, err := cipher.Decrypt(created.ID, "0xfeed0001", created.FeedKey)
	if err != nil {
		t.Fatalf("decrypt stored key: %v", err)
	}
	if string(got) != plaintext {
		t.Fatalf("decrypted key mismatch: %q", got)
	}

	// The store read path returns only the encrypted form.
	fetched, err := store.FindRegistryByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("find registry: %v", err)
	}
	if !fetched.FeedKeySet || fetched.FeedKey.KeyVersion != cipher.CurrentVersion() {
		t.Fatalf("fetched registry must carry the encrypted key, got %+v", fetched.FeedKey)
	}
	if bytes.Equal(fetched.FeedKey.Ciphertext, []byte(plaintext)) {
		t.Fatal("stored ciphertext must never equal the plaintext")
	}
}

func TestStoreCreateRegistryRejectsMissingPlaintextWithCipher(t *testing.T) {
	t.Parallel()
	store, err := OpenSQLite("file:keycrypto_noplain?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	owner, err := store.CreateUser(context.Background(), "alice@example.com", "hash")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	_, err = store.CreateRegistry(context.Background(), Registry{
		Slug: "alice", Host: "alice.uncloud-registry.com", ENSName: "alice.eth",
		OwnerUserID: owner.ID, FeedOwnerAddress: "0xfeed0001", DefaultStampBatchID: "batch-1",
	}, newTestFeedKeyCipher(t), "")
	if err == nil {
		t.Fatal("cipher configured with empty plaintext must be rejected")
	}
}

func TestServiceCreateRegistryFailsClosedWithoutCipher(t *testing.T) {
	t.Parallel()
	store, err := OpenSQLite("file:keycrypto_nocipher?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	service := &Service{Store: store, Tokens: newTestSessionManager(t), RegistryDomain: "uncloud-registry.com"}
	user, _, err := service.RegisterUser(context.Background(), "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	_, err = service.CreateRegistry(context.Background(), user.ID, "alice", "alice.eth", false, "batch-1")
	if !errors.Is(err, errFeedKeyCipherNotConfigured) {
		t.Fatalf("expected the fail-closed cipher error, got %v", err)
	}
}

// TestLegacyPlaintextNeverMigratedWithoutOptIn pins the schema-migration side
// of the gate: advancing the schema (v1 → v2) must NEVER read, touch, or
// clear the legacy plaintext column. Only the explicitly invoked, opt-in-gated
// MigrateLegacyFeedKeys operation (called by cmd/controlplane only when
// CONTROLPLANE_MIGRATE_LEGACY_KEYS=true) may read it.
//
// NOT parallel: openRawTestDB shares the fixed "migration_test" in-memory
// database name with the other migration tests, and this one seeds the legacy
// schema — parallel seeding would collide.
func TestLegacyPlaintextNeverMigratedWithoutOptIn(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)
	seedLegacyDB(t, db, now, now, true)

	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	var legacy string
	var version sql.NullInt64
	if err := db.QueryRowContext(ctx, `select encrypted_feed_private_key, feed_key_version from registries where id = 1`).Scan(&legacy, &version); err != nil {
		t.Fatalf("scan legacy row: %v", err)
	}
	if legacy != "ciphertext" {
		t.Fatalf("schema migration must not read/clear legacy plaintext; got %q", legacy)
	}
	if version.Valid {
		t.Fatal("schema migration must not populate encrypted key columns")
	}
}

// TestMigrateLegacyFeedKeysEncryptsAndClearsAtomically drives the opt-in
// migration: with a configured cipher each legacy row is encrypted with its
// own ID/owner AAD and the legacy value is cleared in the same transaction.
//
// NOT parallel: shares the fixed "migration_test" in-memory database name
// with the other migration tests.
func TestMigrateLegacyFeedKeysEncryptsAndClearsAtomically(t *testing.T) {
	// no t.Parallel: shared fixed-name in-memory database
	db := openRawTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)
	seedLegacyDB(t, db, now, now, true)
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	service := newStoreService(t, db)
	migrated, err := service.MigrateLegacyFeedKeys(ctx)
	if err != nil {
		t.Fatalf("migrate legacy feed keys: %v", err)
	}
	if migrated != 1 {
		t.Fatalf("expected 1 migrated row, got %d", migrated)
	}

	var legacy string
	var ciphertext, nonce []byte
	var version sql.NullInt64
	if err := db.QueryRowContext(ctx, `select encrypted_feed_private_key, feed_key_ciphertext, feed_key_nonce, feed_key_version from registries where id = 1`).Scan(&legacy, &ciphertext, &nonce, &version); err != nil {
		t.Fatalf("scan migrated row: %v", err)
	}
	if legacy != "" {
		t.Fatalf("legacy plaintext must be cleared in the same transaction, got %q", legacy)
	}
	if len(ciphertext) == 0 || len(nonce) == 0 || !version.Valid {
		t.Fatal("encrypted key columns must be populated after migration")
	}

	// The migrated ciphertext decrypts under the row's own context to the
	// original legacy plaintext.
	got, err := service.FeedKeys.Decrypt(1, "0xfeed", EncryptedFeedKey{Ciphertext: ciphertext, Nonce: nonce, KeyVersion: int(version.Int64)})
	if err != nil {
		t.Fatalf("decrypt migrated key: %v", err)
	}
	if string(got) != "ciphertext" {
		t.Fatalf("migrated plaintext mismatch: %q", got)
	}

	// Idempotent: nothing left to migrate.
	migrated, err = service.MigrateLegacyFeedKeys(ctx)
	if err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if migrated != 0 {
		t.Fatalf("second migration must be a no-op, got %d", migrated)
	}
}

// TestMigrateLegacyFeedKeysRollsBackOnFailure pins atomicity and fail-closed
// behavior: a row whose encryption fails (empty owner context) leaves that
// row's legacy plaintext and key columns untouched, while earlier rows stay
// migrated — each row is its own transaction.
//
// NOT parallel: shares the fixed "migration_test" in-memory database name
// with the other migration tests.
func TestMigrateLegacyFeedKeysRollsBackOnFailure(t *testing.T) {
	// no t.Parallel: shared fixed-name in-memory database
	db := openRawTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)

	seedLegacyDBSchema(t, db)
	if _, err := db.ExecContext(ctx, `insert into users (email, password_hash, created_at) values (?, ?, ?)`, "alice@example.com", "hash", now); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	insertRegistry := func(slug, host, owner, legacy string) {
		if _, err := db.ExecContext(ctx, `insert into registries
			(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at)
			values (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			slug, host, "alice.eth", 1, owner, legacy, "batch-1", 1, now); err != nil {
			t.Fatalf("seed registry %s: %v", slug, err)
		}
	}
	insertRegistry("alice", "alice.uncloud-registry.com", "0xfeed", strings.Repeat("c0ffee", 8))
	insertRegistry("broken", "broken.uncloud-registry.com", "", strings.Repeat("deadbe", 8)) // empty owner → encryption must fail

	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	service := newStoreService(t, db)
	_, err := service.MigrateLegacyFeedKeys(ctx)
	if err == nil {
		t.Fatal("migration must fail on the broken row")
	}
	if msg := err.Error(); strings.Contains(msg, strings.Repeat("c0ffee", 8)) || strings.Contains(msg, strings.Repeat("deadbe", 8)) {
		t.Fatalf("migration error must not contain plaintext material: %v", err)
	}

	// Row 1 migrated and cleared; row 2 (the failing one) fully untouched.
	var legacy1, legacy2 string
	var version1, version2 sql.NullInt64
	if err := db.QueryRowContext(ctx, `select encrypted_feed_private_key, feed_key_version from registries where slug = 'alice'`).Scan(&legacy1, &version1); err != nil {
		t.Fatalf("scan row 1: %v", err)
	}
	if err := db.QueryRowContext(ctx, `select encrypted_feed_private_key, feed_key_version from registries where slug = 'broken'`).Scan(&legacy2, &version2); err != nil {
		t.Fatalf("scan row 2: %v", err)
	}
	if legacy1 != "" || !version1.Valid {
		t.Fatalf("row 1 must be migrated (legacy=%q version=%v)", legacy1, version1.Valid)
	}
	if legacy2 != strings.Repeat("deadbe", 8) || version2.Valid {
		t.Fatalf("row 2 must be untouched (legacy present, no ciphertext): legacy=%q", legacy2)
	}
}

// TestReencryptFeedKeysRotatesRows rotates a v1 row to the explicitly
// requested loaded version 2 (not merely `current`), preserves the owner, and
// skips rows not at fromVersion without touching them.
func TestReencryptFeedKeysRotatesRows(t *testing.T) {
	t.Parallel()
	store, err := OpenSQLite("file:keycrypto_rotatemain?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	ctx := context.Background()
	service := newStoreService(t, store.DB)
	cipher := service.FeedKeys

	owner, err := store.CreateUser(ctx, "alice@example.com", "hash")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	ptA := testFeedKeyPlaintext()
	regA, err := store.CreateRegistry(ctx, Registry{
		Slug: "alice", Host: "alice.uncloud-registry.com", ENSName: "alice.eth",
		OwnerUserID: owner.ID, FeedOwnerAddress: "0xfeed0001", DefaultStampBatchID: "batch-1",
	}, cipher, ptA)
	if err != nil {
		t.Fatalf("create registry A: %v", err)
	}
	// Registry B is ALREADY at version 2 (e.g. a previous rotation pass) — it
	// must be skipped, not downgraded or re-encrypted.
	ptB := "bbbb1111" + strings.Repeat("bb", 20)
	regB, err := store.CreateRegistry(ctx, Registry{
		Slug: "bob", Host: "bob.uncloud-registry.com", ENSName: "bob.eth",
		OwnerUserID: owner.ID, FeedOwnerAddress: "0xfeed0002", DefaultStampBatchID: "batch-1",
	}, nil, "")
	if err != nil {
		t.Fatalf("create registry B: %v", err)
	}
	encB, err := cipher.EncryptWith(2, regB.ID, "0xfeed0002", []byte(ptB))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.ExecContext(ctx, `update registries set feed_key_ciphertext = ?, feed_key_nonce = ?, feed_key_version = ? where id = ?`,
		encB.Ciphertext, encB.Nonce, encB.KeyVersion, regB.ID); err != nil {
		t.Fatalf("set B at version 2: %v", err)
	}
	var bCiphertextBefore []byte
	if err := store.DB.QueryRowContext(ctx, `select feed_key_ciphertext from registries where id = ?`, regB.ID).Scan(&bCiphertextBefore); err != nil {
		t.Fatalf("read B ciphertext: %v", err)
	}

	res, err := service.ReencryptFeedKeys(ctx, 1, 2)
	if err != nil {
		t.Fatalf("re-encrypt: %v", err)
	}
	if res.Reencrypted != 1 || res.Skipped != 1 {
		t.Fatalf("expected 1 re-encrypted and 1 skipped, got %+v", res)
	}

	// A: version 2 now, same plaintext, owner preserved.
	var aVersion int64
	if err := store.DB.QueryRowContext(ctx, `select feed_key_version from registries where id = ?`, regA.ID).Scan(&aVersion); err != nil {
		t.Fatalf("read A version: %v", err)
	}
	if aVersion != 2 {
		t.Fatalf("A must be at version 2, got %d", aVersion)
	}
	fetchedA, err := store.FindRegistryByID(ctx, regA.ID)
	if err != nil {
		t.Fatal(err)
	}
	if fetchedA.FeedOwnerAddress != "0xfeed0001" {
		t.Fatalf("owner must be preserved, got %q", fetchedA.FeedOwnerAddress)
	}
	gotA, err := cipher.Decrypt(fetchedA.ID, fetchedA.FeedOwnerAddress, fetchedA.FeedKey)
	if err != nil {
		t.Fatalf("decrypt rotated A: %v", err)
	}
	if string(gotA) != ptA {
		t.Fatalf("rotated plaintext mismatch: %q", gotA)
	}

	// B: untouched (bytes identical, still version 2, still decryptable).
	var bVersion int64
	var bCiphertextAfter []byte
	if err := store.DB.QueryRowContext(ctx, `select feed_key_version, feed_key_ciphertext from registries where id = ?`, regB.ID).Scan(&bVersion, &bCiphertextAfter); err != nil {
		t.Fatalf("read B after: %v", err)
	}
	if bVersion != 2 || !bytes.Equal(bCiphertextAfter, bCiphertextBefore) {
		t.Fatal("row not at fromVersion must be skipped untouched")
	}
	if _, err := cipher.Decrypt(regB.ID, "0xfeed0002", EncryptedFeedKey{Ciphertext: bCiphertextAfter, Nonce: encB.Nonce, KeyVersion: 2}); err != nil {
		t.Fatalf("B must remain decryptable: %v", err)
	}
}

func TestReencryptFeedKeysRejectsBadArguments(t *testing.T) {
	t.Parallel()
	store, err := OpenSQLite("file:keycrypto_rotateerr?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	ctx := context.Background()
	service := newStoreService(t, store.DB)

	// Cipher missing: fail closed.
	noCipher := &Service{Store: store, RegistryDomain: "uncloud-registry.com"}
	if _, err := noCipher.ReencryptFeedKeys(ctx, 1, 2); !errors.Is(err, errFeedKeyCipherNotConfigured) {
		t.Fatalf("nil cipher: got %v", err)
	}
	// Same version.
	if _, err := service.ReencryptFeedKeys(ctx, 1, 1); err == nil {
		t.Fatal("fromVersion == toVersion must be rejected")
	}
	// Source version not loaded.
	if _, err := service.ReencryptFeedKeys(ctx, 3, 2); err == nil || !strings.Contains(err.Error(), "3") {
		t.Fatalf("unloaded source version must be rejected: %v", err)
	}
	// Target version not loaded.
	if _, err := service.ReencryptFeedKeys(ctx, 1, 3); err == nil || !strings.Contains(err.Error(), "3") {
		t.Fatalf("unloaded target version must be rejected: %v", err)
	}
}

// TestReencryptFeedKeysTamperedRowFailsAndRollsBack pins that a row whose old
// ciphertext fails authentication aborts the rotation with ErrKeyDecrypt and
// leaves that row fully unchanged (per-row transaction rollback).
func TestReencryptFeedKeysTamperedRowFailsAndRollsBack(t *testing.T) {
	t.Parallel()
	store, err := OpenSQLite("file:keycrypto_rotatetamper?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	ctx := context.Background()
	service := newStoreService(t, store.DB)

	owner, err := store.CreateUser(ctx, "alice@example.com", "hash")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	reg, err := store.CreateRegistry(ctx, Registry{
		Slug: "alice", Host: "alice.uncloud-registry.com", ENSName: "alice.eth",
		OwnerUserID: owner.ID, FeedOwnerAddress: "0xfeed0001", DefaultStampBatchID: "batch-1",
	}, service.FeedKeys, testFeedKeyPlaintext())
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}

	var ciphertext []byte
	if err := store.DB.QueryRowContext(ctx, `select feed_key_ciphertext from registries where id = ?`, reg.ID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	ciphertext[0] ^= 0xff
	if _, err := store.DB.ExecContext(ctx, `update registries set feed_key_ciphertext = ? where id = ?`, ciphertext, reg.ID); err != nil {
		t.Fatal(err)
	}

	_, err = service.ReencryptFeedKeys(ctx, 1, 2)
	if !errors.Is(err, ErrKeyDecrypt) {
		t.Fatalf("tampered row must fail authentication: %v", err)
	}

	// The row must be unchanged: still version 1, still the corrupted bytes.
	var version int64
	var after []byte
	if err := store.DB.QueryRowContext(ctx, `select feed_key_version, feed_key_ciphertext from registries where id = ?`, reg.ID).Scan(&version, &after); err != nil {
		t.Fatal(err)
	}
	if version != 1 || !bytes.Equal(after, ciphertext) {
		t.Fatal("tampered row must be left fully unchanged after the failed rotation")
	}
}

func TestReencryptFeedKeysSkipsRowsWithoutKey(t *testing.T) {
	t.Parallel()
	store, err := OpenSQLite("file:keycrypto_rotateskip?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	ctx := context.Background()
	service := newStoreService(t, store.DB)

	owner, err := store.CreateUser(ctx, "alice@example.com", "hash")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	for _, slug := range []string{"alice", "bob"} {
		if _, err := store.CreateRegistry(ctx, Registry{
			Slug: slug, Host: slug + ".uncloud-registry.com", ENSName: slug + ".eth",
			OwnerUserID: owner.ID, FeedOwnerAddress: "0xfeed0001", DefaultStampBatchID: "batch-1",
		}, nil, ""); err != nil {
			t.Fatalf("create registry %s: %v", slug, err)
		}
	}
	res, err := service.ReencryptFeedKeys(ctx, 1, 2)
	if err != nil {
		t.Fatalf("re-encrypt: %v", err)
	}
	if res.Reencrypted != 0 || res.Skipped != 2 {
		t.Fatalf("rows without a stored key must be skipped, got %+v", res)
	}
}

func TestServiceDecryptFeedKeyBoundary(t *testing.T) {
	t.Parallel()
	store, err := OpenSQLite("file:keycrypto_decryptfeed?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	ctx := context.Background()
	service := newStoreService(t, store.DB)

	// No cipher configured: fail closed.
	noCipher := &Service{Store: store, RegistryDomain: "uncloud-registry.com"}
	if _, err := noCipher.DecryptFeedKey(ctx, Registry{ID: 999}); !errors.Is(err, errFeedKeyCipherNotConfigured) {
		t.Fatalf("nil cipher must fail closed: %v", err)
	}

	owner, err := store.CreateUser(ctx, "alice@example.com", "hash")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	plaintext := testFeedKeyPlaintext()
	reg, err := store.CreateRegistry(ctx, Registry{
		Slug: "alice", Host: "alice.uncloud-registry.com", ENSName: "alice.eth",
		OwnerUserID: owner.ID, FeedOwnerAddress: "0xfeed0001", DefaultStampBatchID: "batch-1",
	}, service.FeedKeys, plaintext)
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}

	got, err := service.DecryptFeedKey(ctx, Registry{ID: reg.ID})
	if err != nil {
		t.Fatalf("decrypt feed key: %v", err)
	}
	if got != plaintext {
		t.Fatalf("decrypted key mismatch: %q", got)
	}

	// A registry with no stored key fails closed.
	noKey, err := store.CreateRegistry(ctx, Registry{
		Slug: "bob", Host: "bob.uncloud-registry.com", ENSName: "bob.eth",
		OwnerUserID: owner.ID, FeedOwnerAddress: "0xfeed0002", DefaultStampBatchID: "batch-1",
	}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.DecryptFeedKey(ctx, Registry{ID: noKey.ID}); err == nil {
		t.Fatal("registry without a stored key must fail closed")
	}
}

// TestBeeRegistryFeedUpdaterBoundary pins the publisher boundary: the Bee
// updater must never hand stored ciphertext to the signer. Without a
// configured decryptor it refuses outright; with one, the decryptor's key
// material is what reaches the signer (proven by the signer accepting the
// key and proceeding past parsing to the feed operation).
type stubFeedKeyDecryptor struct {
	key string
	err error
}

func (s stubFeedKeyDecryptor) DecryptFeedKey(_ context.Context, _ Registry) (string, error) {
	return s.key, s.err
}

func TestBeeRegistryFeedUpdaterBoundary(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// No decryptor: refuse, never hand anything to the signer.
	updater := BeeRegistryFeedUpdater{BaseURL: "http://bee.invalid", HTTPClient: nil}
	err := updater.UpdateRegistryFeed(ctx, Registry{ID: 1}, "feed", "ref")
	if err == nil {
		t.Fatal("updater without a decryptor must fail closed")
	}
	if !strings.Contains(err.Error(), "decryptor") {
		t.Fatalf("expected the fail-closed decryptor error, got: %v", err)
	}

	// With a decryptor: the supplied key reaches the signer — the signer
	// parses it (no ciphertext-parse error) and fails on the feed operation.
	updater = BeeRegistryFeedUpdater{
		BaseURL: "http://bee.invalid",
		Keys:    stubFeedKeyDecryptor{key: strings.Repeat("ab", 32)},
	}
	err = updater.UpdateRegistryFeed(ctx, Registry{ID: 1, FeedOwnerAddress: "0xfeed"}, "feed", "ref")
	if err == nil {
		t.Fatal("expected the signer to fail on the unreachable bee endpoint")
	}
	if strings.Contains(err.Error(), "parse feed signer private key") {
		t.Fatalf("the signer must have received the DECRYPTED key, not ciphertext: %v", err)
	}
}
