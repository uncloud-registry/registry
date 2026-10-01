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
		Publisher:      newMemPublisher(),
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
	}, cipher, []byte(plaintext))
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
	}, newTestFeedKeyCipher(t), nil)
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
	service := &Service{Store: store, Tokens: newTestSessionManager(t), RegistryDomain: "uncloud-registry.com", Publisher: newMemPublisher()}
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
	}, cipher, []byte(ptA))
	if err != nil {
		t.Fatalf("create registry A: %v", err)
	}
	// Registry B is ALREADY at version 2 (e.g. a previous rotation pass) — it
	// must be skipped, not downgraded or re-encrypted.
	ptB := "bbbb1111" + strings.Repeat("bb", 20)
	regB, err := store.CreateRegistry(ctx, Registry{
		Slug: "bob", Host: "bob.uncloud-registry.com", ENSName: "bob.eth",
		OwnerUserID: owner.ID, FeedOwnerAddress: "0xfeed0002", DefaultStampBatchID: "batch-1",
	}, nil, nil)
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
	}, service.FeedKeys, []byte(testFeedKeyPlaintext()))
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
		}, nil, nil); err != nil {
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

func TestServiceWithDecryptedFeedKeyBoundary(t *testing.T) {
	t.Parallel()
	store, err := OpenSQLite("file:keycrypto_decryptfeed?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	ctx := context.Background()
	service := newStoreService(t, store.DB)

	// No cipher configured: fail closed before any callback.
	noCipher := &Service{Store: store, RegistryDomain: "uncloud-registry.com"}
	if err := noCipher.WithDecryptedFeedKey(ctx, 999, func([]byte) error { return nil }); !errors.Is(err, errFeedKeyCipherNotConfigured) {
		t.Fatalf("nil cipher must fail closed: %v", err)
	}
	// Nil callback: rejected outright (the decrypted bytes must never be
	// dropped on the floor unhandled).
	if err := service.WithDecryptedFeedKey(ctx, 999, nil); err == nil {
		t.Fatal("nil callback must be rejected")
	}

	owner, err := store.CreateUser(ctx, "alice@example.com", "hash")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	plaintext := testFeedKeyPlaintext()
	reg, err := store.CreateRegistry(ctx, Registry{
		Slug: "alice", Host: "alice.uncloud-registry.com", ENSName: "alice.eth",
		OwnerUserID: owner.ID, FeedOwnerAddress: "0xfeed0001", DefaultStampBatchID: "batch-1",
	}, service.FeedKeys, []byte(plaintext))
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}

	// The callback receives the exact decrypted plaintext bytes.
	var got []byte
	err = service.WithDecryptedFeedKey(ctx, reg.ID, func(key []byte) error {
		got = append(got, key...)
		return nil
	})
	if err != nil {
		t.Fatalf("with decrypted feed key: %v", err)
	}
	if string(got) != plaintext {
		t.Fatalf("decrypted key mismatch: %q", got)
	}

	// A callback error must propagate (it is the operation's error), and the
	// key must still be wiped (defer) — asserted by the wipe test below.
	sentinel := errors.New("callback failure")
	if err := service.WithDecryptedFeedKey(ctx, reg.ID, func([]byte) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("callback error must propagate: %v", err)
	}

	// A registry with no stored key fails closed.
	noKey, err := store.CreateRegistry(ctx, Registry{
		Slug: "bob", Host: "bob.uncloud-registry.com", ENSName: "bob.eth",
		OwnerUserID: owner.ID, FeedOwnerAddress: "0xfeed0002", DefaultStampBatchID: "batch-1",
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.WithDecryptedFeedKey(ctx, noKey.ID, func([]byte) error { return nil }); err == nil {
		t.Fatal("registry without a stored key must fail closed")
	}
}

// TestWithDecryptedFeedKeyWipesAfterCallback pins the plaintext lifecycle
// behaviorally: the service owns the decrypted byte slice, hands it to the
// callback for the immediate operation only, and zeroes the SAME backing
// array before returning. The callback snapshot (a copy made inside fn)
// proves the contents were the plaintext; the test additionally ALIASES the
// slice (borrowed, never copied) and, after WithDecryptedFeedKey returns,
// reading through that alias must observe zeroed bytes. This is an honest
// behavioral assertion on the owned buffer — no claim that unrelated copies
// (which Go does not let us control) are wiped.
func TestWithDecryptedFeedKeyWipesAfterCallback(t *testing.T) {
	t.Parallel()
	store, err := OpenSQLite("file:keycrypto_wipe?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	ctx := context.Background()
	service := newStoreService(t, store.DB)

	owner, err := store.CreateUser(ctx, "alice@example.com", "hash")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	plaintext := testFeedKeyPlaintext()
	reg, err := store.CreateRegistry(ctx, Registry{
		Slug: "alice", Host: "alice.uncloud-registry.com", ENSName: "alice.eth",
		OwnerUserID: owner.ID, FeedOwnerAddress: "0xfeed0001", DefaultStampBatchID: "batch-1",
	}, service.FeedKeys, []byte(plaintext))
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}

	var snapshot []byte
	var borrowed []byte
	err = service.WithDecryptedFeedKey(ctx, reg.ID, func(key []byte) error {
		snapshot = append(snapshot, key...) // copy INSIDE the callback: proves contents
		borrowed = key                      // alias: proves post-call wipe of the same array
		return nil
	})
	if err != nil {
		t.Fatalf("with decrypted feed key: %v", err)
	}
	if string(snapshot) != plaintext {
		t.Fatalf("callback must have seen the plaintext: %q", snapshot)
	}
	for i, b := range borrowed {
		if b != 0 {
			t.Fatalf("owned plaintext buffer not wiped after callback (byte %d = %d)", i, b)
		}
	}

	// The same guarantee holds on the error path.
	snapshot = nil
	borrowed = nil
	err = service.WithDecryptedFeedKey(ctx, reg.ID, func(key []byte) error {
		snapshot = append(snapshot, key...)
		borrowed = key
		return errors.New("boom")
	})
	if err == nil {
		t.Fatal("expected callback error")
	}
	if string(snapshot) != plaintext {
		t.Fatalf("error path callback must have seen the plaintext: %q", snapshot)
	}
	for i, b := range borrowed {
		if b != 0 {
			t.Fatalf("error path left plaintext un-wiped (byte %d = %d)", i, b)
		}
	}
}

// TestStoreCreateRegistryRejectsIncompleteEnvelope pins the store write guard:
// the direct-craft path (FeedKeySet) must refuse an envelope that is not
// exactly all-present with a structurally valid shape — nonce
// feedKeyEnvelopeNonceSize bytes, ciphertext at least
// feedKeyEnvelopeCiphertextMin bytes, positive version — the schema-level
// invariant mirrored at the application boundary.
func TestStoreCreateRegistryRejectsIncompleteEnvelope(t *testing.T) {
	t.Parallel()
	store, err := OpenSQLite("file:keycrypto_envguard?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	ctx := context.Background()
	owner, err := store.CreateUser(ctx, "alice@example.com", "hash")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	base := Registry{
		Slug: "alice", Host: "alice.uncloud-registry.com", ENSName: "alice.eth",
		OwnerUserID: owner.ID, FeedOwnerAddress: "0xfeed0001", DefaultStampBatchID: "batch-1",
	}
	valid := EncryptedFeedKey{Ciphertext: []byte("0123456789abcdef"), Nonce: []byte("0123456789ab"), KeyVersion: 1}
	cases := []struct {
		name  string
		value EncryptedFeedKey
	}{
		{"ciphertext only", EncryptedFeedKey{Ciphertext: valid.Ciphertext}},
		{"nonce only", EncryptedFeedKey{Nonce: valid.Nonce}},
		{"ciphertext and nonce, no version", EncryptedFeedKey{Ciphertext: valid.Ciphertext, Nonce: valid.Nonce}},
		{"ciphertext and version, no nonce", EncryptedFeedKey{Ciphertext: valid.Ciphertext, KeyVersion: 1}},
		{"nonce and version, no ciphertext", EncryptedFeedKey{Nonce: valid.Nonce, KeyVersion: 1}},
		{"zero version", EncryptedFeedKey{Ciphertext: valid.Ciphertext, Nonce: valid.Nonce, KeyVersion: 0}},
		{"negative version", EncryptedFeedKey{Ciphertext: valid.Ciphertext, Nonce: valid.Nonce, KeyVersion: -1}},
		{"empty ciphertext", EncryptedFeedKey{Ciphertext: []byte{}, Nonce: valid.Nonce, KeyVersion: 1}},
		{"empty nonce", EncryptedFeedKey{Ciphertext: valid.Ciphertext, Nonce: []byte{}, KeyVersion: 1}},
		{"short nonce", EncryptedFeedKey{Ciphertext: valid.Ciphertext, Nonce: []byte("0123456789a"), KeyVersion: 1}},
		{"long nonce", EncryptedFeedKey{Ciphertext: valid.Ciphertext, Nonce: []byte("0123456789abc"), KeyVersion: 1}},
		{"short ciphertext", EncryptedFeedKey{Ciphertext: []byte("0123456789abcde"), Nonce: valid.Nonce, KeyVersion: 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := base
			reg.FeedKey = tc.value
			reg.FeedKeySet = true
			if _, err := store.CreateRegistry(ctx, reg, nil, nil); err == nil {
				t.Fatal("malformed envelope must be rejected by the store write guard")
			} else if !errors.Is(err, ErrFeedKeyEnvelopeMalformed) {
				t.Fatalf("expected ErrFeedKeyEnvelopeMalformed, got %v", err)
			}
		})
	}
	// The complete envelope still passes.
	reg := base
	reg.FeedKey = valid
	reg.FeedKeySet = true
	if _, err := store.CreateRegistry(ctx, reg, nil, nil); err != nil {
		t.Fatalf("complete envelope must be accepted: %v", err)
	}
	// A minimally-valid envelope (16-byte ciphertext, empty plaintext shape)
	// is accepted STRUCTURALLY by the write guard.
	reg2 := base
	reg2.Slug = "min"
	reg2.Host = "min.uncloud-registry.com"
	reg2.FeedKey = EncryptedFeedKey{Ciphertext: []byte("0123456789abcdef"), Nonce: []byte("0123456789ab"), KeyVersion: 1}
	reg2.FeedKeySet = true
	if _, err := store.CreateRegistry(ctx, reg2, nil, nil); err != nil {
		t.Fatalf("16-byte-ciphertext envelope must be accepted structurally: %v", err)
	}
}

// TestFeedKeyEnvelopeTriggerEnforcesCompleteness drives the schema-level
// invariant through DIRECT SQL on the migrated schema: the triggers reject
// every partial combination of the three feed-key columns — and every
// complete-but-malformed envelope (nonce not exactly 12 bytes, ciphertext
// shorter than 16 bytes) — on INSERT and UPDATE, while accepting exactly
// all-NULL and all-present with a structurally valid envelope (12-byte nonce,
// >=16-byte ciphertext, positive version).
func TestFeedKeyEnvelopeTriggerEnforcesCompleteness(t *testing.T) {
	t.Parallel()
	store, err := OpenSQLite("file:keycrypto_triggers?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	ctx := context.Background()
	owner, err := store.CreateUser(ctx, "alice@example.com", "hash")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)

	insertCols := `(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key,
		default_stamp_batch_id, anonymous_pull, created_at, feed_key_ciphertext, feed_key_nonce, feed_key_version)`
	insertBase := func(slug string, ct, nonce, ver any) error {
		_, err := store.DB.ExecContext(ctx, `insert into registries `+insertCols+` values (?,?,?,?,?,?,?,?,?,?,?,?)`,
			slug, slug+".uncloud-registry.com", slug+".eth", owner.ID, "0xfeed", "",
			"batch-1", 0, now, ct, nonce, ver)
		return err
	}

	// All NULL: the no-key state, accepted.
	if err := insertBase("nokey", nil, nil, nil); err != nil {
		t.Fatalf("all-NULL envelope must be accepted: %v", err)
	}
	// All present, structurally valid (16-byte ciphertext = empty-plaintext
	// minimum, 12-byte nonce, positive version): accepted.
	ct := []byte("0123456789abcdef")
	nonce := []byte("0123456789ab")
	if err := insertBase("full", ct, nonce, 1); err != nil {
		t.Fatalf("complete envelope must be accepted: %v", err)
	}

	partial := []struct {
		name  string
		ct    any
		nonce any
		ver   any
	}{
		{"version only", nil, nil, 1},
		{"ciphertext only", ct, nil, nil},
		{"nonce only", nil, nonce, nil},
		{"ciphertext and nonce, no version", ct, nonce, nil},
		{"ciphertext and version, no nonce", ct, nil, 1},
		{"nonce and version, no ciphertext", nil, nonce, 1},
		{"zero version", ct, nonce, 0},
		{"negative version", ct, nonce, -1},
		{"empty ciphertext", []byte{}, nonce, 1},
		{"empty nonce", ct, []byte{}, 1},
		{"short nonce", ct, []byte("0123456789a"), 1},
		{"long nonce", ct, []byte("0123456789abc"), 1},
		{"short ciphertext", []byte("0123456789abcde"), nonce, 1},
	}
	for i, tc := range partial {
		if err := insertBase("partial"+strconv.Itoa(i), tc.ct, tc.nonce, tc.ver); err == nil {
			t.Fatalf("%s: malformed envelope INSERT must be rejected by the trigger", tc.name)
		}
	}

	// UPDATE is guarded the same way: a complete row cannot be mutated into a
	// partial envelope, and a partial envelope cannot be written into one.
	if _, err := store.DB.ExecContext(ctx, `update registries set feed_key_version = 1 where host = ?`, "nokey.uncloud-registry.com"); err == nil {
		t.Fatal("UPDATE to a partial envelope must be rejected by the trigger")
	}
	if _, err := store.DB.ExecContext(ctx, `update registries set feed_key_version = null where host = ?`, "full.uncloud-registry.com"); err == nil {
		t.Fatal("UPDATE to a partial envelope must be rejected by the trigger")
	}
	// A complete row cannot be mutated into a complete-but-malformed envelope.
	if _, err := store.DB.ExecContext(ctx, `update registries set feed_key_nonce = ? where host = ?`, []byte("short"), "full.uncloud-registry.com"); err == nil {
		t.Fatal("UPDATE to a short nonce must be rejected by the trigger")
	}
	if _, err := store.DB.ExecContext(ctx, `update registries set feed_key_ciphertext = ? where host = ?`, []byte("short"), "full.uncloud-registry.com"); err == nil {
		t.Fatal("UPDATE to a short ciphertext must be rejected by the trigger")
	}
	// Valid UPDATEs still pass.
	if _, err := store.DB.ExecContext(ctx, `update registries set feed_key_version = 2 where host = ?`, "full.uncloud-registry.com"); err != nil {
		t.Fatalf("valid envelope UPDATE must be accepted: %v", err)
	}
	if _, err := store.DB.ExecContext(ctx, `update registries set feed_key_ciphertext = ?, feed_key_nonce = ? where host = ?`,
		[]byte("0123456789abcdef00"), []byte("0123456789ab"), "full.uncloud-registry.com"); err != nil {
		t.Fatalf("structurally valid envelope UPDATE must be accepted: %v", err)
	}
}

// dropFeedKeyTriggers removes the schema-level envelope triggers so tests can
// seed malformed rows (which the triggers otherwise refuse) and prove the
// application layers — scan/list, migration, rotation — reject them on read.
func dropFeedKeyTriggers(t *testing.T, store *Store) {
	t.Helper()
	for _, name := range []string{"registries_feed_key_complete_insert", "registries_feed_key_complete_update"} {
		if _, err := store.DB.Exec(`drop trigger if exists ` + name); err != nil {
			t.Fatalf("drop trigger %s: %v", name, err)
		}
	}
}

// TestScanRejectsPartialEnvelopes proves every registry read path validates
// the envelope invariant: a row whose three feed-key columns disagree is
// rejected with ErrFeedKeyEnvelopeInconsistent instead of being silently
// scanned (a partial envelope would otherwise be handed to the cipher as a
// plausible-looking or nil-panicking value, or a plaintext-preserving row
// would be skipped as "no key").
func TestScanRejectsPartialEnvelopes(t *testing.T) {
	t.Parallel()
	store, err := OpenSQLite("file:keycrypto_scanpartial?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	ctx := context.Background()
	owner, err := store.CreateUser(ctx, "alice@example.com", "hash")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	dropFeedKeyTriggers(t, store)

	seed := func(slug string, ct, nonce, ver any) {
		if _, err := store.DB.ExecContext(ctx, `insert into registries
			(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at, feed_key_ciphertext, feed_key_nonce, feed_key_version)
			values (?,?,?,?,?,?,?,?,?,?,?,?)`,
			slug, slug+".uncloud-registry.com", slug+".eth", owner.ID, "0xfeed", "",
			"batch-1", 0, now, ct, nonce, ver); err != nil {
			t.Fatalf("seed %s: %v", slug, err)
		}
	}
	seed("veronly", nil, nil, 1)
	seed("ctonly", []byte("0123456789abcdef"), nil, nil)
	seed("nonceonly", nil, []byte("0123456789ab"), nil)
	seed("ctnonce", []byte("0123456789abcdef"), []byte("0123456789ab"), nil)
	seed("emptyct", []byte{}, []byte("0123456789ab"), 1)
	seed("zerover", []byte("0123456789abcdef"), []byte("0123456789ab"), 0)
	// Memberships make every seeded row reachable through the user JOIN (the
	// JOIN query must also exercise scan validation, not silently return zero
	// rows).
	for i := 1; i <= 6; i++ {
		if _, err := store.DB.ExecContext(ctx, `insert into registry_memberships (registry_id, user_id, role, can_pull, can_push, created_at) values (?,?,?,?,?,?)`,
			int64(i), owner.ID, "owner", 1, 1, now); err != nil {
			t.Fatalf("seed membership %d: %v", i, err)
		}
	}

	if _, err := store.ListRegistries(ctx); !errors.Is(err, ErrFeedKeyEnvelopeInconsistent) {
		t.Fatalf("ListRegistries must reject partial envelopes: %v", err)
	}
	if _, err := store.ListRegistriesForUser(ctx, owner.ID); !errors.Is(err, ErrFeedKeyEnvelopeInconsistent) {
		t.Fatalf("ListRegistriesForUser must reject partial envelopes: %v", err)
	}
	if _, err := store.FindRegistryByID(ctx, 1); !errors.Is(err, ErrFeedKeyEnvelopeInconsistent) {
		t.Fatalf("FindRegistryByID must reject partial envelopes: %v", err)
	}
	if _, err := store.FindRegistryByHost(ctx, "veronly.uncloud-registry.com"); !errors.Is(err, ErrFeedKeyEnvelopeInconsistent) {
		t.Fatalf("FindRegistryByHost must reject partial envelopes: %v", err)
	}
}

// TestScanRejectsMalformedCompleteEnvelopes proves every registry read path
// validates the envelope STRUCTURALLY, not just its presence: a row whose
// three columns are all present but carry a nonce of the wrong length or a
// ciphertext below the 16-byte GCM minimum is rejected with
// ErrFeedKeyEnvelopeInconsistent — it is never scanned as a plausible-looking
// key (which would then be handed to the cipher and panic/classify oddly).
func TestScanRejectsMalformedCompleteEnvelopes(t *testing.T) {
	t.Parallel()
	store, err := OpenSQLite("file:keycrypto_scanmalformed?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	ctx := context.Background()
	owner, err := store.CreateUser(ctx, "alice@example.com", "hash")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	dropFeedKeyTriggers(t, store)

	seed := func(slug string, ct, nonce []byte, ver int) {
		if _, err := store.DB.ExecContext(ctx, `insert into registries
			(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at, feed_key_ciphertext, feed_key_nonce, feed_key_version)
			values (?,?,?,?,?,?,?,?,?,?,?,?)`,
			slug, slug+".uncloud-registry.com", slug+".eth", owner.ID, "0xfeed", "",
			"batch-1", 0, now, ct, nonce, ver); err != nil {
			t.Fatalf("seed %s: %v", slug, err)
		}
	}
	// Complete (all three present) but cryptographically malformed envelopes.
	seed("shortnonce", []byte("0123456789abcdef"), []byte("0123456789a"), 1)   // nonce 11 bytes
	seed("longnonce", []byte("0123456789abcdef"), []byte("0123456789abcd"), 1) // nonce 14 bytes
	seed("shortct", []byte("0123456789abcde"), []byte("0123456789ab"), 1)      // ciphertext 15 bytes
	for i := 1; i <= 3; i++ {
		if _, err := store.DB.ExecContext(ctx, `insert into registry_memberships (registry_id, user_id, role, can_pull, can_push, created_at) values (?,?,?,?,?,?)`,
			int64(i), owner.ID, "owner", 1, 1, now); err != nil {
			t.Fatalf("seed membership %d: %v", i, err)
		}
	}

	if _, err := store.ListRegistries(ctx); !errors.Is(err, ErrFeedKeyEnvelopeInconsistent) {
		t.Fatalf("ListRegistries must reject malformed complete envelopes: %v", err)
	}
	if _, err := store.ListRegistriesForUser(ctx, owner.ID); !errors.Is(err, ErrFeedKeyEnvelopeInconsistent) {
		t.Fatalf("ListRegistriesForUser must reject malformed complete envelopes: %v", err)
	}
	if _, err := store.FindRegistryByID(ctx, 1); !errors.Is(err, ErrFeedKeyEnvelopeInconsistent) {
		t.Fatalf("FindRegistryByID must reject malformed complete envelopes: %v", err)
	}
	if _, err := store.FindRegistryByHost(ctx, "shortnonce.uncloud-registry.com"); !errors.Is(err, ErrFeedKeyEnvelopeInconsistent) {
		t.Fatalf("FindRegistryByHost must reject malformed complete envelopes: %v", err)
	}

	// A row whose all-present envelope is structurally VALID (16-byte
	// ciphertext minimum, 12-byte nonce, positive version) scans fine.
	seed("good", []byte("0123456789abcdef"), []byte("0123456789ab"), 1)
	good, err := store.FindRegistryByHost(ctx, "good.uncloud-registry.com")
	if err != nil {
		t.Fatalf("structurally valid envelope must scan: %v", err)
	}
	if !good.FeedKeySet || len(good.FeedKey.Ciphertext) != 16 || len(good.FeedKey.Nonce) != 12 {
		t.Fatalf("valid envelope scanned incorrectly: %+v", good.FeedKey)
	}
}

// TestMigrateLegacyFeedKeysRejectsInconsistentRows pins that the opt-in
// legacy migration rejects (never silently skips) a row whose envelope state
// is partial — such a row must not be left half-encrypted or treated as
// "already migrated".
func TestMigrateLegacyFeedKeysRejectsInconsistentRows(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)
	seedLegacyDB(t, db, now, now, true)
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	store := &Store{DB: db}
	dropFeedKeyTriggers(t, store)
	// Row 1: version set but ciphertext/nonce NULL — partial envelope.
	if _, err := db.ExecContext(ctx, `update registries set feed_key_version = 1 where id = 1`); err != nil {
		t.Fatalf("seed partial row: %v", err)
	}

	service := newStoreService(t, db)
	_, err := service.MigrateLegacyFeedKeys(ctx)
	if !errors.Is(err, ErrFeedKeyEnvelopeInconsistent) {
		t.Fatalf("migration must reject the inconsistent row: %v", err)
	}
	// The row is untouched: legacy plaintext still at rest, partial envelope
	// unchanged.
	var legacy string
	var version sql.NullInt64
	if err := db.QueryRowContext(ctx, `select encrypted_feed_private_key, feed_key_version from registries where id = 1`).Scan(&legacy, &version); err != nil {
		t.Fatal(err)
	}
	if legacy != "ciphertext" || !version.Valid {
		t.Fatalf("inconsistent row must be left fully untouched: legacy=%q version set=%v", legacy, version.Valid)
	}
}

// TestMigrateLegacyFeedKeysRejectsMalformedCompleteEnvelopes pins that the
// opt-in legacy migration rejects a COMPLETE-but-malformed envelope (nonce
// not 12 bytes / ciphertext under 16 bytes) regardless of the legacy
// plaintext or the stored version: such a row is never classified as
// "already encrypted" and skipped, and never re-encrypted from the legacy
// value over a malformed stored shape.
func TestMigrateLegacyFeedKeysRejectsMalformedCompleteEnvelopes(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)
	seedLegacyDB(t, db, now, now, true)
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	store := &Store{DB: db}
	dropFeedKeyTriggers(t, store)

	cases := []struct {
		name       string
		ct         []byte
		nonce      []byte
		ver        int
		withLegacy bool
	}{
		{"short nonce, empty legacy", []byte("0123456789abcdef"), []byte("0123456789a"), 1, false},
		{"long nonce, empty legacy", []byte("0123456789abcdef"), []byte("0123456789abc"), 1, false},
		{"short ciphertext, legacy present", []byte("0123456789abcde"), []byte("0123456789ab"), 1, true},
		{"malformed at stored version 2, legacy empty", []byte("0123456789abcdef"), []byte("short"), 2, false},
	}
	for i, tc := range cases {
		slug := "mal" + strconv.Itoa(i)
		legacyVal := ""
		if tc.withLegacy {
			legacyVal = "ciphertext"
		}
		if _, err := db.ExecContext(ctx, `insert into registries
			(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at, feed_key_ciphertext, feed_key_nonce, feed_key_version)
			values (?,?,?,?,?,?,?,?,?,?,?,?)`,
			slug, slug+".uncloud-registry.com", slug+".eth", 1, "0xfeed", legacyVal,
			"batch-1", 1, now, tc.ct, tc.nonce, tc.ver); err != nil {
			t.Fatalf("seed %s: %v", tc.name, err)
		}
	}

	service := newStoreService(t, db)
	_, err := service.MigrateLegacyFeedKeys(ctx)
	if !errors.Is(err, ErrFeedKeyEnvelopeInconsistent) {
		t.Fatalf("migration must reject malformed complete envelopes: %v", err)
	}
	// Every row must be untouched (legacy plaintext and envelope state).
	for i, tc := range cases {
		slug := "mal" + strconv.Itoa(i)
		var legacy string
		var ctLen, nonceLen int
		var ver sql.NullInt64
		if err := db.QueryRowContext(ctx, `select encrypted_feed_private_key, length(feed_key_ciphertext), length(feed_key_nonce), feed_key_version from registries where slug = ?`, slug).
			Scan(&legacy, &ctLen, &nonceLen, &ver); err != nil {
			t.Fatal(err)
		}
		wantLegacy := ""
		if tc.withLegacy {
			wantLegacy = "ciphertext"
		}
		if legacy != wantLegacy || ctLen != len(tc.ct) || nonceLen != len(tc.nonce) || !ver.Valid || int(ver.Int64) != tc.ver {
			t.Fatalf("%s: row must be left fully untouched: legacy=%q ctLen=%d nonceLen=%d ver=%v", tc.name, legacy, ctLen, nonceLen, ver)
		}
	}
}

// TestMigrateLegacyFeedKeysReencryptsRowWithBothEnvelopeAndLegacy pins that a
// row carrying BOTH a complete envelope and legacy plaintext is re-encrypted
// from the legacy value and cleared — plaintext is never preserved alongside
// an envelope, and the row is never silently skipped.
func TestMigrateLegacyFeedKeysReencryptsRowWithBothEnvelopeAndLegacy(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)
	seedLegacyDB(t, db, now, now, true)
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	store := &Store{DB: db}
	dropFeedKeyTriggers(t, store)
	// Row 1 already "encrypted" (complete shape) but the legacy plaintext was
	// never cleared — the migration must re-encrypt and clear it.
	if _, err := db.ExecContext(ctx, `update registries set
		feed_key_ciphertext = ?, feed_key_nonce = ?, feed_key_version = ? where id = 1`,
		[]byte("0123456789abcdef"), []byte("0123456789ab"), 1); err != nil {
		t.Fatalf("seed envelope+legacy row: %v", err)
	}

	service := newStoreService(t, db)
	migrated, err := service.MigrateLegacyFeedKeys(ctx)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if migrated != 1 {
		t.Fatalf("expected 1 migrated row, got %d", migrated)
	}
	var legacy string
	var ciphertext, nonce []byte
	var version sql.NullInt64
	if err := db.QueryRowContext(ctx, `select encrypted_feed_private_key, feed_key_ciphertext, feed_key_nonce, feed_key_version from registries where id = 1`).Scan(&legacy, &ciphertext, &nonce, &version); err != nil {
		t.Fatal(err)
	}
	if legacy != "" {
		t.Fatalf("legacy plaintext must be cleared, got %q", legacy)
	}
	if len(ciphertext) == 0 || len(nonce) == 0 || !version.Valid {
		t.Fatal("envelope must be present")
	}
	got, err := service.FeedKeys.Decrypt(1, "0xfeed", EncryptedFeedKey{Ciphertext: ciphertext, Nonce: nonce, KeyVersion: int(version.Int64)})
	if err != nil {
		t.Fatalf("decrypt re-encrypted key: %v", err)
	}
	if string(got) != "ciphertext" {
		t.Fatalf("re-encrypted plaintext mismatch: %q", got)
	}
	// Idempotent afterwards.
	migrated, err = service.MigrateLegacyFeedKeys(ctx)
	if err != nil || migrated != 0 {
		t.Fatalf("second migration must be a no-op: migrated=%d err=%v", migrated, err)
	}
}

// TestMigrateLegacyFeedKeysUsesTransactionalOwner pins the stale-owner fix:
// the legacy migration must re-read owner, plaintext, and envelope state
// INSIDE the same per-row transaction and bind the AAD to THAT owner. A
// committed owner change between enumeration and the transactional read must
// be reflected in the resulting ciphertext; the stale enumerated owner must
// not authenticate it. The deterministic hook sits exactly between the two.
func TestMigrateLegacyFeedKeysUsesTransactionalOwner(t *testing.T) {
	db := openRawTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)
	seedLegacyDB(t, db, now, now, true)
	if err := ApplyMigrations(ctx, db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	service := newStoreService(t, db)
	// Between enumeration (IDs only) and the per-row transaction, commit an
	// owner change on a separate connection.
	service.Store.migrateRowHook = func(id int64) {
		if _, err := db.ExecContext(context.Background(), `update registries set feed_owner_address = ? where id = ?`, "0xnewowner", id); err != nil {
			t.Fatalf("hook owner change: %v", err)
		}
	}

	migrated, err := service.MigrateLegacyFeedKeys(ctx)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if migrated != 1 {
		t.Fatalf("expected 1 migrated row, got %d", migrated)
	}

	var owner string
	var ciphertext, nonce []byte
	var version sql.NullInt64
	var legacy string
	if err := db.QueryRowContext(ctx, `select feed_owner_address, encrypted_feed_private_key, feed_key_ciphertext, feed_key_nonce, feed_key_version from registries where id = 1`).Scan(&owner, &legacy, &ciphertext, &nonce, &version); err != nil {
		t.Fatal(err)
	}
	if owner != "0xnewowner" {
		t.Fatalf("owner update must be committed: %q", owner)
	}
	if legacy != "" || !version.Valid {
		t.Fatalf("row must be migrated: legacy=%q version set=%v", legacy, version.Valid)
	}
	env := EncryptedFeedKey{Ciphertext: ciphertext, Nonce: nonce, KeyVersion: int(version.Int64)}
	if _, err := service.FeedKeys.Decrypt(1, "0xnewowner", env); err != nil {
		t.Fatalf("ciphertext must decrypt under the COMMITTED owner: %v", err)
	}
	if _, err := service.FeedKeys.Decrypt(1, "0xfeed", env); !errors.Is(err, ErrKeyDecrypt) {
		t.Fatalf("ciphertext must NOT decrypt under the stale enumerated owner: %v", err)
	}
}

// TestReencryptRegistryFeedKeyRejectsInconsistentRows pins that rotation
// rejects (never silently skips) rows whose envelope is partial: a version
// without ciphertext/nonce, ciphertext/nonce without a version, empty blobs,
// or a non-positive version all abort the row transaction.
func TestReencryptRegistryFeedKeyRejectsInconsistentRows(t *testing.T) {
	t.Parallel()
	store, err := OpenSQLite("file:keycrypto_rotpartial?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	ctx := context.Background()
	service := newStoreService(t, store.DB)
	owner, err := store.CreateUser(ctx, "alice@example.com", "hash")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	dropFeedKeyTriggers(t, store)
	seed := func(slug string, ct, nonce, ver any) int64 {
		res, err := store.DB.ExecContext(ctx, `insert into registries
			(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at, feed_key_ciphertext, feed_key_nonce, feed_key_version)
			values (?,?,?,?,?,?,?,?,?,?,?,?)`,
			slug, slug+".uncloud-registry.com", slug+".eth", owner.ID, "0xfeed", "",
			"batch-1", 0, time.Now().UTC().Format(time.RFC3339), ct, nonce, ver)
		if err != nil {
			t.Fatalf("seed %s: %v", slug, err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	ct := []byte("0123456789abcdef")
	nonce := []byte("0123456789ab")
	rows := map[string]int64{
		"veronly":   seed("veronly", nil, nil, 1),
		"ctonly":    seed("ctonly", ct, nil, nil),
		"nonceonly": seed("nonceonly", nil, nonce, nil),
		"emptyct":   seed("emptyct", []byte{}, nonce, 1),
		"zerover":   seed("zerover", ct, nonce, 0),
	}
	for name, id := range rows {
		_, err := service.Store.ReencryptRegistryFeedKey(ctx, id, 1, 2, service.FeedKeys)
		if !errors.Is(err, ErrFeedKeyEnvelopeInconsistent) {
			t.Fatalf("%s: rotation must reject the inconsistent row: %v", name, err)
		}
	}
	// A no-key row (all NULL) is still skipped, not rejected.
	noKey := seed("nokey", nil, nil, nil)
	ok, err := service.Store.ReencryptRegistryFeedKey(ctx, noKey, 1, 2, service.FeedKeys)
	if err != nil || ok {
		t.Fatalf("all-NULL row must be skipped: ok=%v err=%v", ok, err)
	}
}

// TestReencryptFeedKeysFailsOnPartialRow pins the service-level rotation: an
// inconsistent row fails the whole pass with the envelope sentinel — it is
// never silently skipped.
func TestReencryptFeedKeysFailsOnPartialRow(t *testing.T) {
	t.Parallel()
	store, err := OpenSQLite("file:keycrypto_rotfail?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	ctx := context.Background()
	service := newStoreService(t, store.DB)
	owner, err := store.CreateUser(ctx, "alice@example.com", "hash")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	dropFeedKeyTriggers(t, store)
	if _, err := store.DB.ExecContext(ctx, `insert into registries
		(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at, feed_key_version)
		values (?,?,?,?,?,?,?,?,?,?)`,
		"partial", "partial.uncloud-registry.com", "partial.eth", owner.ID, "0xfeed", "",
		"batch-1", 0, time.Now().UTC().Format(time.RFC3339), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReencryptFeedKeys(ctx, 1, 2); !errors.Is(err, ErrFeedKeyEnvelopeInconsistent) {
		t.Fatalf("rotation pass must fail on the partial row: %v", err)
	}
}

// TestReencryptRegistryFeedKeyRejectsMalformedCompleteEnvelopes pins that
// rotation validates the envelope STRUCTURALLY before ANY version-based
// decision: a complete-but-malformed envelope (nonce not 12 bytes, ciphertext
// under 16 bytes) is rejected with ErrFeedKeyEnvelopeInconsistent even when
// its stored version differs from fromVersion — the path that previously
// skipped it untouched.
func TestReencryptRegistryFeedKeyRejectsMalformedCompleteEnvelopes(t *testing.T) {
	t.Parallel()
	store, err := OpenSQLite("file:keycrypto_rotmalformed?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	ctx := context.Background()
	service := newStoreService(t, store.DB)
	owner, err := store.CreateUser(ctx, "alice@example.com", "hash")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	dropFeedKeyTriggers(t, store)
	seed := func(slug string, ct, nonce []byte, ver int) int64 {
		res, err := store.DB.ExecContext(ctx, `insert into registries
			(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at, feed_key_ciphertext, feed_key_nonce, feed_key_version)
			values (?,?,?,?,?,?,?,?,?,?,?,?)`,
			slug, slug+".uncloud-registry.com", slug+".eth", owner.ID, "0xfeed", "",
			"batch-1", 0, time.Now().UTC().Format(time.RFC3339), ct, nonce, ver)
		if err != nil {
			t.Fatalf("seed %s: %v", slug, err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	// fromVersion is 1: these rows are stored at version 1 (the would-be
	// decrypt path) and at version 2 (the would-be skip path) — both must be
	// rejected on shape, not skipped/decrypted.
	rows := map[string]int64{
		"shortnonce_at1": seed("shortnonce_at1", []byte("0123456789abcdef"), []byte("0123456789a"), 1),
		"longnonce_at1":  seed("longnonce_at1", []byte("0123456789abcdef"), []byte("0123456789abc"), 1),
		"shortct_at1":    seed("shortct_at1", []byte("0123456789abcde"), []byte("0123456789ab"), 1),
		"shortnonce_at2": seed("shortnonce_at2", []byte("0123456789abcdef"), []byte("0123456789a"), 2),
		"shortct_at2":    seed("shortct_at2", []byte("0123456789abcde"), []byte("0123456789ab"), 2),
	}
	for name, id := range rows {
		_, err := service.Store.ReencryptRegistryFeedKey(ctx, id, 1, 2, service.FeedKeys)
		if !errors.Is(err, ErrFeedKeyEnvelopeInconsistent) {
			t.Fatalf("%s: rotation must reject the malformed complete envelope (before any version skip): %v", name, err)
		}
	}
	// The row is left untouched (rollback).
	var version int64
	var ctLen, nonceLen int
	if err := store.DB.QueryRowContext(ctx, `select feed_key_version, length(feed_key_ciphertext), length(feed_key_nonce) from registries where id = ?`, rows["shortct_at2"]).
		Scan(&version, &ctLen, &nonceLen); err != nil {
		t.Fatal(err)
	}
	if version != 2 || ctLen != 15 || nonceLen != 12 {
		t.Fatalf("malformed row must be left untouched after rejection: version=%d ctLen=%d nonceLen=%d", version, ctLen, nonceLen)
	}
	// A structurally VALID row at version 2 (stored != fromVersion 1) is
	// still skipped untouched, not rejected.
	validRes, err := store.DB.ExecContext(ctx, `insert into registries
		(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at, feed_key_ciphertext, feed_key_nonce, feed_key_version)
		values (?,?,?,?,?,?,?,?,?,?,?,?)`,
		"validat2", "validat2.uncloud-registry.com", "validat2.eth", owner.ID, "0xfeed", "",
		"batch-1", 0, time.Now().UTC().Format(time.RFC3339), []byte("0123456789abcdef"), []byte("0123456789ab"), 2)
	if err != nil {
		t.Fatal(err)
	}
	validID, _ := validRes.LastInsertId()
	ok, err := service.Store.ReencryptRegistryFeedKey(ctx, validID, 1, 2, service.FeedKeys)
	if err != nil || ok {
		t.Fatalf("structurally valid row not at fromVersion must be skipped: ok=%v err=%v", ok, err)
	}
}

// TestReencryptFeedKeysFailsOnMalformedRow pins the service-level rotation
// against a complete-but-malformed envelope whose stored version DIFFERS from
// fromVersion: the pass must fail with the envelope sentinel instead of
// skipping the malformed row untouched.
func TestReencryptFeedKeysFailsOnMalformedRow(t *testing.T) {
	t.Parallel()
	store, err := OpenSQLite("file:keycrypto_rotfailmalformed?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	ctx := context.Background()
	service := newStoreService(t, store.DB)
	owner, err := store.CreateUser(ctx, "alice@example.com", "hash")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	dropFeedKeyTriggers(t, store)
	// Stored version 2 != fromVersion 1 with a malformed (short-nonce)
	// envelope: rotation must REJECT, not skip.
	if _, err := store.DB.ExecContext(ctx, `insert into registries
		(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at, feed_key_ciphertext, feed_key_nonce, feed_key_version)
		values (?,?,?,?,?,?,?,?,?,?,?,?)`,
		"malformedv2", "malformedv2.uncloud-registry.com", "malformedv2.eth", owner.ID, "0xfeed", "",
		"batch-1", 0, time.Now().UTC().Format(time.RFC3339), []byte("0123456789abcdef"), []byte("short"), 2); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReencryptFeedKeys(ctx, 1, 2); !errors.Is(err, ErrFeedKeyEnvelopeInconsistent) {
		t.Fatalf("rotation pass must fail on the malformed row even at a different version: %v", err)
	}
}

// TestBeeRegistryFeedUpdaterBoundary pins the publisher boundary: the Bee
// updater must never hand stored ciphertext to the signer. Without a
// configured decryptor it refuses outright; with one, the decryptor's raw
// key BYTES reach the signer (proven by the signer accepting the bytes and
// proceeding past key parsing to the feed operation).
type stubFeedKeyDecryptor struct {
	key []byte
	err error
}

func (s stubFeedKeyDecryptor) WithDecryptedFeedKey(_ context.Context, _ int64, fn func([]byte) error) error {
	if s.err != nil {
		return s.err
	}
	return fn(s.key)
}

func TestBeeRegistryFeedUpdaterBoundary(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// Canonical values so the signer reaches the OWNER check (never a
	// validation failure): the ref/batch are 64-hex and the feed owner is
	// canonical 40-hex but does not match the arbitrary test key's owner.
	canonicalFeed := "feed://1111111111111111111111111111111111111111/" + strings.Repeat("ab", 32)
	hexRef := strings.Repeat("ab", 32)
	hexBatch := strings.Repeat("cd", 32)
	// No decryptor: refuse, never hand anything to the signer.
	updater := BeeRegistryFeedUpdater{BaseURL: "http://bee.invalid", HTTPClient: nil}
	err := updater.UpdateRegistryFeed(ctx, Registry{ID: 1}, canonicalFeed, hexRef, hexBatch, false)
	if err == nil {
		t.Fatal("updater without a decryptor must fail closed")
	}
	if !strings.Contains(err.Error(), "decryptor") {
		t.Fatalf("expected the fail-closed decryptor error, got: %v", err)
	}

	// With a decryptor: the supplied 32-byte key reaches the signer — the
	// signer parses it (no byte-parse error) and fails on the feed operation
	// (owner mismatch with the arbitrary test key).
	key := bytes.Repeat([]byte{0x11}, 32)
	updater = BeeRegistryFeedUpdater{
		BaseURL: "http://bee.invalid",
		Keys:    stubFeedKeyDecryptor{key: key},
	}
	err = updater.UpdateRegistryFeed(ctx, Registry{ID: 1, FeedOwnerAddress: "0xfeed"}, canonicalFeed, hexRef, hexBatch, false)
	if err == nil {
		t.Fatal("expected the signer to fail on the unreachable bee endpoint")
	}
	if strings.Contains(err.Error(), "parse feed signer private key") {
		t.Fatalf("the signer must have received the DECRYPTED bytes, not garbage/ciphertext: %v", err)
	}
	// The decryptor's error propagates untouched.
	decErr := errors.New("decryptor failure")
	updater.Keys = stubFeedKeyDecryptor{err: decErr}
	if err := updater.UpdateRegistryFeed(ctx, Registry{ID: 1}, canonicalFeed, hexRef, hexBatch, false); !errors.Is(err, decErr) {
		t.Fatalf("decryptor error must propagate: %v", err)
	}
}
