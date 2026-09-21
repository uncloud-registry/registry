package controlplane

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	DB *sql.DB
}

type User struct {
	ID           int64
	Email        string
	PasswordHash string
	CreatedAt    time.Time
}

// Registry is the persistence record for a registry. Feed-owner signing key
// material is stored ONLY in encrypted form: FeedKey carries the AES-GCM
// envelope (ciphertext/nonce/version) and FeedKeySet reports whether a key is
// present. There is deliberately no plaintext field on this struct — CreateRegistry
// takes plaintext only transiently and the cipher encrypts it inside the
// insert transaction (see CreateRegistry). The legacy encrypted_feed_private_key
// column is never read or written by any store path other than the
// opt-in-gated legacy migration.
type Registry struct {
	ID                  int64
	Slug                string
	Host                string
	ENSName             string
	OwnerUserID         int64
	FeedOwnerAddress    string
	FeedKey             EncryptedFeedKey
	FeedKeySet          bool
	DefaultStampBatchID string
	AnonymousPull       bool
	CreatedAt           time.Time
}

type Membership struct {
	ID         int64
	RegistryID int64
	UserID     int64
	Email      string
	Role       string
	CanPull    bool
	CanPush    bool
	CreatedAt  time.Time
}

type Invite struct {
	ID         int64
	RegistryID int64
	Email      string
	Role       string
	CanPull    bool
	CanPush    bool
	TokenHash  string
	Status     string
	ExpiresAt  time.Time
	CreatedAt  time.Time
}

func OpenSQLite(path string) (*Store, error) {
	db, err := sql.Open("sqlite", withForeignKeys(path))
	if err != nil {
		return nil, err
	}
	store := &Store{DB: db}
	if err := ApplyMigrations(context.Background(), db); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *Store) CreateUser(ctx context.Context, email string, passwordHash string) (User, error) {
	now := time.Now().UTC()
	result, err := s.DB.ExecContext(ctx, `insert into users (email, password_hash, created_at) values (?, ?, ?)`, strings.ToLower(email), passwordHash, now.Format(time.RFC3339))
	if err != nil {
		return User{}, err
	}
	id, _ := result.LastInsertId()
	return User{ID: id, Email: strings.ToLower(email), PasswordHash: passwordHash, CreatedAt: now}, nil
}

func (s *Store) FindUserByEmail(ctx context.Context, email string) (User, error) {
	var user User
	var createdAt string
	err := s.DB.QueryRowContext(ctx, `select id, email, password_hash, created_at from users where email = ?`, strings.ToLower(email)).
		Scan(&user.ID, &user.Email, &user.PasswordHash, &createdAt)
	if err != nil {
		return User{}, err
	}
	user.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return user, nil
}

// registryColumns is the canonical read column list for registries; it reads
// ONLY the encrypted feed-key columns and never the legacy plaintext column.
const registryColumns = `id, slug, host, ens_name, owner_user_id, feed_owner_address,
	feed_key_ciphertext, feed_key_nonce, feed_key_version,
	default_stamp_batch_id, anonymous_pull, created_at`

// scanRow is satisfied by *sql.Row and *sql.Rows.
type scanRow interface {
	Scan(dest ...any) error
}

// scanRegistryRow scans the canonical registry column list into reg,
// materializing the encrypted feed-key envelope (FeedKeySet reflects whether
// a version is stored).
func scanRegistryRow(s scanRow, reg *Registry) error {
	var createdAt string
	var anonymous int
	var ciphertext, nonce []byte
	var version sql.NullInt64
	if err := s.Scan(&reg.ID, &reg.Slug, &reg.Host, &reg.ENSName, &reg.OwnerUserID, &reg.FeedOwnerAddress,
		&ciphertext, &nonce, &version, &reg.DefaultStampBatchID, &anonymous, &createdAt); err != nil {
		return err
	}
	reg.FeedKey = EncryptedFeedKey{Ciphertext: ciphertext, Nonce: nonce, KeyVersion: int(version.Int64)}
	reg.FeedKeySet = version.Valid
	reg.AnonymousPull = anonymous == 1
	reg.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return nil
}

// CreateRegistry inserts a new registry row. When keyCipher is non-nil, the
// row is inserted with empty key columns and feedKeyHex (the hex-encoded
// signing key material) is encrypted inside the SAME transaction with the
// row's own ID and owner as AES-GCM AAD, so a created registry can never
// exist without its encrypted key and the envelope is bound to the row from
// birth. When keyCipher is nil, registry.FeedKey is persisted verbatim if
// FeedKeySet (test-only crafting); no plaintext is ever written to the
// database.
func (s *Store) CreateRegistry(ctx context.Context, registry Registry, keyCipher *FeedKeyCipher, feedKeyHex string) (Registry, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Registry{}, err
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, `insert into registries
		(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at)
		values (?, ?, ?, ?, ?, '', ?, ?, ?)`,
		registry.Slug, registry.Host, registry.ENSName, registry.OwnerUserID, registry.FeedOwnerAddress, registry.DefaultStampBatchID, boolToInt(registry.AnonymousPull), now.Format(time.RFC3339))
	if err != nil {
		return Registry{}, err
	}
	id, _ := result.LastInsertId()

	switch {
	case keyCipher != nil:
		if feedKeyHex == "" {
			return Registry{}, errors.New("create registry: feed key plaintext is required when a cipher is configured")
		}
		enc, err := keyCipher.Encrypt(id, registry.FeedOwnerAddress, []byte(feedKeyHex))
		if err != nil {
			return Registry{}, err
		}
		if _, err := tx.ExecContext(ctx, `update registries set feed_key_ciphertext = ?, feed_key_nonce = ?, feed_key_version = ? where id = ?`,
			enc.Ciphertext, enc.Nonce, enc.KeyVersion, id); err != nil {
			return Registry{}, err
		}
		registry.FeedKey = enc
		registry.FeedKeySet = true
	case registry.FeedKeySet:
		if _, err := tx.ExecContext(ctx, `update registries set feed_key_ciphertext = ?, feed_key_nonce = ?, feed_key_version = ? where id = ?`,
			registry.FeedKey.Ciphertext, registry.FeedKey.Nonce, registry.FeedKey.KeyVersion, id); err != nil {
			return Registry{}, err
		}
	default:
		// No key material: the row keeps NULL key columns.
	}

	if err := tx.Commit(); err != nil {
		return Registry{}, err
	}
	registry.ID = id
	registry.CreatedAt = now
	return registry, nil
}

func (s *Store) CreateMembership(ctx context.Context, membership Membership) (Membership, error) {
	now := time.Now().UTC()
	result, err := s.DB.ExecContext(ctx, `insert into registry_memberships (registry_id, user_id, role, can_pull, can_push, created_at) values (?, ?, ?, ?, ?, ?)`,
		membership.RegistryID, membership.UserID, membership.Role, boolToInt(membership.CanPull), boolToInt(membership.CanPush), now.Format(time.RFC3339))
	if err != nil {
		return Membership{}, err
	}
	id, _ := result.LastInsertId()
	membership.ID = id
	membership.CreatedAt = now
	return membership, nil
}

func (s *Store) ListRegistriesForUser(ctx context.Context, userID int64) ([]Registry, error) {
	// Explicit per-column prefix: the JOIN makes bare column names ambiguous
	// (both tables carry created_at), so registryColumns is not reused here.
	rows, err := s.DB.QueryContext(ctx, `
		select r.id, r.slug, r.host, r.ens_name, r.owner_user_id, r.feed_owner_address,
			r.feed_key_ciphertext, r.feed_key_nonce, r.feed_key_version,
			r.default_stamp_batch_id, r.anonymous_pull, r.created_at
		from registries r
		join registry_memberships m on m.registry_id = r.id
		where m.user_id = ?
		order by r.id asc`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var registries []Registry
	for rows.Next() {
		var registry Registry
		if err := scanRegistryRow(rows, &registry); err != nil {
			return nil, err
		}
		registries = append(registries, registry)
	}
	return registries, rows.Err()
}

func (s *Store) ListRegistries(ctx context.Context) ([]Registry, error) {
	rows, err := s.DB.QueryContext(ctx, `select `+registryColumns+` from registries order by id asc`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var registries []Registry
	for rows.Next() {
		var registry Registry
		if err := scanRegistryRow(rows, &registry); err != nil {
			return nil, err
		}
		registries = append(registries, registry)
	}
	return registries, rows.Err()
}

func (s *Store) FindRegistryByID(ctx context.Context, registryID int64) (Registry, error) {
	var registry Registry
	err := scanRegistryRow(s.DB.QueryRowContext(ctx, `select `+registryColumns+` from registries where id = ?`, registryID), &registry)
	if err != nil {
		return Registry{}, err
	}
	return registry, nil
}

func (s *Store) FindRegistryByHost(ctx context.Context, host string) (Registry, error) {
	var registry Registry
	err := scanRegistryRow(s.DB.QueryRowContext(ctx, `select `+registryColumns+` from registries where host = ?`, host), &registry)
	if err != nil {
		return Registry{}, err
	}
	return registry, nil
}

func (s *Store) UpdateRegistrySettings(ctx context.Context, registryID int64, anonymousPull bool, defaultStampBatchID string) (Registry, error) {
	_, err := s.DB.ExecContext(ctx, `update registries set anonymous_pull = ?, default_stamp_batch_id = ? where id = ?`,
		boolToInt(anonymousPull), defaultStampBatchID, registryID)
	if err != nil {
		return Registry{}, err
	}
	return s.FindRegistryByID(ctx, registryID)
}

func (s *Store) FindMembership(ctx context.Context, registryID int64, userID int64) (Membership, error) {
	var membership Membership
	var createdAt string
	var canPull, canPush int
	err := s.DB.QueryRowContext(ctx, `select id, registry_id, user_id, role, can_pull, can_push, created_at from registry_memberships where registry_id = ? and user_id = ?`, registryID, userID).
		Scan(&membership.ID, &membership.RegistryID, &membership.UserID, &membership.Role, &canPull, &canPush, &createdAt)
	if err != nil {
		return Membership{}, err
	}
	membership.CanPull = canPull == 1
	membership.CanPush = canPush == 1
	membership.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return membership, nil
}

func (s *Store) ListMembershipsForRegistry(ctx context.Context, registryID int64) ([]Membership, error) {
	rows, err := s.DB.QueryContext(ctx, `
		select m.id, m.registry_id, m.user_id, coalesce(u.email, ''), m.role, m.can_pull, m.can_push, m.created_at
		from registry_memberships m
		left join users u on u.id = m.user_id
		where m.registry_id = ?
		order by m.id asc`, registryID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var memberships []Membership
	for rows.Next() {
		var membership Membership
		var createdAt string
		var canPull, canPush int
		if err := rows.Scan(&membership.ID, &membership.RegistryID, &membership.UserID, &membership.Email, &membership.Role, &canPull, &canPush, &createdAt); err != nil {
			return nil, err
		}
		membership.CanPull = canPull == 1
		membership.CanPush = canPush == 1
		membership.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		memberships = append(memberships, membership)
	}
	return memberships, rows.Err()
}

func (s *Store) ListInvitesForRegistry(ctx context.Context, registryID int64) ([]Invite, error) {
	rows, err := s.DB.QueryContext(ctx, `select id, registry_id, email, role, can_pull, can_push, token_hash, status, expires_at, created_at from registry_invites where registry_id = ? order by id desc`, registryID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var invites []Invite
	for rows.Next() {
		var invite Invite
		var createdAt, expiresAt string
		var canPull, canPush int
		if err := rows.Scan(&invite.ID, &invite.RegistryID, &invite.Email, &invite.Role, &canPull, &canPush, &invite.TokenHash, &invite.Status, &expiresAt, &createdAt); err != nil {
			return nil, err
		}
		invite.CanPull = canPull == 1
		invite.CanPush = canPush == 1
		invite.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		invite.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
		invites = append(invites, invite)
	}
	return invites, rows.Err()
}

func (s *Store) CreateInvite(ctx context.Context, invite Invite) (Invite, string, error) {
	now := time.Now().UTC()
	token, tokenHash, err := makeInviteToken()
	if err != nil {
		return Invite{}, "", err
	}
	result, err := s.DB.ExecContext(ctx, `insert into registry_invites (registry_id, email, role, can_pull, can_push, token_hash, status, expires_at, created_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		invite.RegistryID, strings.ToLower(invite.Email), invite.Role, boolToInt(invite.CanPull), boolToInt(invite.CanPush), tokenHash, "pending", invite.ExpiresAt.Format(time.RFC3339), now.Format(time.RFC3339))
	if err != nil {
		return Invite{}, "", err
	}
	id, _ := result.LastInsertId()
	invite.ID = id
	invite.Email = strings.ToLower(invite.Email)
	invite.TokenHash = tokenHash
	invite.Status = "pending"
	invite.CreatedAt = now
	return invite, token, nil
}

func (s *Store) AcceptInvite(ctx context.Context, token string, userID int64) (Invite, error) {
	tokenHash := hashInviteToken(token)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Invite{}, err
	}
	defer tx.Rollback()

	var invite Invite
	var createdAt, expiresAt string
	var canPull, canPush int
	err = tx.QueryRowContext(ctx, `select id, registry_id, email, role, can_pull, can_push, token_hash, status, expires_at, created_at from registry_invites where token_hash = ?`, tokenHash).
		Scan(&invite.ID, &invite.RegistryID, &invite.Email, &invite.Role, &canPull, &canPush, &invite.TokenHash, &invite.Status, &expiresAt, &createdAt)
	if err != nil {
		return Invite{}, err
	}
	invite.CanPull = canPull == 1
	invite.CanPush = canPush == 1
	invite.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	invite.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
	if invite.ExpiresAt.Before(time.Now().UTC()) {
		return Invite{}, errors.New("invite is not valid")
	}
	if invite.Status == "accepted" {
		var existingID int64
		err = tx.QueryRowContext(ctx, `select id from registry_memberships where registry_id = ? and user_id = ?`, invite.RegistryID, userID).Scan(&existingID)
		if err != nil {
			if err == sql.ErrNoRows {
				return Invite{}, errors.New("invite is not valid")
			}
			return Invite{}, err
		}
		if err := tx.Commit(); err != nil {
			return Invite{}, err
		}
		return invite, nil
	}
	if invite.Status != "pending" {
		return Invite{}, errors.New("invite is not valid")
	}

	var existingID int64
	err = tx.QueryRowContext(ctx, `select id from registry_memberships where registry_id = ? and user_id = ?`, invite.RegistryID, userID).Scan(&existingID)
	switch {
	case err == nil:
	case err == sql.ErrNoRows:
		if _, err := tx.ExecContext(ctx, `insert into registry_memberships (registry_id, user_id, role, can_pull, can_push, created_at) values (?, ?, ?, ?, ?, ?)`,
			invite.RegistryID, userID, invite.Role, boolToInt(invite.CanPull), boolToInt(invite.CanPush), time.Now().UTC().Format(time.RFC3339)); err != nil {
			return Invite{}, err
		}
	default:
		return Invite{}, err
	}
	if _, err := tx.ExecContext(ctx, `update registry_invites set status = ? where id = ?`, "accepted", invite.ID); err != nil {
		return Invite{}, err
	}
	if err := tx.Commit(); err != nil {
		return Invite{}, err
	}
	invite.Status = "accepted"
	return invite, nil
}

func (s *Store) FindInviteByToken(ctx context.Context, token string) (Invite, error) {
	tokenHash := hashInviteToken(token)
	var invite Invite
	var createdAt, expiresAt string
	var canPull, canPush int
	err := s.DB.QueryRowContext(ctx, `select id, registry_id, email, role, can_pull, can_push, token_hash, status, expires_at, created_at from registry_invites where token_hash = ?`, tokenHash).
		Scan(&invite.ID, &invite.RegistryID, &invite.Email, &invite.Role, &canPull, &canPush, &invite.TokenHash, &invite.Status, &expiresAt, &createdAt)
	if err != nil {
		return Invite{}, err
	}
	invite.CanPull = canPull == 1
	invite.CanPush = canPush == 1
	invite.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	invite.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
	return invite, nil
}

func (s *Store) UpdateMembershipPermissions(ctx context.Context, registryID int64, updates []Membership) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, membership := range updates {
		if _, err := tx.ExecContext(ctx, `update registry_memberships set can_pull = ?, can_push = ? where registry_id = ? and user_id = ?`,
			boolToInt(membership.CanPull), boolToInt(membership.CanPush), registryID, membership.UserID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// legacyFeedKeyRow is the migration-only read shape. It is the ONLY place the
// legacy encrypted_feed_private_key column is ever selected, and the caller
// (MigrateLegacyFeedKeys) is only reachable when the operator explicitly opts
// in (CONTROLPLANE_MIGRATE_LEGACY_KEYS=true).
type legacyFeedKeyRow struct {
	ID         int64
	Owner      string
	LegacyKey  string
	KeyVersion sql.NullInt64
}

// ListLegacyFeedKeyRows reads every registry's legacy plaintext feed key and
// its current encrypted state. MUST only be called from the opt-in-gated
// MigrateLegacyFeedKeys path.
func (s *Store) ListLegacyFeedKeyRows(ctx context.Context) ([]legacyFeedKeyRow, error) {
	rows, err := s.DB.QueryContext(ctx, `select id, feed_owner_address, encrypted_feed_private_key, feed_key_version from registries order by id asc`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []legacyFeedKeyRow
	for rows.Next() {
		var row legacyFeedKeyRow
		if err := rows.Scan(&row.ID, &row.Owner, &row.LegacyKey, &row.KeyVersion); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// MigrateLegacyFeedKeys encrypts every legacy plaintext feed key with the
// row's own ID/owner AAD and clears the plaintext in the same per-row
// transaction. Rows that are already encrypted (version set) or carry no
// legacy plaintext are skipped. A row whose encryption fails rolls back fully
// and aborts the operation; errors never contain key or owner material.
func (s *Store) MigrateLegacyFeedKeys(ctx context.Context, cipher *FeedKeyCipher) (int, error) {
	if cipher == nil {
		return 0, errFeedKeyCipherNotConfigured
	}
	rows, err := s.ListLegacyFeedKeyRows(ctx)
	if err != nil {
		return 0, fmt.Errorf("migrate legacy feed keys: %w", err)
	}
	migrated := 0
	for _, row := range rows {
		ok, err := s.migrateLegacyFeedKey(ctx, row, cipher)
		if err != nil {
			return migrated, err
		}
		if ok {
			migrated++
		}
	}
	return migrated, nil
}

func (s *Store) migrateLegacyFeedKey(ctx context.Context, row legacyFeedKeyRow, cipher *FeedKeyCipher) (bool, error) {
	if row.LegacyKey == "" {
		return false, nil
	}
	if row.KeyVersion.Valid {
		return false, nil // already encrypted; the encrypted state is authoritative
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("migrate legacy feed key: %w", err)
	}
	defer tx.Rollback()

	// Re-read inside the transaction so the plaintext that gets encrypted and
	// the row that gets updated are the same version of the row.
	var legacy string
	var version sql.NullInt64
	if err := tx.QueryRowContext(ctx, `select encrypted_feed_private_key, feed_key_version from registries where id = ?`, row.ID).Scan(&legacy, &version); err != nil {
		return false, fmt.Errorf("migrate legacy feed key: %w", err)
	}
	if legacy == "" || version.Valid {
		return false, tx.Commit()
	}

	enc, err := cipher.Encrypt(row.ID, row.Owner, []byte(legacy))
	if err != nil {
		return false, fmt.Errorf("migrate legacy feed key: %w", err)
	}
	// Ciphertext+nonce+version written and the legacy plaintext cleared in the
	// SAME statement inside the SAME transaction: there is no intermediate
	// state where the row is encrypted but the plaintext still sits at rest.
	if _, err := tx.ExecContext(ctx, `update registries
		set feed_key_ciphertext = ?, feed_key_nonce = ?, feed_key_version = ?, encrypted_feed_private_key = ''
		where id = ?`, enc.Ciphertext, enc.Nonce, enc.KeyVersion, row.ID); err != nil {
		return false, fmt.Errorf("migrate legacy feed key: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("migrate legacy feed key: %w", err)
	}
	return true, nil
}

// ReencryptRegistryFeedKey rotates one registry's feed key from fromVersion to
// toVersion, one row per transaction. The old ciphertext is authenticated with
// the row's OWN current owner/ID context (tampering aborts), the decrypted
// plaintext is re-sealed under the explicitly requested toVersion with the
// same owner, and the row is updated atomically. Returns ok=false when the row
// is skipped (no stored key, or its stored version != fromVersion); a skipped
// row is never touched. The temporary plaintext is zeroed after use.
func (s *Store) ReencryptRegistryFeedKey(ctx context.Context, registryID int64, owner string, fromVersion, toVersion int, cipher *FeedKeyCipher) (bool, error) {
	if cipher == nil {
		return false, errFeedKeyCipherNotConfigured
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var ownerInDB string
	var ciphertext, nonce []byte
	var version sql.NullInt64
	err = tx.QueryRowContext(ctx, `select feed_owner_address, feed_key_ciphertext, feed_key_nonce, feed_key_version from registries where id = ?`, registryID).
		Scan(&ownerInDB, &ciphertext, &nonce, &version)
	if err != nil {
		return false, err
	}
	if !version.Valid {
		return false, tx.Commit() // no stored key: skip
	}
	if int(version.Int64) != fromVersion {
		return false, tx.Commit() // not at fromVersion: skip untouched
	}

	enc := EncryptedFeedKey{Ciphertext: ciphertext, Nonce: nonce, KeyVersion: int(version.Int64)}
	plaintext, err := cipher.Decrypt(registryID, ownerInDB, enc)
	if err != nil {
		return false, fmt.Errorf("re-encrypt feed key for registry %d: %w", registryID, err)
	}
	defer zeroBytes(plaintext)

	out, err := cipher.EncryptWith(toVersion, registryID, ownerInDB, plaintext)
	if err != nil {
		return false, fmt.Errorf("re-encrypt feed key for registry %d: %w", registryID, err)
	}
	if _, err := tx.ExecContext(ctx, `update registries set feed_key_ciphertext = ?, feed_key_nonce = ?, feed_key_version = ? where id = ?`,
		out.Ciphertext, out.Nonce, out.KeyVersion, registryID); err != nil {
		return false, fmt.Errorf("re-encrypt feed key for registry %d: %w", registryID, err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("re-encrypt feed key for registry %d: %w", registryID, err)
	}
	return true, nil
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func makeInviteToken() (string, string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	return token, hashInviteToken(token), nil
}

func hashInviteToken(token string) string {
	return hex.EncodeToString([]byte(token))
}
