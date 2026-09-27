package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	sqlite "modernc.org/sqlite"
)

type Store struct {
	DB *sql.DB
	// migrateRowHook is a TEST-ONLY deterministic hook invoked between legacy
	// row enumeration and each per-row migration transaction, so tests can
	// prove a committed owner/plaintext change is observed transactionally.
	// Production code never sets it.
	migrateRowHook func(id int64)
	// now is a TEST-ONLY injectable clock used by every invite-expiry and
	// revocation timestamp decision (nowUTC). Production code never sets it,
	// so time.Now().UTC() applies everywhere.
	now func() time.Time
}

// nowUTC returns the store's effective current UTC time: the injected test
// clock when set (deterministic expiry-boundary tests), time.Now().UTC()
// otherwise. Every invite lifecycle decision (creation expiry validation,
// acceptance expiry boundary, revocation timestamps) goes through this single
// seam so tests can drive it without parsing ambiguity.
func (s *Store) nowUTC() time.Time {
	if s.now != nil {
		return s.now().UTC()
	}
	return time.Now().UTC()
}

// SQLite result codes used for busy/locked classification (SQLITE_BUSY,
// SQLITE_LOCKED, and the shared-cache table lock variant). See
// modernc.org/sqlite Error.Code().
const (
	sqliteCodeBusy           = 5   // SQLITE_BUSY: database file is locked
	sqliteCodeLocked         = 6   // SQLITE_LOCKED: table in the database is locked
	sqliteCodeLockedShared   = 262 // SQLITE_LOCKED | (1 << 8): shared-cache table lock
	sqliteWriteTxMaxAttempts = 20
)

// isBusyOrLocked reports whether err is a SQLite busy/locked conflict that a
// retried write transaction can overcome. It classifies both the typed
// modernc.org/sqlite *Error (by result code) and wrapped/stringified driver
// errors, so classification never depends on a single error shape.
func isBusyOrLocked(err error) bool {
	if err == nil {
		return false
	}
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() {
		case sqliteCodeBusy, sqliteCodeLocked, sqliteCodeLockedShared:
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "database is locked") ||
		strings.Contains(msg, "sqlite_busy") ||
		strings.Contains(msg, "sqlite_locked")
}

// withWriteTx runs fn inside a SQLite write transaction on ONE pinned
// connection. Unlike a deferred read→write transaction (which can hit
// snapshot and lock-upgrade conflicts under concurrent acceptance/revocation),
// the transaction starts with BEGIN IMMEDIATE so the write lock is acquired up
// front and every statement in fn executes on the same connection.
//
// Busy/locked conflicts (SQLITE_BUSY/SQLITE_LOCKED, incl. the shared-cache
// table-lock variant) retry the COMPLETE transaction — fn is re-run from
// scratch on a fresh connection, no partial writes survive — for a bounded
// number of attempts with a short backoff that respects ctx cancellation.
// Errors are classified without leaking invite state: retryable conflicts are
// absorbed, ctx cancellation is returned as-is, retry exhaustion surfaces the
// underlying busy error, and any other failure is returned unwrapped from fn.
// The connection is closed after every attempt and `rollback` is best-effort
// on failure, so no half-open transaction or borrowed connection leaks.
func (s *Store) withWriteTx(ctx context.Context, fn func(ctx context.Context, c *sql.Conn) error) error {
	const (
		baseBackoff = time.Millisecond
		maxBackoff  = 50 * time.Millisecond
	)
	var attempt int
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		attempt++

		conn, err := s.DB.Conn(ctx)
		if err != nil {
			return err
		}

		if _, err := conn.ExecContext(ctx, `begin immediate`); err != nil {
			_ = conn.Close()
			if !isBusyOrLocked(err) {
				return err
			}
			if attempt >= sqliteWriteTxMaxAttempts {
				return fmt.Errorf("write transaction: %w", err)
			}
			if werr := waitBackoff(ctx, attempt, baseBackoff, maxBackoff); werr != nil {
				return werr
			}
			continue
		}

		fnErr := fn(ctx, conn)
		if fnErr != nil {
			// Best-effort rollback before the pinned connection is closed:
			// the transaction never leaks onto the pool.
			_, _ = conn.ExecContext(context.WithoutCancel(ctx), `rollback`)
			_ = conn.Close()
			if !isBusyOrLocked(fnErr) {
				return fnErr
			}
			if attempt >= sqliteWriteTxMaxAttempts {
				return fmt.Errorf("write transaction: %w", fnErr)
			}
			if werr := waitBackoff(ctx, attempt, baseBackoff, maxBackoff); werr != nil {
				return werr
			}
			continue
		}

		_, commitErr := conn.ExecContext(ctx, `commit`)
		if commitErr != nil {
			// A failed COMMIT leaves the transaction state undefined on this
			// connection; roll back best-effort, close, and re-run fn fully.
			_, _ = conn.ExecContext(context.WithoutCancel(ctx), `rollback`)
			_ = conn.Close()
			if !isBusyOrLocked(commitErr) {
				return fmt.Errorf("commit write transaction: %w", commitErr)
			}
			if attempt >= sqliteWriteTxMaxAttempts {
				return fmt.Errorf("write transaction: %w", commitErr)
			}
			if werr := waitBackoff(ctx, attempt, baseBackoff, maxBackoff); werr != nil {
				return werr
			}
			continue
		}
		_ = conn.Close()
		return nil
	}
}

// waitBackoff sleeps base<<(attempt-1) (capped at max) or returns ctx.Err()
// when the context is cancelled first.
func waitBackoff(ctx context.Context, attempt int, base, max time.Duration) error {
	shift := attempt - 1
	if shift > 16 {
		shift = 16
	}
	d := base << shift
	if d > max {
		d = max
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// execQuerier is the subset of *sql.Tx / *sql.Conn transaction-surface used
// by the write-transaction helpers, so the same body can run against either.
type execQuerier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
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
	// ProvisioningState is the explicit transactional provisioning vocabulary
	// (provisioning|ready|failed). Fresh registrations are born 'provisioning'
	// and reach 'ready' only after both bootstrap jobs complete verified
	// read-back; pre-outbox registries migrate as 'ready'.
	ProvisioningState string
	CreatedAt         time.Time
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

// Invite is the persistence record for a collaborator invite. Only the
// one-way TokenDigest (SHA-256 of the canonical raw token) is ever stored or
// read by this struct: there is deliberately no raw-token field, and no code
// path reconstructs the token from the digest. AcceptedByUserID / AcceptedAt /
// RevokedAt are audit/consistency fields (nullable); status transitions are
// additionally guarded by schema CHECK constraints and triggers (migration 4).
// LegacyUnattributed marks accepted invites migrated from the pre-Task-7
// schema whose historical accepter is unknowable: such rows carry
// accepted_by_user_id NULL, can never be accepted again, and the flag is
// migration-only state (schema triggers reject setting it on live rows).
type Invite struct {
	ID                 int64
	RegistryID         int64
	Email              string
	Role               string
	CanPull            bool
	CanPush            bool
	TokenDigest        []byte
	Status             string
	AcceptedByUserID   *int64
	LegacyUnattributed bool
	ExpiresAt          time.Time
	AcceptedAt         *time.Time
	RevokedAt          *time.Time
	CreatedAt          time.Time
}

// inviteColumns is the canonical read column list for registry_invites.
const inviteColumns = `id, registry_id, email, role, can_pull, can_push, token_digest, status,
	accepted_by_user_id, legacy_unattributed, expires_at, accepted_at, revoked_at, created_at`

// scanInviteRow scans the canonical invite column list into invite. The
// digest is picked up as raw bytes (BLOB); it is never stringified.
func scanInviteRow(s scanRow, invite *Invite) error {
	var (
		canPull, canPush      int
		legacyUnattributed    int
		createdAt, expiresAt  string
		acceptedBy            sql.NullInt64
		acceptedAt, revokedAt sql.NullString
	)
	err := s.Scan(&invite.ID, &invite.RegistryID, &invite.Email, &invite.Role,
		&canPull, &canPush, &invite.TokenDigest, &invite.Status, &acceptedBy,
		&legacyUnattributed, &expiresAt, &acceptedAt, &revokedAt, &createdAt)
	if err != nil {
		return err
	}
	invite.CanPull = canPull == 1
	invite.CanPush = canPush == 1
	invite.LegacyUnattributed = legacyUnattributed == 1
	if acceptedBy.Valid {
		id := acceptedBy.Int64
		invite.AcceptedByUserID = &id
	}
	invite.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	invite.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
	if acceptedAt.Valid {
		if t, err := time.Parse(time.RFC3339, acceptedAt.String); err == nil {
			invite.AcceptedAt = &t
		}
	}
	if revokedAt.Valid {
		if t, err := time.Parse(time.RFC3339, revokedAt.String); err == nil {
			invite.RevokedAt = &t
		}
	}
	return nil
}

func OpenSQLite(path string) (*Store, error) {
	db, err := sql.Open("sqlite", withForeignKeys(path))
	if err != nil {
		return nil, err
	}
	store := &Store{DB: db}
	if err := ApplyMigrations(context.Background(), db); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) CreateUser(ctx context.Context, email string, passwordHash string) (User, error) {
	now := time.Now().UTC()
	// Account identity is the canonical normalized email; the unique index
	// then enforces one account per normalized address.
	email = NormalizeEmail(email)
	result, err := s.DB.ExecContext(ctx, `insert into users (email, password_hash, created_at) values (?, ?, ?)`, email, passwordHash, now.Format(time.RFC3339))
	if err != nil {
		return User{}, err
	}
	id, _ := result.LastInsertId()
	return User{ID: id, Email: email, PasswordHash: passwordHash, CreatedAt: now}, nil
}

func (s *Store) FindUserByEmail(ctx context.Context, email string) (User, error) {
	return s.findUser(ctx, `select id, email, password_hash, created_at from users where email = ?`, NormalizeEmail(email))
}

// FindUserByID loads a user by primary key. Acceptance uses this to load the
// accepting user fresh from the database before binding an invite, so the
// caller-supplied email/role are never trusted.
func (s *Store) FindUserByID(ctx context.Context, userID int64) (User, error) {
	return s.findUser(ctx, `select id, email, password_hash, created_at from users where id = ?`, userID)
}

func (s *Store) findUser(ctx context.Context, query string, arg any) (User, error) {
	var user User
	var createdAt string
	err := s.DB.QueryRowContext(ctx, query, arg).
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
	default_stamp_batch_id, anonymous_pull, provisioning_state, created_at`

// scanRow is satisfied by *sql.Row and *sql.Rows.
type scanRow interface {
	Scan(dest ...any) error
}

// scanRegistryRow scans the canonical registry column list into reg,
// materializing the encrypted feed-key envelope. It also enforces the
// schema-level envelope invariant on READ: the three feed-key columns must be
// either ALL absent or ALL present with a structurally valid envelope — nonce
// exactly feedKeyEnvelopeNonceSize bytes, ciphertext at least
// feedKeyEnvelopeCiphertextMin bytes, strictly positive version. A partial
// envelope (version without ciphertext, ciphertext without version,
// zero-length blobs, non-positive version) or a complete-but-malformed
// envelope (wrong nonce length, ciphertext below the GCM tag minimum) is
// rejected with ErrFeedKeyEnvelopeInconsistent — it is never silently scanned
// as a plausible-looking value or as "no key".
func scanRegistryRow(s scanRow, reg *Registry) error {
	var createdAt string
	var anonymous int
	var ciphertext, nonce []byte
	var version sql.NullInt64
	if err := s.Scan(&reg.ID, &reg.Slug, &reg.Host, &reg.ENSName, &reg.OwnerUserID, &reg.FeedOwnerAddress,
		&ciphertext, &nonce, &version, &reg.DefaultStampBatchID, &anonymous, &reg.ProvisioningState, &createdAt); err != nil {
		return err
	}
	ctSet := len(ciphertext) > 0 // NULL and zero-length blobs are both "absent"
	nonceSet := len(nonce) > 0
	if version.Valid {
		if !ctSet || !nonceSet || version.Int64 <= 0 {
			return ErrFeedKeyEnvelopeInconsistent
		}
		// Complete but cryptographically malformed (wrong nonce/ciphertext
		// lengths): reject like any other inconsistent row — never scanned as
		// a plausible-looking key.
		if err := validateFeedKeyEnvelopeShape(EncryptedFeedKey{Ciphertext: ciphertext, Nonce: nonce, KeyVersion: int(version.Int64)}); err != nil {
			return ErrFeedKeyEnvelopeInconsistent
		}
		reg.FeedKey = EncryptedFeedKey{Ciphertext: ciphertext, Nonce: nonce, KeyVersion: int(version.Int64)}
		reg.FeedKeySet = true
	} else {
		if ctSet || nonceSet {
			return ErrFeedKeyEnvelopeInconsistent
		}
		reg.FeedKeySet = false
	}
	reg.AnonymousPull = anonymous == 1
	reg.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return nil
}

// CreateRegistry inserts a new registry row. When keyCipher is non-nil, the
// row is inserted with empty key columns and feedKey (the raw mutable signing
// key bytes) is encrypted inside the SAME transaction with the row's own ID
// and owner as AES-GCM AAD, so a created registry can never exist without its
// encrypted key and the envelope is bound to the row from birth. feedKey is
// owned by the CALLER (the service wipes it after the call); the plaintext is
// never written to the database. When keyCipher is nil, registry.FeedKey is
// persisted verbatim if FeedKeySet (test-only crafting) after the complete-
// envelope shape guard accepts it; no plaintext is ever written.
func (s *Store) CreateRegistry(ctx context.Context, registry Registry, keyCipher *FeedKeyCipher, feedKey []byte) (Registry, error) {
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
		if len(feedKey) == 0 {
			return Registry{}, errors.New("create registry: feed key plaintext is required when a cipher is configured")
		}
		enc, err := keyCipher.Encrypt(id, registry.FeedOwnerAddress, feedKey)
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
		// The schema-level invariant mirrored at the write boundary: a
		// crafted envelope must be exactly all-present with a structurally
		// valid shape (nonce feedKeyEnvelopeNonceSize bytes, ciphertext at
		// least feedKeyEnvelopeCiphertextMin bytes, positive version) before
		// it can be persisted.
		if err := validateFeedKeyEnvelopeShape(registry.FeedKey); err != nil {
			return Registry{}, fmt.Errorf("create registry: %w", err)
		}
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
			r.default_stamp_batch_id, r.anonymous_pull, r.provisioning_state, r.created_at
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

// UpdateRegistrySettings mutates anonymous_pull / default_stamp_batch_id ONLY
// when the registry is fully provisioned (provisioning_state == ready). The
// guard is a conditional UPDATE inside a BEGIN IMMEDIATE write transaction, so
// it is race-safe relative to the reconciler's final provisioning→ready
// transition: the two coordinators serialize on the SQLite write lock, and if
// the registry is still 'provisioning' (or the reconciler has not yet
// committed ready) the settings row is left untouched — the whole point of
// the gate is that a stale provisioning jobs pass must never later overwrite
// a newer policy published from settings. On rejection nothing is mutated and
// the typed errRegistryNotReady is returned so the caller can map it to a
// clear, safe API/UI response (and its publisher is never invoked). A
// nonexistent registry still returns sql.ErrNoRows exactly as before.
func (s *Store) UpdateRegistrySettings(ctx context.Context, registryID int64, anonymousPull bool, defaultStampBatchID string) (Registry, error) {
	err := s.withWriteTx(ctx, func(ctx context.Context, c *sql.Conn) error {
		res, err := c.ExecContext(ctx, `update registries set anonymous_pull = ?, default_stamp_batch_id = ? where id = ? and provisioning_state = 'ready'`,
			boolToInt(anonymousPull), defaultStampBatchID, registryID)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 1 {
			return nil
		}
		// Nothing changed: either the registry does not exist or it is not
		// ready yet. Distinguish so the two callers get the right story.
		var exists int
		if err := c.QueryRowContext(ctx, `select count(*) from registries where id = ?`, registryID).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			return sql.ErrNoRows
		}
		return errRegistryNotReady
	})
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
	rows, err := s.DB.QueryContext(ctx, `select `+inviteColumns+` from registry_invites where registry_id = ? order by id desc`, registryID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var invites []Invite
	for rows.Next() {
		var invite Invite
		if err := scanInviteRow(rows, &invite); err != nil {
			return nil, err
		}
		invites = append(invites, invite)
	}
	return invites, rows.Err()
}

// CreateInvite persists a new pending invite. Only the one-way SHA-256 digest
// of a fresh canonical raw token is stored; the raw token is returned to the
// caller EXACTLY ONCE. The caller-supplied Invite must already carry the
// normalized recipient email, role, permission flags, and an expiry that is
// strictly in the future and bounded by inviteMaxTTL — all validated here at
// the persistence boundary (expiry is validated against the store clock).
func (s *Store) CreateInvite(ctx context.Context, invite Invite) (Invite, string, error) {
	now := s.nowUTC()
	invite.Email = NormalizeEmail(invite.Email)
	if invite.Email == "" {
		return Invite{}, "", fmt.Errorf("create invite: %w", errInviteRecipientRequired)
	}
	if !invite.CanPull && !invite.CanPush {
		return Invite{}, "", fmt.Errorf("create invite: invite must grant pull or push access")
	}
	if !now.Before(invite.ExpiresAt) {
		return Invite{}, "", fmt.Errorf("create invite: expiry must be in the future")
	}
	if invite.ExpiresAt.After(now.Add(inviteMaxTTL)) {
		return Invite{}, "", fmt.Errorf("create invite: expiry exceeds %s", inviteMaxTTL)
	}
	token, digest, err := NewInviteToken()
	if err != nil {
		return Invite{}, "", err
	}
	result, err := s.DB.ExecContext(ctx, `insert into registry_invites (registry_id, email, role, can_pull, can_push, token_digest, status, expires_at, created_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		invite.RegistryID, invite.Email, invite.Role, boolToInt(invite.CanPull), boolToInt(invite.CanPush), digest, "pending", invite.ExpiresAt.Format(time.RFC3339), now.Format(time.RFC3339))
	if err != nil {
		return Invite{}, "", err
	}
	id, _ := result.LastInsertId()
	invite.ID = id
	invite.TokenDigest = digest
	invite.Status = "pending"
	invite.CreatedAt = now
	return invite, token, nil
}

// AcceptInvite binds a pending invite to the accepting user, atomically, in a
// BEGIN IMMEDIATE write transaction (see withWriteTx) so concurrent
// acceptance/revocation races are serialized on the write lock instead of
// hitting deferred-read upgrade conflicts. The caller-supplied User's identity
// (email/role) is NEVER trusted — the user row is re-loaded by User.ID inside
// the same transaction, the invite is looked up by the one-way digest of the
// CANONICAL raw token (malformed or non-canonical tokens are rejected before
// any hashing or querying), and the normalized stored emails must match.
//
// Decision order: user → invite → recipient binding → status/accepted_by →
// expiry. The status/accepted_by decision PRECEDES the expiry gate: an invite
// already accepted by this same database user with its atomic membership is a
// stable idempotent success even AFTER expiry (expiry only blocks
// pending→accepted); revoked invites and legacy_unattributed invites (whose
// historical accepter is unknowable) never succeed for anyone. The state
// transition is a guarded UPDATE (pending/unrevoked/unexpired → accepted, with
// accepted_by): exactly one concurrent transition wins; a retry by the SAME
// database-loaded user observes the accepted state and its atomic membership
// and returns the same successful Invite (no duplicate membership), while any
// other principal or a terminal state gets the generic failure. Membership is
// merged permission-safely: an existing stronger membership is never
// downgraded (see mergeMembershipTx).
func (s *Store) AcceptInvite(ctx context.Context, rawToken string, accepting User) (Invite, error) {
	canonical, err := ParseInviteToken(rawToken)
	if err != nil {
		return Invite{}, err // malformed/noncanonical: rejected before hashing/querying
	}
	digest := DigestInviteToken(canonical)
	now := s.nowUTC()

	var result Invite
	err = s.withWriteTx(ctx, func(ctx context.Context, c *sql.Conn) error {
		// Load the accepting user fresh by ID; the caller-supplied email is
		// not trusted for the binding comparison.
		var user User
		var createdAt string
		if err := c.QueryRowContext(ctx, `select id, email, password_hash, created_at from users where id = ?`, accepting.ID).
			Scan(&user.ID, &user.Email, &user.PasswordHash, &createdAt); err != nil {
			return errInviteNotFound
		}

		var invite Invite
		if err := scanInviteRow(c.QueryRowContext(ctx, `select `+inviteColumns+` from registry_invites where token_digest = ?`, digest), &invite); err != nil {
			return errInviteNotFound // includes unknown digest: same generic story
		}
		if NormalizeEmail(user.Email) != NormalizeEmail(invite.Email) {
			return errInviteNotFound // wrong recipient
		}

		// Idempotent retry decision BEFORE the expiry gate: an accepted
		// invite retried by its own accepter (with the atomic membership
		// present) is a stable success even past expires_at. Accepted-by-
		// someone-else, legacy_unattributed (accepted_by NULL), and revoked
		// invites NEVER succeed; expiry only blocks pending→accepted.
		if invite.Status == "accepted" {
			if invite.AcceptedByUserID == nil || *invite.AcceptedByUserID != accepting.ID || invite.LegacyUnattributed {
				return errInviteNotFound
			}
			var membershipID int64
			if err := c.QueryRowContext(ctx, `select id from registry_memberships where registry_id = ? and user_id = ?`, invite.RegistryID, accepting.ID).Scan(&membershipID); err != nil {
				return errInviteNotFound // accepted without its membership: anomalous, fail generically
			}
			result = invite
			return nil
		}
		if invite.Status != "pending" {
			return errInviteNotFound // revoked or otherwise terminal
		}
		// Explicit boundary semantics: at expires_at the invite IS expired.
		if !now.Before(invite.ExpiresAt) {
			return errInviteNotFound
		}

		// Claim the transition atomically. Expiry is rechecked in SQL against
		// the same RFC3339-UTC text (lexicographic == chronological) so a
		// race cannot accept an invite that expired mid-flight — including
		// the clock advancing within this very transaction.
		res, err := c.ExecContext(ctx, `update registry_invites
			set status = 'accepted', accepted_by_user_id = ?, accepted_at = ?
			where id = ? and status = 'pending' and revoked_at is null and expires_at > ?`,
			accepting.ID, now.Format(time.RFC3339), invite.ID, now.Format(time.RFC3339))
		if err != nil {
			return err
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if affected == 1 {
			if err := s.mergeMembershipTx(ctx, c, invite.RegistryID, invite.Role, invite.CanPull, invite.CanPush, accepting.ID, now); err != nil {
				return err
			}
			invite.Status = "accepted"
			invite.AcceptedByUserID = &accepting.ID
			result = invite
			return nil
		}

		// The guarded update changed nothing: another transaction transitioned
		// the invite first (or it became expired/revoked). Only an idempotent
		// retry by the SAME user against the accepted invite with its atomic
		// membership can succeed; everything else is the generic failure.
		var reload Invite
		if err := scanInviteRow(c.QueryRowContext(ctx, `select `+inviteColumns+` from registry_invites where id = ?`, invite.ID), &reload); err != nil {
			return errInviteNotFound
		}
		if reload.Status == "accepted" && reload.AcceptedByUserID != nil && *reload.AcceptedByUserID == accepting.ID && !reload.LegacyUnattributed {
			var membershipID int64
			if err := c.QueryRowContext(ctx, `select id from registry_memberships where registry_id = ? and user_id = ?`, reload.RegistryID, accepting.ID).Scan(&membershipID); err != nil {
				return errInviteNotFound // accepted without its membership: anomalous, fail generically
			}
			result = reload
			return nil
		}
		return errInviteNotFound
	})
	if err != nil {
		return Invite{}, err
	}
	return result, nil
}

// mergeMembershipTx inserts or merges the acceptance membership inside the
// acceptance transaction. Permission merge semantics are deliberately
// permission-safe: an invite acceptance must NEVER downgrade an existing
// stronger membership, so the merged membership takes the permission-wise OR
// of the existing row and the invite grant, and a pre-existing owner/admin
// role is preserved (the invite role only applies when the existing role is
// not a senior one).
func (s *Store) mergeMembershipTx(ctx context.Context, q execQuerier, registryID int64, role string, canPull, canPush bool, userID int64, now time.Time) error {
	var existingID int64
	var existingRole string
	var existingPull, existingPush int
	err := q.QueryRowContext(ctx, `select id, role, can_pull, can_push from registry_memberships where registry_id = ? and user_id = ?`, registryID, userID).
		Scan(&existingID, &existingRole, &existingPull, &existingPush)
	switch {
	case err == sql.ErrNoRows:
		_, err := q.ExecContext(ctx, `insert into registry_memberships (registry_id, user_id, role, can_pull, can_push, created_at) values (?, ?, ?, ?, ?, ?)`,
			registryID, userID, role, boolToInt(canPull), boolToInt(canPush), now.Format(time.RFC3339))
		return err
	case err != nil:
		return err
	default:
		mergedRole := existingRole
		if existingRole != "owner" && existingRole != "admin" {
			mergedRole = role
		}
		_, err := q.ExecContext(ctx, `update registry_memberships set role = ?, can_pull = ?, can_push = ? where id = ?`,
			mergedRole, boolToInt(existingPull == 1 || canPull), boolToInt(existingPush == 1 || canPush), existingID)
		return err
	}
}

// RevokeInvite transitions a PENDING invite to revoked atomically (in a
// BEGIN IMMEDIATE write transaction — see withWriteTx) and idempotently for
// repeated revocations of the same invite: only pending invites can be
// revoked; an accepted invite cannot be revoked (terminal) and returns the
// generic failure; an already-revoked invite is reported as a successful
// revocation (no state change, no duplicate). The raw token is never
// consulted and the digest is never exposed.
func (s *Store) RevokeInvite(ctx context.Context, registryID int64, inviteID int64) (Invite, error) {
	now := s.nowUTC()
	var result Invite
	err := s.withWriteTx(ctx, func(ctx context.Context, c *sql.Conn) error {
		res, err := c.ExecContext(ctx, `update registry_invites
			set status = 'revoked', revoked_at = ?
			where id = ? and registry_id = ? and status = 'pending'`,
			now.Format(time.RFC3339), inviteID, registryID)
		if err != nil {
			return err
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if affected == 1 {
			var invite Invite
			if err := scanInviteRow(c.QueryRowContext(ctx, `select `+inviteColumns+` from registry_invites where id = ?`, inviteID), &invite); err != nil {
				return err
			}
			result = invite
			return nil
		}

		// Nothing changed: either the invite does not exist (generic
		// not-found) or it already left pending. Already-revoked is an
		// idempotent success; anything else (accepted) is terminal and cannot
		// be revoked.
		var invite Invite
		if err := scanInviteRow(c.QueryRowContext(ctx, `select `+inviteColumns+` from registry_invites where id = ? and registry_id = ?`, inviteID, registryID), &invite); err != nil {
			return errInviteNotFound
		}
		if invite.Status == "revoked" {
			result = invite
			return nil
		}
		return errInviteCannotRevoke
	})
	if err != nil {
		return Invite{}, err
	}
	return result, nil
}

// FindInviteByDigest looks up an invite by the one-way digest of a canonical
// token. It returns the generic errInviteNotFound for unknown digests. The
// digest itself is never exposed by callers.
func (s *Store) FindInviteByDigest(ctx context.Context, digest []byte) (Invite, error) {
	var invite Invite
	if err := scanInviteRow(s.DB.QueryRowContext(ctx, `select `+inviteColumns+` from registry_invites where token_digest = ?`, digest), &invite); err != nil {
		return Invite{}, errInviteNotFound
	}
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

// ListLegacyFeedKeyIDs enumerates ONLY the registry IDs eligible for the
// opt-in legacy migration. No owner, plaintext, or envelope state is read
// here: every one of those is re-read INSIDE the per-row transaction, so the
// AAD context (owner) and the material being encrypted are always the SAME
// committed version of the row — never a stale enumeration snapshot. MUST
// only be called from the opt-in-gated MigrateLegacyFeedKeys path.
func (s *Store) ListLegacyFeedKeyIDs(ctx context.Context) ([]int64, error) {
	rows, err := s.DB.QueryContext(ctx, `select id from registries order by id asc`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// MigrateLegacyFeedKeys encrypts every legacy plaintext feed key with the
// row's own ID and the TRANSACTIONALLY re-read owner as AAD and clears the
// plaintext in the same per-row transaction. Rows that are already encrypted
// (complete envelope, legacy cleared) or carry no legacy plaintext are
// skipped. A row whose envelope state is PARTIAL is rejected with
// ErrFeedKeyEnvelopeInconsistent (never silently skipped), and a row carrying
// BOTH a complete envelope and legacy plaintext is re-encrypted from the
// legacy value so no plaintext is preserved alongside an envelope. A row
// whose encryption fails rolls back fully and aborts the operation; errors
// never contain key or owner material.
func (s *Store) MigrateLegacyFeedKeys(ctx context.Context, cipher *FeedKeyCipher) (int, error) {
	if cipher == nil {
		return 0, errFeedKeyCipherNotConfigured
	}
	ids, err := s.ListLegacyFeedKeyIDs(ctx)
	if err != nil {
		return 0, fmt.Errorf("migrate legacy feed keys: %w", err)
	}
	migrated := 0
	for _, id := range ids {
		// Test-only deterministic hook between enumeration and the per-row
		// transaction, so tests can prove a committed owner/plaintext change
		// is observed transactionally. Production never sets it.
		if s.migrateRowHook != nil {
			s.migrateRowHook(id)
		}
		ok, err := s.migrateLegacyFeedKey(ctx, id, cipher)
		if err != nil {
			return migrated, err
		}
		if ok {
			migrated++
		}
	}
	return migrated, nil
}

// migrateLegacyFeedKey encrypts ONE row's legacy plaintext inside its own
// transaction. Owner, plaintext, AND envelope state are all re-read from the
// row inside the transaction (the enumeration carries only the ID), so the
// AAD is bound to the committed owner and the encrypted bytes match the
// committed plaintext even if either changed after enumeration. The plaintext
// is scanned into a mutable []byte and zeroed after encryption; it never
// becomes a string.
func (s *Store) migrateLegacyFeedKey(ctx context.Context, id int64, cipher *FeedKeyCipher) (bool, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("migrate legacy feed key: %w", err)
	}
	defer tx.Rollback()

	// Full transactional re-read: owner, legacy plaintext, envelope state.
	var owner string
	var legacy []byte
	var ciphertext, nonce []byte
	var version sql.NullInt64
	if err := tx.QueryRowContext(ctx, `select feed_owner_address, encrypted_feed_private_key, feed_key_ciphertext, feed_key_nonce, feed_key_version from registries where id = ?`, id).
		Scan(&owner, &legacy, &ciphertext, &nonce, &version); err != nil {
		return false, fmt.Errorf("migrate legacy feed key: %w", err)
	}
	switch {
	case version.Valid:
		// A stored envelope version: the envelope must be complete AND
		// structurally valid BEFORE any decision about the legacy plaintext.
		// A complete-but-malformed envelope (wrong nonce/ciphertext lengths)
		// is rejected — never skipped as "already encrypted" even when the
		// legacy column is empty, and never re-encrypted from the legacy
		// value even when a version is stored. Shape is also validated here
		// so a malformed row is caught regardless of its stored version.
		if len(ciphertext) == 0 || len(nonce) == 0 || version.Int64 <= 0 {
			return false, fmt.Errorf("migrate legacy feed key for registry %d: %w", id, ErrFeedKeyEnvelopeInconsistent)
		}
		if err := validateFeedKeyEnvelopeShape(EncryptedFeedKey{Ciphertext: ciphertext, Nonce: nonce, KeyVersion: int(version.Int64)}); err != nil {
			// The row-level sentinel applies: the persisted columns are
			// inconsistent with the envelope contract.
			return false, fmt.Errorf("migrate legacy feed key for registry %d: %w", id, ErrFeedKeyEnvelopeInconsistent)
		}
	case len(ciphertext) > 0 || len(nonce) > 0:
		// Envelope material without a version: inconsistent; reject.
		return false, fmt.Errorf("migrate legacy feed key for registry %d: %w", id, ErrFeedKeyEnvelopeInconsistent)
	}
	if len(legacy) == 0 {
		// Nothing at rest to migrate; with a structurally valid envelope this
		// is an already-migrated row, otherwise a plaintext-free row — both
		// clean.
		return false, tx.Commit()
	}
	defer zeroBytes(legacy)

	// Encrypt under the TRANSACTIONALLY read owner; owner is the committed
	// value even if it changed after enumeration.
	enc, err := cipher.Encrypt(id, owner, legacy)
	if err != nil {
		return false, fmt.Errorf("migrate legacy feed key: %w", err)
	}
	// Ciphertext+nonce+version written and the legacy plaintext cleared in the
	// SAME statement inside the SAME transaction: there is no intermediate
	// state where the row is encrypted but the plaintext still sits at rest.
	if _, err := tx.ExecContext(ctx, `update registries
		set feed_key_ciphertext = ?, feed_key_nonce = ?, feed_key_version = ?, encrypted_feed_private_key = ''
		where id = ?`, enc.Ciphertext, enc.Nonce, enc.KeyVersion, id); err != nil {
		return false, fmt.Errorf("migrate legacy feed key: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("migrate legacy feed key: %w", err)
	}
	return true, nil
}

// ReencryptRegistryFeedKey rotates one registry's feed key from fromVersion to
// toVersion, one row per transaction. The old ciphertext is authenticated with
// the row's OWN current owner/ID context re-read inside the transaction
// (tampering or context drift aborts), the decrypted plaintext is re-sealed
// under the explicitly requested toVersion with the same owner, and the row is
// updated atomically. Envelope state is validated first: a PARTIAL envelope
// AND a complete-but-malformed envelope (wrong nonce/ciphertext lengths)
// reject with ErrFeedKeyEnvelopeInconsistent — before any version-based skip,
// so a malformed row is never skipped untouched merely because its stored
// version differs from fromVersion. Only an all-NULL row is skipped (no
// stored key), and a structurally valid row whose stored version != fromVersion
// is skipped untouched. The temporary plaintext is zeroed after use.
func (s *Store) ReencryptRegistryFeedKey(ctx context.Context, registryID int64, fromVersion, toVersion int, cipher *FeedKeyCipher) (bool, error) {
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
	ctSet := len(ciphertext) > 0
	nonceSet := len(nonce) > 0
	switch {
	case version.Valid && (!ctSet || !nonceSet || version.Int64 <= 0):
		// Partial envelope: reject — never silently skip, never rotate a
		// half-encrypted row.
		return false, fmt.Errorf("re-encrypt feed key for registry %d: %w", registryID, ErrFeedKeyEnvelopeInconsistent)
	case !version.Valid && (ctSet || nonceSet):
		return false, fmt.Errorf("re-encrypt feed key for registry %d: %w", registryID, ErrFeedKeyEnvelopeInconsistent)
	case !version.Valid:
		return false, tx.Commit() // no stored key: skip
	}
	// Complete envelope: validate structural shape BEFORE the version-based
	// skip. A malformed envelope (nonce != feedKeyEnvelopeNonceSize bytes,
	// ciphertext < feedKeyEnvelopeCiphertextMin bytes) is rejected even when
	// the stored version differs from fromVersion — it is never skipped
	// untouched just because the version gate would have excluded it.
	enc := EncryptedFeedKey{Ciphertext: ciphertext, Nonce: nonce, KeyVersion: int(version.Int64)}
	if err := validateFeedKeyEnvelopeShape(enc); err != nil {
		return false, fmt.Errorf("re-encrypt feed key for registry %d: %w", registryID, ErrFeedKeyEnvelopeInconsistent)
	}
	if int(version.Int64) != fromVersion {
		return false, tx.Commit() // not at fromVersion: skip untouched
	}

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
