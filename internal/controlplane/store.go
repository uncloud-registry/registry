package controlplane

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
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

type Registry struct {
	ID                      int64
	Slug                    string
	Host                    string
	ENSName                 string
	OwnerUserID             int64
	FeedOwnerAddress        string
	EncryptedFeedPrivateKey string
	DefaultStampBatchID     string
	AnonymousPull           bool
	CreatedAt               time.Time
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
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	store := &Store{DB: db}
	if err := store.Migrate(context.Background()); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *Store) Migrate(ctx context.Context) error {
	stmts := []string{
		`create table if not exists users (
			id integer primary key autoincrement,
			email text not null unique,
			password_hash text not null,
			created_at text not null
		)`,
		`create table if not exists registries (
			id integer primary key autoincrement,
			slug text not null unique,
			host text not null unique,
			ens_name text not null,
			owner_user_id integer not null,
			feed_owner_address text not null,
			encrypted_feed_private_key text not null,
			default_stamp_batch_id text not null,
			anonymous_pull integer not null,
			created_at text not null
		)`,
		`create table if not exists registry_memberships (
			id integer primary key autoincrement,
			registry_id integer not null,
			user_id integer not null,
			role text not null,
			can_pull integer not null default 1,
			can_push integer not null default 0,
			created_at text not null,
			unique(registry_id, user_id)
		)`,
		`create table if not exists registry_invites (
			id integer primary key autoincrement,
			registry_id integer not null,
			email text not null,
			role text not null,
			can_pull integer not null default 1,
			can_push integer not null default 0,
			token_hash text not null unique,
			status text not null,
			expires_at text not null,
			created_at text not null
		)`,
	}
	for _, stmt := range stmts {
		if _, err := s.DB.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	alterStmts := []string{
		`alter table registry_memberships add column can_pull integer not null default 1`,
		`alter table registry_memberships add column can_push integer not null default 0`,
		`alter table registry_invites add column can_pull integer not null default 1`,
		`alter table registry_invites add column can_push integer not null default 0`,
	}
	for _, stmt := range alterStmts {
		if _, err := s.DB.ExecContext(ctx, stmt); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
			return err
		}
	}
	return nil
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

func (s *Store) CreateRegistry(ctx context.Context, registry Registry) (Registry, error) {
	now := time.Now().UTC()
	result, err := s.DB.ExecContext(ctx, `insert into registries
		(slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at)
		values (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		registry.Slug, registry.Host, registry.ENSName, registry.OwnerUserID, registry.FeedOwnerAddress, registry.EncryptedFeedPrivateKey, registry.DefaultStampBatchID, boolToInt(registry.AnonymousPull), now.Format(time.RFC3339))
	if err != nil {
		return Registry{}, err
	}
	id, _ := result.LastInsertId()
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
	rows, err := s.DB.QueryContext(ctx, `
		select r.id, r.slug, r.host, r.ens_name, r.owner_user_id, r.feed_owner_address, r.encrypted_feed_private_key, r.default_stamp_batch_id, r.anonymous_pull, r.created_at
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
		var createdAt string
		var anonymous int
		if err := rows.Scan(&registry.ID, &registry.Slug, &registry.Host, &registry.ENSName, &registry.OwnerUserID, &registry.FeedOwnerAddress, &registry.EncryptedFeedPrivateKey, &registry.DefaultStampBatchID, &anonymous, &createdAt); err != nil {
			return nil, err
		}
		registry.AnonymousPull = anonymous == 1
		registry.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		registries = append(registries, registry)
	}
	return registries, rows.Err()
}

func (s *Store) FindRegistryByID(ctx context.Context, registryID int64) (Registry, error) {
	var registry Registry
	var createdAt string
	var anonymous int
	err := s.DB.QueryRowContext(ctx, `select id, slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at from registries where id = ?`, registryID).
		Scan(&registry.ID, &registry.Slug, &registry.Host, &registry.ENSName, &registry.OwnerUserID, &registry.FeedOwnerAddress, &registry.EncryptedFeedPrivateKey, &registry.DefaultStampBatchID, &anonymous, &createdAt)
	if err != nil {
		return Registry{}, err
	}
	registry.AnonymousPull = anonymous == 1
	registry.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return registry, nil
}

func (s *Store) FindRegistryByHost(ctx context.Context, host string) (Registry, error) {
	var registry Registry
	var createdAt string
	var anonymous int
	err := s.DB.QueryRowContext(ctx, `select id, slug, host, ens_name, owner_user_id, feed_owner_address, encrypted_feed_private_key, default_stamp_batch_id, anonymous_pull, created_at from registries where host = ?`, host).
		Scan(&registry.ID, &registry.Slug, &registry.Host, &registry.ENSName, &registry.OwnerUserID, &registry.FeedOwnerAddress, &registry.EncryptedFeedPrivateKey, &registry.DefaultStampBatchID, &anonymous, &createdAt)
	if err != nil {
		return Registry{}, err
	}
	registry.AnonymousPull = anonymous == 1
	registry.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
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
