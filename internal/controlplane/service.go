package controlplane

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/bcrypt"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/spec"
)

type Service struct {
	Store          *Store
	Tokens         *auth.SessionTokenManager
	RegistryTokens *auth.RegistryTokenIssuer
	RegistryDomain string
	Publisher      *Publisher
	// FeedKeys is the AES-GCM cipher wrapping registry feed-owner signing keys
	// at rest. Production startup requires it (cmd/controlplane loads the
	// master-key file and fails closed when it is missing); operations that
	// would otherwise store or expose plaintext fail closed when it is nil.
	FeedKeys *FeedKeyCipher
}

type CreatedRegistry struct {
	Registry  Registry             `json:"registry"`
	Bootstrap BootstrapPublication `json:"bootstrap"`
}

type RegistryDashboard struct {
	Registry    Registry                 `json:"registry"`
	Memberships []Membership             `json:"memberships"`
	Invites     []Invite                 `json:"invites"`
	AuthPolicy  spec.AuthPolicyDocument  `json:"authPolicy"`
	StampPolicy spec.StampPolicyDocument `json:"stampPolicy"`
}

func (s *Service) RegisterUser(ctx context.Context, email string, password string) (User, string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, "", err
	}
	user, err := s.Store.CreateUser(ctx, email, string(hash))
	if err != nil {
		return User{}, "", err
	}
	token, err := s.Tokens.Issue(fmt.Sprintf("user:%d", user.ID), 24*time.Hour)
	return user, token, err
}

func (s *Service) Login(ctx context.Context, email string, password string) (User, string, error) {
	user, err := s.Store.FindUserByEmail(ctx, email)
	if err != nil {
		return User{}, "", err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return User{}, "", err
	}
	token, err := s.Tokens.Issue(fmt.Sprintf("user:%d", user.ID), 24*time.Hour)
	return user, token, err
}

func (s *Service) CreateRegistry(ctx context.Context, ownerUserID int64, slug string, ensName string, anonymousPull bool, defaultStampBatchID string) (CreatedRegistry, error) {
	if s.FeedKeys == nil {
		return CreatedRegistry{}, errFeedKeyCipherNotConfigured
	}
	privateKey, err := generatePrivateKeyHex()
	if err != nil {
		return CreatedRegistry{}, err
	}
	key, err := ethcrypto.HexToECDSA(privateKey)
	if err != nil {
		return CreatedRegistry{}, err
	}
	host := slug + "." + s.RegistryDomain
	registry := Registry{
		Slug:                slug,
		Host:                host,
		ENSName:             ensName,
		OwnerUserID:         ownerUserID,
		FeedOwnerAddress:    strings.ToLower(ethcrypto.PubkeyToAddress(key.PublicKey).Hex()),
		DefaultStampBatchID: defaultStampBatchID,
		AnonymousPull:       anonymousPull,
	}

	// The key is encrypted at rest by the store, inside the insert
	// transaction, bound with AES-GCM AAD to the row's own ID and owner. The
	// transient plaintext lives only in this frame (the hex string) and in the
	// store's encryption call; nothing is ever persisted in plaintext.
	registry, err = s.Store.CreateRegistry(ctx, registry, s.FeedKeys, privateKey)
	if err != nil {
		return CreatedRegistry{}, err
	}
	membership, err := s.Store.CreateMembership(ctx, Membership{
		RegistryID: registry.ID,
		UserID:     ownerUserID,
		Role:       "owner",
		CanPull:    true,
		CanPush:    true,
	})
	if err != nil {
		return CreatedRegistry{}, err
	}

	created := CreatedRegistry{Registry: registry}
	if s.Publisher != nil {
		bootstrap, err := s.Publisher.PublishBootstrap(ctx, registry, []MembershipSubject{{
			UserID:  membership.UserID,
			Role:    membership.Role,
			CanPull: membership.CanPull,
			CanPush: membership.CanPush,
		}})
		if err != nil {
			return CreatedRegistry{}, err
		}
		created.Bootstrap = bootstrap
	}
	return created, nil
}

func (s *Service) ListRegistries(ctx context.Context, userID int64) ([]Registry, error) {
	return s.Store.ListRegistriesForUser(ctx, userID)
}

func (s *Service) GetRegistry(ctx context.Context, userID int64, registryID int64) (Registry, error) {
	if _, err := s.Store.FindMembership(ctx, registryID, userID); err != nil {
		return Registry{}, err
	}
	return s.Store.FindRegistryByID(ctx, registryID)
}

func (s *Service) GetRegistryDashboard(ctx context.Context, userID int64, registryID int64) (RegistryDashboard, error) {
	registry, err := s.GetRegistry(ctx, userID, registryID)
	if err != nil {
		return RegistryDashboard{}, err
	}
	memberships, err := s.Store.ListMembershipsForRegistry(ctx, registryID)
	if err != nil {
		return RegistryDashboard{}, err
	}
	invites, err := s.Store.ListInvitesForRegistry(ctx, registryID)
	if err != nil {
		return RegistryDashboard{}, err
	}
	return RegistryDashboard{
		Registry:    registry,
		Memberships: memberships,
		Invites:     invites,
		AuthPolicy:  buildAuthPolicyDocument(registry, membershipSubjects(memberships)),
		StampPolicy: buildStampPolicyDocument(registry, membershipSubjects(memberships)),
	}, nil
}

func (s *Service) UpdateRegistrySettings(ctx context.Context, userID int64, registryID int64, anonymousPull bool, defaultStampBatchID string) (RegistryDashboard, error) {
	membership, err := s.Store.FindMembership(ctx, registryID, userID)
	if err != nil {
		return RegistryDashboard{}, err
	}
	if membership.Role != "owner" && membership.Role != "admin" {
		return RegistryDashboard{}, fmt.Errorf("user is not allowed to update registry settings")
	}
	registry, err := s.Store.UpdateRegistrySettings(ctx, registryID, anonymousPull, defaultStampBatchID)
	if err != nil {
		return RegistryDashboard{}, err
	}
	memberships, err := s.Store.ListMembershipsForRegistry(ctx, registryID)
	if err != nil {
		return RegistryDashboard{}, err
	}
	if s.Publisher != nil {
		subjects := membershipSubjects(memberships)
		if _, err := s.Publisher.PublishAuthPolicy(ctx, registry, subjects); err != nil {
			return RegistryDashboard{}, err
		}
		if _, err := s.Publisher.PublishStampPolicy(ctx, registry, subjects); err != nil {
			return RegistryDashboard{}, err
		}
	}
	return s.GetRegistryDashboard(ctx, userID, registryID)
}

func (s *Service) CreateInvite(ctx context.Context, registryID int64, inviterUserID int64, email string, canPull bool, canPush bool) (Invite, string, error) {
	membership, err := s.Store.FindMembership(ctx, registryID, inviterUserID)
	if err != nil {
		return Invite{}, "", err
	}
	if membership.Role != "owner" && membership.Role != "admin" {
		return Invite{}, "", fmt.Errorf("user is not allowed to invite collaborators")
	}
	if !canPull && !canPush {
		return Invite{}, "", fmt.Errorf("invite must grant pull or push access")
	}
	return s.Store.CreateInvite(ctx, Invite{
		RegistryID: registryID,
		Email:      email,
		Role:       "member",
		CanPull:    canPull || canPush,
		CanPush:    canPush,
		ExpiresAt:  time.Now().UTC().Add(7 * 24 * time.Hour),
	})
}

func (s *Service) AcceptInvite(ctx context.Context, token string, userID int64) (Invite, error) {
	invite, err := s.Store.AcceptInvite(ctx, token, userID)
	if err != nil {
		return Invite{}, err
	}
	return invite, nil
}

func (s *Service) GetInvite(ctx context.Context, token string) (Invite, Registry, error) {
	invite, err := s.Store.FindInviteByToken(ctx, token)
	if err != nil {
		return Invite{}, Registry{}, err
	}
	registry, err := s.Store.FindRegistryByID(ctx, invite.RegistryID)
	if err != nil {
		return Invite{}, Registry{}, err
	}
	return invite, registry, nil
}

func (s *Service) requireRegistryAdmin(ctx context.Context, userID int64, registryID int64) (Registry, error) {
	membership, err := s.Store.FindMembership(ctx, registryID, userID)
	if err != nil {
		return Registry{}, err
	}
	if membership.Role != "owner" && membership.Role != "admin" {
		return Registry{}, fmt.Errorf("user is not allowed to update registry settings")
	}
	return s.Store.FindRegistryByID(ctx, registryID)
}

func (s *Service) UpdateCollaboratorPermissions(ctx context.Context, userID int64, registryID int64, updates []Membership) (RegistryDashboard, error) {
	if _, err := s.requireRegistryAdmin(ctx, userID, registryID); err != nil {
		return RegistryDashboard{}, err
	}
	current, err := s.Store.ListMembershipsForRegistry(ctx, registryID)
	if err != nil {
		return RegistryDashboard{}, err
	}
	byUserID := make(map[int64]Membership, len(current))
	for _, membership := range current {
		byUserID[membership.UserID] = membership
	}

	allowed := make([]Membership, 0, len(updates))
	for _, update := range updates {
		existing, ok := byUserID[update.UserID]
		if !ok {
			return RegistryDashboard{}, fmt.Errorf("unknown collaborator %d", update.UserID)
		}
		if existing.Role == "owner" || existing.Role == "admin" {
			continue
		}
		update.RegistryID = registryID
		update.Role = existing.Role
		update.Email = existing.Email
		if update.CanPush {
			update.CanPull = true
		}
		allowed = append(allowed, update)
	}

	if err := s.Store.UpdateMembershipPermissions(ctx, registryID, allowed); err != nil {
		return RegistryDashboard{}, err
	}
	return s.GetRegistryDashboard(ctx, userID, registryID)
}

// MigrateLegacyFeedKeys encrypts every legacy plaintext feed key at rest using
// the configured cipher and clears the plaintext in the same per-row
// transaction. It is invoked ONLY by cmd/controlplane startup when the
// operator explicitly opts in (CONTROLPLANE_MIGRATE_LEGACY_KEYS=true); the
// schema migration itself never touches legacy plaintext. Returns the number
// of rows migrated. Errors are data-free (no key or owner material).
func (s *Service) MigrateLegacyFeedKeys(ctx context.Context) (int, error) {
	if s.FeedKeys == nil {
		return 0, errFeedKeyCipherNotConfigured
	}
	return s.Store.MigrateLegacyFeedKeys(ctx, s.FeedKeys)
}

// FeedKeyReencryptResult reports a ReencryptFeedKeys pass. Reencrypted counts
// rows rotated to the target version; Skipped counts rows left untouched
// (rows not at fromVersion — e.g. already rotated in an earlier pass — and
// rows without a stored key).
type FeedKeyReencryptResult struct {
	Reencrypted int
	Skipped     int
}

// ReencryptFeedKeys rotates every registry feed key from fromVersion to
// toVersion, one registry transaction at a time. The target version must be
// the explicitly requested LOADED version (not merely `current`), the source
// version must also be loaded (it is what authenticates the old rows), and
// every row's owner is preserved: each row is decrypted under its own
// ID/owner AAD and re-sealed under the same owner with the target version.
// Rows not at fromVersion and rows without a stored key are skipped untouched,
// so a pass interrupted midway is safe to resume. A row whose old ciphertext
// fails authentication aborts the pass (fail closed) and is left fully
// unchanged. Errors carry no key or owner material.
func (s *Service) ReencryptFeedKeys(ctx context.Context, fromVersion, toVersion int) (FeedKeyReencryptResult, error) {
	if s.FeedKeys == nil {
		return FeedKeyReencryptResult{}, errFeedKeyCipherNotConfigured
	}
	if fromVersion == toVersion {
		return FeedKeyReencryptResult{}, errors.New("re-encrypt feed keys: fromVersion and toVersion must differ")
	}
	if !s.FeedKeys.HasVersion(fromVersion) {
		return FeedKeyReencryptResult{}, fmt.Errorf("re-encrypt feed keys: source version %d is not loaded", fromVersion)
	}
	if !s.FeedKeys.HasVersion(toVersion) {
		return FeedKeyReencryptResult{}, fmt.Errorf("re-encrypt feed keys: target version %d is not loaded", toVersion)
	}

	registries, err := s.Store.ListRegistries(ctx)
	if err != nil {
		return FeedKeyReencryptResult{}, fmt.Errorf("re-encrypt feed keys: %w", err)
	}
	res := FeedKeyReencryptResult{}
	for _, registry := range registries {
		ok, err := s.Store.ReencryptRegistryFeedKey(ctx, registry.ID, registry.FeedOwnerAddress, fromVersion, toVersion, s.FeedKeys)
		if err != nil {
			return res, err
		}
		if ok {
			res.Reencrypted++
		} else {
			res.Skipped++
		}
	}
	return res, nil
}

// DecryptFeedKey resolves the transient plaintext signing key for a registry
// from the row's OWN current stored context (fresh read), authenticating the
// envelope with the row's ID and owner. The returned hex string is the
// direct input for feed signing (Task 9/10 consume this boundary); the
// intermediate byte buffer is zeroed before returning. Errors never contain
// key or owner material.
func (s *Service) DecryptFeedKey(ctx context.Context, registry Registry) (string, error) {
	if s.FeedKeys == nil {
		return "", errFeedKeyCipherNotConfigured
	}
	row, err := s.Store.FindRegistryByID(ctx, registry.ID)
	if err != nil {
		return "", fmt.Errorf("resolve feed key: %w", err)
	}
	if !row.FeedKeySet {
		return "", errors.New("registry has no stored encrypted feed key")
	}
	plaintext, err := s.FeedKeys.Decrypt(row.ID, row.FeedOwnerAddress, row.FeedKey)
	if err != nil {
		return "", err
	}
	defer zeroBytes(plaintext)
	return string(plaintext), nil
}

func (s *Service) RegisterAndAcceptInvite(ctx context.Context, token string, email string, password string) (User, Invite, string, error) {
	user, sessionToken, err := s.RegisterUser(ctx, email, password)
	if err != nil {
		return User{}, Invite{}, "", err
	}
	invite, err := s.AcceptInvite(ctx, token, user.ID)
	if err != nil {
		return User{}, Invite{}, "", err
	}
	return user, invite, sessionToken, nil
}

func (s *Service) IssueRegistryToken(ctx context.Context, host string, scope string, email string, password string) (string, error) {
	user, err := s.Store.FindUserByEmail(ctx, email)
	if err != nil {
		return "", err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return "", err
	}
	registry, err := s.Store.FindRegistryByHost(ctx, host)
	if err != nil {
		return "", err
	}

	repository, actions, err := auth.ParseDockerScope(scope)
	if err != nil {
		return "", err
	}

	membership, err := s.Store.FindMembership(ctx, registry.ID, user.ID)
	if err != nil {
		if err != sql.ErrNoRows {
			return "", err
		}
		// No membership: only anonymous pull is possible.
		for _, a := range actions {
			if a == auth.ActionPush {
				return "", fmt.Errorf("user is not allowed to push to this registry")
			}
			if a == auth.ActionPull && !registry.AnonymousPull {
				return "", fmt.Errorf("user is not allowed to pull from this registry")
			}
		}
		return s.issueRegistryToken(host, "anonymous", repository, actions)
	}

	for _, a := range actions {
		switch a {
		case auth.ActionPush:
			// Anonymous pull authorizes pull only: a member (or any actor)
			// without push permission must be denied push even when the
			// registry allows anonymous pulls.
			if !membership.CanPush {
				return "", fmt.Errorf("user is not allowed to push to this registry")
			}
		case auth.ActionPull:
			if !membership.CanPull && !registry.AnonymousPull {
				return "", fmt.Errorf("user is not allowed to pull from this registry")
			}
		}
	}

	subject := "role:read"
	if membership.CanPush {
		subject = "role:write"
	}
	return s.issueRegistryToken(host, subject, repository, actions)
}

func (s *Service) issueRegistryToken(service, subject, repository string, actions []auth.Action) (string, error) {
	if s.RegistryTokens == nil {
		return "", fmt.Errorf("registry token issuer is not configured")
	}
	return s.RegistryTokens.Issue(context.Background(), auth.RegistryTokenRequest{
		Subject:    subject,
		Service:    service,
		Repository: repository,
		Actions:    actions,
		TTL:        time.Hour,
	})
}

func UserIDFromSubject(subject string) (int64, error) {
	var id int64
	if _, err := fmt.Sscanf(subject, "user:%d", &id); err != nil {
		return 0, fmt.Errorf("invalid subject %q", subject)
	}
	return id, nil
}

func membershipSubjects(memberships []Membership) []MembershipSubject {
	subjects := make([]MembershipSubject, 0, len(memberships))
	for _, membership := range memberships {
		subjects = append(subjects, MembershipSubject{
			UserID:  membership.UserID,
			Role:    membership.Role,
			CanPull: membership.CanPull,
			CanPush: membership.CanPush,
		})
	}
	return subjects
}

func buildAuthPolicyDocument(registry Registry, _ []MembershipSubject) spec.AuthPolicyDocument {
	pushActors := []string{"role:write"}
	pullActors := []string{"role:read", "role:write"}
	if registry.AnonymousPull {
		pullActors = append([]string{"anonymous"}, pullActors...)
	}
	return spec.AuthPolicyDocument{
		Version:       1,
		DefaultAccess: "deny",
		DefaultRepo: &spec.RepoAuthPolicyEntry{
			Pull: pullActors,
			Push: pushActors,
		},
		Repos: map[string]spec.RepoAuthPolicyEntry{},
	}
}

func buildStampPolicyDocument(registry Registry, _ []MembershipSubject) spec.StampPolicyDocument {
	return spec.StampPolicyDocument{
		Version: 1,
		DefaultPolicy: spec.StampAccessPolicy{
			BatchID:      registry.DefaultStampBatchID,
			AllowPushFor: []string{"role:write"},
		},
		Repos: map[string]spec.StampAccessPolicy{},
	}
}

func generatePrivateKeyHex() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
