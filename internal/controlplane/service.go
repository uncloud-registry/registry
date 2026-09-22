package controlplane

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
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
	// SessionTTL is the lifetime of issued session tokens. Zero means the
	// default 24h (test/back-compat). RegisterUser and Login use it, and the
	// session cookie's MaxAge/Expires align to the same value.
	SessionTTL time.Duration
	// FeedKeys is the AES-GCM cipher wrapping registry feed-owner signing keys
	// at rest. Startup always loads it (cmd/controlplane requires the
	// master-key file in every mode and loads it before the database);
	// operations that would otherwise store or expose plaintext fail closed
	// when it is nil.
	FeedKeys *FeedKeyCipher
}

// errInvalidCredentials is the single, public credential failure. It is
// returned for unknown email, wrong password, and every other authentication
// failure so a caller can never distinguish which part was wrong (no account
// enumeration).
var errInvalidCredentials = errors.New("invalid email or password")

// authCause is a safe, coarse internal cause classification for correlated
// logging. Values never carry credentials, tokens, scope, or PII, so they can
// be logged verbatim.
type authCause string

const (
	causeUnknownAccount   authCause = "unknown_account"
	causeInvalidPassword  authCause = "invalid_password"
	causeDatastore        authCause = "datastore"
	causeInvalidScope     authCause = "invalid_scope"
	causeForbidden        authCause = "forbidden"
	causeSigning          authCause = "signing"
	causeRegistryNotFound authCause = "registry_not_found"
)

// tokenFailureClass is an internal, coarse class the registry-token endpoint
// uses to select a fixed generic public status+body. No class carries an
// internal error string; the response text for every class is a constant.
type tokenFailureClass int

const (
	tokenClassCredential tokenFailureClass = iota // generic 401
	tokenClassMalformed                           // generic 400 (malformed request/scope)
	tokenClassForbidden                           // generic 403
	tokenClassNotFound                            // 404 (caller-chosen registry missing)
	tokenClassBackend                             // generic 503 (backend/datastore)
	tokenClassSigning                             // generic 500 (signing/issuer)
)

// classifiedFailure is an internal failure carrying a safe cause and a coarse
// public class. It still satisfies errors.Is(errInvalidCredentials) and its
// public text is always the generic credential message, so nothing internal
// leaks through the error value itself.
type classifiedFailure struct {
	cause authCause
	class tokenFailureClass
}

func (e *classifiedFailure) Error() string { return errInvalidCredentials.Error() }

func (e *classifiedFailure) Unwrap() error { return errInvalidCredentials }

// credentialCause extracts the safe classification, or "" for a non-classified
// failure (the caller then logs a generic cause).
func credentialCause(err error) string {
	var cf *classifiedFailure
	if errors.As(err, &cf) {
		return string(cf.cause)
	}
	return ""
}

// dummyPasswordHash is a valid bcrypt hash used to keep comparison work
// constant between a recognised and an unknown email, closing the timing
// side-channel that would otherwise reveal whether an account exists.
const dummyPasswordHash = "$2a$10$KtQ49oBiPrKD2p2IlHaRteBOWzn99gdPl9mzZdHGi0s3o2xh.vige"

// comparePassword validates password against a stored hash, or against the
// dummy hash when no account exists, so both paths perform a bcrypt compare.
func comparePassword(storedHash string, password string) bool {
	hash := storedHash
	if storedHash == "" {
		hash = dummyPasswordHash
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

type CreatedRegistry struct {
	Registry  Registry             `json:"registry"`
	Bootstrap BootstrapPublication `json:"bootstrap"`
	// State is the registry's provisioning state at creation; it is always
	// 'provisioning', because bootstrap is enqueued, not yet published. Public
	// signalling of the transition to ready/failed happens through the
	// registry's provisioningState.
	State string `json:"state"`
}

type RegistryDashboard struct {
	Registry    Registry                 `json:"registry"`
	Memberships []Membership             `json:"memberships"`
	Invites     []Invite                 `json:"invites"`
	AuthPolicy  spec.AuthPolicyDocument  `json:"authPolicy"`
	StampPolicy spec.StampPolicyDocument `json:"stampPolicy"`
}

// defaultSessionTokenTTL is the lifetime used when Service.SessionTTL is zero
// (test/back-compat) — identical to the config default.
const defaultSessionTokenTTL = 24 * time.Hour

// sessionTTL returns the configured session lifetime, defaulting to 24h when
// unset so existing tests and zero-value services keep working.
func (s *Service) sessionTTL() time.Duration {
	if s.SessionTTL > 0 {
		return s.SessionTTL
	}
	return defaultSessionTokenTTL
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
	token, err := s.Tokens.Issue(fmt.Sprintf("user:%d", user.ID), s.sessionTTL())
	return user, token, err
}

func (s *Service) Login(ctx context.Context, email string, password string) (User, string, error) {
	if s.Tokens == nil {
		return User{}, "", &classifiedFailure{cause: causeSigning, class: tokenClassCredential}
	}
	user, err := s.Store.FindUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Unknown account: still compare a bcrypt hash so an attacker
			// cannot time the difference between a known and unknown email.
			_ = bcrypt.CompareHashAndPassword([]byte(dummyPasswordHash), []byte(password))
			return User{}, "", &classifiedFailure{cause: causeUnknownAccount, class: tokenClassCredential}
		}
		// A backend/datastore failure is logged as such; the public response
		// stays the identical generic 401 so no backend detail leaks.
		return User{}, "", &classifiedFailure{cause: causeDatastore, class: tokenClassBackend}
	}
	if !comparePassword(user.PasswordHash, password) {
		return User{}, "", &classifiedFailure{cause: causeInvalidPassword, class: tokenClassCredential}
	}
	token, err := s.Tokens.Issue(fmt.Sprintf("user:%d", user.ID), s.sessionTTL())
	return user, token, err
}

func (s *Service) CreateRegistry(ctx context.Context, ownerUserID int64, slug string, ensName string, anonymousPull bool, defaultStampBatchID string) (CreatedRegistry, error) {
	// Fail closed on dependencies BEFORE any key generation or DB write: a
	// registry can only be created when the control plane can actually
	// provision it (a Store to persist the outbox, a Publisher with a
	// Documents object store, a Feeds updater, and feed read-back
	// resolution). Otherwise it would silently enqueue a registry that sits
	// provisioning forever. This runs before generatePrivateKeyBytes and
	// before any store call, so misconfiguration causes zero DB effects.
	if s.Store == nil || s.Publisher == nil ||
		s.Publisher.Documents == nil || s.Publisher.Feeds == nil || s.Publisher.FeedsReader == nil {
		return CreatedRegistry{}, errProvisioningNotConfigured
	}
	if s.FeedKeys == nil {
		return CreatedRegistry{}, errFeedKeyCipherNotConfigured
	}
	// The signing key is born as mutable bytes owned by this frame; it is
	// wiped (defer) after the store has sealed it. It is never stringified.
	priv, err := generatePrivateKeyBytes()
	if err != nil {
		return CreatedRegistry{}, err
	}
	defer zeroBytes(priv)
	key, err := ethcrypto.ToECDSA(priv)
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

	// Build the two deterministic default-deny bootstrap policy documents and
	// canonically encode them as the durable outbox payloads. This happens
	// BEFORE the store call so the payloads are fixed at creation time and the
	// reconciler uploads byte-identical copies on retries. Documents never
	// contain secret key material (owner address and role actors only).
	authPayload, err := canonicalJSON(buildAuthPolicyDocument(registry, nil))
	if err != nil {
		return CreatedRegistry{}, err
	}
	stampPayload, err := canonicalJSON(buildStampPolicyDocument(registry, nil))
	if err != nil {
		return CreatedRegistry{}, err
	}

	// One local transaction inserts the registry (provisioning), the owner
	// membership, and both durable bootstrap jobs. The feed-owner key is
	// encrypted inside that transaction bound to the row's ID and owner.
	// Nothing is published externally here: creation returns 'provisioning'
	// with the deterministic feed refs, never a claim of published bootstrap
	// references.
	created, err := s.Store.CreateProvisionedRegistry(ctx, registry, s.FeedKeys, priv, authPayload, stampPayload)
	if err != nil {
		return CreatedRegistry{}, err
	}
	return CreatedRegistry{
		Registry: created,
		State:    ProvisioningStateProvisioning,
		Bootstrap: BootstrapPublication{
			FeedOwnerAddress: created.FeedOwnerAddress,
			AuthPolicyFeed:   authPolicyFeedRef(created),
			StampPolicyFeed:  stampPolicyFeedRef(created),
		},
	}, nil
}

// canonicalJSON marshals a policy document to its deterministic canonical JSON.
// For these fixed-shape documents (string-keyed maps, ordered slices) encoding/
// json emits stable output, so a retried outbox upload is byte-identical.
func canonicalJSON(v any) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encode bootstrap policy payload: %w", err)
	}
	return data, nil
}

func (s *Service) ListRegistries(ctx context.Context, userID int64) ([]Registry, error) {
	return s.Store.ListRegistriesForUser(ctx, userID)
}

// NewReconciler builds the provisioning outbox reconciler over this service's
// already-open store and configured publisher. It FAILS CLOSED (returns the
// data-free errReconcilerNotConfigured) when the service cannot publish and
// verify a job — no Store, no Publisher, or a Publisher missing its Documents,
// Feeds, or feed read-back resolver — so a worker is never silently created
// that could skip a stage or complete an unverified job. It performs no I/O
// and opens no database.
func (s *Service) NewReconciler() (*Reconciler, error) {
	if s.Store == nil || s.Publisher == nil {
		return nil, errReconcilerNotConfigured
	}
	return NewReconciler(s.Store, s.Publisher.Documents, s.Publisher.Feeds, s.Publisher.FeedsReader)
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

// CreateInvite validates an inviter-authorized, recipient-bound invite and
// persists ONLY the digest. The recipient address is normalized with the
// shared identity semantics (NormalizeEmail); the expiry is a bounded future
// window (inviteDefaultTTL from the store clock, capped by inviteMaxTTL at the
// persistence boundary); the permission invariant (pull and/or push, never
// neither) is enforced here and again at the store. The raw one-time token is
// returned exactly once — to this caller (API create response or the UI
// flash) — and can never be recovered from storage afterwards.
func (s *Service) CreateInvite(ctx context.Context, registryID int64, inviterUserID int64, email string, canPull bool, canPush bool) (Invite, string, error) {
	membership, err := s.Store.FindMembership(ctx, registryID, inviterUserID)
	if err != nil {
		return Invite{}, "", err
	}
	if membership.Role != "owner" && membership.Role != "admin" {
		return Invite{}, "", fmt.Errorf("user is not allowed to invite collaborators")
	}
	email = NormalizeEmail(email)
	if email == "" {
		return Invite{}, "", errInviteRecipientRequired
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
		ExpiresAt:  time.Now().UTC().Add(inviteDefaultTTL),
	})
}

// AcceptInvite binds the session user (by ID) to the invitation, recipient-
// bound and atomically. The user is loaded fresh from the database and the
// store re-loads it inside the acceptance transaction by ID; the caller-
// supplied email/role are never trusted. Every failure mode maps to the
// single generic errInviteNotFound so no caller can distinguish invite states.
func (s *Service) AcceptInvite(ctx context.Context, token string, userID int64) (Invite, error) {
	user, err := s.Store.FindUserByID(ctx, userID)
	if err != nil {
		// Unknown/invalid session principal: same generic story as any other
		// acceptance failure.
		return Invite{}, errInviteNotFound
	}
	return s.Store.AcceptInvite(ctx, token, user)
}

// GetInvite resolves the public acceptance page for a canonical raw token:
// the invite must still be pending and unexpired, otherwise the generic
// errInviteNotFound applies (revoked, expired, accepted, unknown, or malformed
// tokens are indistinguishable). Only public fields of the invite are used by
// callers; the digest is never returned.
func (s *Service) GetInvite(ctx context.Context, token string) (Invite, Registry, error) {
	canonical, err := ParseInviteToken(token)
	if err != nil {
		return Invite{}, Registry{}, errInviteNotFound
	}
	invite, err := s.Store.FindInviteByDigest(ctx, DigestInviteToken(canonical))
	if err != nil {
		return Invite{}, Registry{}, errInviteNotFound
	}
	if invite.Status != "pending" || !time.Now().UTC().Before(invite.ExpiresAt) {
		return Invite{}, Registry{}, errInviteNotFound
	}
	registry, err := s.Store.FindRegistryByID(ctx, invite.RegistryID)
	if err != nil {
		return Invite{}, Registry{}, err
	}
	return invite, registry, nil
}

// RevokeInvite revokes a pending invite. Authorization is OWNER-LEVEL: only an
// owner/admin of the registry may revoke; every other principal (non-member,
// plain member, unknown registry) receives the generic errInviteNotFound so
// invite existence is never enumerated. The invite must be pending — an
// accepted invite cannot be revoked, and an already-revoked invite is an
// idempotent success for the same authorized request.
func (s *Service) RevokeInvite(ctx context.Context, callerUserID int64, registryID int64, inviteID int64) (Invite, error) {
	membership, err := s.Store.FindMembership(ctx, registryID, callerUserID)
	if err != nil {
		return Invite{}, errInviteNotFound
	}
	if membership.Role != "owner" && membership.Role != "admin" {
		return Invite{}, errInviteNotFound
	}
	return s.Store.RevokeInvite(ctx, registryID, inviteID)
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
		// Only the ID is passed: the row's owner and envelope are re-read
		// inside the per-row transaction, so rotation never uses (or can be
		// skewed by) a stale enumerated owner.
		ok, err := s.Store.ReencryptRegistryFeedKey(ctx, registry.ID, fromVersion, toVersion, s.FeedKeys)
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

// WithDecryptedFeedKey resolves the transient plaintext signing key for a
// registry from the row's OWN current stored context (fresh read that also
// validates the envelope invariant) and hands it to fn as mutable bytes OWNED
// by this operation. The bytes are valid only inside fn (the callback is the
// immediate signing boundary); the buffer is zeroed after fn returns, on both
// success and error paths, and is never stringified or persisted. Errors
// never contain key or owner material.
func (s *Service) WithDecryptedFeedKey(ctx context.Context, registryID int64, fn func([]byte) error) error {
	if s.FeedKeys == nil {
		return errFeedKeyCipherNotConfigured
	}
	if fn == nil {
		return errors.New("resolve feed key: nil callback")
	}
	row, err := s.Store.FindRegistryByID(ctx, registryID)
	if err != nil {
		return fmt.Errorf("resolve feed key: %w", err)
	}
	if !row.FeedKeySet {
		return errors.New("registry has no stored encrypted feed key")
	}
	plaintext, err := s.FeedKeys.Decrypt(row.ID, row.FeedOwnerAddress, row.FeedKey)
	if err != nil {
		return err
	}
	defer zeroBytes(plaintext)
	return fn(plaintext)
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
	if s.RegistryTokens == nil {
		return "", &classifiedFailure{cause: causeSigning, class: tokenClassSigning}
	}
	user, err := s.Store.FindUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Unknown account: comparable bcrypt work, generic failure (no
			// account enumeration via the token endpoint).
			_ = bcrypt.CompareHashAndPassword([]byte(dummyPasswordHash), []byte(password))
			return "", &classifiedFailure{cause: causeUnknownAccount, class: tokenClassCredential}
		}
		// A backend/datastore failure: classify it (never "unknown_account")
		// so operators can diagnose while the public response stays generic.
		return "", &classifiedFailure{cause: causeDatastore, class: tokenClassBackend}
	}
	if !comparePassword(user.PasswordHash, password) {
		return "", &classifiedFailure{cause: causeInvalidPassword, class: tokenClassCredential}
	}
	registry, err := s.Store.FindRegistryByHost(ctx, host)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// The caller chose the host, so a missing registry reveals nothing
			// about users or credentials.
			return "", &classifiedFailure{cause: causeRegistryNotFound, class: tokenClassNotFound}
		}
		return "", &classifiedFailure{cause: causeDatastore, class: tokenClassBackend}
	}

	repository, actions, err := auth.ParseDockerScope(scope)
	if err != nil {
		return "", &classifiedFailure{cause: causeInvalidScope, class: tokenClassMalformed}
	}

	membership, err := s.Store.FindMembership(ctx, registry.ID, user.ID)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return "", &classifiedFailure{cause: causeDatastore, class: tokenClassBackend}
		}
		// No membership: only anonymous pull is possible.
		for _, a := range actions {
			if a == auth.ActionPush {
				return "", &classifiedFailure{cause: causeForbidden, class: tokenClassForbidden}
			}
			if a == auth.ActionPull && !registry.AnonymousPull {
				return "", &classifiedFailure{cause: causeForbidden, class: tokenClassForbidden}
			}
		}
		return s.classifiedIssue(host, "anonymous", repository, actions)
	}

	for _, a := range actions {
		switch a {
		case auth.ActionPush:
			if !membership.CanPush {
				return "", &classifiedFailure{cause: causeForbidden, class: tokenClassForbidden}
			}
		case auth.ActionPull:
			if !membership.CanPull && !registry.AnonymousPull {
				return "", &classifiedFailure{cause: causeForbidden, class: tokenClassForbidden}
			}
		}
	}

	subject := "role:read"
	if membership.CanPush {
		subject = "role:write"
	}
	return s.classifiedIssue(host, subject, repository, actions)
}

// classifiedIssue signs a registry token, classifying any failure as signing
// (never exposing the internal issuer error text).
func (s *Service) classifiedIssue(service, subject, repository string, actions []auth.Action) (string, error) {
	if s.RegistryTokens == nil {
		return "", &classifiedFailure{cause: causeSigning, class: tokenClassSigning}
	}
	tok, err := s.RegistryTokens.Issue(context.Background(), auth.RegistryTokenRequest{
		Subject:    subject,
		Service:    service,
		Repository: repository,
		Actions:    actions,
		TTL:        time.Hour,
	})
	if err != nil {
		return "", &classifiedFailure{cause: causeSigning, class: tokenClassSigning}
	}
	return tok, nil
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

// generatePrivateKeyBytes returns 32 fresh cryptographically random bytes:
// the raw feed-owner signing key. The caller owns the slice and MUST wipe it
// (zeroBytes) once the immediate operation is done; it is never stringified.
func generatePrivateKeyBytes() ([]byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	return raw, nil
}
