package controlplane

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/spec"
)

func TestServiceRegisterLoginCreateRegistryAndInvite(t *testing.T) {
	t.Parallel()

	store, err := OpenSQLite("file:controlplane_test_one?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	manager := newTestSessionManager(t)
	registryTokens, _ := newTestRegistryPair(t)
	service := &Service{
		Store:          store,
		Tokens:         manager,
		RegistryTokens: registryTokens,
		RegistryDomain: "uncloud-registry.com",
		FeedKeys:       newTestFeedKeyCipher(t),
		Publisher: &Publisher{
			Documents:   &memoryUploader{refs: map[string][]byte{}},
			Feeds:       &MemoryRegistryFeedUpdater{Feeds: map[string]string{}},
			FeedsReader: &MemoryRegistryFeedStore{Feeds: map[string]string{}},
		},
	}

	user, _, err := service.RegisterUser(context.Background(), "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("register user: %v", err)
	}

	if _, _, err := service.Login(context.Background(), "alice@example.com", "password123"); err != nil {
		t.Fatalf("login: %v", err)
	}

	created, err := service.CreateRegistry(context.Background(), user.ID, "alice", "alice.eth", true, "batch-1")
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	registry := created.Registry
	if registry.Host != "alice.uncloud-registry.com" {
		t.Fatalf("unexpected registry host: %s", registry.Host)
	}
	if created.Bootstrap.FeedOwnerAddress == "" || created.Bootstrap.AuthPolicyFeed == "" || created.Bootstrap.StampPolicyFeed == "" {
		t.Fatalf("expected bootstrap publication, got %+v", created.Bootstrap)
	}

	invite, token, err := service.CreateInvite(context.Background(), registry.ID, user.ID, "bob@example.com", true, true)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	if token == "" || !invite.CanPush {
		t.Fatalf("unexpected invite/token: %+v token=%q", invite, token)
	}

	bob, _, err := service.RegisterUser(context.Background(), "bob@example.com", "password123")
	if err != nil {
		t.Fatalf("register bob: %v", err)
	}

	accepted, err := service.AcceptInvite(context.Background(), token, bob.ID)
	if err != nil {
		t.Fatalf("accept invite: %v", err)
	}
	if accepted.Status != "accepted" {
		t.Fatalf("unexpected invite status: %s", accepted.Status)
	}

	registryToken, err := service.IssueRegistryToken(context.Background(), registry.Host, "repository:backend/api:push", "bob@example.com", "password123")
	if err != nil {
		t.Fatalf("issue registry token: %v", err)
	}
	if registryToken == "" {
		t.Fatal("expected registry token")
	}
}

func TestBootstrapPublishesRoleBasedAuthPolicy(t *testing.T) {
	t.Parallel()

	store, err := OpenSQLite("file:controlplane_test_two?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	manager := newTestSessionManager(t)
	uploader := &memoryUploader{refs: map[string][]byte{}}
	feeds := &MemoryRegistryFeedStore{Feeds: map[string]string{}}
	service := &Service{
		Store:          store,
		Tokens:         manager,
		RegistryDomain: "uncloud-registry.com",
		FeedKeys:       newTestFeedKeyCipher(t),
		Publisher: &Publisher{
			Documents:   uploader,
			Feeds:       feeds,
			FeedsReader: feeds,
		},
	}

	alice, _, err := service.RegisterUser(context.Background(), "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("register alice: %v", err)
	}
	created, err := service.CreateRegistry(context.Background(), alice.ID, "alice", "alice.eth", true, "batch-1")
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	if created.State != ProvisioningStateProvisioning {
		t.Fatalf("expected provisioning state at creation, got %q", created.State)
	}

	// Publication is transactional outbox, so nothing is published until the
	// reconciler runs. Drive RunOnce to publish both bootstrap jobs.
	reconciler, err := service.NewReconciler()
	if err != nil {
		t.Fatalf("expected a reconciler from a publisher-backed service: %v", err)
	}
	if err := reconciler.RunOnce(context.Background()); err != nil {
		t.Fatalf("run once: %v", err)
	}

	authFeed := authPolicyFeedRef(created.Registry)
	authRef := feeds.Feeds[authFeed]
	if authRef == "" {
		t.Fatalf("expected auth policy feed update for %s after reconciliation", authFeed)
	}
	// The feed must point at an object whose content read-back matched the
	// published policy document (the reconciler's verified read-back proof).
	data, err := uploader.Get(context.Background(), authRef)
	if err != nil {
		t.Fatalf("read back auth document: %v", err)
	}
	doc, err := spec.DecodeAuthPolicyDocument(data)
	if err != nil {
		t.Fatalf("decode auth policy: %v", err)
	}
	if doc.DefaultRepo == nil {
		t.Fatal("expected default repo policy")
	}
	if len(doc.DefaultRepo.Push) != 1 || doc.DefaultRepo.Push[0] != "role:write" {
		t.Fatalf("expected role-based write policy, got %+v", doc.DefaultRepo.Push)
	}
	if len(doc.DefaultRepo.Pull) != 3 {
		t.Fatalf("expected anonymous + read/write pull policy, got %+v", doc.DefaultRepo.Pull)
	}

	// Both jobs complete verified read-back → the registry is 'ready'.
	registry, err := store.FindRegistryByID(context.Background(), created.Registry.ID)
	if err != nil {
		t.Fatalf("find registry: %v", err)
	}
	if registry.ProvisioningState != ProvisioningStateReady {
		t.Fatalf("expected registry ready after both jobs complete, got %q", registry.ProvisioningState)
	}
}

// TestInviteExpiryBoundary pins the explicit expiry semantics with a
// deterministic injectable clock: creation must reject a non-future expiry,
// acceptance at exactly expires_at must fail ("at expires_at is expired"),
// and acceptance strictly before it must succeed.
func TestInviteExpiryBoundary(t *testing.T) {
	t.Parallel()

	store, err := OpenSQLite("file:controlplane_test_three?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	ctx := context.Background()
	owner, err := store.CreateUser(ctx, "alice@example.com", "hash")
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	registry, err := store.CreateRegistry(ctx, Registry{
		Slug: "alice", Host: "alice.uncloud-registry.com", ENSName: "alice.eth",
		OwnerUserID: owner.ID, FeedOwnerAddress: "0xfeed", DefaultStampBatchID: "batch-1",
		AnonymousPull: true,
	}, nil, nil)
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	bob, err := store.CreateUser(ctx, "bob@example.com", "hash")
	if err != nil {
		t.Fatalf("create bob: %v", err)
	}

	fixed := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return fixed }

	// Creation with an expiry in the past (or exactly at now) must be rejected.
	if _, _, err := store.CreateInvite(ctx, Invite{
		RegistryID: registry.ID, Email: "bob@example.com", Role: "member",
		CanPull: true, CanPush: true, ExpiresAt: fixed.Add(-time.Hour),
	}); err == nil {
		t.Fatal("expected creation with past expiry to be rejected")
	}
	if _, _, err := store.CreateInvite(ctx, Invite{
		RegistryID: registry.ID, Email: "bob@example.com", Role: "member",
		CanPull: true, CanPush: true, ExpiresAt: fixed,
	}); err == nil {
		t.Fatal("expected creation with at-now expiry to be rejected")
	}

	// Expiry strictly inside the future window: acceptable at now...
	invite, token, err := store.CreateInvite(ctx, Invite{
		RegistryID: registry.ID, Email: "bob@example.com", Role: "member",
		CanPull: true, CanPush: true, ExpiresAt: fixed.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	if invite.Status != "pending" || token == "" {
		t.Fatalf("unexpected invite creation result")
	}
	accepted, err := store.AcceptInvite(ctx, token, bob)
	if err != nil {
		t.Fatalf("accept before expiry: %v", err)
	}
	if accepted.Status != "accepted" {
		t.Fatalf("unexpected accepted status: %s", accepted.Status)
	}

	// ...and a SECOND invite expiring at exactly fixed+1h fails AT the boundary:
	// the clock advances to expires_at; "at expires_at is expired".
	_, token2, err := store.CreateInvite(ctx, Invite{
		RegistryID: registry.ID, Email: "bob@example.com", Role: "member",
		CanPull: true, CanPush: true, ExpiresAt: fixed.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatalf("create second invite: %v", err)
	}
	store.now = func() time.Time { return fixed.Add(2 * time.Hour) }
	if _, err := store.AcceptInvite(ctx, token2, bob); err == nil {
		t.Fatal("expected acceptance exactly at expires_at to fail")
	}
}

func TestAcceptInviteIsIdempotentForExistingMembership(t *testing.T) {
	t.Parallel()

	store, err := OpenSQLite("file:controlplane_test_four?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	manager := newTestSessionManager(t)
	uploader := &memoryUploader{refs: map[string][]byte{}}
	feeds := &MemoryRegistryFeedStore{Feeds: map[string]string{}}
	service := &Service{
		Store:          store,
		Tokens:         manager,
		RegistryDomain: "uncloud-registry.com",
		FeedKeys:       newTestFeedKeyCipher(t),
		Publisher: &Publisher{
			Documents:   uploader,
			Feeds:       feeds,
			FeedsReader: feeds,
		},
	}

	alice, _, err := service.RegisterUser(context.Background(), "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("register alice: %v", err)
	}
	created, err := service.CreateRegistry(context.Background(), alice.ID, "alice", "alice.eth", true, "batch-1")
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}

	bob, _, err := service.RegisterUser(context.Background(), "bob@example.com", "password123")
	if err != nil {
		t.Fatalf("register bob: %v", err)
	}
	invite, token, err := service.CreateInvite(context.Background(), created.Registry.ID, alice.ID, "bob@example.com", true, true)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	if _, err := service.AcceptInvite(context.Background(), token, bob.ID); err != nil {
		t.Fatalf("first accept: %v", err)
	}
	acceptedAgain, err := service.AcceptInvite(context.Background(), token, bob.ID)
	if err != nil {
		t.Fatalf("second accept: %v", err)
	}
	if acceptedAgain.Status != "accepted" || invite.Email != acceptedAgain.Email {
		t.Fatalf("unexpected second accept result: %+v", acceptedAgain)
	}
	memberships, err := store.ListMembershipsForRegistry(context.Background(), created.Registry.ID)
	if err != nil {
		t.Fatalf("list memberships: %v", err)
	}
	if len(memberships) != 2 {
		t.Fatalf("expected two memberships, got %d", len(memberships))
	}
}

func TestUpdateCollaboratorPermissionsAffectsIssuedTokenScopes(t *testing.T) {
	t.Parallel()

	store, err := OpenSQLite("file:controlplane_test_five?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	manager := newTestSessionManager(t)
	registryTokens, pubKeys := newTestRegistryPair(t)
	uploader := &memoryUploader{refs: map[string][]byte{}}
	feeds := &MemoryRegistryFeedStore{Feeds: map[string]string{}}
	service := &Service{
		Store:          store,
		Tokens:         manager,
		RegistryTokens: registryTokens,
		RegistryDomain: "uncloud-registry.com",
		FeedKeys:       newTestFeedKeyCipher(t),
		Publisher: &Publisher{
			Documents:   uploader,
			Feeds:       feeds,
			FeedsReader: feeds,
		},
	}

	alice, _, err := service.RegisterUser(context.Background(), "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("register alice: %v", err)
	}
	created, err := service.CreateRegistry(context.Background(), alice.ID, "alice", "alice.eth", false, "batch-1")
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	bob, _, err := service.RegisterUser(context.Background(), "bob@example.com", "password123")
	if err != nil {
		t.Fatalf("register bob: %v", err)
	}
	_, rawToken, err := service.CreateInvite(context.Background(), created.Registry.ID, alice.ID, "bob@example.com", true, true)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	if _, err := service.AcceptInvite(context.Background(), rawToken, bob.ID); err != nil {
		t.Fatalf("accept invite: %v", err)
	}

	_, err = service.UpdateCollaboratorPermissions(context.Background(), alice.ID, created.Registry.ID, []Membership{{
		UserID:  bob.ID,
		CanPull: true,
		CanPush: false,
	}})
	if err != nil {
		t.Fatalf("update permissions: %v", err)
	}

	if _, err := service.IssueRegistryToken(context.Background(), created.Registry.Host, "repository:backend/api:push", "bob@example.com", "password123"); err == nil {
		t.Fatal("expected push token issuance to be denied after removing push permission")
	}
	registryToken, err := service.IssueRegistryToken(context.Background(), created.Registry.Host, "repository:backend/api:pull", "bob@example.com", "password123")
	if err != nil {
		t.Fatalf("expected pull token issuance to succeed: %v", err)
	}
	verifier := auth.NewRegistryTokenVerifier(staticTestKeySet(pubKeys), auth.RegistryIssuer, created.Registry.Host)
	principal, err := verifier.Verify(registryToken, created.Registry.Host, "backend/api", auth.ActionPull)
	if err != nil {
		t.Fatalf("verify registry token: %v", err)
	}
	if principal.Subject != "role:read" {
		t.Fatalf("expected read role subject, got %q", principal.Subject)
	}
}

type memoryUploader struct {
	refs  map[string][]byte
	order int
	mu    sync.Mutex
}

func (m *memoryUploader) Put(_ context.Context, data []byte, _ string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.order++
	ref := fmt.Sprintf("ref-%d", m.order)
	copyData := make([]byte, len(data))
	copy(copyData, data)
	m.refs[ref] = copyData
	return ref, nil
}

// Get implements ObjectStore so memoryUploader can double as the reconciler's
// read-backed store. A missing/unknown ref is treated as an error so a stale
// read-back is distinguishable from success.
func (m *memoryUploader) Get(_ context.Context, ref string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.refs[ref]
	if !ok {
		return nil, fmt.Errorf("memory store: unknown reference %q", ref)
	}
	out := make([]byte, len(data))
	copy(out, data)
	return out, nil
}

func TestAnonymousPullNeverBroadensMemberPush(t *testing.T) {
	t.Parallel()

	store, err := OpenSQLite("file:controlplane_test_anon_matrix?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	manager := newTestSessionManager(t)
	registryTokens, pubKeys := newTestRegistryPair(t)
	uploader := &memoryUploader{refs: map[string][]byte{}}
	feeds := &MemoryRegistryFeedStore{Feeds: map[string]string{}}
	service := &Service{
		Store:          store,
		Tokens:         manager,
		RegistryTokens: registryTokens,
		RegistryDomain: "uncloud-registry.com",
		FeedKeys:       newTestFeedKeyCipher(t),
		Publisher:      &Publisher{Documents: uploader, Feeds: feeds, FeedsReader: feeds},
	}

	alice, _, err := service.RegisterUser(context.Background(), "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("register alice: %v", err)
	}
	// anonymousPull=false initially.
	created, err := service.CreateRegistry(context.Background(), alice.ID, "alice", "alice.eth", false, "batch-1")
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	host := created.Registry.Host

	// The provisioning gate requires settings changes to wait until bootstrap
	// publication completes, so drive the registry to 'ready' first.
	reconciler, err := service.NewReconciler()
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	if err := reconciler.RunOnce(context.Background()); err != nil {
		t.Fatalf("reconcile to ready: %v", err)
	}
	if reg, err := store.FindRegistryByID(context.Background(), created.Registry.ID); err != nil {
		t.Fatalf("find registry: %v", err)
	} else if reg.ProvisioningState != ProvisioningStateReady {
		t.Fatalf("registry must reach ready before settings change, got %q", reg.ProvisioningState)
	}

	// bob is a member with pull-only permission (CanPush=false).
	bob, _, err := service.RegisterUser(context.Background(), "bob@example.com", "password123")
	if err != nil {
		t.Fatalf("register bob: %v", err)
	}
	_, inviteToken, err := service.CreateInvite(context.Background(), created.Registry.ID, alice.ID, "bob@example.com", true, false)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	if _, err := service.AcceptInvite(context.Background(), inviteToken, bob.ID); err != nil {
		t.Fatalf("accept invite: %v", err)
	}

	// carol has no membership.
	carol, _, err := service.RegisterUser(context.Background(), "carol@example.com", "password123")
	if err != nil {
		t.Fatalf("register carol: %v", err)
	}
	_ = carol

	issue := func(email, password, scope string) error {
		_, err := service.IssueRegistryToken(context.Background(), host, scope, email, password)
		return err
	}

	// Explicit matrix: member without push on a NON-anonymous registry.
	if err := issue("bob@example.com", "password123", "repository:backend/api:push"); err == nil {
		t.Fatal("expected pull-only member push to be denied on non-anonymous registry")
	}
	if err := issue("bob@example.com", "password123", "repository:backend/api:pull"); err != nil {
		t.Fatalf("expected pull-only member pull to be allowed on non-anonymous registry: %v", err)
	}
	if err := issue("carol@example.com", "password123", "repository:backend/api:pull"); err == nil {
		t.Fatal("expected non-member pull to be denied on non-anonymous registry")
	}

	// Turn on anonymous pull. Anonymous pull must NOT grant push to a member
	// who lacks push permission.
	if _, err := service.UpdateRegistrySettings(context.Background(), alice.ID, created.Registry.ID, true, "batch-1"); err != nil {
		t.Fatalf("update to anonymous pull: %v", err)
	}

	if err := issue("bob@example.com", "password123", "repository:backend/api:push"); err == nil {
		t.Fatal("expected pull-only member push to be denied even on anonymous-pull registry (anonymous pull authorizes pull only)")
	}
	if err := issue("bob@example.com", "password123", "repository:backend/api:pull"); err != nil {
		t.Fatalf("expected pull-only member pull to be allowed on anonymous-pull registry: %v", err)
	}
	// Anonymous pull authorizes anonymous (non-member) pull.
	if err := issue("carol@example.com", "password123", "repository:backend/api:pull"); err != nil {
		t.Fatalf("expected anonymous non-member pull on anonymous-pull registry: %v", err)
	}
	// But never anonymous push, even on an anonymous-pull registry.
	if err := issue("carol@example.com", "password123", "repository:backend/api:push"); err == nil {
		t.Fatal("expected anonymous non-member push to be denied on anonymous-pull registry")
	}

	// The issued pull token for bob still verifies against the registry verifier
	// with the pull action and a read subject.
	regToken, err := service.IssueRegistryToken(context.Background(), host, "repository:backend/api:pull", "bob@example.com", "password123")
	if err != nil {
		t.Fatalf("issue bob pull token: %v", err)
	}
	verifier := auth.NewRegistryTokenVerifier(staticTestKeySet(pubKeys), auth.RegistryIssuer, host)
	principal, err := verifier.Verify(regToken, host, "backend/api", auth.ActionPull)
	if err != nil {
		t.Fatalf("verify bob pull token: %v", err)
	}
	if principal.Subject != "role:read" {
		t.Fatalf("expected read subject for pull-only member, got %q", principal.Subject)
	}
}

func TestPublisherBuildsBootstrapDocuments(t *testing.T) {
	t.Parallel()

	uploader := &memoryUploader{refs: map[string][]byte{}}
	feeds := &MemoryRegistryFeedStore{Feeds: map[string]string{}}
	publisher := &Publisher{Documents: uploader, Feeds: feeds}

	registry := Registry{
		Slug:                "alice",
		Host:                "alice.uncloud-registry.com",
		FeedOwnerAddress:    "0x1234abcd",
		DefaultStampBatchID: "batch-1",
		AnonymousPull:       true,
	}

	bootstrap, err := publisher.PublishBootstrap(context.Background(), registry, []MembershipSubject{{UserID: 1, Role: "owner", CanPull: true, CanPush: true}})
	if err != nil {
		t.Fatalf("publish bootstrap: %v", err)
	}
	if bootstrap.FeedOwnerAddress != registry.FeedOwnerAddress {
		t.Fatalf("unexpected feed owner address: %s", bootstrap.FeedOwnerAddress)
	}

	authRef := feeds.Feeds[bootstrap.AuthPolicyFeed]
	if authRef == "" {
		t.Fatal("expected auth feed update")
	}
	authDoc, err := spec.DecodeAuthPolicyDocument(uploader.refs[authRef])
	if err != nil {
		t.Fatalf("decode auth document: %v", err)
	}
	if authDoc.DefaultRepo == nil || len(authDoc.DefaultRepo.Pull) == 0 {
		raw, _ := json.Marshal(authDoc)
		t.Fatalf("unexpected auth document: %s", raw)
	}
}

// controlplaneTestSecret is a strong, test-only HMAC secret (>=32 bytes) used
// by newTestSessionManager.
const controlplaneTestSecret = "controlplane-test-session-secret-0123456789abcdef"

// newTestSessionManager builds a control-plane session token manager with the
// default issuer/audience and a fixed test-only secret.
func newTestSessionManager(t *testing.T) *auth.SessionTokenManager {
	t.Helper()
	m, err := auth.NewSessionTokenManager(controlplaneTestSecret, auth.DefaultSessionIssuer, auth.DefaultSessionAudience)
	if err != nil {
		t.Fatalf("new session token manager: %v", err)
	}
	return m
}

// newTestRegistryPair returns a per-test Ed25519 registry issuer and the set of
// public verification keys a matching verifier can use.
func newTestRegistryPair(t *testing.T) (*auth.RegistryTokenIssuer, map[string]ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate registry key: %v", err)
	}
	issuer, err := auth.NewRegistryTokenIssuer(priv, auth.RegistryIssuer, "test-key-1")
	if err != nil {
		t.Fatalf("new registry issuer: %v", err)
	}
	return issuer, map[string]ed25519.PublicKey{"test-key-1": pub}
}

type staticTestKeySet map[string]ed25519.PublicKey

func (s staticTestKeySet) Key(_ context.Context, keyID string) (ed25519.PublicKey, error) {
	pk, ok := s[keyID]
	if !ok {
		return nil, fmt.Errorf("unknown kid %q", keyID)
	}
	return pk, nil
}
