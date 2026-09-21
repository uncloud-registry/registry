package controlplane

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
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
		Publisher: &Publisher{
			Documents: &memoryUploader{refs: map[string][]byte{}},
			Feeds:     &MemoryRegistryFeedUpdater{Feeds: map[string]string{}},
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
	feeds := &MemoryRegistryFeedUpdater{Feeds: map[string]string{}}
	service := &Service{
		Store:          store,
		Tokens:         manager,
		RegistryDomain: "uncloud-registry.com",
		Publisher: &Publisher{
			Documents: uploader,
			Feeds:     feeds,
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
	authFeed := authPolicyFeedRef(created.Registry)
	authRef := feeds.Feeds[authFeed]
	if authRef == "" {
		t.Fatalf("expected auth policy feed update for %s", authFeed)
	}
	data := uploader.refs[authRef]
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
}

func TestInviteExpires(t *testing.T) {
	t.Parallel()

	store, err := OpenSQLite("file:controlplane_test_three?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	owner, err := store.CreateUser(context.Background(), "alice@example.com", "hash")
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	registry, err := store.CreateRegistry(context.Background(), Registry{
		Slug:                    "alice",
		Host:                    "alice.uncloud-registry.com",
		ENSName:                 "alice.eth",
		OwnerUserID:             owner.ID,
		FeedOwnerAddress:        "0xfeed",
		EncryptedFeedPrivateKey: "cipher",
		DefaultStampBatchID:     "batch-1",
		AnonymousPull:           true,
	})
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	invite, token, err := store.CreateInvite(context.Background(), Invite{
		RegistryID: registry.ID,
		Email:      "test@example.com",
		Role:       "member",
		CanPull:    true,
		CanPush:    true,
		ExpiresAt:  time.Now().UTC().Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	if invite.Status != "pending" || token == "" {
		t.Fatalf("unexpected invite creation result")
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
	feeds := &MemoryRegistryFeedUpdater{Feeds: map[string]string{}}
	service := &Service{
		Store:          store,
		Tokens:         manager,
		RegistryDomain: "uncloud-registry.com",
		Publisher: &Publisher{
			Documents: uploader,
			Feeds:     feeds,
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
	feeds := &MemoryRegistryFeedUpdater{Feeds: map[string]string{}}
	service := &Service{
		Store:          store,
		Tokens:         manager,
		RegistryTokens: registryTokens,
		RegistryDomain: "uncloud-registry.com",
		Publisher: &Publisher{
			Documents: uploader,
			Feeds:     feeds,
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
}

func (m *memoryUploader) Put(_ context.Context, data []byte, _ string) (string, error) {
	m.order++
	ref := fmt.Sprintf("ref-%d", m.order)
	copyData := make([]byte, len(data))
	copy(copyData, data)
	m.refs[ref] = copyData
	return ref, nil
}

func TestPublisherBuildsBootstrapDocuments(t *testing.T) {
	t.Parallel()

	uploader := &memoryUploader{refs: map[string][]byte{}}
	feeds := &MemoryRegistryFeedUpdater{Feeds: map[string]string{}}
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

// newTestSessionManager builds a control-plane session token manager with the
// default issuer/audience and a fixed test-only secret.
func newTestSessionManager(t *testing.T) *auth.SessionTokenManager {
	t.Helper()
	m, err := auth.NewSessionTokenManager("secret", auth.DefaultSessionIssuer, auth.DefaultSessionAudience)
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
