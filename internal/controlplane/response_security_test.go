package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/uncloud-registry/registry/internal/auth"
)

const knownRegistryPrivateKey = "surveillance-ciphertext-0123456789abcdef"

// TestPublicResponsesDoNotExposeSecrets drives the real HTTP API and UI render
// boundaries against secret names and deterministic secret values. RED reference:
// Task 1 deferred this test so Task 3 could observe it failing before the fix.
func TestPublicResponsesDoNotExposeSecrets(t *testing.T) {
	t.Parallel()

	store, err := OpenSQLite("file:controlplane_respsec_test?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	tokens, err := auth.NewTokenManager("secret")
	if err != nil {
		t.Fatalf("new token manager: %v", err)
	}
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com"}
	server := httptest.NewServer(NewHTTPServer(service, auth.SubjectResolver{Tokens: tokens}))
	defer server.Close()
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}

	// Registration response must not expose the bcrypt password hash.
	regBody := postJSON(t, client, server.URL, "/api/users/register",
		map[string]string{"email": "alice@example.com", "password": "password123"}, "")
	assertNoSecretField(t, regBody, []byte("PasswordHash"), []byte("passwordHash"))

	// Login response must not expose the bcrypt password hash.
	loginBody := postJSON(t, client, server.URL, "/api/auth/login",
		map[string]string{"email": "alice@example.com", "password": "password123"}, "")
	assertNoSecretField(t, loginBody, []byte("PasswordHash"), []byte("passwordHash"))

	alice, aliceSession, err := service.Login(context.Background(), "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	// Seed a registry with a deterministic private key so any leak is detectable.
	created, err := store.CreateRegistry(context.Background(), Registry{
		Slug: "alice", Host: "alice.uncloud-registry.com", ENSName: "alice.eth",
		OwnerUserID:             alice.ID,
		FeedOwnerAddress:        "0xfeed",
		EncryptedFeedPrivateKey: knownRegistryPrivateKey,
		DefaultStampBatchID:     "batch-1",
		AnonymousPull:           false,
	})
	if err != nil {
		t.Fatalf("create registry via store: %v", err)
	}
	if _, err := store.CreateMembership(context.Background(), Membership{
		RegistryID: created.ID, UserID: alice.ID, Role: "owner", CanPull: true, CanPush: true,
	}); err != nil {
		t.Fatalf("create membership: %v", err)
	}

	// API registry create response: no encrypted private key, no persistence-internal owner id.
	createBody := postJSON(t, client, server.URL, "/api/registries",
		map[string]string{"slug": "charlie", "ensName": "charlie.eth", "defaultStampBatchID": "batch-2"},
		aliceSession)
	assertNoSecretField(t, createBody,
		[]byte("EncryptedFeedPrivateKey"), []byte("encryptedFeedPrivateKey"), []byte("ownerUserID"))

	// API registry list response: deterministic secret must not appear.
	listBody := getWithAuth(t, client, server.URL, "/api/registries", aliceSession)
	assertNoSecretField(t, listBody,
		[]byte(knownRegistryPrivateKey), []byte("EncryptedFeedPrivateKey"), []byte("encryptedFeedPrivateKey"))

	// UI registries dashboard: secret must not survive template rendering.
	uiListBody := getWithCookie(t, client, server.URL, "/ui/registries", aliceSession)
	assertNoSecretField(t, uiListBody, []byte(knownRegistryPrivateKey), []byte("EncryptedFeedPrivateKey"))

	// UI registry detail: secret must not render, memberships (public boundary) must.
	uiDetailBody := getWithCookie(t, client, server.URL, "/ui/registries/"+strconv.FormatInt(created.ID, 10), aliceSession)
	assertNoSecretField(t, uiDetailBody, []byte(knownRegistryPrivateKey), []byte("EncryptedFeedPrivateKey"))
	if !bytes.Contains(uiDetailBody, []byte("alice@example.com")) {
		t.Fatalf("expected member email rendered in detail page (public boundary), body: %s", uiDetailBody)
	}

	// API invite create: one-time raw token in its own field, token hash never.
	inviteBody := postJSON(t, client, server.URL, "/api/registries/"+strconv.FormatInt(created.ID, 10)+"/invites",
		map[string]any{"email": "bob@example.com", "canPull": true, "canPush": true}, aliceSession)
	assertNoSecretField(t, inviteBody, []byte("TokenHash"), []byte("tokenHash"))
	var invited map[string]any
	if err := json.Unmarshal(inviteBody, &invited); err != nil {
		t.Fatalf("decode invite response: %v", err)
	}
	rawToken, _ := invited["token"].(string)
	if rawToken == "" {
		t.Fatalf("expected raw invite token in creation response, body: %s", inviteBody)
	}

	// API invite accept: bob accepts; response must not carry the token hash.
	if _, _, err := service.RegisterUser(context.Background(), "bob@example.com", "password123"); err != nil {
		t.Fatalf("register bob: %v", err)
	}
	_, bobSession, err := service.Login(context.Background(), "bob@example.com", "password123")
	if err != nil {
		t.Fatalf("login bob: %v", err)
	}
	acceptBody := postJSON(t, client, server.URL, "/api/invites/accept",
		map[string]string{"token": rawToken}, bobSession)
	assertNoSecretField(t, acceptBody, []byte("TokenHash"), []byte("tokenHash"))
}

func postJSON(t *testing.T, client *http.Client, base string, path string, body any, bearer string) []byte {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("unexpected status %d for %s: %s", resp.StatusCode, path, data)
	}
	return data
}

func getWithAuth(t *testing.T, client *http.Client, base string, path string, bearer string) []byte {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	return doGet(t, client, req, path)
}

func getWithCookie(t *testing.T, client *http.Client, base string, path string, session string) []byte {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	return doGet(t, client, req, path)
}

func doGet(t *testing.T, client *http.Client, req *http.Request, path string) []byte {
	t.Helper()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("get %s: %v", path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d for %s: %s", resp.StatusCode, path, data)
	}
	return data
}

func assertNoSecretField(t *testing.T, raw []byte, secrets ...[]byte) {
	t.Helper()
	for _, secret := range secrets {
		if bytes.Contains(raw, secret) {
			t.Fatalf("secret leaked in response: %q in %s", secret, raw)
		}
	}
}