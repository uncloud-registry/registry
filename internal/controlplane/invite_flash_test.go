package controlplane

import (
	"bytes"
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/uncloud-registry/registry/internal/auth"
)

// TestUIInviteFlashIsOneTimeAndBound drives the real UI invite-creation flow and
// proves the raw invite token is carried from the POST to the next GET only via a
// server-side one-time flash:
//
//   - the 303 redirect Location carries only a random opaque flash ID — neither the
//     raw token nor the persisted TokenHash;
//   - the first authenticated GET of the redirect renders the raw token exactly once;
//   - a second GET of the identical redirect renders no raw token / hash / accept link;
//   - an authenticated user who is not the flash owner, and the owner against the
//     wrong registry, each reveal nothing and must NOT consume the flash;
//   - an unknown flash ID reveals nothing.
//
// RED reference (round 1/5): the current handler embeds the raw token directly in
// the redirect (`?invite_token=<raw>`), so this test fails on the Location assertion.
func TestUIInviteFlashIsOneTimeAndBound(t *testing.T) {
	t.Parallel()

	store, err := OpenSQLite("file:controlplane_invflash_e2e_test?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	tokens := newTestSessionManager(t)
	service := &Service{Store: store, Tokens: tokens, RegistryDomain: "uncloud-registry.com"}
	server := httptest.NewServer(NewHTTPServer(service, auth.SubjectResolver{Tokens: tokens}))
	defer server.Close()
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}

	// alice owns two registries; charlie is a collaborator on reg1 (can view its
	// detail page) but is not the flash owner; bob is the invitee.
	if _, _, err := service.RegisterUser(context.Background(), "alice@example.com", "password123"); err != nil {
		t.Fatalf("register alice: %v", err)
	}
	if _, _, err := service.RegisterUser(context.Background(), "bob@example.com", "password123"); err != nil {
		t.Fatalf("register bob: %v", err)
	}
	if _, _, err := service.RegisterUser(context.Background(), "charlie@example.com", "password123"); err != nil {
		t.Fatalf("register charlie: %v", err)
	}
	alice, aliceSession, err := service.Login(context.Background(), "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("login alice: %v", err)
	}
	_, charlieSession, err := service.Login(context.Background(), "charlie@example.com", "password123")
	if err != nil {
		t.Fatalf("login charlie: %v", err)
	}
	reg1 := createTestRegistry(t, store, alice.ID, "alice", "alice.uncloud-registry.com")
	reg2 := createTestRegistry(t, store, alice.ID, "alice-two", "alice2.uncloud-registry.com")
	if _, err := store.CreateMembership(context.Background(), Membership{
		RegistryID: reg1.ID, UserID: alice.ID, Role: "owner", CanPull: true, CanPush: true,
	}); err != nil {
		t.Fatalf("create reg1 owner membership: %v", err)
	}
	if _, err := store.CreateMembership(context.Background(), Membership{
		RegistryID: reg2.ID, UserID: alice.ID, Role: "owner", CanPull: true, CanPush: true,
	}); err != nil {
		t.Fatalf("create reg2 owner membership: %v", err)
	}
	charlie, _, err := service.Login(context.Background(), "charlie@example.com", "password123")
	if err != nil {
		t.Fatalf("re-login charlie for id: %v", err)
	}
	if _, err := store.CreateMembership(context.Background(), Membership{
		RegistryID: reg1.ID, UserID: charlie.ID, Role: "member", CanPull: true, CanPush: true,
	}); err != nil {
		t.Fatalf("create charlie collaborator membership: %v", err)
	}

	// --- 1. Submit the UI invite-creation form; capture the actual 303 Location. ---
	reg1Path := "/ui/registries/" + strconv.FormatInt(reg1.ID, 10) + "/invites"
	_, location, _ := postForm(t, client, server.URL, reg1Path,
		url.Values{"email": {"bob@example.com"}, "can_pull": {"true"}, "can_push": {"true"}}, aliceSession)
	if location == "" {
		t.Fatalf("expected a 303 Location on invite creation, got none")
	}

	// Recover the one-time raw token and persisted hex TokenHash from the store so we
	// can assert the redirect leaks neither.
	pending, err := store.ListInvitesForRegistry(context.Background(), reg1.ID)
	if err != nil || len(pending) == 0 {
		t.Fatalf("no persisted invite: %v", err)
	}
	persistedHash := pending[0].TokenHash
	raw, err := hex.DecodeString(persistedHash)
	if err != nil {
		t.Fatalf("persisted TokenHash not hex of raw token: %v", err)
	}
	rawToken := string(raw)

	// Location must contain neither the raw token nor the persisted hex hash; it must
	// carry only a random opaque flash ID.
	if bytes.Contains([]byte(location), []byte(rawToken)) || bytes.Contains([]byte(location), []byte(persistedHash)) {
		t.Fatalf("redirect Location leaks invite token: %s", location)
	}
	locURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	flashID := locURL.Query().Get("invite_flash")
	if flashID == "" {
		t.Fatalf("expected an opaque invite_flash ID in Location, got empty (Location: %s)", location)
	}
	if locURL.Query().Get("invite_token") != "" {
		t.Fatalf("Location still exposes invite_token query param")
	}
	// The flash ID itself must not equal the raw token or the persisted hash (already
	// covered by the substring check above, but asserted explicitly for clarity).
	if flashID == rawToken || flashID == persistedHash {
		t.Fatalf("flash ID looks like the invite secret: %s", flashID)
	}

	// Path helper for the exact redirect Location (a full URL from httptest server).
	locationPath := locURL.RequestURI()

	thisFlash := func(raw []byte) bool {
		return bytes.Contains(raw, []byte(rawToken)) ||
			bytes.Contains(raw, []byte(persistedHash)) ||
			bytes.Contains(raw, []byte("/ui/invites/accept"))
	}

	// --- 2. Wrong user must NOT reveal and must NOT consume. ---
	charlieGET := getRaw(t, client, server.URL, locationPath, charlieSession)
	if charlieGET.status != http.StatusOK {
		t.Fatalf("expected charlie (collaborator) to view detail, got %d", charlieGET.status)
	}
	if thisFlash(charlieGET.body) {
		t.Fatalf("wrong user revealed the invite flash token: %s", charlieGET.body)
	}

	// --- 3. Owner on the WRONG registry must NOT reveal and must NOT consume. ---
	wrongReg := "/ui/registries/" + strconv.FormatInt(reg2.ID, 10) + "?" + locURL.RawQuery
	ownerWrongReg := getRaw(t, client, server.URL, wrongReg, aliceSession)
	if ownerWrongReg.status != http.StatusOK {
		t.Fatalf("expected owner to view their other registry detail, got %d", ownerWrongReg.status)
	}
	if thisFlash(ownerWrongReg.body) {
		t.Fatalf("wrong-registry request revealed the invite flash token: %s", ownerWrongReg.body)
	}

	// --- 4. Legitimate first GET by the owner renders the raw token exactly once. ---
	first := getRaw(t, client, server.URL, locationPath, aliceSession)
	if first.status != http.StatusOK {
		t.Fatalf("expected owner first GET to succeed, got %d", first.status)
	}
	if !bytes.Contains(first.body, []byte(rawToken)) || !bytes.Contains(first.body, []byte("/ui/invites/accept")) {
		t.Fatalf("first GET must render the one-time invite link with the raw token, body: %s", first.body)
	}

	// --- 5. Replaying the identical redirect must reveal nothing further. ---
	second := getRaw(t, client, server.URL, locationPath, aliceSession)
	if second.status != http.StatusOK {
		t.Fatalf("expected replay GET to succeed, got %d", second.status)
	}
	if thisFlash(second.body) {
		t.Fatalf("replayed redirect re-exposed the invite token: %s", second.body)
	}

	// --- 6. Unknown flash ID reveals nothing. ---
	unknown := getRaw(t, client, server.URL,
		"/ui/registries/"+strconv.FormatInt(reg1.ID, 10)+"?invite_flash="+hex.EncodeToString([]byte("not-a-real-flash")), aliceSession)
	if unknown.status != http.StatusOK {
		t.Fatalf("expected unknown-flash GET to succeed, got %d", unknown.status)
	}
	if thisFlash(unknown.body) {
		t.Fatalf("unknown flash ID revealed a token: %s", unknown.body)
	}
}
