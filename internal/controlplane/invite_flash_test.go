package controlplane

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"testing"

	"github.com/uncloud-registry/registry/internal/auth"
)

// acceptLinkTokenRe matches the one-time accept link rendered by the flash
// page: /ui/invites/accept?token=<32 canonical base64url chars>.
var acceptLinkTokenRe = regexp.MustCompile(`/ui/invites/accept\?token=([A-Za-z0-9_-]{32})`)

// TestUIInviteFlashIsOneTimeAndBound drives the real UI invite-creation flow and
// proves the raw invite token is carried from the POST to the next GET only via a
// server-side one-time flash:
//
//   - the 303 redirect Location carries only a random opaque flash ID — neither
//     the raw token nor any encoding of the persisted digest;
//   - the first authenticated GET of the redirect renders the raw token exactly once;
//   - a second GET of the identical redirect renders no raw token / digest / accept link;
//   - an authenticated user who is not the flash owner, and the owner against the
//     wrong registry, each reveal nothing and must NOT consume the flash;
//   - an unknown flash ID reveals nothing.
//
// The persisted token credential is a one-way SHA-256 digest (32 raw bytes) and
// can never be decoded back into the token, so the raw token is recovered from
// the one-time flash render itself (the only place it legitimately appears).
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

	// The persisted credential is the one-way digest: capture every encoding so
	// the redirect can be proven to leak none of them.
	pending, err := store.ListInvitesForRegistry(context.Background(), reg1.ID)
	if err != nil || len(pending) == 0 {
		t.Fatalf("no persisted invite: %v", err)
	}
	digest := pending[0].TokenDigest
	if len(digest) != 32 {
		t.Fatalf("expected 32-byte persisted digest, got %d bytes", len(digest))
	}
	digestHex := hex.EncodeToString(digest)
	digestB64 := base64.RawURLEncoding.EncodeToString(digest)

	leaksAny := func(raw []byte, tokens ...[]byte) bool {
		for _, tok := range tokens {
			if bytes.Contains(raw, tok) {
				return true
			}
		}
		return false
	}
	digestLeak := func(raw []byte) bool {
		return leaksAny(raw, []byte(digestHex), []byte(digestB64), digest, []byte("/ui/invites/accept"))
	}

	// Location must contain neither the raw token (unknown yet, but the accept
	// link would carry it) nor any encoding of the persisted digest; it must
	// carry only a random opaque flash ID.
	if digestLeak([]byte(location)) {
		t.Fatalf("redirect Location leaks invite credential: %s", location)
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
	if flashID == digestHex || flashID == digestB64 {
		t.Fatalf("flash ID looks like the invite secret: %s", flashID)
	}

	// Path helper for the exact redirect Location (a full URL from httptest server).
	locationPath := locURL.RequestURI()

	// --- 2. Wrong user must NOT reveal and must NOT consume. ---
	charlieGET := getRaw(t, client, server.URL, locationPath, charlieSession)
	if charlieGET.status != http.StatusOK {
		t.Fatalf("expected charlie (collaborator) to view detail, got %d", charlieGET.status)
	}
	if digestLeak(charlieGET.body) {
		t.Fatalf("wrong user revealed the invite flash: %s", charlieGET.body)
	}

	// --- 3. Owner on the WRONG registry must NOT reveal and must NOT consume. ---
	wrongReg := "/ui/registries/" + strconv.FormatInt(reg2.ID, 10) + "?" + locURL.RawQuery
	ownerWrongReg := getRaw(t, client, server.URL, wrongReg, aliceSession)
	if ownerWrongReg.status != http.StatusOK {
		t.Fatalf("expected owner to view their other registry detail, got %d", ownerWrongReg.status)
	}
	if digestLeak(ownerWrongReg.body) {
		t.Fatalf("wrong-registry request revealed the invite flash: %s", ownerWrongReg.body)
	}

	// --- 4. Legitimate first GET by the owner renders the raw token exactly once. ---
	first := getRaw(t, client, server.URL, locationPath, aliceSession)
	if first.status != http.StatusOK {
		t.Fatalf("expected owner first GET to succeed, got %d", first.status)
	}
	m := acceptLinkTokenRe.FindSubmatch(first.body)
	if m == nil || len(m) != 2 {
		t.Fatalf("first GET must render the one-time invite link with the raw token, body: %s", first.body)
	}
	rawToken := string(m[1])
	if _, err := ParseInviteToken(rawToken); err != nil {
		t.Fatalf("flash-rendered token is not canonical: %q (%v)", rawToken, err)
	}
	// The raw one-time token renders here, but never any encoding of the
	// persisted digest.
	if bytes.Contains(first.body, []byte(digestHex)) || bytes.Contains(first.body, []byte(digestB64)) {
		t.Fatalf("first GET leaked the persisted digest: %s", first.body)
	}

	// --- 5. Replaying the identical redirect must reveal nothing further. ---
	second := getRaw(t, client, server.URL, locationPath, aliceSession)
	if second.status != http.StatusOK {
		t.Fatalf("expected replay GET to succeed, got %d", second.status)
	}
	if leaksAny(second.body, []byte(rawToken), []byte(digestHex), []byte(digestB64), []byte("/ui/invites/accept")) {
		t.Fatalf("replayed redirect re-exposed the invite credential: %s", second.body)
	}

	// --- 6. Unknown flash ID reveals nothing. ---
	unknown := getRaw(t, client, server.URL,
		"/ui/registries/"+strconv.FormatInt(reg1.ID, 10)+"?invite_flash="+hex.EncodeToString([]byte("not-a-real-flash")), aliceSession)
	if unknown.status != http.StatusOK {
		t.Fatalf("expected unknown-flash GET to succeed, got %d", unknown.status)
	}
	if leaksAny(unknown.body, []byte(rawToken), []byte(digestHex), []byte(digestB64), []byte("/ui/invites/accept")) {
		t.Fatalf("unknown flash ID revealed the invite credential: %s", unknown.body)
	}
}
