package controlplane

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/uncloud-registry/registry/internal/auth"
)

func TestUIRegistryCreationFlow(t *testing.T) {
	t.Parallel()

	store, err := OpenSQLite("file:controlplane_http_test?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	tokens := newTestSessionManager(t)
	server := httptest.NewServer(NewHTTPServer(&Service{
		Store:          store,
		Tokens:         tokens,
		RegistryDomain: "uncloud-registry.com",
		FeedKeys:       newTestFeedKeyCipher(t),
	}, auth.SubjectResolver{Tokens: tokens}))
	defer server.Close()

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	registerResp, err := client.PostForm(server.URL+"/ui/register", url.Values{
		"email":    {"alice@example.com"},
		"password": {"password123"},
	})
	if err != nil {
		t.Fatalf("register request: %v", err)
	}
	defer registerResp.Body.Close()
	if registerResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("unexpected register status: %d", registerResp.StatusCode)
	}
	cookies := registerResp.Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected session cookie")
	}

	form := url.Values{
		"slug":                   {"alice"},
		"ens_name":               {"alice.registry.eth"},
		"default_stamp_batch_id": {"batch-1"},
		"anonymous_pull":         {"true"},
		"_csrf":                  {sessionCSRFForTest(t, cookies[0].Value)},
	}
	req, err := http.NewRequest(http.MethodPost, server.URL+"/ui/registries/new", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookies[0])

	createResp, err := client.Do(req)
	if err != nil {
		t.Fatalf("create registry request: %v", err)
	}
	defer createResp.Body.Close()
	if createResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("unexpected create registry status: %d", createResp.StatusCode)
	}
	if location := createResp.Header.Get("Location"); !strings.HasPrefix(location, "/ui/registries/") {
		t.Fatalf("unexpected redirect location: %s", location)
	}
}

func TestUIInviteAcceptanceFlow(t *testing.T) {
	t.Parallel()

	store, err := OpenSQLite("file:controlplane_http_invite_test?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	tokens := newTestSessionManager(t)
	service := &Service{
		Store:          store,
		Tokens:         tokens,
		RegistryDomain: "uncloud-registry.com",
		FeedKeys:       newTestFeedKeyCipher(t),
	}
	server := httptest.NewServer(NewHTTPServer(service, auth.SubjectResolver{Tokens: tokens}))
	defer server.Close()

	owner, _, err := service.RegisterUser(context.Background(), "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	created, err := service.CreateRegistry(context.Background(), owner.ID, "alice", "alice.registry.eth", true, "batch-1")
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	_, inviteToken, err := service.CreateInvite(context.Background(), created.Registry.ID, owner.ID, "bob@example.com", true, true)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	getResp, err := client.Get(server.URL + "/ui/invites/accept?token=" + url.QueryEscape(inviteToken))
	if err != nil {
		t.Fatalf("get accept invite page: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected accept page status: %d", getResp.StatusCode)
	}
	body, _ := io.ReadAll(getResp.Body)
	if !strings.Contains(string(body), "Create account and accept") {
		t.Fatalf("expected invite acceptance body, got: %s", body)
	}

	resp, err := client.PostForm(server.URL+"/ui/invites/accept?token="+url.QueryEscape(inviteToken), url.Values{
		"email":    {"bob@example.com"},
		"password": {"password123"},
	})
	if err != nil {
		t.Fatalf("post accept invite: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("unexpected accept redirect status: %d", resp.StatusCode)
	}
	if location := resp.Header.Get("Location"); location != "/ui/registries?accepted=1" {
		t.Fatalf("unexpected accept redirect location: %s", location)
	}
}

func TestUIRegistryDetailShowsAcceptedUserEmails(t *testing.T) {
	t.Parallel()

	store, err := OpenSQLite("file:controlplane_http_detail_test?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	tokens := newTestSessionManager(t)
	service := &Service{
		Store:          store,
		Tokens:         tokens,
		RegistryDomain: "uncloud-registry.com",
		FeedKeys:       newTestFeedKeyCipher(t),
	}
	server := httptest.NewServer(NewHTTPServer(service, auth.SubjectResolver{Tokens: tokens}))
	defer server.Close()

	owner, ownerToken, err := service.RegisterUser(context.Background(), "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	created, err := service.CreateRegistry(context.Background(), owner.ID, "alice", "alice.registry.eth", false, "batch-1")
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	_, inviteToken, err := service.CreateInvite(context.Background(), created.Registry.ID, owner.ID, "bob@example.com", true, true)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	bob, _, err := service.RegisterUser(context.Background(), "bob@example.com", "password123")
	if err != nil {
		t.Fatalf("register bob: %v", err)
	}
	if _, err := service.AcceptInvite(context.Background(), inviteToken, bob.ID); err != nil {
		t.Fatalf("accept invite: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, server.URL+"/ui/registries/"+strconv.FormatInt(created.Registry.ID, 10), nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: ownerToken})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get registry detail: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "alice@example.com") || !strings.Contains(string(body), "bob@example.com") {
		t.Fatalf("expected accepted user emails in dashboard, got: %s", body)
	}
	if strings.Contains(string(body), "/ui/invites/accept?token=") {
		t.Fatalf("expected pending invite link text to be hidden, got: %s", body)
	}
}
