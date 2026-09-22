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

// TestUIProvisioningStateAndAsyncCopyRendered verifies the UI (F7):
//   - registration detail renders provisioning|ready|failed state accurately;
//   - creation copy and the created redirect message say "enqueued /
//     provisioning", never "published";
//   - settings controls are disabled while provisioning;
//   - a failed registry is visible and actionable WITHOUT leaking any
//     internal LastError / raw error text.
func TestUIProvisioningStateAndAsyncCopyRendered(t *testing.T) {
	t.Parallel()

	store, err := OpenSQLite("file:ui_prov_state?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	tokens := newTestSessionManager(t)
	uploader := &memoryUploader{refs: map[string][]byte{}}
	feeds := &MemoryRegistryFeedStore{Feeds: map[string]string{}}
	service := &Service{
		Store:          store,
		Tokens:         tokens,
		RegistryDomain: "uncloud-registry.com",
		FeedKeys:       newTestFeedKeyCipher(t),
		Publisher:      &Publisher{Documents: uploader, Feeds: feeds, FeedsReader: feeds},
	}
	server := httptest.NewServer(NewHTTPServer(service, auth.SubjectResolver{Tokens: tokens}))
	defer server.Close()

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	regResp, err := client.PostForm(server.URL+"/ui/register", url.Values{
		"email": {"alice@example.com"}, "password": {"password123"},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	regResp.Body.Close()
	cookies := regResp.Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected session cookie")
	}
	cookie := cookies[0]

	createForm := url.Values{
		"slug": {"provui"}, "ens_name": {"provui.registry.eth"},
		"default_stamp_batch_id": {"snapshot-A"}, "anonymous_pull": {"true"},
		"_csrf": {sessionCSRFForTest(t, cookie.Value)},
	}
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/ui/registries/new", strings.NewReader(createForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	createResp, err := client.Do(req)
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	createResp.Body.Close()
	if createResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("create registry status: %d", createResp.StatusCode)
	}
	loc := createResp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/ui/registries/") {
		t.Fatalf("bad redirect: %s", loc)
	}
	// The created redirect carries ?created=1 so the page flashes the
	// enqueued-for-provisioning message.
	if !strings.Contains(loc, "created=1") {
		t.Fatalf("expected created=1 flash on redirect, got %s", loc)
	}
	regID := strings.Split(strings.TrimPrefix(loc, "/ui/registries/"), "?")[0]

	get := func(path string) string {
		gr, _ := http.NewRequest(http.MethodGet, server.URL+path, nil)
		gr.AddCookie(cookie)
		resp, err := client.Do(gr)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("get %s status: %d", path, resp.StatusCode)
		}
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}

	// 1. While provisioning: state badge, async copy, disabled settings.
	provisioningHTML := get(loc)
	for _, want := range []string{
		"enqueued for provisioning",
		"Provisioning…",
		"Provisioning — bootstrap policy publication is enqueued and runs in the background",
		"Save and publish policy",
		"locked until verified bootstrap publication completes",
	} {
		if !strings.Contains(provisioningHTML, want) {
			t.Fatalf("provisioning detail page missing %q", want)
		}
	}
	if strings.Contains(provisioningHTML, "bootstrap policy is published and verified") {
		t.Fatal("provisioning page must not claim the registry is published/ready")
	}

	// 2. Reconcile to ready, then re-render.
	rec, err := service.NewReconciler()
	if err != nil {
		t.Fatalf("new reconciler: %v", err)
	}
	if err := rec.RunOnce(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	readyHTML := get("/ui/registries/" + regID)
	for _, want := range []string{"Ready", "bootstrap policy is published and verified", "Save and publish policy"} {
		if !strings.Contains(readyHTML, want) {
			t.Fatalf("ready detail page missing %q", want)
		}
	}
	if strings.Contains(readyHTML, "locked until verified bootstrap publication") {
		t.Fatal("ready page must not lock settings")
	}

	// 3. Failed state: visible and actionable, without leaking LastError.
	// Use a SECOND, un-reconciled registry (still provisioning) and mark it
	// failed (the failed transition is only legal from provisioning).
	var ownerID int64
	if err := store.DB.QueryRow(`select id from users where email = 'alice@example.com'`).Scan(&ownerID); err != nil {
		t.Fatalf("read owner id: %v", err)
	}
	created2, err := service.CreateRegistry(context.Background(), ownerID, "provui_failed", "provui_failed.eth", false, "snapshot-B")
	if err != nil {
		t.Fatalf("create failed-state registry: %v", err)
	}
	reg2 := created2.Registry
	// Seed a distinctive internal last_error on a job, then mark failed.
	if _, err := store.DB.Exec(`update registry_publication_jobs set last_error = ? where registry_id = ?`,
		"feed resolution mismatch: sw$(0xTHE-SECRET-INTERNAL) +0012", reg2.ID); err != nil {
		t.Fatalf("seed last_error: %v", err)
	}
	if err := store.MarkRegistryFailed(context.Background(), reg2.ID); err != nil {
		t.Fatalf("mark failed: %v", err)
	}
	failedHTML := get("/ui/registries/" + strconv.FormatInt(reg2.ID, 10))
	for _, want := range []string{"Failed", "bootstrap policy could not be verified", "contact the operator"} {
		if !strings.Contains(failedHTML, want) {
			t.Fatalf("failed detail page missing %q", want)
		}
	}
	if strings.Contains(failedHTML, "THE-SECRET-INTERNAL") {
		t.Fatal("failed state must never leak LastError / internal error text")
	}
	// The settings button must not be enabled to re-publish on a failed registry.
	if strings.Contains(failedHTML, `<button type="submit">Save and publish policy</button>`) {
		t.Fatal("failed registry must not offer a saving-and-publishing settings button")
	}
}
