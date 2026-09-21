package controlplane

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func createTestRegistry(t *testing.T, store *Store, ownerID int64, slug, host string) Registry {
	t.Helper()
	created, err := store.CreateRegistry(context.Background(), Registry{
		Slug: slug, Host: host, ENSName: slug + ".eth",
		OwnerUserID: ownerID, FeedOwnerAddress: "0xfeed", DefaultStampBatchID: "batch-1",
		AnonymousPull: false,
	}, nil, nil)
	if err != nil {
		t.Fatalf("create registry: %v", err)
	}
	return created
}

func postForm(t *testing.T, client *http.Client, base, path string, form url.Values, session string) (int, string, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("new post form: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("post form %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read post form %s: %v", path, err)
	}
	return resp.StatusCode, resp.Header.Get("Location"), body
}

type rawGET struct {
	status int
	body   []byte
}

func getRaw(t *testing.T, client *http.Client, base, path string, session string) rawGET {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		t.Fatalf("new get: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("get %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read get %s: %v", path, err)
	}
	return rawGET{status: resp.StatusCode, body: body}
}
