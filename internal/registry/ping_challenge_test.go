package registry

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPingChallenge(t *testing.T) {
	t.Parallel()
	h := &Handler{AuthRealm: "https://r.example/token", PingChallenge: true}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.Host = "r.example:443"
	h.serveHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	want := `Bearer realm="https://r.example/token",service="r.example"`
	if got := rec.Header().Get("WWW-Authenticate"); got != want {
		t.Fatalf("challenge = %q, want %q", got, want)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.Header.Set("Authorization", "Bearer x")
	h.serveHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authorized ping status = %d, want 200", rec.Code)
	}

	h.PingChallenge = false
	rec = httptest.NewRecorder()
	h.serveHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("default ping status = %d, want 200", rec.Code)
	}
}
