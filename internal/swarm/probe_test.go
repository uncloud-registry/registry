package swarm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestProbeHealthPassesOn2xx proves the readiness probe reports a healthy Bee
// node (any 2xx /health response) and FAILS on a non-2xx or a stalled node,
// and that the probe's error is a fixed data-free classification (the probe
// is a readiness probe — its text must never carry the URL or response
// detail).
func TestProbeHealthPassesOn2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("probe path = %q, want /health", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	probe := ProbeHealth(server.URL, server.Client())
	if err := probe(context.Background()); err != nil {
		t.Fatalf("healthy Bee node must pass readiness: %v", err)
	}
}

// TestProbeHealthFailsOnNon2xx proves a non-2xx /health response fails the
// probe with a fixed data-free error that never echoes the URL or status.
func TestProbeHealthFailsOnNon2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	probe := ProbeHealth(server.URL, server.Client())
	err := probe(context.Background())
	if err == nil {
		t.Fatal("a non-2xx /health response must fail the readiness probe")
	}
	for _, leak := range []string{server.URL, "503", "Service Unavailable"} {
		if contains(err.Error(), leak) {
			t.Fatalf("probe error must not carry response detail %q: %v", leak, err)
		}
	}
}

// TestProbeHealthBoundedTimeout proves the probe uses a SHORT dedicated
// timeout: a node that never answers fails the probe within the bound instead
// of inheriting the (longer) dependency client deadline.
func TestProbeHealthBoundedTimeout(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // never answer until the probe's own timeout has fired
	}))
	defer func() {
		close(release)
		server.Close()
	}()

	probe := ProbeHealth(server.URL, &http.Client{Transport: &http.Transport{}})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	if err := probe(ctx); err == nil {
		t.Fatal("a stalled Bee node must fail the readiness probe")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("probe took %v, want a short bounded timeout", elapsed)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
