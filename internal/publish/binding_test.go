package publish

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func validBinding() OperationBindingRequest {
	return OperationBindingRequest{
		OperationID:    "op-bind-abc",
		RegistryID:     7,
		Owner:          "0xabababababababababababababababababababab",
		Repo:           "myrepo",
		Tag:            "latest",
		ManifestDigest: "sha256:" + strings.Repeat("ab", 32),
	}
}

// bindingEchoServer is the fake control plane for the BINDING route: it
// asserts the method, exact path, and the constant credential header, checks
// the request body never carries the credential, then returns a canned status.
func bindingEchoServer(t *testing.T, status int, respBody string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != InternalOperationBindingPath {
			w.WriteHeader(500)
			return
		}
		if got := r.Header.Get(InternalAuthHeader); got != commitSecret {
			w.WriteHeader(401)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req OperationBindingRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("server failed to decode binding request: %v", err)
		}
		// The credential and any key material never travel in the body.
		if strings.Contains(string(body), commitSecret) {
			t.Fatal("credential leaked into the binding request body")
		}
		for _, field := range []string{req.OperationID, req.Repo, req.Tag, req.ManifestDigest} {
			if strings.Contains(string(body), field) == false && field != "" {
				t.Fatalf("binding field %q missing from the strict request body", field)
			}
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(respBody))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestControlPlaneOperationBinderHappyPath(t *testing.T) {
	srv := bindingEchoServer(t, 200, `{"status":"reserved"}`)
	c := &ControlPlaneOperationBinder{BaseURL: srv.URL, Secret: []byte(commitSecret), HTTPClient: srv.Client()}
	if err := c.Bind(context.Background(), validBinding()); err != nil {
		t.Fatalf("bind: %v", err)
	}
}

func TestControlPlaneOperationBinderStatusBodyAcceptedForms(t *testing.T) {
	// Go's JSON decoder matches struct field names case-insensitively, so the
	// exact lowercase "reserved" value is required but the field-name spelling
	// may vary. Anything else — a capitalized value included — is rejected as
	// backend-class (the control plane's contract body is exact).
	for _, statusText := range []string{`{"status":"reserved"}`, `{"Status":"reserved"}`} {
		srv := bindingEchoServer(t, 200, statusText)
		c := &ControlPlaneOperationBinder{BaseURL: srv.URL, Secret: []byte(commitSecret), HTTPClient: srv.Client()}
		if err := c.Bind(context.Background(), validBinding()); err != nil {
			t.Fatalf("status body %q: %v", statusText, err)
		}
	}
	for _, statusText := range []string{`{"status":"Reserved"}`, `{"status":"RESERVED"}`} {
		srv := bindingEchoServer(t, 200, statusText)
		c := &ControlPlaneOperationBinder{BaseURL: srv.URL, Secret: []byte(commitSecret), HTTPClient: srv.Client()}
		if err := c.Bind(context.Background(), validBinding()); !errors.Is(err, ErrCommitBackend) {
			t.Fatalf("status body %q: got %v want backend", statusText, err)
		}
	}
}

func TestControlPlaneOperationBinderStatusMapping(t *testing.T) {
	cases := map[int]error{
		401: ErrCommitUnauthorized,
		400: ErrCommitMalformed,
		404: ErrCommitUnknownRegistry,
		409: ErrCommitConflict,
		503: ErrCommitBackend,
	}
	for status, want := range cases {
		srv := bindingEchoServer(t, status, `{"error":"x"}`)
		c := &ControlPlaneOperationBinder{BaseURL: srv.URL, Secret: []byte(commitSecret), HTTPClient: srv.Client()}
		if err := c.Bind(context.Background(), validBinding()); !errors.Is(err, want) {
			t.Fatalf("status %d: got %v want %v", status, err, want)
		}
	}
}

func TestControlPlaneOperationBinderFailsBeforeNetworkOnBadConfig(t *testing.T) {
	c := &ControlPlaneOperationBinder{BaseURL: "", Secret: []byte(commitSecret), HTTPClient: http.DefaultClient}
	if err := c.Bind(context.Background(), validBinding()); !errors.Is(err, ErrCommitBackend) {
		t.Fatalf("empty base URL: got %v want backend", err)
	}
	c = &ControlPlaneOperationBinder{BaseURL: "http://127.0.0.1:1", Secret: nil, HTTPClient: http.DefaultClient}
	if err := c.Bind(context.Background(), validBinding()); !errors.Is(err, ErrCommitBackend) {
		t.Fatalf("empty secret: got %v want backend", err)
	}
}

func TestControlPlaneOperationBinderRejectsMalformedRequestBeforeNetwork(t *testing.T) {
	c := &ControlPlaneOperationBinder{BaseURL: "http://127.0.0.1:1", Secret: []byte(commitSecret), HTTPClient: http.DefaultClient}
	req := validBinding()
	req.ManifestDigest = "not-a-digest"
	if err := c.Bind(context.Background(), req); !errors.Is(err, ErrCommitMalformed) {
		t.Fatalf("bad manifest digest: got %v want malformed", err)
	}
	req = validBinding()
	req.RegistryID = 0
	if err := c.Bind(context.Background(), req); !errors.Is(err, ErrCommitMalformed) {
		t.Fatalf("non-positive registryID: got %v want malformed", err)
	}
	req = validBinding()
	req.Tag = ""
	if err := c.Bind(context.Background(), req); !errors.Is(err, ErrCommitMalformed) {
		t.Fatalf("empty tag: got %v want malformed", err)
	}
	req = validBinding()
	req.Repo = ""
	if err := c.Bind(context.Background(), req); !errors.Is(err, ErrCommitMalformed) {
		t.Fatalf("empty repo: got %v want malformed", err)
	}
	req = validBinding()
	req.OperationID = strings.Repeat("x", 129)
	if err := c.Bind(context.Background(), req); !errors.Is(err, ErrCommitMalformed) {
		t.Fatalf("oversized key: got %v want malformed", err)
	}
}

func TestControlPlaneOperationBinderResponseStrictness(t *testing.T) {
	for name, body := range map[string]string{
		"wrong status":  `{"status":"other"}`,
		"duplicate":     `{"status":"reserved","status":"reserved"}`,
		"unknown field": `{"status":"reserved","extra":1}`,
		"trailing":      `{"status":"reserved"} trailing`,
		"not json":      `not json`,
	} {
		srv := bindingEchoServer(t, 200, body)
		c := &ControlPlaneOperationBinder{BaseURL: srv.URL, Secret: []byte(commitSecret), HTTPClient: srv.Client()}
		if err := c.Bind(context.Background(), validBinding()); !errors.Is(err, ErrCommitBackend) {
			t.Fatalf("%s: got %v want backend", name, err)
		}
	}
}

func TestControlPlaneOperationBinderResponseBoundAndEmpty(t *testing.T) {
	srv := bindingEchoServer(t, 200, `{"status":"`+strings.Repeat("x", BindingResponseMaxBody+1)+`"}`)
	c := &ControlPlaneOperationBinder{BaseURL: srv.URL, Secret: []byte(commitSecret), HTTPClient: srv.Client()}
	if err := c.Bind(context.Background(), validBinding()); !errors.Is(err, ErrCommitBackend) {
		t.Fatalf("oversized response: got %v want backend", err)
	}
	srv = bindingEchoServer(t, 200, "")
	c = &ControlPlaneOperationBinder{BaseURL: srv.URL, Secret: []byte(commitSecret), HTTPClient: srv.Client()}
	if err := c.Bind(context.Background(), validBinding()); !errors.Is(err, ErrCommitBackend) {
		t.Fatalf("empty response: got %v want backend", err)
	}
}

func TestControlPlaneOperationBinderRespectsCallerDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-make(chan struct{}):
		}
	}))
	t.Cleanup(srv.Close)
	c := &ControlPlaneOperationBinder{BaseURL: srv.URL, Secret: []byte(commitSecret), HTTPClient: srv.Client()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Bind(ctx, validBinding()); !errors.Is(err, ErrCommitBackend) {
		t.Fatalf("pre-cancelled context: got %v want backend", err)
	}
}

func TestControlPlaneOperationBinderErrorIsDataFree(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("the internal database hostname is db.internal.corp:5432"))
	}))
	t.Cleanup(srv.Close)
	c := &ControlPlaneOperationBinder{BaseURL: srv.URL, Secret: []byte(commitSecret), HTTPClient: srv.Client()}
	err := c.Bind(context.Background(), validBinding())
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrCommitBackend) {
		t.Fatalf("got %v want backend class", err)
	}
	for _, leak := range []string{"db.internal.corp", "5432", "internal database hostname"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("error must be data-free, leaked %q in %q", leak, err.Error())
		}
	}
}

// TestControlPlaneOperationBinderRequiresOriginOnly pins the transport
// sanitization: the data-plane binder accepts ONLY an absolute http/https
// ORIGIN — a base URL with a path, query, fragment, or userinfo is rejected
// before any request is built, mirroring the commit client's fail-closed
// rule.
func TestControlPlaneOperationBinderRequiresOriginOnly(t *testing.T) {
	srv := bindingEchoServer(t, 200, `{"status":"reserved"}`)
	for name, base := range map[string]string{
		"path":     srv.URL + "/extra/path",
		"query":    srv.URL + "?a=1",
		"fragment": srv.URL + "#frag",
		"userinfo": "http://user:pass@127.0.0.1:1",
		"scheme":   "tcp://127.0.0.1:1",
	} {
		c := &ControlPlaneOperationBinder{BaseURL: base, Secret: []byte(commitSecret), HTTPClient: srv.Client()}
		if err := c.Bind(context.Background(), validBinding()); !errors.Is(err, ErrCommitBackend) {
			t.Fatalf("%s: got %v want backend", name, err)
		}
	}
}
