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
	"time"
)

const commitSecret = "shared-internal-secret-bytes"

func commitServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *ControlPlaneCommitter) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, &ControlPlaneCommitter{BaseURL: srv.URL, Secret: []byte(commitSecret), HTTPClient: srv.Client()}
}

func validCommit() FeedCommitRequest {
	return FeedCommitRequest{
		OperationID: "op-abc", RegistryID: 7,
		Owner: "0xabcDEF", Topic: "feed://abcdef/0123",
		Reference: strings.Repeat("a", 64), BatchID: "batch-1", ExpectedGeneration: 0,
	}
}

// echoServer is the fake control plane: it asserts the credential header,
// method, and path, then returns a canned status with the body.
func echoServer(t *testing.T, status int, respBody string, checkResults bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != InternalFeedUpdatePath {
			w.WriteHeader(500)
			return
		}
		if got := r.Header.Get(InternalAuthHeader); got != commitSecret {
			w.WriteHeader(401)
			return
		}
		if checkResults {
			body, _ := io.ReadAll(r.Body)
			var req FeedCommitRequest
			if err := json.Unmarshal(body, &req); err != nil {
				t.Fatalf("server failed to decode request: %v", err)
			}
			// Assert the credential is NOT part of the request body.
			if strings.Contains(string(body), commitSecret) {
				t.Fatal("credential leaked into the request body")
			}
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(respBody))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestControlPlaneCommitterHappyPath(t *testing.T) {
	want := FeedCommitResult{OperationID: "op-abc", Feed: "feed://abcdef/0123", Reference: strings.Repeat("a", 64)}
	body, _ := json.Marshal(want)
	srv := echoServer(t, 200, string(body), true)
	c := &ControlPlaneCommitter{BaseURL: srv.URL, Secret: []byte(commitSecret), HTTPClient: srv.Client()}
	got, err := c.Commit(context.Background(), validCommit())
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if got != want {
		t.Fatalf("got %+v want %+v", got, want)
	}
}

func TestControlPlaneCommitterStatusMapping(t *testing.T) {
	cases := map[int]error{
		401: ErrCommitUnauthorized,
		400: ErrCommitMalformed,
		404: ErrCommitUnknownRegistry,
		409: ErrCommitConflict,
		503: ErrCommitBackend,
	}
	for status, want := range cases {
		srv := echoServer(t, status, `{"error":"x"}`, false)
		c := &ControlPlaneCommitter{BaseURL: srv.URL, Secret: []byte(commitSecret), HTTPClient: srv.Client()}
		_, err := c.Commit(context.Background(), validCommit())
		if !errors.Is(err, want) {
			t.Fatalf("status %d: got %v want %v", status, err, want)
		}
	}
}

func TestControlPlaneCommitterFailsBeforeNetworkOnBadConfig(t *testing.T) {
	c := &ControlPlaneCommitter{BaseURL: "", Secret: []byte(commitSecret), HTTPClient: http.DefaultClient}
	if _, err := c.Commit(context.Background(), validCommit()); !errors.Is(err, ErrCommitBackend) {
		t.Fatalf("empty base URL: got %v want backend", err)
	}
	c = &ControlPlaneCommitter{BaseURL: "http://127.0.0.1:1", Secret: nil, HTTPClient: http.DefaultClient}
	if _, err := c.Commit(context.Background(), validCommit()); !errors.Is(err, ErrCommitBackend) {
		t.Fatalf("empty secret: got %v want backend", err)
	}
}

func TestControlPlaneCommitterRejectsMalformedRequestBeforeNetwork(t *testing.T) {
	req := validCommit()
	req.Reference = "not-hex"
	c := &ControlPlaneCommitter{BaseURL: "http://127.0.0.1:1", Secret: []byte(commitSecret), HTTPClient: http.DefaultClient}
	if _, err := c.Commit(context.Background(), req); !errors.Is(err, ErrCommitMalformed) {
		t.Fatalf("bad reference: got %v want malformed", err)
	}
	req = validCommit()
	req.RegistryID = 0
	if _, err := c.Commit(context.Background(), req); !errors.Is(err, ErrCommitMalformed) {
		t.Fatalf("non-positive registryID: got %v want malformed", err)
	}
}

func TestControlPlaneCommitterResponseBound(t *testing.T) {
	srv := echoServer(t, 200, `{"operationID":"a`+strings.Repeat("x", CommitResponseMaxBody)+`"}`, false)
	c := &ControlPlaneCommitter{BaseURL: srv.URL, Secret: []byte(commitSecret), HTTPClient: srv.Client()}
	if _, err := c.Commit(context.Background(), validCommit()); !errors.Is(err, ErrCommitBackend) {
		t.Fatalf("oversized response: got %v want backend", err)
	}
}

func TestControlPlaneCommitterRejectsTrailingResponse(t *testing.T) {
	srv := echoServer(t, 200, `{"operationID":"a","feed":"f","reference":"`+strings.Repeat("a", 64)+`"} trailing`, false)
	c := &ControlPlaneCommitter{BaseURL: srv.URL, Secret: []byte(commitSecret), HTTPClient: srv.Client()}
	if _, err := c.Commit(context.Background(), validCommit()); !errors.Is(err, ErrCommitBackend) {
		t.Fatalf("trailing response: got %v want backend", err)
	}
}

func TestControlPlaneCommitterRespectsCallerDeadline(t *testing.T) {
	// The fake control plane hangs; the caller's deadline must win.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(503)
	}))
	t.Cleanup(srv.Close)
	client := srv.Client()
	client.Timeout = 100 * time.Millisecond
	c := &ControlPlaneCommitter{BaseURL: srv.URL, Secret: []byte(commitSecret), HTTPClient: client}
	_, err := c.Commit(context.Background(), validCommit())
	if !errors.Is(err, ErrCommitBackend) {
		t.Fatalf("deadline: got %v want backend", err)
	}
}

func TestComputeOperationIDIsStableAndDomainSeparated(t *testing.T) {
	a := ComputeOperationID(7, "0xowner", "repo", "latest", "digest", 3)
	b := ComputeOperationID(7, "0xowner", "repo", "latest", "digest", 3)
	if a != b {
		t.Fatalf("expected stable operation ID, got %q vs %q", a, b)
	}
	c := ComputeOperationID(7, "0xowner", "repo", "latest", "digest2", 3)
	if a == c {
		t.Fatal("expected digest to change the operation ID")
	}
	if len(a) != 64 {
		t.Fatalf("expected a 64-hex operation ID, got %d chars", len(a))
	}
}
