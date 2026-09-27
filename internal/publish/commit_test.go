package publish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
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
		OperationID: "op-abc", PublicationID: "op-abc-pub", RegistryID: 7,
		Owner: "0xabcDEF", Topic: "feed://abababababababababababababababababababab/cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
		Reference: strings.Repeat("a", 64), BatchID: "batch-1", ExpectedGeneration: 0,
	}
}

// echoServer is the fake control plane: it asserts the credential header,
// method, and path, then returns a canned status with the body. The path
// assertion is the CURRENT (v2) protocol endpoint: ControlPlaneCommitter is
// the production client and posts ONLY there (see
// TestControlPlaneCommitterPostsToCurrentV2Endpoint).
func echoServer(t *testing.T, status int, respBody string, checkResults bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != InternalFeedUpdatePathV2 {
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
	want := FeedCommitResult{OperationID: "op-abc", Feed: "feed://abababababababababababababababababababab/cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", Reference: strings.Repeat("a", 64)}
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
		412: ErrCommitGenerationConflict,
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

// TestControlPlaneCommitterRequiresNonEmptyPublicationID proves the CURRENT
// production committer (round 3 / Finding 2) fails a request with an empty
// PublicationID BEFORE any network attempt: the current protocol mandates the
// stable/attempt identity split unconditionally, never falling back to
// treating OperationID as its own stable identity (that legacy shape is only
// ever accepted on the isolated legacy endpoint, never through this client).
func TestControlPlaneCommitterRequiresNonEmptyPublicationID(t *testing.T) {
	req := validCommit()
	req.PublicationID = ""
	c := &ControlPlaneCommitter{BaseURL: "http://127.0.0.1:1", Secret: []byte(commitSecret), HTTPClient: http.DefaultClient}
	if _, err := c.Commit(context.Background(), req); !errors.Is(err, ErrCommitMalformed) {
		t.Fatalf("empty publicationID: got %v want malformed", err)
	}
}

// TestControlPlaneCommitterPostsToCurrentV2Endpoint proves the production
// committer sends every request to the CURRENT versioned endpoint
// (InternalFeedUpdatePathV2), never the legacy InternalFeedUpdatePath —
// closing the round-3 "silent missing-field mode" gap where an old strict
// control plane could otherwise be accidentally sent a current-shaped
// request on the legacy path.
func TestControlPlaneCommitterPostsToCurrentV2Endpoint(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, _ := json.Marshal(FeedCommitResult{OperationID: "op-abc", Feed: validCommit().Topic, Reference: strings.Repeat("a", 64)})
		w.WriteHeader(200)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	c := &ControlPlaneCommitter{BaseURL: srv.URL, Secret: []byte(commitSecret), HTTPClient: srv.Client()}
	if _, err := c.Commit(context.Background(), validCommit()); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if gotPath != InternalFeedUpdatePathV2 {
		t.Fatalf("got path %q want the current versioned endpoint %q", gotPath, InternalFeedUpdatePathV2)
	}
	if gotPath == InternalFeedUpdatePath {
		t.Fatal("the production committer must never post to the legacy path")
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

func TestParseCommitBaseURLOrigin(t *testing.T) {
	good := map[string]string{
		"http://127.0.0.1:8080":  "http://127.0.0.1:8080",
		"http://127.0.0.1":       "http://127.0.0.1",
		"http://localhost:8080":  "http://localhost:8080",
		"http://[::1]:8080":      "http://[::1]:8080",
		"https://cp.internal":    "https://cp.internal",
		"https://cp.internal/":   "https://cp.internal",
		"http://127.0.0.1:8080/": "http://127.0.0.1:8080",
	}
	for raw, want := range good {
		got, err := parseCommitBaseURL(raw)
		if err != nil || got != want {
			t.Fatalf("parse %q: got %q want %q (err %v)", raw, got, want, err)
		}
	}
	bad := []string{
		"", "ftp://x", "http://controlplane.internal:8080", "http://user:pass@host",
		"http://host/path", "http://host?q=1", "http://host#frag", "host:8080",
		"http://", "http://host:0",
	}
	for _, raw := range bad {
		if _, err := parseCommitBaseURL(raw); err == nil {
			t.Fatalf("expected %q to be rejected as an internal origin", raw)
		}
	}
}

func TestControlPlaneCommitterRejectsMismatchedResult(t *testing.T) {
	valid := validCommit()
	cases := map[string]string{
		"operationID": `{"operationID":"other","feed":"feed://abababababababababababababababababababab/cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","reference":"` + strings.Repeat("a", 64) + `"}`,
		"feed":        `{"operationID":"op-abc","feed":"feed://0000000000000000000000000000000000000000/cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","reference":"` + strings.Repeat("a", 64) + `"}`,
		"reference":   `{"operationID":"op-abc","feed":"feed://abababababababababababababababababababab/cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","reference":"` + strings.Repeat("b", 64) + `"}`,
		"case":        `{"operationID":"op-abc","feed":"feed://abababababababababababababababababababab/cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","reference":"` + strings.ToUpper(strings.Repeat("a", 64)) + `"}`,
		"duplicate":   `{"operationID":"op-abc","operationID":"op-abc","feed":"feed://abababababababababababababababababababab/cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","reference":"` + strings.Repeat("a", 64) + `"}`,
		// Malformed / non-canonical FEED values must never be accepted as a
		// matching success, even when the reference matches.
		"feed-short-owner":     `{"operationID":"op-abc","feed":"feed://abcd` + strings.Repeat("e", 36) + `/` + strings.Repeat("c", 64) + `","reference":"` + strings.Repeat("a", 64) + `"}`,
		"feed-no-slash":        `{"operationID":"op-abc","feed":"feed://` + strings.Repeat("b", 40) + strings.Repeat("c", 64) + `","reference":"` + strings.Repeat("a", 64) + `"}`,
		"feed-extra-slash":     `{"operationID":"op-abc","feed":"feed://` + strings.Repeat("b", 40) + `//` + strings.Repeat("c", 64) + `","reference":"` + strings.Repeat("a", 64) + `"}`,
		"feed-uppercase-owner": `{"operationID":"op-abc","feed":"feed://` + strings.ToUpper(strings.Repeat("b", 40)) + `/` + strings.Repeat("c", 64) + `","reference":"` + strings.Repeat("a", 64) + `"}`,
		"feed-uppercase-topic": `{"operationID":"op-abc","feed":"feed://` + strings.Repeat("b", 40) + `/` + strings.ToUpper(strings.Repeat("c", 64)) + `","reference":"` + strings.Repeat("a", 64) + `"}`,
		"feed-query":           `{"operationID":"op-abc","feed":"feed://` + strings.Repeat("b", 40) + `/` + strings.Repeat("c", 64) + `?x=1","reference":"` + strings.Repeat("a", 64) + `"}`,
	}
	for name, body := range cases {
		srv := echoServer(t, 200, body, false)
		c := &ControlPlaneCommitter{BaseURL: srv.URL, Secret: []byte(commitSecret), HTTPClient: srv.Client()}
		if _, err := c.Commit(context.Background(), valid); !errors.Is(err, ErrCommitBackend) {
			t.Fatalf("%s: expected backend for mismatched/duplicate result, got %v", name, err)
		}
	}
}

func TestControlPlaneCommitterErrorIsDataFree(t *testing.T) {
	c := &ControlPlaneCommitter{BaseURL: "http://127.0.0.1:1", Secret: []byte(commitSecret), HTTPClient: http.DefaultClient}
	_, err := c.Commit(context.Background(), validCommit())
	if !errors.Is(err, ErrCommitBackend) {
		t.Fatalf("transport failure: got %v want backend", err)
	}
	if msg := err.Error(); msg != ErrCommitBackend.Error() || strings.Contains(msg, "127.0.0.1") || strings.Contains(msg, "dial") || strings.Contains(msg, "connect") {
		t.Fatalf("backend error must be bare and data-free, got %q", msg)
	}
}

func TestControlPlaneCommitterTruncatedResponse(t *testing.T) {
	// The surrogate advertises a Content-Length larger than the body it writes,
	// forcing an unexpected-EOF read failure into the backend class.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1024")
		_, _ = w.Write([]byte(`{"operationID":"`))
	}))
	t.Cleanup(srv.Close)
	c := &ControlPlaneCommitter{BaseURL: srv.URL, Secret: []byte(commitSecret), HTTPClient: srv.Client()}
	if _, err := c.Commit(context.Background(), validCommit()); !errors.Is(err, ErrCommitBackend) {
		t.Fatalf("truncated body must collapse to backend, got %v", err)
	}
}

func TestCanonicalFeedCommitResultJSONByteExact(t *testing.T) {
	result := FeedCommitResult{
		OperationID: "op-1",
		Feed:        "feed://" + strings.Repeat("a", 40) + "/" + strings.Repeat("b", 64),
		Reference:   strings.Repeat("ab", 32),
	}
	if err := ValidateCommitResult(result); err != nil {
		t.Fatalf("valid result must pass: %v", err)
	}
	want := `{"operationID":"op-1","feed":"` + result.Feed + `","reference":"` + result.Reference + `"}`
	got := CanonicalFeedCommitResultJSON(result)
	// Byte-for-byte equal to the concatenated canonical layout.
	if string(got) != want {
		t.Fatalf("canonical helper mismatch\n got %q\nwant %q", got, want)
	}
	// And byte-for-byte equal to what Go's json.Marshal emits (the fixed struct
	// member order), so the DB trigger can reconstruct it with plain concatenation.
	wantMarshal, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, wantMarshal) {
		t.Fatalf("canonical helper must equal json.Marshal\n got %q\nwant %q", got, wantMarshal)
	}
	// The DB trigger requires EXACTLY the three keys in canonical order; verify
	// there is no trailing whitespace/newline or escape noise.
	if strings.ContainsAny(string(got), " \n\t") {
		t.Fatalf("canonical form must be perfectly compact, got %q", got)
	}
}

func TestOperationIDJSONSafeConstraint(t *testing.T) {
	bad := []string{
		`a"b`,    // double quote (escaped by json.Marshal -> would break byte-exact)
		`a\\b`,   // backslash
		"a\nb",   // newline
		"a<b",    // '<' (escaped by Go json.Marshal)
		"a>b",    // '>'
		"a&b",    // '&'
		"\u00e9", // non-ASCII
	}
	for _, opID := range bad {
		req := validCommit()
		req.OperationID = opID
		if err := validateCommitRequestShape(req); err == nil {
			t.Fatalf("operationID %q must be rejected by the JSON-safe constraint", opID)
		}
		res := FeedCommitResult{OperationID: opID, Feed: "feed://" + strings.Repeat("a", 40) + "/" + strings.Repeat("b", 64), Reference: strings.Repeat("ab", 32)}
		if err := ValidateCommitResult(res); err == nil {
			t.Fatalf("result operationID %q must be rejected by the JSON-safe constraint", opID)
		}
	}
	// The stable legacy/alphanumeric ids remain accepted.
	for _, opID := range []string{"op-1", "a", "other", "DIFFERENT"} {
		req := validCommit()
		req.OperationID = opID
		if err := validateCommitRequestShape(req); err != nil {
			t.Fatalf("operationID %q must be accepted: %v", opID, err)
		}
	}
}

// echoCommitter is a faithful in-process model of the control-plane feed
// signer's success response: it returns the canonical request-bound result
// and records every request for assertions.
type echoCommitter struct {
	calls int
	last  FeedCommitRequest
}

func (e *echoCommitter) Commit(_ context.Context, req FeedCommitRequest) (FeedCommitResult, error) {
	e.calls++
	e.last = req
	return FeedCommitResult{
		OperationID: req.OperationID,
		Feed:        CanonicalTopic(req.Topic),
		Reference:   CanonicalReference(req.Reference),
	}, nil
}

// TestDeterministicUpdatedAtStablePerOperation pins the restart-safe state
// timestamp contract: UpdatedAt is a pure deterministic function of the
// operation identity, so a retry of one logical publication rebuilds
// BYTE-IDENTICAL repo-state bytes — the precondition for the control plane's
// durable request-hash idempotency after an uncertain commit boundary.
func TestDeterministicUpdatedAtStablePerOperation(t *testing.T) {
	a1 := DeterministicUpdatedAt("op-1")
	a2 := DeterministicUpdatedAt("op-1")
	if a1 != a2 {
		t.Fatalf("same operation must derive the same UpdatedAt: %q vs %q", a1, a2)
	}
	if a1 == DeterministicUpdatedAt("op-2") {
		t.Fatal("distinct operations must derive distinct UpdatedAt values")
	}
	if _, err := time.Parse(time.RFC3339, a1); err != nil {
		t.Fatalf("deterministic UpdatedAt must be RFC3339: %v", err)
	}
}

// TestPublishCommitReturnsExactReceipt proves PublishCommit captures the exact
// publication receipt available BEFORE the uncertain commit boundary: the
// canonical repo feed, the immutable state reference the object store
// returned, the manifest reference, the resulting generation, tag, and
// manifest digest — all verifiable afterwards through the production
// resolver/document path.
func TestPublishCommitReturnsExactReceipt(t *testing.T) {
	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	// No custom committer: PublishCommit falls back to the local Feeds
	// updater, so the receipt reference must equal the feed target exactly.
	p := Publisher{Builder: DefaultBuilder{}, Objects: docs, Feeds: feeds}

	feed := spec.RepoStateFeedRef("0xaliceowner", "backend/api")
	current := spec.RepoStateDocument{}
	input := validBuildInput(t)
	input.UpdatedAt = DeterministicUpdatedAt("op-t14-1")

	receipt, err := p.PublishCommit(context.Background(), feed, current, input, "batch-1", 7, "0xaliceowner", "op-t14-1")
	if err != nil {
		t.Fatalf("publish commit: %v", err)
	}
	if receipt.OperationID != "op-t14-1" {
		t.Fatalf("receipt operation id mismatch: %q", receipt.OperationID)
	}
	if receipt.StateFeed != feed {
		t.Fatalf("receipt feed mismatch: %q", receipt.StateFeed)
	}
	if receipt.Repo != "backend/api" || receipt.Tag != "latest" || receipt.ManifestDigest != input.ManifestDigest {
		t.Fatalf("receipt target mismatch: %+v", receipt)
	}
	if receipt.ExpectedGeneration != 0 || receipt.Generation != 1 {
		t.Fatalf("receipt generation mismatch: expected 0->1, got %+v", receipt)
	}
	if receipt.ManifestRef != contentAddress(docs, input.ManifestJSON) {
		t.Fatalf("receipt manifest ref mismatch: %q", receipt.ManifestRef)
	}
	if receipt.StateRef != feeds.Feeds[feed] {
		t.Fatalf("receipt state ref %q must equal the feed target %q", receipt.StateRef, feeds.Feeds[feed])
	}
}

// contentAddress returns the deterministic content-addressed reference
// resolve.MemoryDocumentStore.Put assigns to data — the exact in-memory model
// of Bee's content addressing that restart-safe retries depend on.
func contentAddress(docs *resolve.MemoryDocumentStore, data []byte) string {
	sum := sha256.Sum256(data)
	return "mem-ref-" + hex.EncodeToString(sum[:])
}
