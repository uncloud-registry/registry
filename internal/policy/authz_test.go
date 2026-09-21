package policy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
)

// writePolicyDocs seeds auth and stamp policy documents for one owner. The
// default repo allows anonymous pull plus role:read/role:write, and authorizes
// only role:write for push; the stamp policy allows only role:write.
func writePolicyDocs(t *testing.T, owner string) (resolve.RegistryIdentity, *resolve.MemoryDocumentStore) {
	t.Helper()
	docs := resolve.NewMemoryDocumentStore()
	authData, err := json.Marshal(spec.AuthPolicyDocument{
		Version:       1,
		DefaultAccess: "deny",
		DefaultRepo: &spec.RepoAuthPolicyEntry{
			Pull: []string{"anonymous", "role:read", "role:write"},
			Push: []string{"role:write"},
		},
		Repos: map[string]spec.RepoAuthPolicyEntry{},
	})
	if err != nil {
		t.Fatalf("marshal auth policy: %v", err)
	}
	stampData, err := json.Marshal(spec.StampPolicyDocument{
		Version: 1,
		DefaultPolicy: spec.StampAccessPolicy{
			BatchID:      "batch-1",
			AllowPushFor: []string{"role:write"},
		},
		Repos: map[string]spec.StampAccessPolicy{},
	})
	if err != nil {
		t.Fatalf("marshal stamp policy: %v", err)
	}
	docs.Documents[spec.AuthPolicyFeedRef(owner)] = authData
	docs.Documents[spec.StampPolicyFeedRef(owner)] = stampData
	return resolve.RegistryIdentity{Host: "alice.example.test", Owner: owner}, docs
}

func principal(subject string) auth.Principal {
	return auth.Principal{Subject: subject}
}

// TestPullAuthorizationOnPrincipal verifies pull decisions are driven ONLY by
// the principal's subject against the explicit policy: anonymous works when
// listed, a verified subject works when listed, and anything unlisted is
// denied. There is no header input anywhere in the API.
func TestPullAuthorizationOnPrincipal(t *testing.T) {
	t.Parallel()
	owner := "0xalice"
	registry, docs := writePolicyDocs(t, owner)
	pull := PullAuthorizer{Policies: AuthPolicyResolver{Docs: docs, Feeds: nil}}

	cases := []struct {
		name   string
		p      auth.Principal
		repo   string
		expect bool
	}{
		{"anonymous listed", principal(auth.AnonymousSubject), "backend/api", true},
		{"verified role:read listed", principal("role:read"), "backend/api", true},
		{"verified role:write listed", principal("role:write"), "backend/api", true},
		{"unknown subject denied", principal("user:someone-else"), "backend/api", false},
		{"empty subject denied", principal(""), "backend/api", false},
	}
	for _, tc := range cases {
		ok, err := pull.Authorize(context.Background(), registry, tc.repo, tc.p)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if ok != tc.expect {
			t.Errorf("%s: got %v, want %v", tc.name, ok, tc.expect)
		}
	}
}

// TestPullAnonymousRequiresExplicitPolicy pins that a repo whose auth policy
// does not list "anonymous" rejects the anonymous principal: a missing token
// can never widen into public access by itself.
func TestPullAnonymousRequiresExplicitPolicy(t *testing.T) {
	t.Parallel()
	owner := "0xbob"
	docs := resolve.NewMemoryDocumentStore()
	authData, err := json.Marshal(spec.AuthPolicyDocument{
		Version:       1,
		DefaultAccess: "deny",
		Repos: map[string]spec.RepoAuthPolicyEntry{
			"closed/app": {Pull: []string{"role:read"}},
		},
	})
	if err != nil {
		t.Fatalf("marshal auth policy: %v", err)
	}
	docs.Documents[spec.AuthPolicyFeedRef(owner)] = authData
	registry := resolve.RegistryIdentity{Host: "bob.example.test", Owner: owner}
	pull := PullAuthorizer{Policies: AuthPolicyResolver{Docs: docs, Feeds: nil}}
	ok, err := pull.Authorize(context.Background(), registry, "closed/app", principal(auth.AnonymousSubject))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if ok {
		t.Fatal("anonymous pull must be denied when policy does not list anonymous")
	}
}

// TestPushNeverAllowsAnonymousOrEmpty pins the fail-closed push rule: even a
// policy that lists "anonymous" in the push list cannot make an anonymous
// principal push. Push requires a verified, non-anonymous subject in BOTH the
// auth policy push list and the stamp policy allow list.
func TestPushNeverAllowsAnonymousOrEmpty(t *testing.T) {
	t.Parallel()
	owner := "0xcharlie"
	docs := resolve.NewMemoryDocumentStore()
	authData, err := json.Marshal(spec.AuthPolicyDocument{
		Version: 1,
		Repos: map[string]spec.RepoAuthPolicyEntry{
			"open/app": {Pull: []string{"anonymous"}, Push: []string{"anonymous"}},
		},
	})
	if err != nil {
		t.Fatalf("marshal auth policy: %v", err)
	}
	stampData, err := json.Marshal(spec.StampPolicyDocument{
		Version: 1,
		Repos: map[string]spec.StampAccessPolicy{
			"open/app": {BatchID: "batch-anon", AllowPushFor: []string{"anonymous"}},
		},
	})
	if err != nil {
		t.Fatalf("marshal stamp policy: %v", err)
	}
	docs.Documents[spec.AuthPolicyFeedRef(owner)] = authData
	docs.Documents[spec.StampPolicyFeedRef(owner)] = stampData
	registry := resolve.RegistryIdentity{Host: "charlie.example.test", Owner: owner}
	push := PushAuthorizer{
		AuthPolicies:  AuthPolicyResolver{Docs: docs, Feeds: nil},
		StampPolicies: StampPolicyResolver{Docs: docs, Feeds: nil},
	}
	for _, p := range []auth.Principal{principal(auth.AnonymousSubject), principal("")} {
		if batchID, ok, err := push.Authorize(context.Background(), registry, "open/app", p); err != nil || ok {
			t.Fatalf("principal %q must never push (batch=%q ok=%v err=%v)", p.Subject, batchID, ok, err)
		}
	}
}

// TestPushAuthorizationOnPrincipal covers the authorized path and the two
// denial points: not in the auth policy push list, or not in the stamp policy
// allow list.
func TestPushAuthorizationOnPrincipal(t *testing.T) {
	t.Parallel()
	owner := "0xdana"
	registry, docs := writePolicyDocs(t, owner)
	push := PushAuthorizer{
		AuthPolicies:  AuthPolicyResolver{Docs: docs, Feeds: nil},
		StampPolicies: StampPolicyResolver{Docs: docs, Feeds: nil},
	}

	batchID, ok, err := push.Authorize(context.Background(), registry, "backend/api", principal("role:write"))
	if err != nil || !ok {
		t.Fatalf("role:write must push (batch=%q ok=%v err=%v)", batchID, ok, err)
	}
	if batchID != "batch-1" {
		t.Fatalf("batchID = %q, want batch-1", batchID)
	}

	if _, ok, err := push.Authorize(context.Background(), registry, "backend/api", principal("role:read")); err != nil || ok {
		t.Fatalf("role:read is not in the push list and must be denied (ok=%v err=%v)", ok, err)
	}
	if _, ok, err := push.Authorize(context.Background(), registry, "backend/api", principal("user:outsider")); err != nil || ok {
		t.Fatalf("unknown subject must be denied (ok=%v err=%v)", ok, err)
	}
}

// TestPolicyErrorsPropagate keeps the contract that unresolvable policy
// documents surface as errors (the handler maps them to 502), not as denials.
func TestPolicyErrorsPropagate(t *testing.T) {
	t.Parallel()
	owner := "0xempty"
	docs := resolve.NewMemoryDocumentStore()
	registry := resolve.RegistryIdentity{Host: "empty.example.test", Owner: owner}
	pull := PullAuthorizer{Policies: AuthPolicyResolver{Docs: docs, Feeds: nil}}
	if _, err := pull.Authorize(context.Background(), registry, "x", principal("role:read")); err == nil {
		t.Fatal("missing policy document must error, not silently deny or allow")
	}
	push := PushAuthorizer{
		AuthPolicies:  AuthPolicyResolver{Docs: docs, Feeds: nil},
		StampPolicies: StampPolicyResolver{Docs: docs, Feeds: nil},
	}
	if _, _, err := push.Authorize(context.Background(), registry, "x", principal("role:write")); err == nil {
		t.Fatal("missing policy document must error on push as well")
	}
}
