package policy

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
)

// policyTestSessionSecret is a strong, test-only HMAC secret (>=32 bytes).
const policyTestSessionSecret = "policy-test-session-secret-0123456789abcdef"

func newPolicySubjectResolver(t *testing.T) (auth.SubjectResolver, *auth.SessionTokenManager) {
	t.Helper()
	m, err := auth.NewSessionTokenManager(policyTestSessionSecret, auth.DefaultSessionIssuer, auth.DefaultSessionAudience)
	if err != nil {
		t.Fatalf("new session manager: %v", err)
	}
	return auth.SubjectResolver{Tokens: m}, m
}

func writePolicyDocs(t *testing.T, owner string) (resolve.RegistryIdentity, *resolve.MemoryDocumentStore) {
	t.Helper()
	docs := resolve.NewMemoryDocumentStore()
	// role:write and role:read are the privileged actors in the pull/push
	// policy; anonymous is allowed to pull.
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

// TestRawBearerCannotBecomePolicyActor is the policy-level regression for the
// raw-bearer fallback in SubjectResolver. Previously an attacker could send
// `Authorization: Bearer role:write` and the resolver would echo `role:write`
// as the subject, which exactly matches the privileged actor in the pull/push
// policy. The resolver now fails closed, so a raw bearer can never drive
// authorization.
func TestRawBearerCannotBecomePolicyActor(t *testing.T) {
	t.Parallel()

	owner := "0xalice"
	registry, docs := writePolicyDocs(t, owner)
	subjects, _ := newPolicySubjectResolver(t)

	pull := PullAuthorizer{
		Policies: AuthPolicyResolver{Docs: docs, Feeds: nil},
		Subjects: subjects,
	}
	push := PushAuthorizer{
		AuthPolicies:  AuthPolicyResolver{Docs: docs, Feeds: nil},
		StampPolicies: StampPolicyResolver{Docs: docs, Feeds: nil},
		Subjects:      subjects,
	}

	// Sanity: the exploitable actor IS present in the privileged policy lists,
	// proving the pre-fix leak was real and would have authorized.
	for _, raw := range []string{"Bearer role:write", "Bearer role:read"} {
		// Pull must be denied: the raw value no longer resolves to the actor.
		ok, err := pull.Authorize(context.Background(), registry, "backend/api", raw)
		if err != nil {
			t.Fatalf("pull authz err: %v", err)
		}
		if ok {
			t.Fatalf("raw %q must not authorize pull", raw)
		}
		// The actor the push path consumes must be empty for a raw bearer.
		actor := subjects.Subject(raw)
		if actor != "" {
			t.Fatalf("raw %q must not become a push actor, got %q", raw, actor)
		}
		if _, ok, err := push.Authorize(context.Background(), registry, "backend/api", actor); err != nil || ok {
			t.Fatalf("raw-derived actor %q must not authorize push (ok=%v err=%v)", actor, ok, err)
		}
	}

	// A cross-purpose/foreign token (not a verifiable session token) presented
	// as a Bearer cannot become a subject either.
	actor := subjects.Subject("Bearer not-a-valid-session-token")
	if actor != "" {
		t.Fatalf("foreign bearer must not become a push actor, got %q", actor)
	}
	if ok, _ := pull.Authorize(context.Background(), registry, "backend/api", "Bearer not-a-valid-session-token"); ok {
		t.Fatal("foreign bearer must not authorize pull")
	}
}

// TestValidSessionSubjectAuthorizesPullConfirms the resolver still works for a
// genuine session token: the documented actor resolution path is intact while
// untrusted bearers are dead.
func TestValidSessionSubjectDoesNotGrantPrivilegedRoles(t *testing.T) {
	t.Parallel()

	owner := "0xbob"
	registry, docs := writePolicyDocs(t, owner)
	subjects, m := newPolicySubjectResolver(t)

	// A genuine, verified session token resolves to its (non-role) subject,
	// which is not in the privileged pull policy, so pull is denied.
	raw, err := m.Issue("user:9", time.Hour)
	if err != nil {
		t.Fatalf("issue session token: %v", err)
	}
	actor := subjects.Subject("Bearer " + raw)
	if actor != "user:9" {
		t.Fatalf("expected user:9, got %q", actor)
	}
	pull := PullAuthorizer{
		Policies: AuthPolicyResolver{Docs: docs, Feeds: nil},
		Subjects: subjects,
	}
	if ok, _ := pull.Authorize(context.Background(), registry, "backend/api", "Bearer "+raw); ok {
		t.Fatal("session subject user:9 must not be granted a privileged policy role")
	}
}
