package policy

import (
	"context"
	"fmt"
	"slices"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
)

type StampPolicyResolver struct {
	Docs  resolve.Reader
	Feeds resolve.FeedResolver
}

func (r StampPolicyResolver) Resolve(ctx context.Context, registry resolve.RegistryIdentity) (spec.StampPolicyDocument, error) {
	ref, err := resolveDocumentRef(ctx, r.Feeds, spec.StampPolicyFeedRef(registry.Owner))
	if err != nil {
		return spec.StampPolicyDocument{}, fmt.Errorf("resolve stamp policy feed: %w", err)
	}
	data, err := r.Docs.Read(ctx, ref)
	if err != nil {
		return spec.StampPolicyDocument{}, fmt.Errorf("read stamp policy document: %w", err)
	}

	return spec.DecodeStampPolicyDocument(data)
}

// PushAuthorizer authorizes push for a single verified principal and returns
// the stamp batch the push may consume. It consumes ONLY auth.Principal; the
// anonymous principal (or an empty subject) can never push, even if a policy
// document listed "anonymous" in a push list. The actor identity used for
// staging ownership and stamp policy is the principal's verified subject.
type PushAuthorizer struct {
	AuthPolicies  AuthPolicyResolver
	StampPolicies StampPolicyResolver
}

func (a PushAuthorizer) Authorize(ctx context.Context, registry resolve.RegistryIdentity, repo string, principal auth.Principal) (string, bool, error) {
	actor := principal.Subject
	if actor == "" || actor == auth.AnonymousSubject {
		return "", false, nil
	}

	authPolicy, err := a.AuthPolicies.Resolve(ctx, registry)
	if err != nil {
		return "", false, err
	}

	authEntry, ok := authPolicy.Repos[repo]
	if !ok {
		if authPolicy.DefaultRepo == nil {
			return "", false, nil
		}
		authEntry = *authPolicy.DefaultRepo
	}
	if !slices.Contains(authEntry.Push, actor) {
		return "", false, nil
	}

	stampPolicy, err := a.StampPolicies.Resolve(ctx, registry)
	if err != nil {
		return "", false, err
	}

	selected := stampPolicy.DefaultPolicy
	if repoPolicy, ok := stampPolicy.Repos[repo]; ok {
		selected = repoPolicy
	}
	if !slices.Contains(selected.AllowPushFor, actor) {
		return "", false, nil
	}

	return selected.BatchID, true, nil
}
