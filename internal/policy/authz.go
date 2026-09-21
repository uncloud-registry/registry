package policy

import (
	"context"
	"fmt"
	"slices"

	"github.com/uncloud-registry/registry/internal/auth"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
)

type AuthPolicyResolver struct {
	Docs  resolve.Reader
	Feeds resolve.FeedResolver
}

func (r AuthPolicyResolver) Resolve(ctx context.Context, registry resolve.RegistryIdentity) (spec.AuthPolicyDocument, error) {
	ref, err := resolveDocumentRef(ctx, r.Feeds, spec.AuthPolicyFeedRef(registry.Owner))
	if err != nil {
		return spec.AuthPolicyDocument{}, fmt.Errorf("resolve auth policy feed: %w", err)
	}
	data, err := r.Docs.Read(ctx, ref)
	if err != nil {
		return spec.AuthPolicyDocument{}, fmt.Errorf("read auth policy document: %w", err)
	}

	return spec.DecodeAuthPolicyDocument(data)
}

// PullAuthorizer authorizes pull for a single verified principal. It consumes
// ONLY auth.Principal: there is no header, actor-string, or free-form identity
// input, so an unverified raw bearer value can never reach a policy decision.
// Anonymous pull is granted only when the resolved auth policy explicitly
// lists the auth.AnonymousSubject ("anonymous") for the repository.
type PullAuthorizer struct {
	Policies AuthPolicyResolver
}

func (a PullAuthorizer) Authorize(ctx context.Context, registry resolve.RegistryIdentity, repo string, principal auth.Principal) (bool, error) {
	policy, err := a.Policies.Resolve(ctx, registry)
	if err != nil {
		return false, err
	}

	entry, ok := policy.Repos[repo]
	if !ok {
		if policy.DefaultRepo == nil {
			return policy.DefaultAccess == "allow", nil
		}
		entry = *policy.DefaultRepo
	}

	return contains(entry.Pull, principal.Subject), nil
}

func contains(items []string, target string) bool {
	return slices.Contains(items, target)
}

func resolveDocumentRef(ctx context.Context, feeds resolve.FeedResolver, ref string) (string, error) {
	if feeds == nil {
		return ref, nil
	}
	return feeds.ResolveFeed(ctx, ref)
}
