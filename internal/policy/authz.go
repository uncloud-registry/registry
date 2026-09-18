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

type PullAuthorizer struct {
	Policies AuthPolicyResolver
	Subjects auth.SubjectResolver
}

func (a PullAuthorizer) Authorize(ctx context.Context, registry resolve.RegistryIdentity, repo string, authHeader string) (bool, error) {
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

	if contains(entry.Pull, "anonymous") && authHeader == "" {
		return true, nil
	}

	subject := a.Subjects.Subject(authHeader)
	if subject == "" {
		return false, nil
	}

	return contains(entry.Pull, subject), nil
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
