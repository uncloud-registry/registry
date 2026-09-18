package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/uncloud-registry/registry/internal/spec"
	"github.com/uncloud-registry/registry/internal/swarm"
)

type DocumentUploader interface {
	Put(ctx context.Context, data []byte, batchID string) (string, error)
}

type RegistryFeedUpdater interface {
	UpdateRegistryFeed(ctx context.Context, registry Registry, feed string, ref string) error
}

type MembershipSubject struct {
	UserID  int64
	Role    string
	CanPull bool
	CanPush bool
}

type BootstrapPublication struct {
	FeedOwnerAddress string `json:"feedOwnerAddress"`
	AuthPolicyFeed   string `json:"authPolicyFeed"`
	StampPolicyFeed  string `json:"stampPolicyFeed"`
}

type Publisher struct {
	Documents DocumentUploader
	Feeds     RegistryFeedUpdater
}

func (p Publisher) PublishBootstrap(ctx context.Context, registry Registry, memberships []MembershipSubject) (BootstrapPublication, error) {
	authFeed := authPolicyFeedRef(registry)
	stampFeed := stampPolicyFeedRef(registry)

	if _, err := p.publishAuthPolicy(ctx, registry, memberships); err != nil {
		return BootstrapPublication{}, err
	}
	if _, err := p.publishStampPolicy(ctx, registry, memberships); err != nil {
		return BootstrapPublication{}, err
	}

	return BootstrapPublication{
		FeedOwnerAddress: registry.FeedOwnerAddress,
		AuthPolicyFeed:   authFeed,
		StampPolicyFeed:  stampFeed,
	}, nil
}

func (p Publisher) PublishAuthPolicy(ctx context.Context, registry Registry, memberships []MembershipSubject) (string, error) {
	return p.publishAuthPolicy(ctx, registry, memberships)
}

func (p Publisher) PublishStampPolicy(ctx context.Context, registry Registry, memberships []MembershipSubject) (string, error) {
	return p.publishStampPolicy(ctx, registry, memberships)
}

func (p Publisher) PublishRawAuthPolicy(ctx context.Context, registry Registry, doc spec.AuthPolicyDocument) (string, error) {
	data, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("marshal auth policy document: %w", err)
	}
	ref, err := p.Documents.Put(ctx, data, registry.DefaultStampBatchID)
	if err != nil {
		return "", fmt.Errorf("upload auth policy document: %w", err)
	}
	feed := authPolicyFeedRef(registry)
	if err := p.Feeds.UpdateRegistryFeed(ctx, registry, feed, ref); err != nil {
		return "", fmt.Errorf("update auth policy feed: %w", err)
	}
	return feed, nil
}

func (p Publisher) PublishRawStampPolicy(ctx context.Context, registry Registry, doc spec.StampPolicyDocument) (string, error) {
	data, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("marshal stamp policy document: %w", err)
	}
	ref, err := p.Documents.Put(ctx, data, registry.DefaultStampBatchID)
	if err != nil {
		return "", fmt.Errorf("upload stamp policy document: %w", err)
	}
	feed := stampPolicyFeedRef(registry)
	if err := p.Feeds.UpdateRegistryFeed(ctx, registry, feed, ref); err != nil {
		return "", fmt.Errorf("update stamp policy feed: %w", err)
	}
	return feed, nil
}

func (p Publisher) publishAuthPolicy(ctx context.Context, registry Registry, memberships []MembershipSubject) (string, error) {
	pushActors := []string{"role:write"}
	pullActors := []string{"role:read", "role:write"}
	if registry.AnonymousPull {
		pullActors = append([]string{"anonymous"}, pullActors...)
	}

	doc := spec.AuthPolicyDocument{
		Version:       1,
		DefaultAccess: "deny",
		DefaultRepo: &spec.RepoAuthPolicyEntry{
			Pull: pullActors,
			Push: pushActors,
		},
		Repos: map[string]spec.RepoAuthPolicyEntry{},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("marshal auth policy document: %w", err)
	}
	ref, err := p.Documents.Put(ctx, data, registry.DefaultStampBatchID)
	if err != nil {
		return "", fmt.Errorf("upload auth policy document: %w", err)
	}
	feed := authPolicyFeedRef(registry)
	if err := p.Feeds.UpdateRegistryFeed(ctx, registry, feed, ref); err != nil {
		return "", fmt.Errorf("update auth policy feed: %w", err)
	}
	return feed, nil
}

func (p Publisher) publishStampPolicy(ctx context.Context, registry Registry, memberships []MembershipSubject) (string, error) {
	doc := spec.StampPolicyDocument{
		Version: 1,
		DefaultPolicy: spec.StampAccessPolicy{
			BatchID:      registry.DefaultStampBatchID,
			AllowPushFor: []string{"role:write"},
		},
		Repos: map[string]spec.StampAccessPolicy{},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("marshal stamp policy document: %w", err)
	}
	ref, err := p.Documents.Put(ctx, data, registry.DefaultStampBatchID)
	if err != nil {
		return "", fmt.Errorf("upload stamp policy document: %w", err)
	}
	feed := stampPolicyFeedRef(registry)
	if err := p.Feeds.UpdateRegistryFeed(ctx, registry, feed, ref); err != nil {
		return "", fmt.Errorf("update stamp policy feed: %w", err)
	}
	return feed, nil
}

func authPolicyFeedRef(registry Registry) string {
	return spec.AuthPolicyFeedRef(registry.FeedOwnerAddress)
}

func stampPolicyFeedRef(registry Registry) string {
	return spec.StampPolicyFeedRef(registry.FeedOwnerAddress)
}

type MemoryRegistryFeedUpdater struct {
	Feeds map[string]string
}

func (m *MemoryRegistryFeedUpdater) UpdateRegistryFeed(_ context.Context, _ Registry, feed string, ref string) error {
	m.Feeds[feed] = ref
	return nil
}

type BeeRegistryFeedUpdater struct {
	BaseURL    string
	HTTPClient *http.Client
}

func (b BeeRegistryFeedUpdater) UpdateRegistryFeed(ctx context.Context, registry Registry, feed string, ref string) error {
	updater, err := swarm.NewBeeSequenceFeedUpdater(b.BaseURL, b.HTTPClient, registry.EncryptedFeedPrivateKey)
	if err != nil {
		return err
	}
	return updater.UpdateFeed(ctx, feed, ref)
}
