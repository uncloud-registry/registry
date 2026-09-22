package publish

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/uncloud-registry/registry/internal/spec"
)

type ObjectUploader interface {
	Put(ctx context.Context, data []byte, batchID string) (string, error)
}

type FeedUpdater interface {
	UpdateFeed(ctx context.Context, feed string, ref string) error
}

// RepoCommitter commits an immutable repository-state reference through the
// control-plane internal feed signer. The control plane verifies the topic is
// the deterministic feed for the referenced repository, the generation
// advanced by exactly one, the batch is permitted by the current stamp policy,
// and the operation ID is durable-idempotent. ControlPlaneCommitter satisfies
// it; in-memory modes use Publisher.Feeds directly and leave it nil.
type RepoCommitter interface {
	Commit(ctx context.Context, req FeedCommitRequest) (FeedCommitResult, error)
}

type RepoStateStore interface {
	LoadCurrent(ctx context.Context, repo string) (spec.RepoStateDocument, error)
}

type Builder interface {
	BuildNext(current spec.RepoStateDocument, input BuildInput) (spec.RepoStateDocument, error)
}

type BuildInput struct {
	Repo           string
	Tag            string
	ManifestDigest string
	ManifestJSON   []byte
	Manifest       spec.ManifestDescriptor
	StagedBlobs    map[string]spec.BlobDescriptor
}

type Publisher struct {
	Builder Builder
	Objects ObjectUploader
	Feeds   FeedUpdater
	// Commits, when set, routes the repository-state feed commit through the
	// control-plane internal feed signer instead of the local Feeds updater.
	// Bee-mode registry processes set it; in-memory mode leaves it nil and
	// publishes through Feeds. It is never an in-process signer — the control
	// plane alone holds and uses the feed-owner signing key.
	Commits RepoCommitter
}

type DefaultBuilder struct{}

type ociManifest struct {
	SchemaVersion int `json:"schemaVersion"`
	Config        struct {
		Digest string `json:"digest"`
	} `json:"config"`
	Layers []struct {
		Digest string `json:"digest"`
	} `json:"layers"`
}

func (p Publisher) Publish(ctx context.Context, stateFeed string, current spec.RepoStateDocument, input BuildInput, batchID string) (spec.RepoStateDocument, error) {
	return p.publish(ctx, stateFeed, current, input, batchID, false, 0, "", "")
}

// PublishCommit is the publisher path that carries the registry identity,
// owner, expected generation, and a stable deterministic operation ID into the
// repository feed commit. When Publisher.Commits is configured (Bee mode) the
// immutable state reference is committed through the control-plane internal
// feed signer with a FeedCommitRequest built from those fields; otherwise it
// falls back to the local Feeds updater (in-memory mode).
func (p Publisher) PublishCommit(ctx context.Context, stateFeed string, current spec.RepoStateDocument, input BuildInput, batchID string, registryID int64, owner string, operationID string) (spec.RepoStateDocument, error) {
	return p.publish(ctx, stateFeed, current, input, batchID, true, registryID, owner, operationID)
}

func (p Publisher) publish(ctx context.Context, stateFeed string, current spec.RepoStateDocument, input BuildInput, batchID string, useCommits bool, registryID int64, owner string, operationID string) (spec.RepoStateDocument, error) {
	manifestRef, err := p.Objects.Put(ctx, input.ManifestJSON, batchID)
	if err != nil {
		return spec.RepoStateDocument{}, fmt.Errorf("upload manifest bytes: %w", err)
	}

	input.Manifest.SwarmRef = manifestRef
	next, err := p.Builder.BuildNext(current, input)
	if err != nil {
		return spec.RepoStateDocument{}, err
	}

	stateBytes, err := json.Marshal(next)
	if err != nil {
		return spec.RepoStateDocument{}, fmt.Errorf("marshal repo state: %w", err)
	}

	stateRef, err := p.Objects.Put(ctx, stateBytes, batchID)
	if err != nil {
		return spec.RepoStateDocument{}, fmt.Errorf("upload repo state: %w", err)
	}

	if useCommits && p.Commits != nil {
		// Bee mode: route the immutable state reference through the control
		// plane. The control plane alone holds and uses the feed-owner signing
		// key; the registry process never receives it.
		if _, err := p.Commits.Commit(ctx, FeedCommitRequest{
			OperationID:        operationID,
			RegistryID:         registryID,
			Owner:              owner,
			Topic:              stateFeed,
			Reference:          stateRef,
			BatchID:            batchID,
			ExpectedGeneration: current.Generation,
		}); err != nil {
			return spec.RepoStateDocument{}, fmt.Errorf("commit state feed: %w", err)
		}
	} else if err := p.Feeds.UpdateFeed(ctx, stateFeed, stateRef); err != nil {
		return spec.RepoStateDocument{}, fmt.Errorf("update state feed: %w", err)
	}

	return next, nil
}

func (DefaultBuilder) BuildNext(current spec.RepoStateDocument, input BuildInput) (spec.RepoStateDocument, error) {
	if input.Repo == "" || input.Tag == "" || input.ManifestDigest == "" {
		return spec.RepoStateDocument{}, fmt.Errorf("build input missing repo, tag, or manifest digest")
	}

	if err := validateManifestReferences(current, input); err != nil {
		return spec.RepoStateDocument{}, err
	}

	next := spec.RepoStateDocument{
		Version:    1,
		Repo:       input.Repo,
		Generation: current.Generation + 1,
		UpdatedAt:  time.Now().UTC().Format(time.RFC3339),
		Tags:       cloneStringMap(current.Tags),
		Manifests:  cloneManifestMap(current.Manifests),
		Blobs:      cloneBlobMap(current.Blobs),
	}

	for digest, desc := range input.StagedBlobs {
		next.Blobs[digest] = desc
	}
	next.Manifests[input.ManifestDigest] = input.Manifest
	next.Tags[input.Tag] = input.ManifestDigest

	return next, next.Validate()
}

func ComputeDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", sum[:])
}

func validateManifestReferences(current spec.RepoStateDocument, input BuildInput) error {
	var manifest ociManifest
	if err := json.Unmarshal(input.ManifestJSON, &manifest); err != nil {
		return fmt.Errorf("decode manifest: %w", err)
	}
	if manifest.SchemaVersion != 2 {
		return fmt.Errorf("unsupported manifest schema version: %d", manifest.SchemaVersion)
	}

	required := []string{}
	if manifest.Config.Digest != "" {
		required = append(required, manifest.Config.Digest)
	}
	for _, layer := range manifest.Layers {
		if layer.Digest != "" {
			required = append(required, layer.Digest)
		}
	}

	for _, digest := range required {
		if _, ok := current.Blobs[digest]; ok {
			continue
		}
		if _, ok := input.StagedBlobs[digest]; ok {
			continue
		}
		return fmt.Errorf("manifest references missing blob %q", digest)
	}

	return nil
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneManifestMap(in map[string]spec.ManifestDescriptor) map[string]spec.ManifestDescriptor {
	out := make(map[string]spec.ManifestDescriptor, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneBlobMap(in map[string]spec.BlobDescriptor) map[string]spec.BlobDescriptor {
	out := make(map[string]spec.BlobDescriptor, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
