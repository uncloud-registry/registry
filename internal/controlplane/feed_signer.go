package controlplane

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"

	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
	"github.com/uncloud-registry/registry/internal/swarm"
)

// Stable, data-free sentinels for the constrained internal feed signer. They
// map to the coarse generic HTTP statuses of the internal endpoint; none ever
// carries an internal error string, secret, key, or topology.
var (
	// errFeedSignerMalformed: 400 (request violated the bounded shape/syntax
	// contract or the topic/reference/batch policy contract).
	errFeedSignerMalformed = errors.New("feed commit request rejected")
	// errFeedSignerRegistryNotFound: 404 (unknown registry, or owner not theirs).
	errFeedSignerRegistryNotFound = errors.New("registry is unknown")
	// errFeedSignerNotReady: 503 (registry still provisioning).
	errFeedSignerNotReady = errors.New("registry is not ready for feed commits")
	// errFeedSignerGenerationConflict: 409 (generation did not advance or
	// advanced elsewhere).
	errFeedSignerGenerationConflict = errors.New("repository generation advanced elsewhere")
	// errFeedSignerConflict: 409 (operation ID reused with different input).
	errFeedSignerConflict = errors.New("feed commit operation conflict")
	// errFeedSignerBackend: 503 (dependency/Bee/datastore failure).
	errFeedSignerBackend = errors.New("feed signing service backend failure")
)

// FeedSigner cleanly separates the two feed-signing sides: the data plane
// (which holds no feed key) submits a bounded request; the control plane (the
// only holder of the feed-owner key) validates it tightly and signs the
// repository feed update. The signer itself never touches raw key bytes — the
// configured RegistryFeedUpdater (BeeRegistryFeedUpdater) obtains the key via
// FeedKeyDecryptor solely for the immediate signing call and wipes it.
type FeedSigner struct {
	// Store resolves the registry by ID and persists the durable idempotency
	// operations.
	Store *Store
	// Feeds writes the repository-state feed update using the registry's
	// feed-owner key. In Bee mode this is a BeeRegistryFeedUpdater backed by a
	// FeedKeyDecryptor; it is invoked only after every owner/topic/generation/
	// batch validation passes.
	Feeds RegistryFeedUpdater
	// ResolveFeeds independently resolves feeds (the repo-state feed and the
	// deterministic stamp-policy feed) to their current refs. In Bee mode a
	// swarm.BeeFeedResolver.
	ResolveFeeds resolve.FeedResolver
	// Docs reads the immutable objects referenced by feeds and by the request
	// (the target repo-state document and the current stamp-policy document).
	Docs resolve.Reader
}

// Commit is the constrained feed-commit boundary. It validates the bounded
// request shape, derives a canonical request hash (never the raw JSON, so
// field order/whitespace cannot alter identity), enforces durable per-
// OperationID idempotency, and only then performs the registry/topic/
// generation/batch/policy validation and the guarded feed update. All
// validation runs BEFORE the feed-owner key is touched or any network update.
func (s *FeedSigner) Commit(ctx context.Context, req publish.FeedCommitRequest) (publish.FeedCommitResult, error) {
	if isNilDependency(s.Store) || isNilDependency(s.Feeds) || isNilDependency(s.ResolveFeeds) || isNilDependency(s.Docs) {
		return publish.FeedCommitResult{}, fmt.Errorf("%w: signer not fully configured", errFeedSignerBackend)
	}
	if err := publish.ValidateCommitRequest(req); err != nil {
		return publish.FeedCommitResult{}, fmt.Errorf("%w: %v", errFeedSignerMalformed, err)
	}
	reqHash := NormalizeFeedCommitHash(req)

	op, err := s.resolveOperation(ctx, req.OperationID, reqHash)
	if err != nil {
		// errFeedSignerConflict and all wrapped errors are already data-free
		// and classified; return as-is.
		return publish.FeedCommitResult{}, err
	}

	// A terminal succeeded operation with an identical request hash returns the
	// stored result without consulting the feed or the key.
	if op.State == FeedSignerOpSucceeded {
		result, err := decodeStoredResult(op.ResultJSON)
		if err != nil {
			return publish.FeedCommitResult{}, fmt.Errorf("%w: %v", errFeedSignerBackend, err)
		}
		return result, nil
	}

	// Pending: perform the guarded signing. done=true means the feed already
	// resolves to the target (a prior uncertain update succeeded); the result is
	// still persisted idempotently, without a second advancement.
	result, _, err := s.signCommit(ctx, req)
	if err != nil {
		return publish.FeedCommitResult{}, err
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return publish.FeedCommitResult{}, fmt.Errorf("%w: encode result: %v", errFeedSignerBackend, err)
	}
	if err := s.Store.CompleteFeedSignerOperation(ctx, req.OperationID, reqHash, resultJSON); err != nil {
		return publish.FeedCommitResult{}, fmt.Errorf("%w: persist result: %v", errFeedSignerBackend, err)
	}
	return result, nil
}

// resolveOperation returns the durable operation row, inserting a pending row
// on first sight of an OperationID or reloading it when a concurrent first
// request won the insert. It returns errFeedSignerConflict for a reused
// OperationID whose request hash differs.
func (s *FeedSigner) resolveOperation(ctx context.Context, operationID string, reqHash [32]byte) (FeedSignerOperation, error) {
	existing, err := s.Store.GetFeedSignerOperation(ctx, operationID)
	if err == nil {
		if existing.RequestHash != reqHash {
			return FeedSignerOperation{}, errFeedSignerConflict
		}
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return FeedSignerOperation{}, fmt.Errorf("%w: lookup: %v", errFeedSignerBackend, err)
	}
	op, created, rerr := s.Store.ReserveFeedSignerOperation(ctx, operationID, reqHash)
	if rerr != nil {
		return FeedSignerOperation{}, fmt.Errorf("%w: reserve: %v", errFeedSignerBackend, rerr)
	}
	if created {
		return op, nil
	}
	// A concurrent request inserted it between our miss and our reserve.
	reload, rerr := s.Store.GetFeedSignerOperation(ctx, operationID)
	if rerr != nil {
		return FeedSignerOperation{}, fmt.Errorf("%w: reload: %v", errFeedSignerBackend, rerr)
	}
	if reload.RequestHash != reqHash {
		return FeedSignerOperation{}, errFeedSignerConflict
	}
	return reload, nil
}

// signCommit performs the tight validation sequence and, only once every check
// passes, the signed feed update. All validation precedes the key/network use.
// done=true reports that the feed already resolves to the target reference
// (uncertain-response recovery), so the caller persists the result without a
// second advancement.
func (s *FeedSigner) signCommit(ctx context.Context, req publish.FeedCommitRequest) (publish.FeedCommitResult, bool, error) {
	reg, err := s.Store.FindRegistryByID(ctx, req.RegistryID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return publish.FeedCommitResult{}, false, fmt.Errorf("%w: registry %d", errFeedSignerRegistryNotFound, req.RegistryID)
		}
		return publish.FeedCommitResult{}, false, fmt.Errorf("%w: registry: %v", errFeedSignerBackend, err)
	}
	if reg.ProvisioningState != ProvisioningStateReady {
		return publish.FeedCommitResult{}, false, errFeedSignerNotReady
	}
	// Owner check BEFORE any key access or network update: normalized
	// constant-time comparison against the stored feed-owner address.
	if !constantEqual(spec.NormalizeOwner(req.Owner), spec.NormalizeOwner(reg.FeedOwnerAddress)) {
		return publish.FeedCommitResult{}, false, errFeedSignerRegistryNotFound
	}

	// Topic proof: the immutable target reference must decode to a validated
	// RepoStateDocument whose canonical Repo derives exactly the requested
	// Topic (feed://<normalized owner>/<topic of "v1:repo:<repo>">), and its
	// generation must be exactly ExpectedGeneration+1, overflow-safe.
	targetRepo, err := s.verifyTopicFromReference(ctx, req, reg)
	if err != nil {
		return publish.FeedCommitResult{}, false, err
	}

	// Re-read the current repo feed and require current generation ==
	// ExpectedGeneration and the repo identity matches. A missing feed
	// (generation-zero bootstrap) fails closed here; Task 13 owns that path. If
	// the current feed already resolves to the requested Reference, recovery
	// completes idempotently (done=true) after validating the target document.
	done, err := s.resolveCurrentFeed(ctx, req, reg, targetRepo)
	if err != nil {
		return publish.FeedCommitResult{}, false, err
	}

	// Resolve the current stamp policy through the registry's deterministic
	// stamp-policy feed and require the request batch exactly equals the
	// selected repo override (or default) policy's batch.
	if err := s.verifyBatch(ctx, req, reg, targetRepo); err != nil {
		return publish.FeedCommitResult{}, false, err
	}

	result := publish.FeedCommitResult{OperationID: req.OperationID, Feed: req.Topic, Reference: req.Reference}
	if done {
		// Already advanced to the target: no second advancement, just report.
		return result, true, nil
	}

	// All validation passed; the key is now decryptable and the feed is signed.
	// This is the ONLY point a network update happens.
	if err := s.Feeds.UpdateRegistryFeed(ctx, reg, req.Topic, req.Reference); err != nil {
		return publish.FeedCommitResult{}, false, fmt.Errorf("%w: feed update: %v", errFeedSignerBackend, err)
	}
	return result, false, nil
}

// verifyTopicFromReference decodes and validates the immutable target document
// and proves the requested Topic is the FULL deterministic repo-state feed ref
// of the document's own canonical Repo under the registry's normalized owner. It
// returns the canonical repo name. An arbitrary, non-deterministic, auth-policy,
// or stamp-policy topic is rejected BEFORE the key is touched or any feed is
// written.
func (s *FeedSigner) verifyTopicFromReference(ctx context.Context, req publish.FeedCommitRequest, reg Registry) (string, error) {
	data, err := s.Docs.Read(ctx, req.Reference)
	if err != nil {
		return "", fmt.Errorf("%w: target reference: %v", errFeedSignerBackend, err)
	}
	doc, err := spec.DecodeRepoStateDocument(data)
	if err != nil {
		return "", fmt.Errorf("%w: target is not a valid repo state document: %v", errFeedSignerMalformed, err)
	}
	derived := spec.RepoStateFeedRef(spec.NormalizeOwner(reg.FeedOwnerAddress), doc.Repo)
	if derived != req.Topic {
		return "", fmt.Errorf("%w: topic is not the deterministic reference for the repository in the target document", errFeedSignerMalformed)
	}
	// Target generation must be exactly ExpectedGeneration+1, overflow-safe:
	// the publication advanced exactly one generation from the caller's view.
	if req.ExpectedGeneration == math.MaxInt64 {
		return "", errFeedSignerGenerationConflict
	}
	if doc.Generation != req.ExpectedGeneration+1 {
		return "", errFeedSignerGenerationConflict
	}
	return doc.Repo, nil
}

// resolveCurrentFeed re-reads the current repo feed via the resolver and the
// immutable object reader, requiring current generation == ExpectedGeneration
// and the repo identity matching the target's repo. done=true means the current
// feed already resolves to the requested Reference (a prior uncertain update
// succeeded), which is reported idempotently.
func (s *FeedSigner) resolveCurrentFeed(ctx context.Context, req publish.FeedCommitRequest, reg Registry, targetRepo string) (bool, error) {
	currentRef, err := s.ResolveFeeds.ResolveFeed(ctx, req.Topic)
	if err != nil {
		return false, fmt.Errorf("%w: current repo feed: %v", errFeedSignerBackend, err)
	}
	if swarm.CanonicalObjectRef(currentRef) == swarm.CanonicalObjectRef(req.Reference) {
		// Already points at the target. Validate the current document identity
		// (repo match) before reporting recovery success; target generation was
		// already validated by verifyTopicFromReference.
		curData, err := s.Docs.Read(ctx, currentRef)
		if err != nil {
			return false, fmt.Errorf("%w: current repo document: %v", errFeedSignerBackend, err)
		}
		curDoc, err := spec.DecodeRepoStateDocument(curData)
		if err != nil {
			return false, fmt.Errorf("%w: current repo document: %v", errFeedSignerBackend, err)
		}
		if curDoc.Repo != targetRepo {
			return false, fmt.Errorf("%w: current repo identity does not match the referenced repository", errFeedSignerMalformed)
		}
		return true, nil
	}
	// Not at the target: the feed must still be at the expected generation and
	// the same repository, or a concurrent/other writer advanced it (conflict).
	curData, err := s.Docs.Read(ctx, currentRef)
	if err != nil {
		return false, fmt.Errorf("%w: current repo document: %v", errFeedSignerBackend, err)
	}
	curDoc, err := spec.DecodeRepoStateDocument(curData)
	if err != nil {
		return false, fmt.Errorf("%w: current repo document: %v", errFeedSignerBackend, err)
	}
	if curDoc.Repo != targetRepo {
		return false, fmt.Errorf("%w: current repo identity does not match the referenced repository", errFeedSignerMalformed)
	}
	if curDoc.Generation != req.ExpectedGeneration {
		return false, errFeedSignerGenerationConflict
	}
	return false, nil
}

// verifyBatch resolves the registry's deterministic stamp-policy feed, decodes
// and validates the current policy, selects the exact repo override (or the
// default), and requires the caller-supplied BatchID to equal it exactly. The
// caller-selected batch is never trusted.
func (s *FeedSigner) verifyBatch(ctx context.Context, req publish.FeedCommitRequest, reg Registry, targetRepo string) error {
	stampFeed := spec.StampPolicyFeedRef(reg.FeedOwnerAddress)
	ref, err := s.ResolveFeeds.ResolveFeed(ctx, stampFeed)
	if err != nil {
		return fmt.Errorf("%w: stamp policy feed: %v", errFeedSignerBackend, err)
	}
	data, err := s.Docs.Read(ctx, ref)
	if err != nil {
		return fmt.Errorf("%w: stamp policy document: %v", errFeedSignerBackend, err)
	}
	doc, err := spec.DecodeStampPolicyDocument(data)
	if err != nil {
		return fmt.Errorf("%w: stamp policy document: %v", errFeedSignerBackend, err)
	}
	selected := doc.DefaultPolicy
	if repoPolicy, ok := doc.Repos[targetRepo]; ok {
		selected = repoPolicy
	}
	if req.BatchID != selected.BatchID {
		return fmt.Errorf("%w: batch is not permitted by the current stamp policy", errFeedSignerMalformed)
	}
	return nil
}

// NormalizeFeedCommitHash derives the deterministic domain-separated SHA-256 of
// the canonical typed request fields (NOT raw JSON, so field order/whitespace
// cannot change identity, and NEVER the credential, which travels only in a
// header). This is the fixed-size value durable-idempotency stores and compares.
func NormalizeFeedCommitHash(req publish.FeedCommitRequest) [32]byte {
	h := sha256.New()
	h.Write([]byte("uncloud-registry-feed-commit-req:v1\x00"))
	h.Write([]byte(req.OperationID))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(req.RegistryID, 10)))
	h.Write([]byte{0})
	h.Write([]byte(req.Owner))
	h.Write([]byte{0})
	h.Write([]byte(req.Topic))
	h.Write([]byte{0})
	h.Write([]byte(req.Reference))
	h.Write([]byte{0})
	h.Write([]byte(req.BatchID))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(req.ExpectedGeneration, 10)))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func decodeStoredResult(data []byte) (publish.FeedCommitResult, error) {
	var result publish.FeedCommitResult
	if err := json.Unmarshal(data, &result); err != nil {
		return publish.FeedCommitResult{}, err
	}
	return result, nil
}
