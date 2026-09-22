package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

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
	// operations (reserve/claim/complete).
	Store *Store
	// Feeds writes the repository-state feed update using the registry's
	// feed-owner key. In Bee mode this is a BeeRegistryFeedUpdater backed by a
	// FeedKeyDecryptor; it is invoked only after every owner/topic/generation/
	// batch validation passes AND this request won the durable (registry, topic)
	// claim — so exactly one request per repository feed ever performs the
	// network/key work at a time.
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
// request shape, derives a canonical domain-separated request hash (never the
// raw JSON), ensures a durable operation row, and then atomically CLAIMS the
// right to perform the network/key work. Exactly one request owns the work for
// a given operation (and for a given repository feed across DISTINCT
// operations — via the partial unique index on processing). A concurrent
// identical caller never performs the work: it bounds its poll for the
// owner's stored result and returns it, or returns a retryable backend error
// when the lease/context bound is reached. All validation runs BEFORE the
// feed-owner key is touched or any network update.
func (s *FeedSigner) Commit(ctx context.Context, req publish.FeedCommitRequest) (publish.FeedCommitResult, error) {
	if isNilDependency(s.Store) || isNilDependency(s.Feeds) || isNilDependency(s.ResolveFeeds) || isNilDependency(s.Docs) {
		return publish.FeedCommitResult{}, fmt.Errorf("%w: signer not fully configured", errFeedSignerBackend)
	}
	if err := publish.ValidateCommitRequest(req); err != nil {
		return publish.FeedCommitResult{}, fmt.Errorf("%w: %v", errFeedSignerMalformed, err)
	}
	reqHash := NormalizeFeedCommitHash(req)
	canonicalTopic := publish.CanonicalTopic(req.Topic)

	// Resolve the registry up front so an unknown registry is a deterministic,
	// data-free "registry not found" (the durable row FK requires an existing
	// registry, so this must precede reserving it). All remaining validation
	// (owner, readiness, topic, generation, batch) runs later under the claim.
	if _, err := s.Store.FindRegistryByID(ctx, req.RegistryID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return publish.FeedCommitResult{}, errFeedSignerRegistryNotFound
		}
		return publish.FeedCommitResult{}, fmt.Errorf("%w: registry: %v", errFeedSignerBackend, err)
	}

	// Ensure a durable pending row exists for this operation. A reused
	// OperationID with different input is a hard conflict.
	op, err := s.Store.ReserveFeedSignerOperation(ctx, req.OperationID, req.RegistryID, canonicalTopic, reqHash)
	if err != nil {
		return publish.FeedCommitResult{}, fmt.Errorf("%w: reserve: %v", errFeedSignerBackend, err)
	}
	if op.RequestHash != reqHash {
		return publish.FeedCommitResult{}, errFeedSignerConflict
	}

	// Claim the work with a bounded poll: a concurrent identical request that
	// already owns the lease must not call the updater — we return its stored
	// result when it succeeds, or a retryable backend error when the bound is
	// reached.
	for attempt := 0; ; attempt++ {
		if attempt >= feedSignerClaimMaxAttempts {
			return publish.FeedCommitResult{}, fmt.Errorf("%w: another request still owns this operation", errFeedSignerBackend)
		}
		op, err = s.Store.GetFeedSignerOperation(ctx, req.OperationID)
		if err != nil {
			return publish.FeedCommitResult{}, fmt.Errorf("%w: lookup: %v", errFeedSignerBackend, err)
		}
		switch op.State {
		case FeedSignerOpSucceeded:
			return s.storedResult(op, req)
		case FeedSignerOpPending:
			token := newClaimToken()
			leaseUntil := time.Now().UTC().Add(feedSignerLeaseDuration)
			won, cerr := s.Store.ClaimFeedSignerOperation(ctx, req.OperationID, reqHash, token, leaseUntil)
			if cerr != nil {
				// The partial-unique (registry, topic) gate refused this
				// operation: a DISTINCT operation already owns the repository
				// feed's processing slot (or a genuine DB failure). Either way
				// we are the loser and must NEVER update. Retryable.
				return publish.FeedCommitResult{}, fmt.Errorf("%w: claim: %v", errFeedSignerBackend, cerr)
			}
			if won {
				return s.runSignedCommit(ctx, req, reqHash, token)
			}
			// An identical request won the claim; reload and poll.
		case FeedSignerOpProcessing:
			if op.LeaseUntil != nil && op.LeaseUntil.After(time.Now()) {
				// A live lease is held by a concurrent owner (identical request,
				// or a distinct operation on the same feed). Wait briefly and
				// poll for its outcome.
				if !waitForLease(ctx) {
					return publish.FeedCommitResult{}, fmt.Errorf("%w: context cancelled while waiting for the operation owner", errFeedSignerBackend)
				}
				continue
			}
			// Expired lease (a crashed/uncertain prior attempt at this same
			// operation): take it over with a fresh token and resolve.
			token := newClaimToken()
			leaseUntil := time.Now().UTC().Add(feedSignerLeaseDuration)
			won, cerr := s.Store.ClaimFeedSignerOperation(ctx, req.OperationID, reqHash, token, leaseUntil)
			if cerr != nil {
				return publish.FeedCommitResult{}, fmt.Errorf("%w: reclaim: %v", errFeedSignerBackend, cerr)
			}
			if won {
				return s.runSignedCommit(ctx, req, reqHash, token)
			}
			// Claim raced; reload and poll.
		}
	}
}

// runSignedCommit performs the guarded signing under a won claim and then
// durably completes it (or conditionally releases on a definite pre-update
// failure). An uncertain update failure keeps the lease until recovery.
func (s *FeedSigner) runSignedCommit(ctx context.Context, req publish.FeedCommitRequest, reqHash [32]byte, claimToken string) (publish.FeedCommitResult, error) {
	result, _, uncertain, err := s.signCommit(ctx, req)
	if err != nil {
		if !uncertain {
			// Definite pre-update failure (malformed/not-ready/owner/topic/
			// generation/batch): release the claim so a retry may re-claim.
			_ = s.Store.ReleaseFeedSignerOperation(ctx, req.OperationID, claimToken)
		}
		// Uncertain update failure is NOT released: the lease is kept until a
		// later identical request reclaims it (after expiry) and resolves the
		// target without a second advancement.
		return publish.FeedCommitResult{}, err
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return publish.FeedCommitResult{}, fmt.Errorf("%w: encode result: %v", errFeedSignerBackend, err)
	}
	if err := s.Store.CompleteFeedSignerOperation(ctx, req.OperationID, reqHash, claimToken, resultJSON); err != nil {
		return publish.FeedCommitResult{}, fmt.Errorf("%w: persist result: %v", errFeedSignerBackend, err)
	}
	return result, nil
}

// storedResult decodes and canonically VERIFIES a stored succeeded result
// against the request before returning it: OperationID must equal the row and
// the request, Feed must equal the canonical request topic, and Reference must
// equal the canonical request reference. A corrupt or mismatched stored result
// is a fail-closed backend error, never a fabricated success.
func (s *FeedSigner) storedResult(op FeedSignerOperation, req publish.FeedCommitRequest) (publish.FeedCommitResult, error) {
	result, err := decodeStoredResult(op.ResultJSON)
	if err != nil {
		return publish.FeedCommitResult{}, fmt.Errorf("%w: stored result: %v", errFeedSignerBackend, err)
	}
	if result.OperationID != op.OperationID || result.OperationID != req.OperationID {
		return publish.FeedCommitResult{}, fmt.Errorf("%w: stored result operation ID mismatch", errFeedSignerBackend)
	}
	if result.Feed != publish.CanonicalTopic(req.Topic) || result.Reference != publish.CanonicalReference(req.Reference) {
		return publish.FeedCommitResult{}, fmt.Errorf("%w: stored result does not match this request", errFeedSignerBackend)
	}
	return result, nil
}

// signCommit performs the tight validation sequence and, only once every check
// passes and the caller already owns the claim, the signed feed update. All
// validation precedes the key/network use. done=true reports that the feed
// already resolves to the target reference (uncertain-response recovery), so
// the caller persists the result without a second advancement. uncertain=true
// reports that the failure occurred DURING the network feed update (the update
// may have partially/fully applied), so the caller keeps the lease.
func (s *FeedSigner) signCommit(ctx context.Context, req publish.FeedCommitRequest) (publish.FeedCommitResult, bool, bool, error) {
	reg, err := s.Store.FindRegistryByID(ctx, req.RegistryID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return publish.FeedCommitResult{}, false, false, fmt.Errorf("%w: registry %d", errFeedSignerRegistryNotFound, req.RegistryID)
		}
		return publish.FeedCommitResult{}, false, false, fmt.Errorf("%w: registry: %v", errFeedSignerBackend, err)
	}
	if reg.ProvisioningState != ProvisioningStateReady {
		return publish.FeedCommitResult{}, false, false, errFeedSignerNotReady
	}
	// Owner check BEFORE any key access or network update: normalized
	// constant-time comparison against the stored feed-owner address.
	if !constantEqual(spec.NormalizeOwner(req.Owner), spec.NormalizeOwner(reg.FeedOwnerAddress)) {
		return publish.FeedCommitResult{}, false, false, errFeedSignerRegistryNotFound
	}

	// Topic proof + canonical target document + generation (definite pre-update).
	targetRepo, err := s.verifyTopicFromReference(ctx, req, reg)
	if err != nil {
		return publish.FeedCommitResult{}, false, false, err
	}

	// Current feed + repo identity + generation (definite pre-update).
	done, err := s.resolveCurrentFeed(ctx, req, reg, targetRepo)
	if err != nil {
		return publish.FeedCommitResult{}, false, false, err
	}

	// Stamp policy / batch proof (definite pre-update).
	if err := s.verifyBatch(ctx, req, reg, targetRepo); err != nil {
		return publish.FeedCommitResult{}, false, false, err
	}

	result := publish.FeedCommitResult{
		OperationID: req.OperationID,
		Feed:        publish.CanonicalTopic(req.Topic),
		Reference:   publish.CanonicalReference(req.Reference),
	}
	if done {
		// Already advanced to the target (recovery): no second advancement.
		return result, true, false, nil
	}

	// All validation passed and we own the claim; the key is now decryptable
	// and the feed is signed. THIS is the only point a network update happens.
	if err := s.Feeds.UpdateRegistryFeed(ctx, reg, req.Topic, req.Reference); err != nil {
		return result, false, true, fmt.Errorf("%w: feed update: %v", errFeedSignerBackend, err)
	}
	return result, false, false, nil
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
	// Target generation must be exactly ExpectedGeneration+1, overflow-safe.
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
// the canonical TYPED request fields (NOT raw JSON, so field order/whitespace
// cannot change identity, and NEVER the credential). Typed fields are
// normalized FIRST (owner via NormalizeOwner, the 64-hex reference lowercased,
// the topic as the canonical deterministic feed ref) and encoded with explicit
// binary fixed-width or length-prefix framing — every string carries a 4-byte
// big-endian length, every integer an 8-byte big-endian width — so no NUL or
// separator byte inside a value can create field-boundary ambiguity. The
// OperationID is deliberately included: the hash binds the request identity to
// the durable operation row, so a reused OperationID with different input is a
// hard conflict.
func NormalizeFeedCommitHash(req publish.FeedCommitRequest) [32]byte {
	h := sha256.New()
	h.Write([]byte("uncloud-registry-feed-commit-req:v1\x00"))
	writeHashBytes(h, publish.CanonicalTopic(req.Topic))
	writeHashBytes(h, spec.NormalizeOwner(req.Owner))
	writeHashBytes(h, publish.CanonicalReference(req.Reference))
	writeHashBytes(h, req.BatchID)
	writeHashInt(h, req.ExpectedGeneration)
	writeHashInt(h, req.RegistryID)
	writeHashBytes(h, req.OperationID)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func writeHashBytes(h io.Writer, s string) {
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(s)))
	h.Write(lb[:])
	h.Write([]byte(s))
}

func writeHashInt(h io.Writer, v int64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(v))
	h.Write(b[:])
}

// decodeStoredResult STRICTLY decodes a stored succeeded result JSON: duplicate
// members anywhere, unknown top-level fields, trailing content, and a field
// contract violation are all rejected so a corrupt store row can never
// fabricate a success.
func decodeStoredResult(data []byte) (publish.FeedCommitResult, error) {
	if len(data) == 0 {
		return publish.FeedCommitResult{}, errors.New("blank stored result")
	}
	if err := rejectDuplicateJSONObjectMembers(data); err != nil {
		return publish.FeedCommitResult{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var result publish.FeedCommitResult
	if err := dec.Decode(&result); err != nil {
		return publish.FeedCommitResult{}, err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return publish.FeedCommitResult{}, errors.New("unexpected trailing content after stored result")
	}
	if err := publish.ValidateCommitResult(result); err != nil {
		return publish.FeedCommitResult{}, err
	}
	return result, nil
}

func waitForLease(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(feedSignerClaimPollInterval):
		return true
	}
}
