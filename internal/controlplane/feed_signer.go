package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"sync"
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

	// Adopt any quarantined migration-9 row for this operation on this FIRST
	// request (before reservation). A quarantined row is located atomically by
	// the CURRENT operation ID OR the DERIVED historical migration-9 operation
	// ID, and its stored request hash must match the algorithm/identity of the
	// row it claims (see legacyComputeOperationID / deriveLegacyOperationID);
	// a differing hash under either identity is a hard conflict (a reused
	// OperationID with different input), a malformed legacy succeeded result
	// fails closed and stays quarantined, and TWO distinct valid candidates are
	// an ambiguity that fails closed (never accidentally adopt a different
	// logical request). The historical ID is only ever derived here to RECOGNIZE
	// a logically-identical m9 row; it is never used as a new active operation
	// ID — the promoted active row always carries the CURRENT operation ID and
	// CURRENT request hash. The round-3 legacy hash — the historical framing
	// over the CURRENT request with the CURRENT operation ID — does NOT match a
	// real m9 row (whose operation ID was the historical value), so it is
	// replaced here by the historical hash over the reconstructed historical
	// request (OperationID := the derived historical ID).
	var legacyOpID string
	var legacyHash [32]byte
	if n, err := s.Store.LegacyOperationCount(ctx); err == nil && n > 0 {
		if id, ok := s.deriveLegacyOperationID(ctx, req); ok {
			legacyOpID = id
			legacyHash = legacyFeedCommitHashFor(id, req)
		}
	}
	_, aerr := s.Store.AdoptLegacyFeedSignerOperation(ctx, req.OperationID, req.RegistryID, canonicalTopic, publish.CanonicalReference(req.Reference), reqHash, legacyOpID, legacyHash)
	if aerr != nil {
		if errors.Is(aerr, errFeedSignerLegacyConflict) {
			return publish.FeedCommitResult{}, errFeedSignerConflict
		}
		return publish.FeedCommitResult{}, fmt.Errorf("%w: adopt legacy operation: %v", errFeedSignerBackend, aerr)
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
			token, terr := newClaimToken()
			if terr != nil {
				return publish.FeedCommitResult{}, fmt.Errorf("%w: claim token entropy: %v", errFeedSignerBackend, terr)
			}
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
			token, terr := newClaimToken()
			if terr != nil {
				return publish.FeedCommitResult{}, fmt.Errorf("%w: claim token entropy: %v", errFeedSignerBackend, terr)
			}
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
//
// The ENTIRE validation+read+update operation runs under a single derived work
// context bounded by feedSignerWorkTimeout (strictly shorter than the lease),
// with a joined renewal heartbeat that extends the caller's own lease every
// feedSignerRenewInterval. Every resolver/doc/updater call inherits the work
// deadline. If the heartbeat fails to renew (a stale/defeated token, or a
// takeover), the work context is cancelled immediately and completion is
// prevented; the caller discovers the cancellation when the work loop returns.
func (s *FeedSigner) runSignedCommit(ctx context.Context, req publish.FeedCommitRequest, reqHash [32]byte, claimToken string) (publish.FeedCommitResult, error) {
	workCtx, cancelWork := context.WithTimeout(ctx, feedSignerWorkTimeout)
	defer cancelWork()

	// Joined renewal heartbeat: extend our own lease (token-owned, conditional)
	// every lease/3. A failure to renew cancels the work immediately.
	heartbeatDone := make(chan struct{})
	var renewOnce sync.Once
	renew := func() {
		renewOnce.Do(func() {
			deadline := time.Now().UTC().Add(feedSignerLeaseDuration)
			if err := s.Store.ExtendFeedSignerLease(workCtx, req.OperationID, claimToken, deadline); err != nil {
				// Lost the lease: stop the work before any update/completion.
				cancelWork()
			}
		})
	}
	go func() {
		ticker := time.NewTicker(feedSignerRenewInterval)
		defer ticker.Stop()
		defer close(heartbeatDone)
		for {
			select {
			case <-workCtx.Done():
				return
			case <-ticker.C:
				renew()
			}
		}
	}()

	result, _, uncertain, err := s.signCommit(workCtx, req, claimToken)
	// Stop the heartbeat now that the work returned (the deferred cancelWork
	// also fires on every return path, but an explicit cancel here guarantees
	// the heartbeat goroutine exits before we wait on it).
	cancelWork()
	<-heartbeatDone

	if err != nil {
		if !uncertain {
			// Definite pre-update failure (malformed/not-ready/owner/topic/
			// generation/batch): release the claim so a retry may re-claim.
			_ = s.Store.ReleaseFeedSignerOperation(ctx, req.OperationID, claimToken)
		}
		// Uncertain update failure is NOT released: the lease is kept until a
		// later identical request reclaims it (after expiry) and resolves the
		// target without a second advancement.
		// If the work context was cancelled (renewal failure / timeout), that
		// cancellation is the cause and surfaces as a retryable backend error.
		return publish.FeedCommitResult{}, err
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return publish.FeedCommitResult{}, fmt.Errorf("%w: encode result: %v", errFeedSignerBackend, err)
	}
	if !bytes.Equal(resultJSON, publish.CanonicalFeedCommitResultJSON(result)) {
		// The canonical byte-exact form must be exactly what the DB trigger
		// will accept; if json.Marshal escaped anything the request violated
		// the JSON-safe contract and we fail closed rather than persist a
		// non-canonical result.
		return publish.FeedCommitResult{}, fmt.Errorf("%w: result is not byte-canonical", errFeedSignerBackend)
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
// passes and the caller still owns the claim, the signed feed update. All
// validation precedes the key/network use. Ownership of the claim (exact token
// + live lease) is re-verified immediately BEFORE the external update, so a
// defeated owner whose lease was taken over discovers it lost the claim before
// touching the updater. done=true reports that the feed already resolves to the
// target reference (uncertain-response recovery), so the caller persists the
// result without a second advancement. uncertain=true reports that the failure
// occurred DURING the network feed update (the update may have partially/fully
// applied), so the caller keeps the lease.
func (s *FeedSigner) signCommit(ctx context.Context, req publish.FeedCommitRequest, claimToken string) (publish.FeedCommitResult, bool, bool, error) {
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

	// All validation passed and we own the claim. Re-verify ownership at this
	// instant so a defeated owner whose lease was taken over fails CLOSED before
	// touching the key/network — after the updater starts, perfect cancellation
	// is impossible, so a stale owner must be caught here.
	if err := s.Store.EnsureFeedSignerLeaseOwned(ctx, req.OperationID, claimToken); err != nil {
		return result, false, false, fmt.Errorf("%w: lost ownership before feed update: %v", errFeedSignerBackend, err)
	}
	// The key is now decryptable and the feed is signed. THIS is the only point
	// a network update happens.
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

// legacyFeedCommitHash reproduces the EXACT migration-9 (1e91614) request hash:
// the ORIGINAL delimiter-framed SHA-256 over the RAW request fields in the
// historical order (OperationID, RegistryID as decimal, Owner, Topic,
// Reference, BatchID, ExpectedGeneration as decimal), each separated by a
// single 0x00 byte, prefixed by the historical domain string. Migration-9
// rows stored exactly this value in feed_signer_operations.request_hash, and
// migration 10 quarantined those rows byte-for-byte.
//
// THIS FUNCTION IS MIGRATION-ONLY: it reproduces old bytes solely so
// AdoptLegacyFeedSignerOperation can recognize and adopt a logically-identical
// m9 row whose stored hash cannot match the length-prefixed
// NormalizeFeedCommitHash. It MUST NOT be used to hash new requests
// (NormalizeFeedCommitHash is the sole forward hashing function), and its
// delimiter framing is deliberately never reintroduced for new rows — a NUL or
// separator byte inside a value here can create field-boundary ambiguity,
// which is exactly why the forward hash switched to fixed-width/length-prefix
// framing. It hashes the RAW (un-normalized, as-supplied) owner/topic/
// reference, precisely matching what migration 9 computed.
func legacyFeedCommitHash(req publish.FeedCommitRequest) [32]byte {
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

// legacyFeedCommitHashFor reproduces the EXACT migration-9 request hash for a
// request whose OperationID is EXACTLY opID. It constructs the historical
// request — every field identical to the current request except OperationID,
// which is the caller-supplied historical ID — and hashes it with the
// delimiter-framed historical algorithm (legacyFeedCommitHash). A real
// migration-9 row stored a hash computed over a request whose OperationID was
// the HISTORICAL ComputeOperationID output, so only this historical-hash-over-
// the-request-with-the-historical-ID byte sequence can ever match it. It only
// ever runs in the adoption bridging path (never for new active operations,
// which are hashed with NormalizeFeedCommitHash).
func legacyFeedCommitHashFor(opID string, req publish.FeedCommitRequest) [32]byte {
	histReq := req
	histReq.OperationID = opID
	return legacyFeedCommitHash(histReq)
}

// legacyComputeOperationID reproduces the EXACT historical migration-9
// (1e91614 internal/publish/commit.go) ComputeOperationID: SHA-256 of the
// original 0x00-delimited domain prefix and RAW fields (registryID as decimal,
// owner, repo, tag, manifestDigest as supplied, expectedGeneration as decimal),
// hex-encoded. It is pinned by test vectors independently recomputed from the
// historical source.
//
// THIS FUNCTION IS MIGRATION-ONLY. It exists solely so
// AdoptLegacyFeedSignerOperation can derive the historical operation ID that a
// migration-9 row's operation_id primary key carried — which the current
// length-prefixed ComputeOperationID no longer equals for the same logical
// publication — and thereby locate and adopt the logically-identical
// quarantined row. It MUST NOT derive identifiers for new active operations
// (ComputeOperationID / NormalizeFeedCommitHash are the sole forward forms),
// and its 0x00 delimiter framing carries the same field-boundary ambiguity the
// forward format abandoned.
func legacyComputeOperationID(registryID int64, owner, repo, tag, manifestDigest string, expectedGeneration int64) string {
	h := sha256.New()
	h.Write([]byte("uncloud-registry-feed-commit-op:v1\x00"))
	h.Write([]byte(strconv.FormatInt(registryID, 10)))
	h.Write([]byte{0})
	h.Write([]byte(owner))
	h.Write([]byte{0})
	h.Write([]byte(repo))
	h.Write([]byte{0})
	h.Write([]byte(tag))
	h.Write([]byte{0})
	h.Write([]byte(manifestDigest))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(expectedGeneration, 10)))
	return hex.EncodeToString(h.Sum(nil))
}

// deriveLegacyOperationID deterministically reconstructs the exact historical
// migration-9 operation ID for the logical publication this request represents,
// by recovering the repository identity from the referenced target repo-state
// document:
//
//   - repo  = the target document's canonical Repo,
//   - tag   = the single unambiguous tag the document carries (the tag the
//     operation published — the manifest-Digest value, exactly as the data
//     plane's ComputeOperationID argument),
//   - manifestDigest = that tag's manifest digest, and
//   - registry/owner/expectedGeneration from the request.
//
// It then applies the migration-only legacyComputeOperationID calculator. This
// is only ever a RECOGNITION key to find a logically-identical quarantined m9
// row keyed by that historical ID; it is never used as a new active operation
// ID.
//
// It returns ok=false — and the caller then skips the historical-ID branch —
// whenever the repository identity is not DETERMINISTICALLY recoverable here:
// the document cannot be read at the request reference, the document has any
// number of tags other than one (multiple tags would make the tag/digest
// ambiguous, so deriving a wrong historical ID and potentially adopting a
// different logical request is refused), or the single tag is malformed. This
// is the fail-closed ambiguity guarantee the adoption path requires: a
// multi-tag or unreadable repository simply cannot be bridged to an exact
// historical ID and the m9 row stays quarantined rather than risk a wrong
// adoption.
func (s *FeedSigner) deriveLegacyOperationID(ctx context.Context, req publish.FeedCommitRequest) (string, bool) {
	data, err := s.Docs.Read(ctx, req.Reference)
	if err != nil {
		return "", false
	}
	var doc struct {
		Repo string            `json:"repo"`
		Tags map[string]string `json:"tags"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return "", false
	}
	if doc.Repo == "" || len(doc.Tags) != 1 {
		return "", false
	}
	var tag, digest string
	var hasTag bool
	for t, d := range doc.Tags {
		tag, digest, hasTag = t, d, true
	}
	if !hasTag || tag == "" || digest == "" || !publish.IsHexReference(digest[strings.LastIndexByte(digest, ':')+1:]) {
		// The manifest digest must be a 64-hex immutable reference (after any
		// "sha256:" prefix); a malformed value cannot reproduce an exact ID.
		return "", false
	}
	return legacyComputeOperationID(req.RegistryID, req.Owner, doc.Repo, tag, digest, req.ExpectedGeneration), true
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
