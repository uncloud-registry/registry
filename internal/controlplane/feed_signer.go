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
	"sort"
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
	// Bytes reads the immutable ARTIFACT-CONTENT objects the operated manifest
	// descriptor points at — GET /bytes/<ref> on the same Bee node, kept
	// SEPARATE from Docs (the /bzz document path) so the signer can
	// INDEPENDENTLY prove the operated manifest BODY before any feed update.
	// Reads are strictly BOUNDED by publish.MaxArtifactBodyBytes with overflow
	// detection, the response body is always closed, and errors are data-free.
	// In Bee mode a swarm.BeeObjectStore; Commit fails closed when absent
	// (startup wiring must always provide it).
	Bytes swarm.BoundedBytesReader
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
	if isNilDependency(s.Store) || isNilDependency(s.Feeds) || isNilDependency(s.ResolveFeeds) || isNilDependency(s.Docs) || isNilDependency(s.Bytes) {
		return publish.FeedCommitResult{}, fmt.Errorf("%w: signer not fully configured", errFeedSignerBackend)
	}
	if err := publish.ValidateCommitRequest(req); err != nil {
		return publish.FeedCommitResult{}, fmt.Errorf("%w: %v", errFeedSignerMalformed, err)
	}
	// The CURRENT wire protocol (publish.InternalFeedUpdatePathV2, the ONLY
	// route InternalFeedServer.ServeHTTP forwards to this method — the legacy
	// publish.InternalFeedUpdatePath is retired outright, not merely
	// deprecated: it is not a recognized route at all) REQUIRES a non-empty
	// PublicationID; the HTTP handler rejects an empty one with 400 before
	// Commit is ever invoked (round 3 / Finding 2). Commit itself stays
	// protocol-agnostic and accepts an empty PublicationID too, but ONLY a
	// direct internal Go-level caller can ever supply one — no wire path
	// reaches this method that way. When PublicationID IS supplied, its
	// OperationID MUST be exactly the deterministic per-ATTEMPT identity
	// derived from that stable id plus THIS attempt's own
	// ExpectedGeneration/Reference (see publish.ComputeCommitAttemptID) —
	// never an arbitrary or reused value. This is checked BEFORE any hashing,
	// reservation, or registry lookup. A request that leaves PublicationID
	// empty is the pre-round-2 shape retained solely for the internal
	// migration-9 quarantine-adoption test surface: its OperationID IS its
	// own stable identity, with no separate per-attempt derivation enforced,
	// and — critically — it NEVER passes through the round-3 execution gate
	// below, so it can neither benefit from nor corrupt a current
	// PublicationID's durable terminal state (see publicationIdentity).
	if req.PublicationID != "" {
		wantAttemptID := publish.ComputeCommitAttemptID(req.PublicationID, req.RegistryID, req.Owner, req.Topic, req.Reference, req.ExpectedGeneration)
		if req.OperationID != wantAttemptID {
			return publish.FeedCommitResult{}, fmt.Errorf("%w: operationID is not the deterministic attempt identity for this publicationID", errFeedSignerMalformed)
		}
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

	// The durable logical-publication EXECUTION gate's cheap, READ-ONLY
	// fast path (round 3 / Finding 1, narrowed by round 4 / Finding 2): ONLY
	// for the current (PublicationID-bearing) protocol. This can reject a
	// request that is ALREADY known-doomed from whatever publication_states
	// row exists TODAY — a permanent conflict against a terminal success
	// under a different attempt, or a live different active attempt — with
	// ZERO durable feed_signer_operations row ever created and ZERO document
	// reads for the rejected attempt. It NEVER reserves an absent row and
	// NEVER performs the replacement CAS: those mutations happen ONLY in
	// authorizePublicationExecution, called from signCommit strictly AFTER
	// this exact attempt's payload has been authenticated (see round 4 /
	// Finding 2 below). A request with PublicationID empty (unreachable from
	// any wire path; see above) never touches publication_states at all,
	// since its OperationID already IS its own generation-bound stable
	// identity.
	if req.PublicationID != "" {
		if err := s.precheckPublicationExecution(ctx, req); err != nil {
			return publish.FeedCommitResult{}, err
		}
	}

	// Adopt any quarantined migration-9 row for this operation on this FIRST
	// request (before reservation). A quarantined row is located atomically by
	// the CURRENT operation ID OR ANY DERIVED HISTORICAL migration-9 operation
	// ID (see deriveLegacyCandidates): for EVERY valid tag entry in the
	// immutable target repo-state document at req.Reference, the exact
	// historical operation ID (registry/owner/repo/that tag/that manifest
	// digest/expected generation) and the exact historical request hash
	// (legacyFeedCommitHashFor over the reconstructed historical request whose
	// OperationID is that historical ID) are derived, deterministically sorted
	// and bounded; the quarantined row's own primary key identifies which
	// candidate was the old publication (this also works when the feed advanced
	// after the historical success — the immutable target document still
	// identifies the row; no predecessor comparison is needed). A candidate row
	// with a differing hash under any claimed identity is a hard conflict (a
	// reused OperationID with different input), a malformed legacy succeeded
	// result fails closed and stays quarantined, and MORE THAN ONE valid
	// candidate row (current+legacy, or two legacy tags) is an ambiguity that
	// fails closed — a conflicting candidate is never ignored merely because
	// another matches. The historical ID is only ever derived here to RECOGNIZE
	// a logically-identical m9 row; it is never used as a new active operation
	// ID — the promoted active row always carries the CURRENT operation ID and
	// CURRENT request hash. The round-3 legacy hash — the historical framing
	// over the CURRENT request with the CURRENT operation ID — does NOT match a
	// real m9 row (whose operation ID was the historical value), so it is
	// replaced here by the historical hash over the reconstructed historical
	// request (OperationID := the derived historical ID).
	var legacyCands []LegacyOperationCandidate
	if n, err := s.Store.LegacyOperationCount(ctx); err == nil && n > 0 {
		legacyCands = s.deriveLegacyCandidates(ctx, req)
	}
	_, aerr := s.Store.AdoptLegacyFeedSignerOperation(ctx, req.OperationID, req.RegistryID, canonicalTopic, publish.CanonicalReference(req.Reference), reqHash, legacyCands)
	if aerr != nil {
		if errors.Is(aerr, errFeedSignerLegacyConflict) || errors.Is(aerr, errFeedSignerLegacyAmbiguous) {
			// A conflicting or ambiguous quarantine identity is a hard user-visible
			// conflict: ALL quarantine rows are retained and the feed is never
			// advanced (fail closed, never adopt a row a conflicting candidate was
			// matched against).
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

// publicationExecutionMaxCASAttempts bounds authorizePublicationExecution's
// re-evaluation loop after a lost replacement CAS: each iteration performs
// real work (a fresh CAS attempt) and only re-loops when the row is STILL
// replaceable under yet another distinct attempt id, which requires an
// entire additional signCommit invocation to have happened between our read
// and our CAS — a bound far beyond any realistic contention is a pure
// defensive backstop against an unforeseen bug looping forever.
const publicationExecutionMaxCASAttempts = 1000

// precheckPublicationExecution is the cheap, READ-ONLY companion to
// authorizePublicationExecution (round 4 / Finding 2). It fetches today's
// publication_states row for req.PublicationID and rejects the request when
// that EXISTING row already, unambiguously forbids it — a terminal success
// under a different attempt (permanent conflict) or a live different active
// attempt (retryable) — but it NEVER creates, reserves, or CASes anything:
// an absent row or a replaceable row both return nil ("proceed"), deferring
// the actual authorization decision — including any reservation or
// replacement — to authorizePublicationExecution, which runs only after this
// exact attempt's payload has been authenticated. This is what closes round 4
// / Finding 2: an unauthenticated attempt can never seize an absent or
// replaceable execution slot merely by presenting a self-consistently
// derived attempt id for an arbitrary (possibly forged) payload, because the
// only two states this function would need to MUTATE to admit such an
// attempt are exactly the two states it leaves untouched. It still preserves
// the round-3 guarantee that a request already known-doomed by EXISTING
// durable state is rejected before wasting a durable feed_signer_operations
// row or any proof-of-work.
func (s *FeedSigner) precheckPublicationExecution(ctx context.Context, req publish.FeedCommitRequest) error {
	exec, err := s.Store.GetPublicationExecution(ctx, req.PublicationID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: publication execution: %v", errFeedSignerBackend, err)
	}
	if exec.RegistryID != req.RegistryID {
		return fmt.Errorf("%w: publication identity is bound to another registry", errFeedSignerConflict)
	}
	switch exec.State {
	case PublicationExecutionSucceeded:
		if exec.AttemptID == req.OperationID {
			return nil
		}
		return errFeedSignerConflict
	case PublicationExecutionActive:
		if exec.AttemptID == req.OperationID {
			return nil
		}
		return fmt.Errorf("%w: another attempt owns this publication", errFeedSignerBackend)
	case PublicationExecutionReplaceable:
		// Deferred: only authorizePublicationExecution may CAS a replaceable
		// row, and only after authentication.
		return nil
	default:
		return fmt.Errorf("%w: publication execution: unrecognized state", errFeedSignerBackend)
	}
}

// authorizePublicationExecution is the durable logical-publication EXECUTION
// gate's AUTHORITATIVE, mutating half (round 3 / Finding 1; relocated by
// round 4 / Finding 2). It is called from signCommit strictly AFTER
// authenticatePublicationProvenance has verified this exact attempt's target
// document and operation-identity binding, and strictly BEFORE any external
// feed update — never earlier: reserving an absent row, or CASing a
// replaceable one, for an attempt whose payload has not yet been proven
// legitimate is exactly how round 4 / Finding 2's poisoning happened (an
// internal-credential caller could seize the publication's execution slot
// with a wrong payload's self-consistently-derived attempt id, and every
// non-generation-conflict failure class left that seizure permanent). It
// decides — atomically, never on a stale read — whether req.OperationID
// (THIS authenticated attempt) may proceed for req.PublicationID (the STABLE
// logical publication):
//
//   - no row yet: this is the FIRST-EVER attempt. ReservePublicationExecution
//     atomically wins (or, if a concurrent distinct attempt already reserved
//     it first, reads back the ACTUAL winner) — never two distinct attempts
//     both pass this gate for a fresh publication id.
//   - state active, SAME attempt id: this is a concurrent/retried instance of
//     the currently-authorized attempt — proceed (the existing
//     feed_signer_operations claim/lease machinery, unchanged, governs it
//     from here).
//   - state active, DIFFERENT attempt id: the recorded attempt has not been
//     proven dead by an authoritative generation conflict. A fresh attempt
//     must NEVER silently replace a still-active one — this is a retryable
//     backend condition, never a fabricated success or a permanent conflict.
//   - state replaceable: the recorded attempt DEFINITIVELY conflicted on
//     generation with zero external write. A DIFFERENT attempt id may
//     atomically CAS the row back to active (exactly one winner under
//     concurrent replacement bids — see ReplacePublicationExecutionAttempt);
//     the loser re-evaluates the row it observes after losing.
//   - state succeeded: TERMINAL. The SAME attempt id that succeeded may
//     proceed (a lost-response retry, answered by the existing
//     feed_signer_operations succeeded-row lookup); any OTHER attempt id is a
//     PERMANENT conflict — the feed must never advance again for this
//     publication, even after an entirely different later publication
//     overwrites the same tag.
//
// A registry mismatch on an existing row (a defensive, cryptographically
// improbable case since PublicationID hashes bind the registry) is also a
// permanent conflict, never silently accepted.
func (s *FeedSigner) authorizePublicationExecution(ctx context.Context, req publish.FeedCommitRequest) error {
	pubID := req.PublicationID
	exec, err := s.Store.GetPublicationExecution(ctx, pubID)
	if errors.Is(err, sql.ErrNoRows) {
		exec, err = s.Store.ReservePublicationExecution(ctx, pubID, req.RegistryID, req.OperationID)
		if err != nil {
			return fmt.Errorf("%w: publication execution: %v", errFeedSignerBackend, err)
		}
	} else if err != nil {
		return fmt.Errorf("%w: publication execution: %v", errFeedSignerBackend, err)
	}

	for attempt := 0; ; attempt++ {
		if attempt >= publicationExecutionMaxCASAttempts {
			return fmt.Errorf("%w: publication execution: replacement contention exceeded the bound", errFeedSignerBackend)
		}
		if exec.RegistryID != req.RegistryID {
			return fmt.Errorf("%w: publication identity is bound to another registry", errFeedSignerConflict)
		}
		switch exec.State {
		case PublicationExecutionSucceeded:
			if exec.AttemptID == req.OperationID {
				return nil
			}
			return errFeedSignerConflict
		case PublicationExecutionActive:
			if exec.AttemptID == req.OperationID {
				return nil
			}
			return fmt.Errorf("%w: another attempt owns this publication", errFeedSignerBackend)
		case PublicationExecutionReplaceable:
			if exec.AttemptID == req.OperationID {
				// Not expected (a fresh attempt id always differs from the
				// one that just conflicted), but if it recurs, treat it as
				// reactivating the same attempt.
				return nil
			}
			won, row, rerr := s.Store.ReplacePublicationExecutionAttempt(ctx, pubID, req.RegistryID, exec.AttemptID, req.OperationID)
			if rerr != nil {
				return fmt.Errorf("%w: publication execution replace: %v", errFeedSignerBackend, rerr)
			}
			if won {
				return nil
			}
			exec = row
			continue
		default:
			return fmt.Errorf("%w: publication execution: unrecognized state", errFeedSignerBackend)
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
			// The publication-execution row is flipped to "replaceable" ONLY
			// for the exact authoritative generation-conflict class — never
			// for malformed/not-ready/owner/batch/provenance failures, which
			// must never silently authorize a fresh attempt to replace this
			// one (round 3 / Finding 1).
			//
			// This transition must be DURABLY CONFIRMED before we report the
			// generation conflict to the caller: PublishCommitWithConflictRebuild
			// treats that error class as "safe to rebuild" and will construct a
			// fresh attempt immediately. If the mark silently failed to apply
			// (a DB error, or the row no longer matched this attempt — e.g. a
			// concurrent observer already moved it), that fresh attempt could
			// never be authorized by authorizePublicationExecution (the row
			// would stay "active" under this same attempt forever, or under
			// whatever a concurrent actor left it as), permanently wedging the
			// publication. So a mark failure or a non-applied mark degrades
			// THIS response to a retryable backend error instead of the
			// generation conflict — never a silent "safe to rebuild" that
			// cannot actually be honored. A later retry of this SAME attempt
			// re-detects the identical generation conflict and retries the
			// mark; only once it durably applies is the caller ever told it
			// may rebuild.
			if req.PublicationID != "" && errors.Is(err, errFeedSignerGenerationConflict) {
				applied, merr := s.Store.MarkPublicationExecutionReplaceable(ctx, req.PublicationID, req.OperationID)
				if merr != nil {
					return publish.FeedCommitResult{}, fmt.Errorf("%w: mark publication replaceable: %v", errFeedSignerBackend, merr)
				}
				if !applied {
					return publish.FeedCommitResult{}, fmt.Errorf("%w: publication replaceable transition did not durably apply", errFeedSignerBackend)
				}
			}
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
	if req.PublicationID != "" {
		// The atomic combined completion: the per-attempt feed_signer_operations
		// row and the logical publication_states terminal marking commit in
		// ONE transaction, so the two can never split (round 3 / Finding 1).
		if err := s.Store.CompleteFeedSignerOperationAndTerminatePublication(ctx, req.OperationID, reqHash, claimToken, resultJSON, req.PublicationID, req.RegistryID, req.OperationID); err != nil {
			return publish.FeedCommitResult{}, fmt.Errorf("%w: persist result: %v", errFeedSignerBackend, err)
		}
		return result, nil
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
//
// The validation order is deliberate (round 4 / Finding 2): for the current
// (PublicationID-bearing) protocol, the exact PublicationID binding and
// immutable payload provenance are authenticated against the target document
// ALONE — before any live current-feed read and before the publication's
// execution row is ever reserved or CASed — so that NEITHER of the two
// authoritative generation-conflict checks below (target generation, then
// live current-feed generation) can ever mutate publication_states for an
// attempt whose payload has not already been authenticated. Only once
// authentication and reservation have both succeeded do the generation
// checks run; either may still, entirely legitimately, report an
// authoritative conflict against the now-authenticated row, which
// runSignedCommit then marks replaceable. For the legacy PublicationID-empty
// protocol (unreachable from any wire path), publication_states is never
// touched at all, so authentication instead keeps its original historical
// position after both generation checks.
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

	// Read the immutable target document and prove the topic derivation
	// (definite pre-update, generation-independent).
	targetRepo, targetDoc, err := s.readTargetDocument(ctx, req, reg)
	if err != nil {
		return publish.FeedCommitResult{}, false, false, err
	}

	// Round 4 / Finding 2: authenticate the exact PublicationID binding and
	// the immutable payload provenance recorded in the target document ALONE
	// — entirely independent of live current-feed state. authenticate is
	// called EXACTLY once below, at a position that depends on the protocol:
	//
	//   - PublicationID != "" (the current protocol): authentication runs
	//     HERE, strictly BEFORE authorizePublicationExecution ever reserves
	//     or CASes a publication_states row for this attempt. A forged,
	//     absent, or mismatched provenance entry, or an operation identity
	//     bound to a DIFFERENT tag/digest, therefore creates ZERO
	//     publication_states mutations — even when it is deliberately shaped
	//     to also trip one of the generation checks below. This is what
	//     closes the round 4 / Finding 2 gap.
	//   - PublicationID == "" (the legacy protocol, unreachable from any wire
	//     path): publication_states is NEVER touched for such a request (the
	//     reservation call below is itself gated on PublicationID != ""), so
	//     there is no mutation-ordering hazard to close; authentication runs
	//     at its ORIGINAL historical position, after both generation checks,
	//     exactly as before this fix.
	var operated string
	authenticate := func() error {
		var aerr error
		operated, aerr = s.authenticatePublicationBinding(ctx, req, targetRepo, targetDoc)
		return aerr
	}

	if req.PublicationID != "" {
		if err := authenticate(); err != nil {
			return publish.FeedCommitResult{}, false, false, err
		}
		// The durable logical-publication EXECUTION gate's AUTHORITATIVE,
		// mutating half (round 3 / Finding 1; reordered by round 4 / Finding
		// 2): runs strictly AFTER the authentication above and strictly
		// BEFORE either generation check, so an authoritative generation
		// conflict discovered by either check below always finds an
		// ALREADY-AUTHENTICATED row to flip to replaceable — never a row
		// reserved for an unauthenticated attempt.
		if err := s.authorizePublicationExecution(ctx, req); err != nil {
			return publish.FeedCommitResult{}, false, false, err
		}
	}

	// Target generation must be exactly ExpectedGeneration+1 (definite
	// pre-update): the first of the two authoritative generation-conflict
	// classes.
	if err := verifyTargetGeneration(req, targetDoc); err != nil {
		return publish.FeedCommitResult{}, false, false, err
	}

	// Current feed + repo identity + generation (definite pre-update): the
	// second authoritative generation-conflict class. create=true means the
	// repo feed is CONCLUSIVELY absent and this is a generation-zero
	// creation: the updater receives the explicit creation intent (Task 13),
	// so a racing creator that wins the CONCURRENT create surfaces as
	// ErrFeedAlreadyExists instead of an overwrite or a success.
	done, create, curDoc, err := s.resolveCurrentFeed(ctx, req, reg, targetRepo)
	if err != nil {
		return publish.FeedCommitResult{}, false, false, err
	}

	if req.PublicationID == "" {
		if err := authenticate(); err != nil {
			return publish.FeedCommitResult{}, false, false, err
		}
	}

	// Current-tag-consistency (definite pre-update): the transition from the
	// resolved current document to the target must be exactly the
	// authenticated operation's own tag, with no unrelated tag mapping,
	// provenance entry, manifest descriptor, or blob record mutated
	// alongside it.
	if err := s.authenticateCurrentTagConsistency(ctx, targetDoc, curDoc, done, operated); err != nil {
		return publish.FeedCommitResult{}, false, false, err
	}

	// Stamp policy / batch proof (definite pre-update). Runs AFTER
	// authorization and both generation checks: an otherwise-authentic
	// attempt with an impermissible batch id must still durably own its
	// publication's execution slot (a non-generation failure never
	// authorizes a replacement — see authorizePublicationExecution), never
	// leave zero trace of it.
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
	// a network update happens. The request's BatchID — already proven to equal
	// the stamp-policy-selected batch — is the exact postage batch propagated
	// into the updater.
	if err := s.Feeds.UpdateRegistryFeed(ctx, reg, req.Topic, req.Reference, req.BatchID, create); err != nil {
		if errors.Is(err, swarm.ErrFeedAlreadyExists) {
			// A create-only update observed an EXISTING feed: a racing creator
			// won the creation race. This is a DEFINITE no-write by OUR
			// operation — the feed at the topic is not ours, so it is a
			// generation conflict, NEVER a success, NEVER the second
			// advancement. The claim is released (there is nothing to retry on
			// our side): a later retry re-resolves the REAL feed and conflicts
			// against it again. No URL/body is ever leaked through the error.
			return result, false, false, errFeedSignerGenerationConflict
		}
		return result, false, true, fmt.Errorf("%w: feed update: %v", errFeedSignerBackend, err)
	}
	return result, false, false, nil
}

// readTargetDocument decodes and validates the immutable target document and
// proves the requested Topic is the FULL deterministic repo-state feed ref of
// the document's own canonical Repo under the registry's normalized owner. It
// returns the canonical repo name AND the decoded target document (the exact
// immutable bytes this operation would publish). An arbitrary,
// non-deterministic, auth-policy, or stamp-policy topic is rejected BEFORE the
// key is touched or any feed is written.
//
// Target-generation coherence is deliberately NOT checked here (round 4 /
// Finding 2 — see verifyTargetGeneration): reading and topic-checking the
// document is itself generation-independent, but a Generation mismatch is
// exactly the authoritative generation-conflict class that must never mutate
// publication_states before this attempt's payload has been authenticated.
func (s *FeedSigner) readTargetDocument(ctx context.Context, req publish.FeedCommitRequest, reg Registry) (string, spec.RepoStateDocument, error) {
	data, err := s.Docs.Read(ctx, req.Reference)
	if err != nil {
		return "", spec.RepoStateDocument{}, fmt.Errorf("%w: target reference: %v", errFeedSignerBackend, err)
	}
	doc, err := spec.DecodeRepoStateDocument(data)
	if err != nil {
		return "", spec.RepoStateDocument{}, fmt.Errorf("%w: target is not a valid repo state document: %v", errFeedSignerMalformed, err)
	}
	derived := spec.RepoStateFeedRef(spec.NormalizeOwner(reg.FeedOwnerAddress), doc.Repo)
	if derived != req.Topic {
		return "", spec.RepoStateDocument{}, fmt.Errorf("%w: topic is not the deterministic reference for the repository in the target document", errFeedSignerMalformed)
	}
	return doc.Repo, doc, nil
}

// verifyTargetGeneration proves the target document's own Generation is
// exactly ExpectedGeneration+1 (overflow-safe) — the first of the two
// authoritative generation-conflict classes (round 4 / Finding 2). It runs
// strictly AFTER authenticatePublicationBinding and authorizePublicationExecution
// in signCommit, so a mismatch here — however trivially an internal caller can
// construct one by choosing an arbitrary target document — can never mutate
// publication_states for an attempt whose payload has not already been
// authenticated.
func verifyTargetGeneration(req publish.FeedCommitRequest, doc spec.RepoStateDocument) error {
	if req.ExpectedGeneration == math.MaxInt64 {
		return errFeedSignerGenerationConflict
	}
	if doc.Generation != req.ExpectedGeneration+1 {
		return errFeedSignerGenerationConflict
	}
	return nil
}

// resolveCurrentFeed re-reads the current repo feed via the resolver and the
// immutable object reader, requiring current generation == ExpectedGeneration
// and the repo identity matching the target's repo. done=true means the current
// feed already resolves to the requested Reference (a prior uncertain update
// succeeded), which is reported idempotently. create=true means the repo feed
// is CONCLUSIVELY absent (never written) with ExpectedGeneration==0 — a
// generation-zero creation whose updater MUST receive the explicit creation
// intent (Task 13). It also returns the decoded CURRENT document (nil on the
// creation path) so the caller can authenticate the exact tag-publication
// transition recorded between the two immutable states.
func (s *FeedSigner) resolveCurrentFeed(ctx context.Context, req publish.FeedCommitRequest, reg Registry, targetRepo string) (done bool, create bool, curDoc *spec.RepoStateDocument, err error) {
	currentRef, err := s.ResolveFeeds.ResolveFeed(ctx, req.Topic)
	if err != nil {
		// Generation-zero first publication: a CONCLUSIVELY absent repo feed
		// (never written) with ExpectedGeneration 0 is a creation, not a
		// failure — the signer proceeds to verify the batch and stamp the
		// first update at the target reference. Any OTHER feed-resolution
		// failure (network, timeout, auth, decode) stays a backend error, and
		// a missing feed with a NONZERO expected generation is inconsistent
		// and fails closed as a generation conflict — the create path exists
		// ONLY for generation zero.
		if errors.Is(err, resolve.ErrFeedNotFound) {
			if req.ExpectedGeneration != 0 {
				return false, false, nil, fmt.Errorf("%w: current repo feed is absent but the request expects generation %d", errFeedSignerGenerationConflict, req.ExpectedGeneration)
			}
			return false, true, nil, nil
		}
		return false, false, nil, fmt.Errorf("%w: current repo feed: %v", errFeedSignerBackend, err)
	}
	if swarm.CanonicalObjectRef(currentRef) == swarm.CanonicalObjectRef(req.Reference) {
		curData, err := s.Docs.Read(ctx, currentRef)
		if err != nil {
			return false, false, nil, fmt.Errorf("%w: current repo document: %v", errFeedSignerBackend, err)
		}
		decodedCur, err := spec.DecodeRepoStateDocument(curData)
		if err != nil {
			return false, false, nil, fmt.Errorf("%w: current repo document: %v", errFeedSignerBackend, err)
		}
		if decodedCur.Repo != targetRepo {
			return false, false, nil, fmt.Errorf("%w: current repo identity does not match the referenced repository", errFeedSignerMalformed)
		}
		return true, false, &decodedCur, nil
	}
	curData, err := s.Docs.Read(ctx, currentRef)
	if err != nil {
		return false, false, nil, fmt.Errorf("%w: current repo document: %v", errFeedSignerBackend, err)
	}
	decodedCur, err := spec.DecodeRepoStateDocument(curData)
	if err != nil {
		return false, false, nil, fmt.Errorf("%w: current repo document: %v", errFeedSignerBackend, err)
	}
	if decodedCur.Repo != targetRepo {
		return false, false, nil, fmt.Errorf("%w: current repo identity does not match the referenced repository", errFeedSignerMalformed)
	}
	if decodedCur.Generation != req.ExpectedGeneration {
		return false, false, nil, errFeedSignerGenerationConflict
	}
	return false, false, &decodedCur, nil
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

// authenticatePublicationBinding is the PRE-GENERATION, PRE-MUTATION half of
// the signer's operation-provenance authentication (round 4 / Finding 2). It
// identifies the operated tag and authenticates the request's STABLE
// publication identity using ONLY the immutable target document and the
// request's own fields — never the live current feed, never a
// publication_states row. The operated tag is the SINGLE entry in the target
// document's TagPublications that records EXACTLY this operation's STABLE
// publication identity (publicationIdentity(req)) at the document's own
// generation, mapping to its recorded digest — the provenance entry NEVER
// carries the per-attempt FeedSigner identity (req.OperationID), only the
// stable publication identity that survives a conflict rebuild. A duplicate,
// zero, or multi-match attribution fails closed as malformed. It then binds
// the semantic request identity (authenticateOperationIdentity): in no case
// can an arbitrary internal request pair a forged document ID with a chosen
// request ID.
//
// This runs strictly BEFORE authorizePublicationExecution ever reserves or
// CASes a publication_states row for this attempt: a payload that fails here
// — a forged, absent, or mismatched provenance entry, or an operation
// identity bound to a DIFFERENT tag/digest — creates ZERO publication_states
// mutations, regardless of what generation-conflict class the later
// (generation-dependent) checks would otherwise have produced. This closes
// the round 4 / Finding 2 gap: an internal-credential caller can no longer
// seize an absent or replaceable execution slot for a PublicationID by
// presenting a self-consistently-derived attempt id over an arbitrary
// (possibly forged) payload, because reaching a generation-conflict class
// error can never again bypass this authentication.
//
// It returns the identified operated tag; the LATER current-tag-consistency
// phase (authenticateCurrentTagConsistency) independently proves that tag is
// also the ONLY tag the transition from the live current document touches,
// and that the manifest/blob state carries no unrelated mutation alongside
// it. All errors are data-free sentinel-wrapped failures.
func (s *FeedSigner) authenticatePublicationBinding(ctx context.Context, req publish.FeedCommitRequest, targetRepo string, targetDoc spec.RepoStateDocument) (string, error) {
	if hasDuplicateOperationAttribution(targetDoc.TagPublications) {
		// One operation identity recorded by TWO tags is never produced by a
		// legitimate publication sequence and defeats single-entry
		// identification.
		return "", fmt.Errorf("%w: duplicate operation attribution in target document", errFeedSignerMalformed)
	}

	pubID := publicationIdentity(req)
	var operated string
	for tag, entry := range targetDoc.TagPublications {
		if entry.OperationID != pubID {
			continue
		}
		if entry.Generation != targetDoc.Generation {
			continue
		}
		if targetDoc.Tags[tag] != entry.Digest {
			continue
		}
		if operated != "" {
			return "", fmt.Errorf("%w: multiple provenance entries record this operation", errFeedSignerMalformed)
		}
		operated = tag
	}
	if operated == "" {
		return "", fmt.Errorf("%w: no provenance entry records this operation at the target generation", errFeedSignerMalformed)
	}
	if err := s.authenticateOperationIdentity(ctx, req, targetRepo, operated, targetDoc.TagPublications[operated].Digest); err != nil {
		return "", err
	}
	return operated, nil
}

// authenticateCurrentTagConsistency is the CURRENT-FEED-DEPENDENT half of the
// signer's operation-provenance authentication (round 4 / Finding 2), run
// AFTER authenticatePublicationBinding has already authenticated this
// attempt's PublicationID binding and AFTER the publication's execution row
// has been reserved/CASed for it. Using the resolved current document, it
// proves the transition cur → target touches EXACTLY the tag
// authenticatePublicationBinding already identified — never an unrelated tag
// mapping, provenance entry, manifest descriptor, or blob record hidden
// alongside it.
//
// The comparison is the SYMMETRIC union of both documents' Tag and
// TagPublications keys (so an unrelated tag mapping or provenance entry
// deleted from the current state, or added to the target, is as much a
// change as an edited value) and across the Manifests and Blobs maps
// (existing entries preserved exactly; the operated manifest descriptor
// added/updated only at the operated digest; new blob records permitted). A
// changed-tag count other than one, or a changed tag that disagrees with the
// already-authenticated operated tag, fails closed as malformed.
//
// On the already-advanced recovery path (done=true, current == target) no
// cur-diff is needed — current==target trivially satisfies it, and
// authenticatePublicationBinding already fully authenticated the operated
// tag against the target document alone — so only the independent
// artifact/blob byte-level proof runs.
func (s *FeedSigner) authenticateCurrentTagConsistency(ctx context.Context, targetDoc spec.RepoStateDocument, curDoc *spec.RepoStateDocument, done bool, operated string) error {
	if done {
		return s.validateArtifactBlobTransition(ctx, targetDoc.Blobs, targetDoc.Blobs, targetDoc, operated)
	}

	var cur spec.RepoStateDocument
	if curDoc != nil {
		cur = *curDoc
	}
	// The transition cur → target must touch EXACTLY ONE tag — in its mapping,
	// its provenance entry, or both. Two tags changing means two publications
	// packed into one document; none changing means this operation has no
	// record at all. Either is malformed.
	changing := changedTransitionTags(cur, targetDoc)
	if len(changing) != 1 {
		return fmt.Errorf("%w: target document mutates %d tags, expected exactly one", errFeedSignerMalformed, len(changing))
	}
	var changedTag string
	for tag := range changing {
		changedTag = tag
	}
	if changedTag != operated {
		return fmt.Errorf("%w: the changed tag does not match the authenticated operation's tag", errFeedSignerMalformed)
	}
	// The SAME root class extends to the other state maps: the transition must
	// be exactly the operation's own, with NO unrelated semantic change
	// hidden alongside the one tag transition. Manifests follow the actual
	// DefaultBuilder rule (every existing descriptor preserved verbatim; the
	// operated descriptor added or replaced ONLY at the operated digest);
	// blobs follow the builder's clone+add rule (existing records preserved
	// exactly, referenced staged additions allowed, deletions/mutations
	// impossible in any legitimate publication).
	if err := validateManifestTransition(cur.Manifests, targetDoc.Manifests, targetDoc.Tags[operated]); err != nil {
		return err
	}
	return s.validateArtifactBlobTransition(ctx, cur.Blobs, targetDoc.Blobs, targetDoc, operated)
}

// changedTransitionTags computes the set of tag names whose TAG MAPPING or
// PROVENANCE ENTRY differs between cur and target, iterating the SYMMETRIC
// union of both sides' keys with explicit PRESENCE comparison: a key present
// on one side only is a change (absent and a zero value on the other side are
// distinct), so current-only deletions and target-only additions are detected
// exactly like value edits. One tag counts once even when both its mapping and
// its provenance entry changed.
func changedTransitionTags(cur, target spec.RepoStateDocument) map[string]struct{} {
	seen := make(map[string]struct{})
	note := func(tag string) { seen[tag] = struct{}{} }
	for tag := range cur.Tags {
		note(tag)
	}
	for tag := range target.Tags {
		note(tag)
	}
	for tag := range cur.TagPublications {
		note(tag)
	}
	for tag := range target.TagPublications {
		note(tag)
	}
	changing := make(map[string]struct{})
	for tag := range seen {
		curDigest, curHasTag := cur.Tags[tag]
		targetDigest, targetHasTag := target.Tags[tag]
		if curHasTag != targetHasTag || (curHasTag && curDigest != targetDigest) {
			changing[tag] = struct{}{}
			continue
		}
		curPub, curHasPub := cur.TagPublications[tag]
		targetPub, targetHasPub := target.TagPublications[tag]
		if curHasPub != targetHasPub || (curHasPub && curPub != targetPub) {
			changing[tag] = struct{}{}
		}
	}
	return changing
}

// validateManifestTransition enforces the actual DefaultBuilder manifest rule
// across the transition: EVERY existing manifest descriptor is cloned into the
// next state verbatim, and the operated manifest descriptor may be ADDED or
// REPLACED only at the operated digest (the digest the operated tag maps to).
// A current-only deletion, an addition at any other digest, or the mutation
// of any retained descriptor is an unrelated semantic change and fails closed
// as malformed. Errors are value-free (no digest ever appears).
func validateManifestTransition(cur, target map[string]spec.ManifestDescriptor, operatedDigest string) error {
	for digest, desc := range cur {
		targetDesc, ok := target[digest]
		if !ok {
			return fmt.Errorf("%w: target document deletes an existing manifest descriptor", errFeedSignerMalformed)
		}
		if digest != operatedDigest && targetDesc != desc {
			return fmt.Errorf("%w: target document mutates an unrelated manifest descriptor", errFeedSignerMalformed)
		}
	}
	for digest := range target {
		if _, ok := cur[digest]; !ok && digest != operatedDigest {
			return fmt.Errorf("%w: target document adds an unrelated manifest descriptor", errFeedSignerMalformed)
		}
	}
	return nil
}

// validateArtifactBlobTransition is the signer's INDEPENDENT proof that the
// transition's blob state is EXACTLY the operated manifest artifact's. It
// reads the operated manifest's immutable BODY through the separately-wired
// bounded /bytes reader (never the docs path, never unbounded) at the operated
// descriptor's SwarmRef, and the body MUST parse with the strict Task-12
// artifact parser under the descriptor media type, MUST hash to the operated
// digest, MUST match the descriptor's size, and MUST NOT be an image index
// (index publication is rejected — the Task 19 gate). The parser's exact
// reference set is then enforced against the blob state: EVERY reference must
// exist in the target Blobs with coherent size/media, EVERY existing record
// must be preserved byte-identically, and EVERY NEW target blob record must
// belong to the reference set — an unreferenced addition, a missing or
// mismatched descriptor, wrong manifest bytes/ref/media/size, or an oversize/
// failed bounded read ALL fail closed with zero external updates (malformed
// for provably-wrong content, backend for unreadable content). Errors are
// data-free: no digest, ref, size, media value, or error body ever appears.
func (s *FeedSigner) validateArtifactBlobTransition(ctx context.Context, cur, target map[string]spec.BlobDescriptor, targetDoc spec.RepoStateDocument, operated string) error {
	operatedDigest := targetDoc.Tags[operated]
	desc, ok := targetDoc.Manifests[operatedDigest]
	if !ok {
		return fmt.Errorf("%w: operated manifest descriptor is missing from the target document", errFeedSignerMalformed)
	}
	// Bounded independent read of the operated manifest BODY. Any read
	// failure (transport, status, oversize beyond the bound) is a backend/
	// dependency condition — the signer never signs a transition whose
	// manifest content it could not verify.
	body, err := s.Bytes.ReadBounded(ctx, desc.SwarmRef, publish.MaxArtifactBodyBytes)
	if err != nil {
		return fmt.Errorf("%w: operated manifest object: %v", errFeedSignerBackend, err)
	}
	if publish.ComputeDigest(body) != operatedDigest {
		return fmt.Errorf("%w: operated manifest object bytes do not match the operated digest", errFeedSignerMalformed)
	}
	if int64(len(body)) != desc.Size {
		return fmt.Errorf("%w: operated manifest object size disagrees with its descriptor", errFeedSignerMalformed)
	}
	artifact, err := publish.ParseArtifact(desc.MediaType, body)
	if err != nil {
		return fmt.Errorf("%w: operated manifest body is not a valid artifact: %v", errFeedSignerMalformed, err)
	}
	if artifact.Kind == publish.ArtifactKindIndex {
		return fmt.Errorf("%w: operated manifest is an image index, which cannot be published yet", errFeedSignerMalformed)
	}
	refs := artifact.References()
	referenced := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		referenced[ref.Digest] = struct{}{}
		blob, ok := target[ref.Digest]
		if !ok {
			return fmt.Errorf("%w: operated manifest references a blob absent from the target document", errFeedSignerMalformed)
		}
		if err := publish.CheckBlobReferenceCoherence(ref, blob); err != nil {
			return fmt.Errorf("%w: operated manifest reference disagrees with its stored blob record", errFeedSignerMalformed)
		}
	}
	// Every existing record is cloned into the next state verbatim.
	for digest, desc := range cur {
		targetDesc, ok := target[digest]
		if !ok {
			return fmt.Errorf("%w: target document deletes an existing blob record", errFeedSignerMalformed)
		}
		if targetDesc != desc {
			return fmt.Errorf("%w: target document mutates an existing blob record", errFeedSignerMalformed)
		}
	}
	// Every NEW target blob record must be one of the operated artifact's
	// references — arbitrary additions are never inert.
	for digest := range target {
		if _, inCur := cur[digest]; inCur {
			continue
		}
		if _, isRef := referenced[digest]; !isRef {
			return fmt.Errorf("%w: target document adds a blob record the operated artifact does not reference", errFeedSignerMalformed)
		}
	}
	return nil
}

// publicationIdentity returns the request's STABLE logical publication
// identity: req.PublicationID when the caller supplied one (the ONLY shape
// reachable from any wire path — the current v2 endpoint requires it, and
// the legacy v1 endpoint no longer exists), or req.OperationID for the
// pre-round-2 shape that carries no separate attempt identity (its
// OperationID IS its own stable identity — Commit's attempt-identity check
// never runs for such a request, and it never passes through the round-3
// execution gate). This is the ONLY identity ever compared against durable
// publication_bindings rows or recorded/expected in a repo-state document's
// TagPublications — the per-attempt req.OperationID (see
// publish.ComputeCommitAttemptID) never crosses that boundary.
func publicationIdentity(req publish.FeedCommitRequest) string {
	if req.PublicationID != "" {
		return req.PublicationID
	}
	return req.OperationID
}

// authenticateOperationIdentity proves the request's STABLE publication
// identity is NOT attacker-selected and decides it ATOMICALLY — never on a
// stale absence.
//
// When the publication identity (publicationIdentity(req)) is EXACTLY the
// deterministic recomputation of ComputeOperationID over (registry ID, owner,
// repo, operated tag, digest, expected generation), the identity IS that
// generated publication AT ITS ORIGINAL EXPECTED GENERATION: the signer
// ATOMICALLY RESERVES a permanent binding row for it (ReservePublicationBinding
// — insert-or-read), which serializes with any concurrent explicit preflight
// at the data plane: there is exactly ONE permanent binding winner per
// publication identity, and the returned row must match the request registry
// and the exact binding hash. A pre-existing conflicting row (a preflight
// bound the generated-looking key to a different payload) is a hard conflict
// BEFORE the updater; the stale-absence decision is eliminated because the
// row is created by the reserve itself, never assumed absent. This is also
// the compatibility fallback for direct/legacy callers with no preflight
// wiring: the FIRST attempt of a generated publication self-reserves its own
// binding.
//
// For any OTHER publication identity — an explicit caller key, OR a generated
// identity being REBUILT at a generation different from the one it encodes
// (its recomputation no longer matches) — the durable preflight row MUST
// already exist: the signer reads it (never auto-reserves), requires the
// exact registry and hash, and a missing row is malformed. This is exactly
// why the data plane preflight-binds EVERY logical publication (generated and
// explicit) before its first immutable write: a rebuilt generated publication
// depends on that binding surviving the conflict, since its own recomputation
// check will fail on the second (fresh-generation) attempt.
//
// A DB/query/reserve failure is a backend/uncertain condition and NEVER falls
// back to accepting without a binding. All errors are data-free (fixed
// sentinel + fixed message; the DB failure keeps its cause server-side only).
func (s *FeedSigner) authenticateOperationIdentity(ctx context.Context, req publish.FeedCommitRequest, targetRepo, operatedTag, digest string) error {
	pubID := publicationIdentity(req)
	bindingHash := NormalizePublicationBindingHash(req.RegistryID, req.Owner, targetRepo, operatedTag, digest)
	if pubID == publish.ComputeOperationID(req.RegistryID, req.Owner, targetRepo, operatedTag, digest, req.ExpectedGeneration) {
		// Generated identity at its own expected generation: ATOMIC
		// insert-or-read. This single statement serializes with any
		// concurrent explicit preflight for the same key — one permanent
		// winner per identity, never a stale-absence decision.
		binding, err := s.Store.ReservePublicationBinding(ctx, pubID, req.RegistryID, bindingHash)
		if err != nil {
			return fmt.Errorf("%w: publication binding: %v", errFeedSignerBackend, err)
		}
		if binding.RegistryID != req.RegistryID {
			return fmt.Errorf("%w: operation identity is bound to another registry", errFeedSignerConflict)
		}
		if binding.BindingHash != bindingHash {
			return fmt.Errorf("%w: operation identity is bound to a different publication", errFeedSignerConflict)
		}
		return nil
	}
	// Explicit caller key, or a generated identity being rebuilt at a
	// different generation than it encodes: require the data plane's
	// pre-existing preflight row; the signer NEVER auto-reserves it here.
	binding, err := s.Store.GetPublicationBinding(ctx, pubID)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: publication binding: %v", errFeedSignerBackend, err)
		}
		return fmt.Errorf("%w: operation identity is not durably bound to this publication", errFeedSignerMalformed)
	}
	if binding.RegistryID != req.RegistryID {
		return fmt.Errorf("%w: operation identity is bound to another registry", errFeedSignerConflict)
	}
	if binding.BindingHash != bindingHash {
		return fmt.Errorf("%w: operation identity is bound to a different publication", errFeedSignerConflict)
	}
	return nil
}

// hasDuplicateOperationAttribution reports whether any operation identity in
// the document's provenance records appears for MORE THAN ONE tag — a pattern
// no legitimate publication sequence produces (entries are replaced per tag,
// every identity is unique per operation) and which would defeat
// single-entry identification.
func hasDuplicateOperationAttribution(pubs map[string]spec.TagPublication) bool {
	byOp := make(map[string]string, len(pubs)) // operation ID -> tag
	for tag, entry := range pubs {
		if _, exists := byOp[entry.OperationID]; exists {
			return true
		}
		byOp[entry.OperationID] = tag
	}
	return false
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
	writeHashBytes(h, req.PublicationID)
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

// feedSignerLegacyDocMaxBytes bounds the target repo-state document read for
// legacy candidate derivation. There is no proven bound on the resolve.Reader
// interface (a reader may return arbitrary bytes), so the legacy derivation
// imposes a local, explicit cap: a document larger than this fails closed
// (no candidates, no adoption) rather than decoding an unbounded payload. 1 MiB
// is far beyond any legitimate repo-state document (which carries a bounded set
// of tag/digest entries plus manifest/blob descriptors) and is deliberately
// local to this task — it does not preempt a shared reader-level bound.
const feedSignerLegacyDocMaxBytes = 1 << 20 // 1 MiB

// deriveLegacyCandidates deterministically reconstructs the EXACT historical
// migration-9 operation identity candidates for the logical publication this
// request represents, by recovering the repository identity from the referenced
// target repo-state document:
//
//   - the document is read at req.Reference with a local byte bound and parsed
//     with the EXISTING spec validation (spec.DecodeRepoStateDocument), so an
//     unreadable, oversized, or malformed document fails closed;
//   - repo  = the target document's canonical Repo;
//   - for EVERY VALID tag entry (tag → manifest digest) of the document (a
//     multi-tag repository — the normal case after tags are overwritten,
//     retagged, or aliased — never requires a single-tag target), the exact
//     historical operation ID is derived via the migration-only
//     legacyComputeOperationID over registry/owner/repo/that tag/that digest/
//     expected generation, and the exact historical request hash via
//     legacyFeedCommitHashFor (the historical framing over the reconstructed
//     historical request whose OperationID is that historical ID) — the only
//     byte sequence a real m9 row keyed by that ID can store;
//   - candidates are deterministically sorted (by derived operation ID);
//   - explicit safe bounds are enforced: the document byte size and the tag
//     candidate count are capped (feedSignerLegacyDocMaxBytes /
//     feedSignerLegacyMaxCandidates), a malformed tag/digest entry fails the
//     WHOLE set closed, and a duplicate derived ID (an ambiguity — two entries
//     collapsing to one historical identity) fails the whole set closed.
//
// Empty/no-valid/oversized/ambiguous candidate sets return nil and the caller
// fails closed with NO adoption (the m9 rows stay quarantined rather than risk
// a wrong adoption). This is only ever a RECOGNITION key set to find a
// logically-identical quarantined m9 row; the historical IDs are never used as
// new active operation IDs.
func (s *FeedSigner) deriveLegacyCandidates(ctx context.Context, req publish.FeedCommitRequest) []LegacyOperationCandidate {
	data, err := s.Docs.Read(ctx, req.Reference)
	if err != nil {
		return nil
	}
	if len(data) > feedSignerLegacyDocMaxBytes {
		return nil
	}
	doc, err := spec.DecodeRepoStateDocument(data)
	if err != nil {
		return nil
	}
	if len(doc.Tags) > feedSignerLegacyMaxCandidates {
		return nil
	}
	cands := make([]LegacyOperationCandidate, 0, len(doc.Tags))
	seen := make(map[string]struct{}, len(doc.Tags))
	for tag, digest := range doc.Tags {
		// The manifest digest must be a 64-hex immutable reference (after any
		// "sha256:" prefix), exactly as the data plane supplied it to the
		// historical ComputeOperationID; a malformed value means the entry's
		// identity cannot be reproduced EXACTLY, so the whole set fails closed.
		if !publish.IsHexReference(digest[strings.LastIndexByte(digest, ':')+1:]) {
			return nil
		}
		id := legacyComputeOperationID(req.RegistryID, req.Owner, doc.Repo, tag, digest, req.ExpectedGeneration)
		if _, dup := seen[id]; dup {
			// Two distinct tag entries collapsed to one historical identity:
			// the quarantine row's primary key could not disambiguate them.
			return nil
		}
		seen[id] = struct{}{}
		cands = append(cands, LegacyOperationCandidate{OperationID: id, RequestHash: legacyFeedCommitHashFor(id, req)})
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].OperationID < cands[j].OperationID })
	if len(cands) == 0 {
		// An empty candidate set (no valid tags) is the same fail-closed outcome
		// as an unreadable document: nil means "do not attempt adoption".
		return nil
	}
	return cands
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
