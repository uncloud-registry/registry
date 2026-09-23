package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/spec"
	"github.com/uncloud-registry/registry/internal/swarm"
)

// racingCreateUpdater simulates a racing creator at the updater boundary: on a
// CREATE-ONLY update it lets a different writer win the feed FIRST, then
// delegates to the inner updater, which (create-only + existing) must return
// ErrFeedAlreadyExists without any write.
type racingCreateUpdater struct {
	inner     RegistryFeedUpdater
	feeds     *MemoryRegistryFeedStore
	racingRef string
}

func (r racingCreateUpdater) UpdateRegistryFeed(ctx context.Context, reg Registry, feed, ref, batchID string, createOnly bool) error {
	if createOnly {
		r.feeds.mu.Lock()
		r.feeds.Feeds[feed] = r.racingRef
		r.feeds.mu.Unlock()
	}
	return r.inner.UpdateRegistryFeed(ctx, reg, feed, ref, batchID, createOnly)
}

// TestFeedSignerCreateOnlyRaceDetectedAsGenerationConflict proves the signer
// maps a definite already-exists outcome from the updater to a GENERATION
// CONFLICT (never a success), releases the claim for a later retry (the row
// returns to pending), and never overwrites the existing feed. This is the
// memory-fake model of the Bee SOC-level race: between the signer's own
// resolution (feed absent) and the updater's write, a different process
// created the feed.
func TestFeedSignerCreateOnlyRaceDetectedAsGenerationConflict(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	// The repository feed is conclusively absent: creation is allowed.
	delete(w.feedStore.Feeds, w.repoTopic)

	racingRef := refHex('d')
	w.signer.Feeds = racingCreateUpdater{inner: w.signer.Feeds, feeds: w.feedStore, racingRef: racingRef}

	_, err := w.signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerGenerationConflict) {
		t.Fatalf("already-exists on create-only must be a generation conflict, got %v", err)
	}
	// The existing feed is never overwritten.
	if got := w.feedStore.Feeds[w.repoTopic]; got != racingRef {
		t.Fatalf("existing feed must never be overwritten: got %q want the racing creator's %q", got, racingRef)
	}
	// Definite no-write by THIS operation: the claim is released for a later
	// retry, and the operation is NOT completed as a success.
	op, err := w.store.GetFeedSignerOperation(context.Background(), req.OperationID)
	if err != nil {
		t.Fatalf("load operation: %v", err)
	}
	if op.State != FeedSignerOpPending {
		t.Fatalf("definite already-exists must release the claim to pending, got %q", op.State)
	}

	// A retry re-resolves and conflicts again WITHOUT a second advancement:
	// the feed now exists at generation 1, so the generation guard fails
	// closed even without the simulated racer.
	w.docs.Documents[racingRef] = mustRepoDoc(t, testRepo, 1)
	if _, err := w.signer.Commit(context.Background(), req); !errors.Is(err, errFeedSignerGenerationConflict) {
		t.Fatalf("retry after already-exists must conflict again (feed now exists), got %v", err)
	}
	if got := w.feedStore.Feeds[w.repoTopic]; got != racingRef {
		t.Fatalf("retry must not advance or overwrite the feed: got %q", got)
	}
}

// createOnlyRaceBee is the fake Bee for the two-independent-stores race. It
// implements the REAL Bee surface the control plane talks to, under the
// Round 2 root fact: the pusher COALESCES duplicate in-flight POST /soc
// operations on the identical zero-index SOC, so BOTH writers receive 201
// while only the FIRST payload is ever persisted (SOCs and feeds are
// immutable):
//
//   - GET /feeds/<owner>/<topic>: 404 until the creation settles (both
//     signers' resolve + updater lookups — four conclusive-absent reads —
//     ordered by the SOC writergate below), then 200 with the WINNER's 32
//     raw binary payload bytes and Swarm-Feed-Index "0000000000000000"
//     (sequence zero — no advancement). Effective-feed read-backs are held
//     until BOTH SOC POSTs completed, so the race is decided purely by the
//     read-back, never by a manufactured 400.
//   - GET /bzz/<ref>: immutable document reads (target repo docs, stamp doc).
//   - POST /chunks: 201 with a deterministic content address per writer.
//   - POST /soc/<owner>/<id>: WAITS until both signers' conclusive-absent
//     lookups returned (so neither lookup can observe the winner), then
//     ALWAYS 201 — the coalescing model — persisting ONLY the first payload
//     atomically.
//   - GET /soc/<owner>/<id>: the precise conditional probe (200 + strictly
//     valid Swarm-Soc-Signature when present), kept for the separate
//     400+valid-probe conflict path.
type createOnlyRaceBee struct {
	mu          sync.Mutex
	repoPath    string
	feeds       map[string][]byte // path -> 32 binary payload bytes
	indexes     map[string]string
	payloads    map[string][]byte // /bzz/<ref> -> document bytes
	lookupsDone chan struct{}
	postsDone   chan struct{}
	repo404     int
	soc201      int
	soc400      int
	socWinner   []byte
	readbacks   int
	visible     bool
}

func newCreateOnlyRaceBee(t *testing.T, repoPath string, seedFeeds map[string][]byte, seedIndexes map[string]string, payloads map[string][]byte) (*createOnlyRaceBee, *httptest.Server) {
	t.Helper()
	b := &createOnlyRaceBee{
		repoPath:    repoPath,
		feeds:       map[string][]byte{},
		indexes:     map[string]string{},
		payloads:    payloads,
		lookupsDone: make(chan struct{}),
		postsDone:   make(chan struct{}),
	}
	for path, payload := range seedFeeds {
		b.feeds[path] = payload
		if idx, ok := seedIndexes[path]; ok {
			b.indexes[path] = idx
		} else {
			b.indexes[path] = "0000000000000000"
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/feeds/"):
			b.mu.Lock()
			visible := b.visible
			isRepo := r.URL.Path == b.repoPath
			payload, ok := b.feeds[r.URL.Path]
			idx := b.indexes[r.URL.Path]
			b.mu.Unlock()
			if isRepo && !visible {
				// Conclusive-absent sequence lookup (resolve + updater lookup
				// per signer); the writergate below waits for all four.
				b.mu.Lock()
				b.repo404++
				n := b.repo404
				b.mu.Unlock()
				if n >= 4 {
					close(b.lookupsDone)
				}
				http.NotFound(w, r)
				return
			}
			if isRepo {
				// Effective-feed read-back: both SOC POSTs must have completed
				// (and persisted the winner) before ANY read-back is answered,
				// so both writers decide purely on the read-back result.
				select {
				case <-b.postsDone:
				case <-time.After(30 * time.Second):
				}
				b.mu.Lock()
				b.readbacks++
				payload, ok = b.feeds[b.repoPath]
				idx = b.indexes[b.repoPath]
				b.mu.Unlock()
			}
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Swarm-Feed-Index", idx)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(payload)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/bzz/"):
			ref := strings.TrimPrefix(r.URL.Path, "/bzz/")
			b.mu.Lock()
			payload, ok := b.payloads[ref]
			b.mu.Unlock()
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(payload)
		case r.Method == http.MethodPost && r.URL.Path == "/chunks":
			body, _ := io.ReadAll(r.Body)
			ref := chunkRefSHA(body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(w, `{"reference":"%s"}`, ref)
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/soc/"):
			body, _ := io.ReadAll(r.Body)
			// Coalescing writergate: BOTH signers must have seen absent
			// lookups (4 repo 404s) before either SOC POST is processed, so
			// the race really happens at the SOC layer with both lookups
			// conclusive-absent.
			select {
			case <-b.lookupsDone:
			case <-time.After(30 * time.Second):
			}
			b.mu.Lock()
			b.soc201++
			if b.socWinner == nil {
				b.socWinner = body
				// The winner's payload is the framed chunk: 8-byte span + the
				// 32 raw reference bytes now stored at the repo feed
				// (sequence zero).
				if len(body) == 8+32 {
					b.feeds[b.repoPath] = body[8:]
					b.indexes[b.repoPath] = "0000000000000000"
				}
				b.visible = true
			}
			if b.soc201 == 2 {
				close(b.postsDone)
			}
			b.mu.Unlock()
			// REAL model: 201 to BOTH duplicate in-flight writers.
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/soc/"):
			b.mu.Lock()
			winner := len(b.socWinner) != 0
			b.mu.Unlock()
			if winner {
				w.Header().Set("Swarm-Soc-Signature", strings.Repeat("ab", 65))
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"reference":"` + refHex('f') + `"}`))
				return
			}
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return b, srv
}

func chunkRefSHA(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// TestFeedSignerTwoIndependentStoresCreateOnlyRaceOneWinner proves the
// Round 2 root fact end to end: real Bee may return 201 to BOTH duplicate
// in-flight POST /soc operations on the identical zero-index SOC (pusher
// duplicate coalescing), so 201 alone is never proof a payload won. TWO
// INDEPENDENT signer Stores (separate on-disk databases — the shared-DB claim
// test alone is insufficient, because the durable (registry, topic) claim
// gate cannot span processes) with distinct first-push operation IDs share
// ONE fake Bee and the same feed. Both signers see the missing feed and
// interleave at the SOC layer; the fake Bee returns 201 to BOTH writers,
// persisting exactly ONE zero-index SOC; each writer then reads the
// effective feed back (the read-backs are held until both posts completed) —
// the winner proves its own reference at sequence 0 and succeeds, the loser
// observes the winner's reference and fails as a generation conflict; the
// final feed carries the winner at sequence 0 (never sequence 1, never
// overwritten). The loser's 400 is NEVER manufactured.
func TestFeedSignerTwoIndependentStoresCreateOnlyRaceOneWinner(t *testing.T) {
	// Two independent databases — process-like signer Stores.
	storeA := mustOpenFileStore(t, filepath.Join(t.TempDir(), "race-a.db"))
	storeB := mustOpenFileStore(t, filepath.Join(t.TempDir(), "race-b.db"))

	ctx := context.Background()
	// The exact 64-hex Bee postage batch the stamp policy grants.
	testRaceBatch := strings.Repeat("cd", 32)
	// The feed owner MUST be the signer key's own address: the production
	// updater rejects any feed whose owner differs from the signer key.
	feedKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate feed key: %v", err)
	}
	feedOwner := strings.ToLower(ethcrypto.PubkeyToAddress(feedKey.PublicKey).Hex()[2:])
	feedKeyBytes := ethcrypto.FromECDSA(feedKey)
	provision := func(store *Store, slug, host string) (int64, error) {
		owner, err := store.CreateUser(ctx, host+"@example.com", "hash")
		if err != nil {
			return 0, err
		}
		reg, err := store.CreateProvisionedRegistry(ctx, Registry{
			Slug: slug, Host: host, ENSName: "",
			OwnerUserID: owner.ID, FeedOwnerAddress: feedOwner, DefaultStampBatchID: testRaceBatch,
			AnonymousPull: true,
		}, newTestFeedKeyCipherForStore(t), feedKeyBytes,
			[]byte(testAuthPayload), []byte(testStampPayload))
		if err != nil {
			return 0, err
		}
		if err := store.MarkRegistryReady(ctx, reg.ID); err != nil {
			return 0, err
		}
		return reg.ID, nil
	}
	regA, err := provision(storeA, "racea", "racea.test")
	if err != nil {
		t.Fatalf("provision store A: %v", err)
	}
	regB, err := provision(storeB, "raceb", "raceb.test")
	if err != nil {
		t.Fatalf("provision store B: %v", err)
	}
	if regA != regB {
		t.Fatalf("independent stores must resolve the SAME registry identity for the race, got %d vs %d", regA, regB)
	}

	repoTopic := spec.RepoStateFeedRef(feedOwner, testRepo)
	stampFeed := spec.StampPolicyFeedRef(feedOwner)
	stampRef := refHex('c')

	bee, srv := newCreateOnlyRaceBee(t,
		pathForFeedRef(repoTopic),
		map[string][]byte{pathForFeedRef(stampFeed): refBytesForTest(t, stampRef)},
		map[string]string{pathForFeedRef(stampFeed): "0000000000000000"},
		map[string][]byte{
			refHex('a'): mustRepoDoc(t, testRepo, 1), // target doc for op A (gen 1 = 0+1)
			refHex('d'): mustRepoDoc(t, testRepo, 1), // target doc for op B
			stampRef:    mustStampDoc(t, testRaceBatch),
		})

	feedResolver := swarm.NewBeeFeedResolver(srv.URL, srv.Client())
	docs := swarm.NewBeeDocumentStore(srv.URL, srv.Client())
	serviceA := &Service{Store: storeA, FeedKeys: newTestFeedKeyCipher(t)}
	serviceB := &Service{Store: storeB, FeedKeys: newTestFeedKeyCipher(t)}

	signerA := &FeedSigner{
		Store:        storeA,
		Feeds:        BeeRegistryFeedUpdater{BaseURL: srv.URL, HTTPClient: srv.Client(), Keys: serviceA},
		ResolveFeeds: feedResolver,
		Docs:         docs,
	}
	signerB := &FeedSigner{
		Store:        storeB,
		Feeds:        BeeRegistryFeedUpdater{BaseURL: srv.URL, HTTPClient: srv.Client(), Keys: serviceB},
		ResolveFeeds: feedResolver,
		Docs:         docs,
	}

	reqA := publish.FeedCommitRequest{
		OperationID: "first-push-A", RegistryID: regA, Owner: "0x" + feedOwner,
		Topic: repoTopic, Reference: refHex('a'), BatchID: testRaceBatch, ExpectedGeneration: 0,
	}
	reqB := reqA
	reqB.OperationID = "first-push-B"
	reqB.Reference = refHex('d')

	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	done.Add(2)
	var mu sync.Mutex
	successes := 0
	var firstErr error
	run := func(signer *FeedSigner, req publish.FeedCommitRequest) {
		defer done.Done()
		start.Wait()
		if _, err := signer.Commit(ctx, req); err == nil {
			mu.Lock()
			successes++
			mu.Unlock()
		} else {
			mu.Lock()
			if firstErr == nil {
				firstErr = err
			}
			mu.Unlock()
		}
	}
	go run(signerA, reqA)
	go run(signerB, reqB)
	start.Done()
	done.Wait()

	if successes != 1 {
		t.Fatalf("exactly one independent-store first push must succeed, got %d (first err %v)", successes, firstErr)
	}
	if firstErr == nil || !errors.Is(firstErr, errFeedSignerGenerationConflict) {
		t.Fatalf("the losing writer must fail with a generation conflict, got %v", firstErr)
	}
	if bee.soc201 != 2 {
		t.Fatalf("the coalescing model REQUIRES 201 to BOTH writers, got %d", bee.soc201)
	}
	if bee.soc400 != 0 {
		t.Fatalf("the both-201 model must never manufacture a 400 for the loser, got %d", bee.soc400)
	}
	if bee.repo404 != 4 {
		t.Fatalf("both signers must see the missing feed (resolve + updater lookup each), got %d repo 404s", bee.repo404)
	}
	if bee.readbacks < 2 {
		t.Fatalf("each signer must read the effective feed back after its 201, got %d read-backs", bee.readbacks)
	}

	// Final feed: the WINNER's payload at sequence zero — never sequence one,
	// never the loser's ref.
	value, err := feedResolver.ReadFeed(ctx, repoTopic)
	if err != nil {
		t.Fatalf("read back repo feed: %v", err)
	}
	if value.Reference != refHex('a') && value.Reference != refHex('d') {
		t.Fatalf("final feed must carry ONE winner's reference, got %q", value.Reference)
	}
	if value.Index != "0000000000000000" {
		t.Fatalf("created feed must stay at sequence 0 (no advancement), got index %q", value.Index)
	}
}

func refBytesForTest(t *testing.T, ref string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(ref)
	if err != nil || len(raw) != 32 {
		t.Fatalf("fixture ref must be 64 hex: %q (%v)", ref, err)
	}
	return raw
}

// uncertainCreateUpdater models the Round 2 uncertain outcome at the updater
// boundary: the SOC POST returned 201 but the effective-feed read-back was
// UNAVAILABLE (still 404 past the bound, 5xx, decode failure, deadline). The
// write may have applied, so the updater returns an ordinary DEPENDENCY error
// — never ErrFeedAlreadyExists (not a definite conflict) and never success.
// The signer MUST respond by keeping its durable lease so a later retry
// resolves the effective feed before any other update can advance it.
type uncertainCreateUpdater struct{}

func (uncertainCreateUpdater) UpdateRegistryFeed(_ context.Context, _ Registry, _ string, _ string, _ string, createOnly bool) error {
	if !createOnly {
		return errors.New("uncertain create updater must only see create-only updates")
	}
	return errors.New("create-only feed verification: bee feed resolution failed")
}

// TestFeedSignerCreateOnlyUncertainUpdateKeepsLease proves the signer's
// uncertain handling for the Round 2 root fact: when a create-only update's
// SOC 201 cannot be verified by the effective-feed read-back (read-back
// unavailable → an ordinary dependency error, NOT ErrFeedAlreadyExists), the
// durable lease is KEPT — the operation stays processing — so a retry is
// forced to resolve the effective feed before any other update can advance
// it; a DIFFERENT first-push operation on the same feed is blocked while the
// lease is live; and after the lease expires with the feed settled at the
// target, an identical retry resolves IDEMPOTENTLY (done path) with ZERO
// second advancement.
func TestFeedSignerCreateOnlyUncertainUpdateKeepsLease(t *testing.T) {
	req := validCommitReq(1, "batch-1")
	w := newFeedTestWorld(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 0, targetRef: refHex('a'), targetGen: 1, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	ctx := context.Background()
	// Generation-zero creation: the repository feed is conclusively absent.
	delete(w.feedStore.Feeds, w.repoTopic)

	// First attempt: create-only write goes out, read-back unavailable.
	w.signer.Feeds = uncertainCreateUpdater{}
	_, err := w.signer.Commit(ctx, req)
	if !errors.Is(err, errFeedSignerBackend) {
		t.Fatalf("unverifiable create-only write must surface as a backend (dependency) error, got %v", err)
	}
	if errors.Is(err, errFeedSignerGenerationConflict) {
		t.Fatalf("an UNVERIFIABLE write is NOT a definite conflict, got %v", err)
	}
	// The lease is KEPT: the operation stays processing (never released to
	// pending, never succeeded) with a live lease — the uncertain write is
	// not resolved until a later retry re-resolves the effective feed.
	op, err := w.store.GetFeedSignerOperation(ctx, req.OperationID)
	if err != nil {
		t.Fatalf("load operation: %v", err)
	}
	if op.State != FeedSignerOpProcessing {
		t.Fatalf("uncertain create-only failure must keep the operation processing, got %q", op.State)
	}
	if op.LeaseUntil == nil || !op.LeaseUntil.After(time.Now()) {
		t.Fatalf("uncertain failure must keep a live lease, got %v", op.LeaseUntil)
	}

	// A DIFFERENT first-push operation on the same feed is BLOCKED while the
	// lease is live: its claim collides with the (registry, topic) processing
	// gate, so it can never advance or overwrite the uncertain feed.
	racing := req
	racing.OperationID = "first-push-racing"
	racing.Reference = refHex('d')
	if _, err := w.signer.Commit(ctx, racing); !errors.Is(err, errFeedSignerBackend) {
		t.Fatalf("a distinct operation must be blocked while the uncertain lease is live, got %v", err)
	}
	if _, ok := w.feedStore.Feeds[w.repoTopic]; ok {
		t.Fatal("no operation may advance the feed while the uncertain lease is live")
	}

	// The uncertain write actually applied (as the fake Bee's 201 suggested):
	// the feed now settles at the target. Age the lease (a crashed/uncertain
	// attempt that never resolved) and retry the IDENTICAL request: it
	// re-resolves, observes the feed already at the target, and completes
	// WITHOUT a second advancement.
	w.feedStore.Feeds[w.repoTopic] = publish.CanonicalReference(req.Reference) // settled externally
	pastNanos := timeToNanos(time.Now().UTC().Add(-time.Minute))
	if _, err := w.store.DB.ExecContext(ctx,
		`update feed_signer_operations set lease_until = ? where operation_id = ?`, pastNanos, req.OperationID); err != nil {
		t.Fatalf("age lease: %v", err)
	}
	counting := &countingFeedUpdater{inner: w.feedStore}
	w.signer.Feeds = counting
	result, err := w.signer.Commit(ctx, req)
	if err != nil {
		t.Fatalf("identical retry must resolve the uncertain creation: %v", err)
	}
	if result.OperationID != req.OperationID || result.Feed != req.Topic || result.Reference != publish.CanonicalReference(req.Reference) {
		t.Fatalf("unexpected resolution result: %+v", result)
	}
	if got := counting.count(); got != 0 {
		t.Fatalf("resolution must not re-run the external feed update, got %d", got)
	}
	op, err = w.store.GetFeedSignerOperation(ctx, req.OperationID)
	if err != nil {
		t.Fatalf("reload operation: %v", err)
	}
	if op.State != FeedSignerOpSucceeded {
		t.Fatalf("the retried operation must settle as succeeded, got %q", op.State)
	}
}
