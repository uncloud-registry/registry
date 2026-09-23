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
// implements the REAL Bee surface the control plane talks to:
//
//   - GET /feeds/<owner>/<topic>: 404 while absent; once the winner's SOC is
//     stored, 200 with the winner's 32 raw binary payload bytes and the
//     Swarm-Feed-Index "0000000000000000" (sequence zero — no advancement).
//   - GET /bzz/<ref>: immutable document reads (target repo docs, stamp doc).
//   - POST /chunks: BARRIER — blocks until BOTH racing writers have arrived,
//     then 201 with a deterministic content address per writer (bounded wait
//     so a mechanism failure fails the test instead of hanging).
//   - POST /soc/<owner>/<id>: ATOMICALLY accepts exactly ONE zero-index SOC
//     (the identifier is identical for both writers) with 201; the loser gets
//     the real Bee conflict, 400 "chunk write error" (ethersphere/bee master
//     pkg/api/soc.go maps every chunk-write failure, including the immutable
//     SOC alias conflict, to 400).
//   - GET /soc/<owner>/<id>: 200 + Swarm-Soc-Signature when the winner's SOC
//     exists (the precise conditional disambiguation), 404 otherwise.
type createOnlyRaceBee struct {
	mu        sync.Mutex
	repoPath  string
	feeds     map[string][]byte // path -> 32 binary payload bytes
	indexes   map[string]string
	payloads  map[string][]byte // /bzz/<ref> -> document bytes
	repo404   int
	chunkSeen int
	chunkRel  chan struct{}
	soc201    int
	soc400    int
	socID     string
	socWinner []byte
	releaseAt int
}

func newCreateOnlyRaceBee(t *testing.T, repoPath string, seedFeeds map[string][]byte, seedIndexes map[string]string, payloads map[string][]byte) (*createOnlyRaceBee, *httptest.Server) {
	t.Helper()
	b := &createOnlyRaceBee{
		repoPath:  repoPath,
		feeds:     map[string][]byte{},
		indexes:   map[string]string{},
		payloads:  payloads,
		chunkRel:  make(chan struct{}),
		releaseAt: 2, // exactly two racing writers
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
			payload, ok := b.feeds[r.URL.Path]
			idx := b.indexes[r.URL.Path]
			b.mu.Unlock()
			if !ok {
				b.mu.Lock()
				b.repo404++
				b.mu.Unlock()
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
			b.mu.Lock()
			b.chunkSeen++
			n := b.chunkSeen
			b.mu.Unlock()
			if n >= b.releaseAt {
				select {
				case <-b.chunkRel:
				default:
					close(b.chunkRel)
				}
			} else if n < b.releaseAt {
				select {
				case <-b.chunkRel:
				case <-time.After(30 * time.Second):
				}
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(w, `{"reference":"%s"}`, ref)
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/soc/"):
			body, _ := io.ReadAll(r.Body)
			id := strings.TrimPrefix(r.URL.Path, "/soc/")
			b.mu.Lock()
			if len(b.socWinner) == 0 {
				b.socWinner = body
				b.socID = id
				b.soc201++
				// The winner's payload is the framed chunk: 8-byte span + the
				// 32 raw reference bytes now stored at the repo feed
				// (sequence zero).
				if len(body) == 8+32 {
					b.feeds[b.repoPath] = body[8:]
					b.indexes[b.repoPath] = "0000000000000000"
				}
				b.mu.Unlock()
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{}`))
				return
			}
			b.soc400++
			b.mu.Unlock()
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"code":427,"message":"chunk write error"}`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/soc/"):
			id := strings.TrimPrefix(r.URL.Path, "/soc/")
			b.mu.Lock()
			winner := b.socID == id && len(b.socWinner) != 0
			b.mu.Unlock()
			if winner {
				w.Header().Set("Swarm-Soc-Signature", refHex('f'))
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("probe"))
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

// TestFeedSignerTwoIndependentStoresCreateOnlyRaceOneWinner proves the Bee
// SOC-level TOCTOU closure end to end through TWO INDEPENDENT signer Stores
// (separate on-disk databases — the shared-DB claim test alone is
// insufficient, because the durable (registry, topic) claim gate cannot span
// processes) with distinct first-push operation IDs sharing ONE fake Bee and
// the same feed. Both signers see the missing feed and interleave at the
// /chunks barrier; the fake Bee atomically accepts exactly ONE zero-index SOC;
// exactly one logical success, the loser conflicts, and the final feed carries
// the winner at sequence 0 (never sequence 1, never overwritten).
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
	if bee.soc201 != 1 {
		t.Fatalf("fake Bee must atomically accept exactly ONE zero-index SOC, got %d", bee.soc201)
	}
	if bee.soc400 != 1 {
		t.Fatalf("the loser must receive exactly ONE SOC conflict, got %d", bee.soc400)
	}
	if bee.repo404 != 4 {
		t.Fatalf("both signers must see the missing feed (resolve + updater lookup each), got %d repo 404s", bee.repo404)
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
