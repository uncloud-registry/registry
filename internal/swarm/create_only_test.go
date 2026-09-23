package swarm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// socSigHex is a plausible valid Swarm-Soc-Signature header value: the
// hex-encoded 65-byte recoverable secp256k1 signature (32-byte R + 32-byte S
// + 1 recovery byte => exactly 130 hex chars) the Bee socGetHandler emits on
// a present SOC.
func socSigHex() string { return strings.Repeat("ab", 65) }

// socProbeBody returns the exact JSON body Bee's socGetHandler serves on a
// present SOC ({"reference":"<64 hex>"} — the SOC chunk's own address).
func socProbeBody(ref string) []byte {
	return []byte(`{"reference":"` + ref + `"}`)
}

// TestBeeSequenceFeedUpdaterCreateOnlyExistingFailsBeforeWrites proves the
// create-only contract at the lookup stage: a 200 sequence lookup (the feed
// EXISTS) returns the stable ErrFeedAlreadyExists BEFORE any /chunks or /soc
// request — zero write side effects. A non-404 lookup failure stays a
// dependency error, never an already-exists classification.
func TestBeeSequenceFeedUpdaterCreateOnlyExistingFailsBeforeWrites(t *testing.T) {
	t.Parallel()

	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	owner := strings.ToLower(ethcrypto.PubkeyToAddress(privateKey.PublicKey).Hex()[2:])
	topic := strings.Repeat("ab", 32)

	for _, tc := range []struct {
		name    string
		lookup  func(w http.ResponseWriter)
		wantAe  bool // want ErrFeedAlreadyExists
		wantDep bool // want a plain dependency error (never already-exists)
	}{
		{
			name: "200 existing feed is already-exists",
			lookup: func(w http.ResponseWriter) {
				w.Header().Set("Swarm-Feed-Index-Next", "0000000000000001")
				w.Header().Set("Swarm-Feed-Index", "0000000000000000")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(refBytes64('b'))
			},
			wantAe: true,
		},
		{
			name: "500 lookup stays dependency error",
			lookup: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("boom"))
			},
			wantDep: true,
		},
		{
			name: "400 lookup stays dependency error",
			lookup: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte("boom"))
			},
			wantDep: true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var chunks, socs int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/feeds/"+owner+"/"+topic:
					tc.lookup(w)
				case r.Method == http.MethodPost && r.URL.Path == "/chunks":
					chunks++
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{"reference":"` + hex64('c') + `"}`))
				case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/soc/"+owner+"/"):
					socs++
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			updater, err := NewBeeSequenceFeedUpdater(server.URL, server.Client(), hex.EncodeToString(ethcrypto.FromECDSA(privateKey)))
			if err != nil {
				t.Fatalf("create updater: %v", err)
			}
			err = updater.Update(context.Background(), FeedUpdate{
				Feed:       "feed://" + owner + "/" + topic,
				Reference:  hex64('a'),
				BatchID:    hex64('b'),
				CreateOnly: true,
			})
			switch {
			case tc.wantAe && !errors.Is(err, ErrFeedAlreadyExists):
				t.Fatalf("expected ErrFeedAlreadyExists, got %v", err)
			case tc.wantDep && err == nil:
				t.Fatal("expected a dependency error, got nil")
			case tc.wantDep && errors.Is(err, ErrFeedAlreadyExists):
				t.Fatalf("non-404 lookup failure must stay a dependency error, got already-exists: %v", err)
			}
			if chunks != 0 || socs != 0 {
				t.Fatalf("create-only must have ZERO write side effects on an existing/errored lookup, got chunks=%d socs=%d", chunks, socs)
			}
		})
	}
}

// createOnlyRaceBee models the REAL Bee creation behavior the Round 2 root
// fact establishes: the pusher COALESCES duplicate in-flight POST /soc
// operations on the identical zero-index SOC (same owner, same identifier) so
// BOTH writers receive 201, while only the FIRST payload is ever persisted
// (SOCs and feeds are immutable). The fake:
//
//   - GET /feeds/<owner>/<topic>: 404 until the creation settles (both
//     lookups and both read-backs ordered by the barriers below), then 200
//     with the WINNER's 32 raw binary payload bytes and Swarm-Feed-Index
//     "0000000000000000" (sequence zero — no advancement).
//   - POST /soc/<owner>/<id>: WAITS until both writers' sequence lookups
//     returned 404 (so neither lookup can observe the winner), then ALWAYS
//     201 — the coalescing model — persisting ONLY the first payload
//     atomically. Response order of the two writers is decided by arrival.
//   - Read-backs are held until BOTH SOC POSTs have completed, so the race is
//     decided purely by the effective-feed read-back, never by 400s.
type createOnlyRaceBee struct {
	mu          sync.Mutex
	owner       string
	topic       string
	lookupsDone chan struct{}
	postsDone   chan struct{}
	lookups     int
	soc201      int
	soc400      int
	socWinner   []byte // framed chunk data of the FIRST accepted SOC
	readbacks   int
	visible     bool
}

func newCreateOnlyRaceBee(owner, topic string) *createOnlyRaceBee {
	return &createOnlyRaceBee{
		owner:       owner,
		topic:       topic,
		lookupsDone: make(chan struct{}),
		postsDone:   make(chan struct{}),
	}
}

func (b *createOnlyRaceBee) handler() http.Handler {
	feedPath := "/feeds/" + b.owner + "/" + b.topic
	socPath := "/soc/" + b.owner + "/"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == feedPath:
			b.mu.Lock()
			visible := b.visible
			b.mu.Unlock()
			if !visible {
				// Sequence lookup (or an eventual-consistency read-back race,
				// which the updater retries): the feed is not yet visible.
				b.mu.Lock()
				b.lookups++
				n := b.lookups
				b.mu.Unlock()
				if n == 2 {
					close(b.lookupsDone)
				}
				http.NotFound(w, r)
				return
			}
			// Read-back: both SOC POSTs must have completed (and persisted
			// the winner) before ANY read-back is answered — the barrier that
			// makes the both-201 race deterministic.
			select {
			case <-b.postsDone:
			case <-time.After(30 * time.Second):
			}
			b.mu.Lock()
			b.readbacks++
			winner := b.socWinner
			b.mu.Unlock()
			w.Header().Set("Swarm-Feed-Index", "0000000000000000")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(winner[8:]) // the 32 raw reference bytes
		case r.Method == http.MethodPost && r.URL.Path == "/chunks":
			body, _ := io.ReadAll(r.Body)
			ref := chunkContentRef(body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"reference":"` + ref + `"}`))
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, socPath):
			body, _ := io.ReadAll(r.Body)
			// Coalescing writergate: both writers must have seen 404 lookups
			// before either SOC POST is processed, so the race really
			// happens at the SOC layer with both lookups conclusive-absent.
			select {
			case <-b.lookupsDone:
			case <-time.After(30 * time.Second):
			}
			b.mu.Lock()
			b.soc201++
			if b.socWinner == nil {
				b.socWinner = body
				b.visible = true
				if len(body) == 8+32 {
					// The winner's payload is the framed chunk: 8-byte span +
					// the 32 raw reference bytes now stored at the repo feed
					// (sequence zero).
				}
			}
			if b.soc201 == 2 {
				close(b.postsDone)
			}
			b.mu.Unlock()
			// REAL model: 201 to BOTH duplicate in-flight writers.
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, socPath):
			// The conditional probe stays realistic (200 + valid signature +
			// exact SOC JSON body when present); the both-201 race never
			// reaches it, but the "keep 400+valid probe" path uses it.
			b.mu.Lock()
			winner := b.socWinner != nil
			b.mu.Unlock()
			if winner {
				w.Header().Set("Swarm-Soc-Signature", socSigHex())
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(socProbeBody(hex64('f')))
				return
			}
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// TestBeeSequenceFeedUpdaterCreateOnlyRaceBothSOC201OneWinner proves the
// Round 2 root fact end to end: real Bee may return 201 to BOTH duplicate
// in-flight POST /soc operations on the identical zero-index SOC (pusher
// duplicate coalescing), so 201 alone is never proof a payload won. Two
// process-like updaters (same owner key, same feed, DISTINCT target refs)
// race a fake Bee that persists the FIRST payload but returns 201 to BOTH —
// with a barrier so BOTH SOC POSTs complete before either read-back. The
// winner's read-back proves its own reference at sequence zero and succeeds;
// the loser's read-back observes the winner's reference, conflicts
// (ErrFeedAlreadyExists) — the 400 is never manufactured — and the final
// feed carries ONE winner at index 0, never sequence one.
func TestBeeSequenceFeedUpdaterCreateOnlyRaceBothSOC201OneWinner(t *testing.T) {
	t.Parallel()

	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	owner := strings.ToLower(ethcrypto.PubkeyToAddress(privateKey.PublicKey).Hex()[2:])
	topic := strings.Repeat("ab", 32)

	bee := newCreateOnlyRaceBee(owner, topic)
	server := httptest.NewServer(bee.handler())
	defer server.Close()

	var (
		start   = make(chan struct{})
		results = make(chan error, 2)
	)
	write := func(ref string) {
		<-start
		updater, err := NewBeeSequenceFeedUpdater(server.URL, server.Client(), hex.EncodeToString(ethcrypto.FromECDSA(privateKey)))
		if err != nil {
			results <- err
			return
		}
		// Shorten the eventual-consistency read-back backoff so any hidden
		// 404 retry runs fast instead of sleeping the production bound.
		updater.createVerifyBackoff = time.Millisecond
		results <- updater.Update(context.Background(), FeedUpdate{
			Feed:       "feed://" + owner + "/" + topic,
			Reference:  ref,
			BatchID:    hex64('b'),
			CreateOnly: true,
		})
	}
	go write(hex64('a'))
	go write(hex64('d'))
	close(start)

	var errs []error
	for i := 0; i < 2; i++ {
		errs = append(errs, <-results)
	}
	var successes, alreadyExists int
	for _, err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrFeedAlreadyExists):
			alreadyExists++
		default:
			t.Fatalf("unexpected writer outcome: %v", err)
		}
	}
	if successes != 1 || alreadyExists != 1 {
		t.Fatalf("expected exactly one winner and one already-exists loser, got successes=%d alreadyExists=%d (errs %v)", successes, alreadyExists, errs)
	}

	bee.mu.Lock()
	soc201, soc400 := bee.soc201, bee.soc400
	winner := bee.socWinner
	lookups, readbacks := bee.lookups, bee.readbacks
	bee.mu.Unlock()
	if soc201 != 2 {
		t.Fatalf("the coalescing model REQUIRES 201 to BOTH writers, got %d", soc201)
	}
	if soc400 != 0 {
		t.Fatalf("the both-201 model must never manufacture a 400 for the loser, got %d", soc400)
	}
	if lookups != 2 {
		t.Fatalf("exactly two conclusive-absent lookups required, got %d", lookups)
	}
	if readbacks < 2 {
		t.Fatalf("each writer must read the effective feed back after its 201, got %d read-backs", readbacks)
	}
	if winner == nil || len(winner) != 8+32 {
		t.Fatalf("the fake Bee must persist exactly one framed winner payload, got %d bytes", len(winner))
	}
	winnerRef := hex.EncodeToString(winner[8:])
	if winnerRef != hex64('a') && winnerRef != hex64('d') {
		t.Fatalf("the winner payload must be one of the two racing references, got %s", winnerRef)
	}
	// The winning writer is the one whose reference the feed now holds; the
	// loser's read-back saw that mismatch and conflicted. Both outcomes were
	// decided by the read-back, never by a SOC 400 (asserted above).
}

// TestBeeSequenceFeedUpdaterCreateOnlySameRefIdempotent proves the
// documented both-writers-same-reference case: two creators racing with the
// IDENTICAL zero-index payload both receive 201, and both read-backs observe
// the same effective feed (the immutable SOC and feed payload are
// byte-identical, so no overwrite is possible) — both report idempotent
// success at sequence zero. The distinct-reference race is the one that must
// yield exactly one winner (proven by the test above).
func TestBeeSequenceFeedUpdaterCreateOnlySameRefIdempotent(t *testing.T) {
	t.Parallel()

	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	owner := strings.ToLower(ethcrypto.PubkeyToAddress(privateKey.PublicKey).Hex()[2:])
	topic := strings.Repeat("ab", 32)

	bee := newCreateOnlyRaceBee(owner, topic)
	server := httptest.NewServer(bee.handler())
	defer server.Close()

	var (
		start   = make(chan struct{})
		results = make(chan error, 2)
	)
	write := func() {
		<-start
		updater, err := NewBeeSequenceFeedUpdater(server.URL, server.Client(), hex.EncodeToString(ethcrypto.FromECDSA(privateKey)))
		if err != nil {
			results <- err
			return
		}
		updater.createVerifyBackoff = time.Millisecond
		results <- updater.Update(context.Background(), FeedUpdate{
			Feed:       "feed://" + owner + "/" + topic,
			Reference:  hex64('a'),
			BatchID:    hex64('b'),
			CreateOnly: true,
		})
	}
	go write()
	go write()
	close(start)

	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatalf("identical-reference creators must both succeed idempotently, got %v", err)
		}
	}
	bee.mu.Lock()
	soc201, soc400 := bee.soc201, bee.soc400
	winner := bee.socWinner
	bee.mu.Unlock()
	if soc201 != 2 || soc400 != 0 {
		t.Fatalf("both-201 coalescing required (soc201=%d soc400=%d)", soc201, soc400)
	}
	if winner == nil || hex.EncodeToString(winner[8:]) != hex64('a') {
		t.Fatalf("the settled feed must hold the shared reference at sequence zero")
	}
}

// TestBeeSequenceFeedUpdaterCreateOnlyEffectiveFeedVerified proves the
// post-write read-back contract (Round 2): after a 201, a create-only update
// reports success ONLY when the strict Task 11 binary read-back shows index
// exactly zero AND this update's canonical reference. Index nonzero or a
// different reference is ErrFeedAlreadyExists; a conclusively-absent feed
// past the bounded read-only retry, a malformed/strict-contract violation,
// an oversize/5xx response, or a stalled read-back past the caller deadline
// is an UNCERTAIN dependency error — never success, never already-exists.
func TestBeeSequenceFeedUpdaterCreateOnlyEffectiveFeedVerified(t *testing.T) {
	t.Parallel()

	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	owner := strings.ToLower(ethcrypto.PubkeyToAddress(privateKey.PublicKey).Hex()[2:])
	topic := strings.Repeat("ab", 32)
	feedPath := "/feeds/" + owner + "/" + topic

	sigHeader := func(w http.ResponseWriter) {
		w.Header().Set("Swarm-Soc-Signature", socSigHex())
	}

	for _, tc := range []struct {
		name        string
		readBack    func(attempt int, w http.ResponseWriter) // GET /feeds AFTER the lookup
		wantSuccess bool
		wantAe      bool
		wantDep     bool
		wantCanc    bool // want errors.Is(context.DeadlineExceeded)
		wantReads   int  // exact read-back request count (0 = don't assert)
	}{
		{
			name: "index zero and same reference succeeds",
			readBack: func(a int, w http.ResponseWriter) {
				w.Header().Set("Swarm-Feed-Index", "0000000000000000")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(refBytes64('a'))
			},
			wantSuccess: true,
			wantReads:   1,
		},
		{
			name: "index nonzero is already-exists",
			readBack: func(a int, w http.ResponseWriter) {
				w.Header().Set("Swarm-Feed-Index", "0000000000000001")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(refBytes64('a'))
			},
			wantAe:    true,
			wantReads: 1,
		},
		{
			name: "different reference at index zero is already-exists",
			readBack: func(a int, w http.ResponseWriter) {
				w.Header().Set("Swarm-Feed-Index", "0000000000000000")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(refBytes64('d'))
			},
			wantAe:    true,
			wantReads: 1,
		},
		{
			name: "eventual consistency 404 then exact feed succeeds",
			readBack: func(a int, w http.ResponseWriter) {
				if a < 3 {
					http.NotFound(w, nil)
					return
				}
				w.Header().Set("Swarm-Feed-Index", "0000000000000000")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(refBytes64('a'))
			},
			wantSuccess: true,
			wantReads:   4, // 3 conclusive-404 retries + the successful read
		},
		{
			name: "persistent 404 past the bound is uncertain dependency",
			readBack: func(a int, w http.ResponseWriter) {
				http.NotFound(w, nil)
			},
			wantDep:   true,
			wantReads: beeFeedCreateVerifyMaxAttempts,
		},
		{
			name: "read-back 5xx is uncertain dependency",
			readBack: func(a int, w http.ResponseWriter) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("boom"))
			},
			wantDep: true,
		},
		{
			name: "duplicate index headers fail the strict contract",
			readBack: func(a int, w http.ResponseWriter) {
				w.Header().Add("Swarm-Feed-Index", "0000000000000000")
				w.Header().Add("Swarm-Feed-Index", "0000000000000000")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(refBytes64('a'))
			},
			wantDep: true,
		},
		{
			name: "ascii-hex body fails the strict binary contract",
			readBack: func(a int, w http.ResponseWriter) {
				// The old 64-ASCII-hex form, NOT the 32 raw binary bytes.
				w.Header().Set("Swarm-Feed-Index", "0000000000000000")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(hex64('a')))
			},
			wantDep: true,
		},
		{
			name: "oversized read-back body is uncertain dependency",
			readBack: func(a int, w http.ResponseWriter) {
				w.Header().Set("Swarm-Feed-Index", "0000000000000000")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(bytesN(beeFeedResolveMaxBody + 1))
			},
			wantDep: true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var (
				mu       sync.Mutex
				lookups  int
				readBack int
			)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == feedPath:
					mu.Lock()
					lookups++
					isReadBack := lookups > 1
					mu.Unlock()
					if !isReadBack {
						http.NotFound(w, r)
						return
					}
					mu.Lock()
					readBack++
					attempt := readBack - 1
					mu.Unlock()
					// http.NotFound(w, nil) is fine for the retry cases; a nil
					// error is only used as a marker.
					if tc.readBack == nil {
						http.NotFound(w, r)
						return
					}
					tc.readBack(attempt, w)
				case r.Method == http.MethodPost && r.URL.Path == "/chunks":
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{"reference":"` + hex64('c') + `"}`))
				case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/soc/"+owner+"/"):
					sigHeader(w)
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			updater, err := NewBeeSequenceFeedUpdater(server.URL, server.Client(), hex.EncodeToString(ethcrypto.FromECDSA(privateKey)))
			if err != nil {
				t.Fatalf("create updater: %v", err)
			}
			updater.createVerifyBackoff = time.Millisecond
			err = updater.Update(context.Background(), FeedUpdate{
				Feed:       "feed://" + owner + "/" + topic,
				Reference:  hex64('a'),
				BatchID:    hex64('b'),
				CreateOnly: true,
			})
			switch {
			case tc.wantSuccess && err != nil:
				t.Fatalf("expected success, got %v", err)
			case tc.wantAe && !errors.Is(err, ErrFeedAlreadyExists):
				t.Fatalf("expected ErrFeedAlreadyExists, got %v", err)
			case tc.wantDep && err == nil:
				t.Fatal("expected an uncertain dependency error, got nil")
			case tc.wantDep && errors.Is(err, ErrFeedAlreadyExists):
				t.Fatalf("read-back failure must NEVER be already-exists, got %v", err)
			case tc.wantCanc && !errors.Is(err, context.DeadlineExceeded):
				t.Fatalf("stalled read-back must surface the deadline sentinel, got %v", err)
			}
			mu.Lock()
			gotReads := readBack
			mu.Unlock()
			if tc.wantReads > 0 && gotReads != tc.wantReads {
				t.Fatalf("read-back request count = %d, want %d", gotReads, tc.wantReads)
			}
		})
	}
}

// bytesN returns a byte slice of length n (n copies of 'x').
func bytesN(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = 'x'
	}
	return out
}

// TestBeeSequenceFeedUpdaterCreateOnlyStalledReadBackKeepsDeadline proves a
// stalled effective-feed read-back cannot block past the caller's overall
// deadline: the retry loop and per-request timeouts inherit the caller
// context, and the returned error preserves the context deadline sentinel
// data-free (never success, never already-exists — the signer keeps its
// durable lease on exactly this outcome).
func TestBeeSequenceFeedUpdaterCreateOnlyStalledReadBackKeepsDeadline(t *testing.T) {
	t.Parallel()

	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	owner := strings.ToLower(ethcrypto.PubkeyToAddress(privateKey.PublicKey).Hex()[2:])
	topic := strings.Repeat("ab", 32)
	feedPath := "/feeds/" + owner + "/" + topic
	release := make(chan struct{})

	var mu sync.Mutex
	lookups := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == feedPath:
			mu.Lock()
			lookups++
			isReadBack := lookups > 1
			mu.Unlock()
			if !isReadBack {
				http.NotFound(w, r)
				return
			}
			// Stalled read-back: never answer until the test fully exits.
			<-release
			w.Header().Set("Swarm-Feed-Index", "0000000000000000")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(refBytes64('a'))
		case r.Method == http.MethodPost && r.URL.Path == "/chunks":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"reference":"` + hex64('c') + `"}`))
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/soc/"+owner+"/"):
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))
	// LIFO: `close(release)` is registered LAST so it runs FIRST — unblocking
	// the stalled read-back handler before server.Close waits for it.
	defer server.Close()
	defer close(release)

	updater, err := NewBeeSequenceFeedUpdater(server.URL, server.Client(), hex.EncodeToString(ethcrypto.FromECDSA(privateKey)))
	if err != nil {
		t.Fatalf("create updater: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err = updater.Update(ctx, FeedUpdate{
		Feed:       "feed://" + owner + "/" + topic,
		Reference:  hex64('a'),
		BatchID:    hex64('b'),
		CreateOnly: true,
	})
	if err == nil {
		t.Fatal("a stalled read-back must fail the create-only update, got success")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("must preserve the deadline sentinel, got %v", err)
	}
	if errors.Is(err, ErrFeedAlreadyExists) {
		t.Fatalf("an unverifiable write must never be already-exists: %v", err)
	}
	requireDataFree(t, err, "stalled read-back", owner, hex64('b'), hex64('a'), "sig=", "soc")
}

// TestBeeSequenceFeedUpdaterNonCreateSkipsReadBack proves ordinary (non
// create-only) updates keep the pre-Round-2 write flow: the sequence lookup
// and SOC 201 complete the update and NO post-write read-back is issued
// (read-after-write stays Task 14 scope for non-create updates).
func TestBeeSequenceFeedUpdaterNonCreateSkipsReadBack(t *testing.T) {
	t.Parallel()

	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	owner := strings.ToLower(ethcrypto.PubkeyToAddress(privateKey.PublicKey).Hex()[2:])
	topic := strings.Repeat("ab", 32)
	feedPath := "/feeds/" + owner + "/" + topic

	var mu sync.Mutex
	feedGets := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == feedPath:
			mu.Lock()
			feedGets++
			mu.Unlock()
			w.Header().Set("Swarm-Feed-Index-Next", "0000000000000001")
			w.Header().Set("Swarm-Feed-Index", "0000000000000000")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(refBytes64('b'))
		case r.Method == http.MethodPost && r.URL.Path == "/chunks":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"reference":"` + hex64('c') + `"}`))
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/soc/"+owner+"/"):
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	updater, err := NewBeeSequenceFeedUpdater(server.URL, server.Client(), hex.EncodeToString(ethcrypto.FromECDSA(privateKey)))
	if err != nil {
		t.Fatalf("create updater: %v", err)
	}
	if err := updater.Update(context.Background(), FeedUpdate{
		Feed:      "feed://" + owner + "/" + topic,
		Reference: hex64('a'),
		BatchID:   hex64('b'),
	}); err != nil {
		t.Fatalf("non-create update must succeed on 201 without a read-back: %v", err)
	}
	mu.Lock()
	gets := feedGets
	mu.Unlock()
	if gets != 1 {
		t.Fatalf("non-create update must issue exactly ONE feed GET (the lookup), got %d — no post-write read-back", gets)
	}
}

// TestBeeSequenceFeedUpdaterCreateOnly400ProbeHardened keeps the real Bee
// 400-conflict path (socUploadHandler collapses the immutable-alias conflict
// to 400 "chunk write error") and proves the disambiguating GET /soc probe
// classifies EXACTLY per the actual Bee contract: a 200 is existence only
// with exactly one valid Swarm-Soc-Signature header (130 hex chars = 65-byte
// recoverable secp256k1 signature) AND the exact bounded JSON body
// socGetHandler serves; every malformed shape, duplicate/comma header,
// wrong-size/oversize signature, oversized body, 3xx/5xx, absent feed, and
// transport/read failure is a DEPENDENCY error (never ErrFeedAlreadyExists),
// so an attacker's intermediary 200 can never be mistaken for the immutable
// SOC and can never leak body/signature/URL. The direct 409 mapping is also
// pinned.
func TestBeeSequenceFeedUpdaterCreateOnly400ProbeHardened(t *testing.T) {
	t.Parallel()

	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	owner := strings.ToLower(ethcrypto.PubkeyToAddress(privateKey.PublicKey).Hex()[2:])
	topic := strings.Repeat("ab", 32)

	validBody := socProbeBody(hex64('f'))
	for _, tc := range []struct {
		name        string
		socStatus   int // POST /soc status (400 to force the probe, 409 direct conflict)
		probeStatus int // GET /soc status
		probeSigs   []string
		probeBody   []byte
		wantAe      bool
		wantDep     bool
	}{
		{
			name:      "400 + valid signature header + exact body is already-exists",
			socStatus: http.StatusBadRequest, probeStatus: http.StatusOK,
			probeSigs: []string{socSigHex()}, probeBody: validBody,
			wantAe: true,
		},
		{
			name:      "direct 409 maps to already-exists",
			socStatus: http.StatusConflict, probeStatus: http.StatusNotFound,
			wantAe: true,
		},
		{
			name:      "probe 200 missing signature is dependency",
			socStatus: http.StatusBadRequest, probeStatus: http.StatusOK,
			probeSigs: nil, probeBody: validBody,
			wantDep: true,
		},
		{
			name:      "probe 200 duplicate signature headers is dependency",
			socStatus: http.StatusBadRequest, probeStatus: http.StatusOK,
			probeSigs: []string{socSigHex(), socSigHex()}, probeBody: validBody,
			wantDep: true,
		},
		{
			name:      "probe 200 comma-joined signature is dependency",
			socStatus: http.StatusBadRequest, probeStatus: http.StatusOK,
			probeSigs: []string{socSigHex() + "," + socSigHex()}, probeBody: validBody,
			wantDep: true,
		},
		{
			name:      "probe 200 wrong-size signature (32-byte hex) is dependency",
			socStatus: http.StatusBadRequest, probeStatus: http.StatusOK,
			probeSigs: []string{hex64('f')}, probeBody: validBody,
			wantDep: true,
		},
		{
			name:      "probe 200 non-65-byte signature is dependency",
			socStatus: http.StatusBadRequest, probeStatus: http.StatusOK,
			probeSigs: []string{strings.Repeat("ab", 66)}, probeBody: validBody,
			wantDep: true,
		},
		{
			name:      "probe 200 oversized signature value is dependency",
			socStatus: http.StatusBadRequest, probeStatus: http.StatusOK,
			probeSigs: []string{strings.Repeat("ab", 200)}, probeBody: validBody,
			wantDep: true,
		},
		{
			name:      "probe 200 non-hex signature is dependency",
			socStatus: http.StatusBadRequest, probeStatus: http.StatusOK,
			probeSigs: []string{strings.Repeat("zz", 65)}, probeBody: validBody,
			wantDep: true,
		},
		{
			name:      "probe 200 valid signature + wrong body shape is dependency",
			socStatus: http.StatusBadRequest, probeStatus: http.StatusOK,
			probeSigs: []string{socSigHex()}, probeBody: []byte(`{}`),
			wantDep: true,
		},
		{
			name:      "probe 200 valid signature + unknown body member is dependency",
			socStatus: http.StatusBadRequest, probeStatus: http.StatusOK,
			probeSigs: []string{socSigHex()}, probeBody: []byte(`{"reference":"` + hex64('f') + `","extra":1}`),
			wantDep: true,
		},
		{
			name:      "probe 200 valid signature + oversized body is dependency",
			socStatus: http.StatusBadRequest, probeStatus: http.StatusOK,
			probeSigs: []string{socSigHex()}, probeBody: bytesN(beeFeedWriteMaxBody + 1),
			wantDep: true,
		},
		{
			name:      "probe 404 is dependency (genuine write failure)",
			socStatus: http.StatusBadRequest, probeStatus: http.StatusNotFound,
			wantDep: true,
		},
		{
			name:      "probe 500 is dependency",
			socStatus: http.StatusBadRequest, probeStatus: http.StatusInternalServerError,
			wantDep: true,
		},
		{
			name:      "probe 302 is dependency",
			socStatus: http.StatusBadRequest, probeStatus: http.StatusFound,
			wantDep: true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			feedPath := "/feeds/" + owner + "/" + topic
			var mu sync.Mutex
			probeCalls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == feedPath:
					http.NotFound(w, r)
				case r.Method == http.MethodPost && r.URL.Path == "/chunks":
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{"reference":"` + hex64('c') + `"}`))
				case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/soc/"+owner+"/"):
					w.WriteHeader(tc.socStatus)
					if tc.socStatus == http.StatusBadRequest {
						_, _ = w.Write([]byte(`{"code":427,"message":"chunk write error"}`))
					}
				case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/soc/"+owner+"/"):
					mu.Lock()
					probeCalls++
					mu.Unlock()
					for _, v := range tc.probeSigs {
						w.Header().Add("Swarm-Soc-Signature", v)
					}
					w.WriteHeader(tc.probeStatus)
					if tc.probeBody != nil {
						_, _ = w.Write(tc.probeBody)
					}
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			updater, err := NewBeeSequenceFeedUpdater(server.URL, server.Client(), hex.EncodeToString(ethcrypto.FromECDSA(privateKey)))
			if err != nil {
				t.Fatalf("create updater: %v", err)
			}
			err = updater.Update(context.Background(), FeedUpdate{
				Feed:       "feed://" + owner + "/" + topic,
				Reference:  hex64('a'),
				BatchID:    hex64('b'),
				CreateOnly: true,
			})
			switch {
			case tc.wantAe && !errors.Is(err, ErrFeedAlreadyExists):
				t.Fatalf("expected ErrFeedAlreadyExists, got %v", err)
			case tc.wantDep && err == nil:
				t.Fatal("expected a dependency error, got nil")
			case tc.wantDep && errors.Is(err, ErrFeedAlreadyExists):
				t.Fatalf("malformed/absent probe must NEVER classify as already-exists, got %v", err)
			}
			requireDataFree(t, err, "hardened probe", owner, hex64('b'), hex64('a'), socSigHex(), "sig=", "/soc/")
			if tc.probeStatus != 0 && tc.socStatus == http.StatusBadRequest {
				mu.Lock()
				calls := probeCalls
				mu.Unlock()
				if calls != 1 {
					t.Fatalf("the 400 disambiguation must issue exactly ONE probe, got %d", calls)
				}
			}
		})
	}
}

// TestBeeSequenceFeedUpdaterProbeTransportAndReadFailuresAreDependency proves
// the probe's transport and body-read failures — including a malicious
// transport that smuggles marker text and sentinel-wrapping errors — fail the
// probe as dependency errors with data-free text and NEVER classify the SOC
// as existing (never ErrFeedAlreadyExists).
func TestBeeSequenceFeedUpdaterProbeTransportAndReadFailuresAreDependency(t *testing.T) {
	t.Parallel()

	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	owner := strings.ToLower(ethcrypto.PubkeyToAddress(privateKey.PublicKey).Hex()[2:])
	topic := strings.Repeat("ab", 32)
	feedPath := "/feeds/" + owner + "/" + topic

	for _, tc := range []struct {
		name string
		rt   http.RoundTripper
	}{
		{
			name: "transport failure with injected text and forged sentinel",
			rt: socProbeFailTransport{
				base: &http.Transport{Proxy: http.ProxyFromEnvironment},
				err:  fmt.Errorf("%s: %w", dataFreeText, context.Canceled),
			},
		},
		{
			name: "probe body read failure with injected text",
			rt: socProbeReadFailTransport{
				base: &http.Transport{Proxy: http.ProxyFromEnvironment},
				err:  errors.New(dataFreeText),
			},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == feedPath:
					http.NotFound(w, r)
				case r.Method == http.MethodPost && r.URL.Path == "/chunks":
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{"reference":"` + hex64('c') + `"}`))
				case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/soc/"+owner+"/"):
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"code":427,"message":"chunk write error"}`))
				case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/soc/"):
					// The fake probe transport intercepts this; never reached.
					http.NotFound(w, r)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			updater, err := NewBeeSequenceFeedUpdater(server.URL, &http.Client{Transport: tc.rt}, hex.EncodeToString(ethcrypto.FromECDSA(privateKey)))
			if err != nil {
				t.Fatalf("create updater: %v", err)
			}
			err = updater.Update(context.Background(), FeedUpdate{
				Feed:       "feed://" + owner + "/" + topic,
				Reference:  hex64('a'),
				BatchID:    hex64('b'),
				CreateOnly: true,
			})
			if err == nil {
				t.Fatal("a failed probe must fail the create-only update, got success")
			}
			if errors.Is(err, ErrFeedAlreadyExists) {
				t.Fatalf("a probe transport/read failure must NEVER classify as already-exists, got %v", err)
			}
			requireDataFree(t, err, "probe failure", owner, hex64('b'), hex64('a'), dataFreeText, socSigHex(), "sig=", "/soc/")
		})
	}
}

// socProbeFailTransport fails ONLY the GET /soc probe with the wrapped error
// (smuggling injected text into the transport error) and forwards everything
// else to the base transport, so the probe failure is exercised in the middle
// of an otherwise-successful create-only write flow.
type socProbeFailTransport struct {
	base *http.Transport
	err  error
}

func (t socProbeFailTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/soc/") {
		return nil, t.err
	}
	return t.base.RoundTrip(r)
}

// socProbeReadFailTransport answers the GET /soc probe with a 200 whose body
// read fails with the wrapped error (injected text) while forwarding every
// other request to the base transport.
type socProbeReadFailTransport struct {
	base *http.Transport
	err  error
}

func (t socProbeReadFailTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/soc/") {
		h := make(http.Header)
		h.Set("Swarm-Soc-Signature", socSigHex())
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     h,
			Body:       markerReadCloser{err: t.err},
			Request:    r,
		}, nil
	}
	return t.base.RoundTrip(r)
}

// chunkContentRef derives a deterministic 64-hex content address for a chunk
// body so the fake Bee's /chunks responses are plausible Swarm references.
func chunkContentRef(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
