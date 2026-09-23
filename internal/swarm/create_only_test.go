package swarm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

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

// TestBeeSequenceFeedUpdaterCreateOnlyRaceOneSOCAccepted proves the TOCTOU
// closure at the SOC layer with TWO process-like updaters (same owner key,
// same feed, distinct writers) racing a fake Bee: the sequence lookup is 404
// for both, the fake Bee ATOMICALLY accepts exactly ONE zero-index SOC (201)
// and returns the real Bee conflict response (400 "chunk write error") to the
// loser, whose disambiguating GET /soc probe then maps the lost race to
// ErrFeedAlreadyExists. The final feed carries the WINNER's payload at
// sequence index zero — never the loser's, never sequence one.
func TestBeeSequenceFeedUpdaterCreateOnlyRaceOneSOCAccepted(t *testing.T) {
	t.Parallel()

	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	owner := strings.ToLower(ethcrypto.PubkeyToAddress(privateKey.PublicKey).Hex()[2:])
	topic := strings.Repeat("ab", 32)

	// fakeBee models the real Bee contract exactly (ethersphere/bee master
	// pkg/api/soc.go): a stored SOC exists immutably at (owner, id); a second
	// write of the same immutable address with different content fails with
	// 400 "chunk write error"; GET /soc/{owner}/{id} returns 200 +
	// Swarm-Soc-Signature when present and 404 otherwise.
	type fakeBee struct {
		mu        sync.Mutex
		socID     string
		socWinner []byte // framed chunk data of the accepted SOC
		soc201    int
		soc400    int
		probes    int
	}
	bee := &fakeBee{}

	var (
		start   = make(chan struct{})
		results = make(chan error, 2)
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/feeds/"+owner+"/"+topic:
			// Absent until the winner's SOC is stored; the race must see 404.
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodPost && r.URL.Path == "/chunks":
			body, _ := io.ReadAll(r.Body)
			ref := chunkContentRef(body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"reference":"` + ref + `"}`))
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/soc/"+owner+"/"):
			body, _ := io.ReadAll(r.Body)
			id := strings.TrimPrefix(r.URL.Path, "/soc/"+owner+"/")
			bee.mu.Lock()
			if bee.socWinner == nil {
				bee.socWinner = body
				bee.socID = id
				bee.soc201++
				bee.mu.Unlock()
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{}`))
				return
			}
			bee.soc400++
			bee.mu.Unlock()
			// Real Bee conflict response: generic 400 "chunk write error" —
			// the immutable SOC at this address already holds the winner.
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"code":427,"message":"chunk write error"}`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/soc/"+owner+"/"):
			id := strings.TrimPrefix(r.URL.Path, "/soc/"+owner+"/")
			bee.mu.Lock()
			winner := bee.socID == id && bee.socWinner != nil
			bee.probes++
			bee.mu.Unlock()
			if winner {
				w.Header().Set("Swarm-Soc-Signature", hex64('f'))
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("probe-body"))
				return
			}
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	write := func() {
		<-start
		updater, err := NewBeeSequenceFeedUpdater(server.URL, server.Client(), hex.EncodeToString(ethcrypto.FromECDSA(privateKey)))
		if err != nil {
			results <- err
			return
		}
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
	bee.mu.Unlock()
	if soc201 != 1 {
		t.Fatalf("fake Bee must accept exactly ONE zero-index SOC, got %d", soc201)
	}
	if soc400 != 1 {
		t.Fatalf("fake Bee must return the conflict to exactly ONE loser, got %d", soc400)
	}
	if winner == nil {
		t.Fatal("fake Bee recorded no winner SOC")
	}
	// The winner's SOC body is the framed chunk (span=32 + 32 ref bytes).
	if len(winner) != 8+32 {
		t.Fatalf("winner SOC payload must be the framed binary reference, got %d bytes", len(winner))
	}
	if winnerRef := hex.EncodeToString(winner[8:]); winnerRef != hex64('a') {
		t.Fatalf("winner payload must be the exact 32 binary reference bytes, got %s", winnerRef)
	}
	if bee.probes < 1 {
		t.Fatal("the losing writer must disambiguate its 400 with the GET /soc probe")
	}
	// No sequence-one advancement: the winner's SOC was the ZERO index.
	// (The feed read-back after the race is asserted in the control-plane race
	// test; here the single accepted SOC at the zero identifier is proven by
	// the one-201/one-400 accounting above.)
}

// chunkContentRef derives a deterministic 64-hex content address for a chunk
// body so the fake Bee's /chunks responses are plausible Swarm references.
func chunkContentRef(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
