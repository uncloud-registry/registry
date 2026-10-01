package swarm

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// feedTestServer is a minimal fake Bee /feeds surface: it returns the raw
// binary payload (the decoded 32-byte reference) on 200 with the REQUIRED
// Swarm-Feed-Index / Swarm-Feed-Index-Next headers, exactly as the production
// Bee API does (GET /feeds/{owner}/{topic} serves application/octet-stream —
// the chunk payload with the span stripped — plus the hex index headers).
func feedTestServer(t *testing.T, body []byte, setIndex bool, index string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if setIndex {
			w.Header().Set("Swarm-Feed-Index", index)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
}

// TestReadFeedSuccessBinaryPayload is the production ReadFeed contract: the
// /feeds body is the RAW 32 binary bytes of the decoded reference (Bee serves
// the chunk payload directly, no span, no ASCII hex) and the index header is
// the current feed index. Both come back normalized: lowercase 64-hex
// reference and the exact index value.
func TestReadFeedSuccessBinaryPayload(t *testing.T) {
	t.Parallel()
	// Mixed-case hex reference decoded to binary; read-back must normalize to
	// lowercase.
	const ref = "AaBbCcDdEeFf00112233445566778899aabbccddeeff00112233445566778899"
	body, err := hex.DecodeString(ref)
	if err != nil {
		t.Fatalf("decode ref: %v", err)
	}
	server := feedTestServer(t, body, true, "0000000000000002")
	defer server.Close()

	resolver := NewBeeFeedResolver(server.URL, server.Client())
	got, err := resolver.ReadFeed(context.Background(), feedRef("owner"))
	if err != nil {
		t.Fatalf("read feed: %v", err)
	}
	if got.Reference != strings.ToLower(ref) {
		t.Fatalf("reference must be normalized lowercase 64-hex, got %q", got.Reference)
	}
	if got.Index != "0000000000000002" {
		t.Fatalf("index must be the found-update index, got %q", got.Index)
	}
}

// TestReadFeedRequiresIndexHeader proves the Swarm-Feed-Index header is
// REQUIRED on a 200 feed response: a 200 without it is a malformed response
// and fails closed (the header is the only way the reader knows WHICH index
// the returned payload was found at).
func TestReadFeedRequiresIndexHeader(t *testing.T) {
	t.Parallel()
	server := feedTestServer(t, refBytes64('a'), false, "")
	defer server.Close()
	resolver := NewBeeFeedResolver(server.URL, server.Client())
	if _, err := resolver.ReadFeed(context.Background(), feedRef("owner")); err == nil {
		t.Fatal("expected a 200 feed response without Swarm-Feed-Index to fail")
	}
}

// TestReadFeedAny32BinaryBytesDecode proves the reader is STRUCTURAL over the
// binary payload: any 32 bytes are a valid decoded reference (the reference is
// content-addressed, so the reader's job is the exact 32-byte frame and hex
// normalization, not judging which bytes are plausible). This pins the
// difference from the old ASCII contract: arbitrary 32 bytes are accepted and
// hex-encoded to the normalized form.
func TestReadFeedAny32BinaryBytesDecode(t *testing.T) {
	t.Parallel()
	body := []byte{0x00, 0x01, 0x02, 0xfe, 0xff}
	body = append(body, make([]byte, 27)...) // 32 bytes total, arbitrary values
	want := hex.EncodeToString(body)
	server := feedTestServer(t, body, true, "0000000000000007")
	defer server.Close()
	resolver := NewBeeFeedResolver(server.URL, server.Client())
	got, err := resolver.ReadFeed(context.Background(), feedRef("owner"))
	if err != nil {
		t.Fatalf("read feed: %v", err)
	}
	if got.Reference != want {
		t.Fatalf("expected hex-normalized reference %q, got %q", want, got.Reference)
	}
	if got.Index != "0000000000000007" {
		t.Fatalf("unexpected index %q", got.Index)
	}
}

// TestReadFeedIndexHeaderValidation proves the required index header is
// strictly validated: malformed hex, wrong-size (not 8 bytes), oversized, and
// duplicate index headers all fail closed.
func TestReadFeedIndexHeaderValidation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		index string
		dup   bool
	}{
		{"malformed hex", "nothex", false},
		{"wrong size", "00112233445566", false}, // 7 bytes
		{"wrong size long", "001122334455667788", false},
		{"oversized", strings.Repeat("ab", 200), false},
		{"duplicate", "0000000000000001", true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Add("Swarm-Feed-Index", tc.index)
				if tc.dup {
					w.Header().Add("Swarm-Feed-Index", "0000000000000002")
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(refBytes64('a'))
			}))
			defer server.Close()
			resolver := NewBeeFeedResolver(server.URL, server.Client())
			if _, err := resolver.ReadFeed(context.Background(), feedRef("owner")); err == nil {
				t.Fatalf("expected %s index header to fail closed", tc.name)
			}
		})
	}
}

// TestReadFeedBodyValidation proves the reader accepts EXACTLY the 32-byte
// binary payload and rejects every other body — empty, wrong size, garbage,
// or the OLD pre-Task-11 ASCII-hex 64-byte representation — with bounded
// reads (an oversized body beyond the bound is also rejected, not silently
// truncated).
func TestReadFeedBodyValidation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body []byte
	}{
		{"empty", []byte{}},
		{"whitespace", []byte("   ")},
		{"31 bytes", refBytes64('a')[:31]},
		{"33 bytes", append(append([]byte(nil), refBytes64('a')...), 0x00)},
		{"old ascii hex representation", []byte(hex64('a'))},
		{"ascii hex plus extra", []byte(hex64('a') + "extra")},
		{"oversized past bound", append(append([]byte(nil), refBytes64('a')...), make([]byte, beeFeedResolveMaxBody)...)},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			server := feedTestServer(t, tc.body, true, "0000000000000000")
			defer server.Close()
			resolver := NewBeeFeedResolver(server.URL, server.Client())
			if _, err := resolver.ReadFeed(context.Background(), feedRef("owner")); err == nil {
				t.Fatalf("expected body %q to be rejected", tc.body)
			}
		})
	}
}

// TestReadFeedNon200ErrorIsDataFree proves a non-200 feed response returns a
// data-free status error and never echoes the raw response body.
func TestReadFeedNon200ErrorIsDataFree(t *testing.T) {
	t.Parallel()
	secret := "internal-secret-" + strings.Repeat("x", 500)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(secret))
	}))
	defer server.Close()
	resolver := NewBeeFeedResolver(server.URL, server.Client())
	_, err := resolver.ReadFeed(context.Background(), feedRef("owner"))
	if err == nil {
		t.Fatal("expected a non-200 to be an error")
	}
	if strings.Contains(err.Error(), "internal-secret") || strings.Contains(err.Error(), strings.Repeat("x", 8)) {
		t.Fatalf("error must not leak the raw Bee body: %v", err)
	}
}

// TestReadFeedStalledRespectsDeadline proves a stalled /feeds response cannot
// block indefinitely: the per-request context deadline aborts it.
func TestReadFeedStalledRespectsDeadline(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		w.Header().Set("Swarm-Feed-Index", "0000000000000000")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(refBytes64('a'))
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })

	resolver := NewBeeFeedResolver(server.URL, server.Client())
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := resolver.ReadFeed(ctx, feedRef("owner"))
	if err == nil {
		<-started
		t.Fatal("expected a stalled request to time out")
	}
	<-started
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("stalled request must abort near the deadline, took %v", elapsed)
	}
}

// TestReadFeedCanceledContext proves a cancelled context aborts the request.
func TestReadFeedCanceledContext(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	defer close(release)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.Header().Set("Swarm-Feed-Index", "0000000000000000")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(refBytes64('a'))
	}))
	defer server.Close()

	resolver := NewBeeFeedResolver(server.URL, server.Client())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolver.ReadFeed(ctx, feedRef("owner")); err == nil {
		t.Fatal("expected a cancelled context to abort the request")
	}
}

// TestReadFeedClosesBody proves ReadFeed always closes the response body on
// both success and error paths.
func TestReadFeedClosesBody(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		code int
		body []byte
	}{
		{"success", http.StatusOK, refBytes64('a')},
		{"non-200", http.StatusBadRequest, []byte("boom")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			closed := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.code == http.StatusOK {
					w.Header().Set("Swarm-Feed-Index", "0000000000000000")
				}
				w.WriteHeader(tc.code)
				_, _ = w.Write(tc.body)
			}))
			defer server.Close()
			rt := &bodyTrackingTransport{base: &http.Transport{Proxy: http.ProxyFromEnvironment}, closed: closed}
			client := &http.Client{Transport: rt}
			resolver := NewBeeFeedResolver(server.URL, client)
			_, _ = resolver.ReadFeed(context.Background(), feedRef("owner"))
			select {
			case <-closed:
			case <-time.After(2 * time.Second):
				t.Fatal("ReadFeed must close the response body")
			}
		})
	}
}

// TestReadFeedZeroValueFailsClosed proves a zero-value resolver (no base URL)
// fails with an error and never panics.
func TestReadFeedZeroValueFailsClosed(t *testing.T) {
	t.Parallel()
	resolver := BeeFeedResolver{}
	if _, err := resolver.ReadFeed(context.Background(), feedRef("owner")); err == nil {
		t.Fatal("expected a zero-value resolver (no base URL) to fail, got nil")
	}
}

// TestReadFeedUnreadableBodyRejects proves a body read error is a fail-closed
// backend error (never a fabricated success).
func TestReadFeedUnreadableBodyRejects(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Swarm-Feed-Index", "0000000000000000")
		w.WriteHeader(http.StatusOK)
		// hijack and kill the connection so the body read fails
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		_ = conn.Close()
	}))
	defer server.Close()
	resolver := NewBeeFeedResolver(server.URL, server.Client())
	_, err := resolver.ReadFeed(context.Background(), feedRef("owner"))
	if err == nil {
		t.Fatal("expected an unreadable body to fail closed")
	}
}

// TestReadFeedEmptyBaseURLRejects pins the base-URL configuration guard used
// by both ReadFeed and ResolveFeed: an unconfigured base URL is a data-free
// error, never a request to an empty origin.
func TestReadFeedEmptyBaseURLRejects(t *testing.T) {
	t.Parallel()
	r := NewBeeFeedResolver("", nil)
	if _, err := r.ReadFeed(context.Background(), feedRef("owner")); err == nil {
		t.Fatal("expected an unconfigured base URL to fail")
	}
}

// TestReadFeedMalformedFeedRefRejects proves a malformed feed reference fails
// before any request is issued.
func TestReadFeedMalformedFeedRefRejects(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("no request should be issued for a malformed feed ref")
	}))
	defer server.Close()
	resolver := NewBeeFeedResolver(server.URL, server.Client())
	for _, feed := range []string{"", "feed://", "feed://owner", "not-a-feed"} {
		if _, err := resolver.ReadFeed(context.Background(), feed); err == nil {
			t.Fatalf("expected malformed feed %q to be rejected", feed)
		}
	}
}
