package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/uncloud-registry/registry/internal/swarm"
)

// countingBody is an io.ReadCloser that counts how many bytes are actually
// pulled from the simulated transport response body.
type countingBody struct {
	src  io.Reader
	read int
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.src.Read(p)
	c.read += n
	return n, err
}

func (c *countingBody) Close() error { return nil }

// countingTransport serves an OVERSIZED object (larger than any allowed
// artifact bound) as the GET /bytes/<ref> response, wrapping the body in a
// counter so the test can observe exactly how many bytes the client pulled.
type countingTransport struct {
	payload []byte
	body    *countingBody
	round   int
}

func (t *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.round++
	if !strings.HasPrefix(req.URL.Path, "/bytes/") {
		return nil, errors.New("unexpected path " + req.URL.Path)
	}
	t.body = &countingBody{src: bytes.NewReader(t.payload)}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/octet-stream"}},
		Body:       t.body,
		Request:    req,
	}, nil
}

// TestBeeObjectStoreReadBoundedTransportReadsAtMostLimitPlusOne proves the
// PRODUCTION bounded artifact-byte reader (BeeObjectStore.ReadBounded) streams
// an oversized /bytes object reading AT MOST limit+1 bytes from the transport
// and FAILS CLOSED instead of buffering the whole oversized payload. This is
// the wiring the post-commit publication verification relies on for index /
// manifest bodies.
func TestBeeObjectStoreReadBoundedTransportReadsAtMostLimitPlusOne(t *testing.T) {
	const limit = int64(64)
	payload := []byte(strings.Repeat("z", 4096)) // far larger than the bound
	tr := &countingTransport{payload: payload}
	store := &swarm.BeeObjectStore{BaseURL: "http://unused.invalid", HTTPClient: &http.Client{Transport: tr}}

	_, err := store.ReadBounded(context.Background(), strings.Repeat("1", 64), limit)
	if err == nil {
		t.Fatal("an oversized /bytes object must fail closed")
	}
	// The client read exactly limit+1 bytes (the overflow detector), never the
	// full oversized payload.
	if tr.body == nil {
		t.Fatal("transport body was not observed")
	}
	if tr.body.read != int(limit)+1 {
		t.Fatalf("transport pulled %d bytes, want exactly limit+1 = %d", tr.body.read, limit+1)
	}
	if len(payload) <= int(limit)+1 {
		t.Fatalf("fixture payload must be larger than limit+1")
	}
	_ = io.Discard
}
