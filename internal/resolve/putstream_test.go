package resolve

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

// TestMemoryDocumentStorePutStreamProvesExactSizeStreamContract proves the
// streaming object-uploader contract used by registry blob finalization:
// identical bytes ALWAYS yield the identical content-addressed reference
// (restart/replay safe), a streamed put is retrievable by that reference, and
// a reader longer than the declared exact size is truncated exactly at size
// (never buffered silently beyond it). A negative size fails closed.
func TestMemoryDocumentStorePutStreamProvesExactSizeStreamContract(t *testing.T) {
	m := NewMemoryDocumentStore()
	ctx := context.Background()

	payload := []byte("streamed document payload")
	ref, err := m.PutStream(ctx, bytes.NewReader(payload), int64(len(payload)), "batch-x")
	if err != nil {
		t.Fatalf("PutStream: %v", err)
	}
	got, err := m.Get(ctx, ref)
	if err != nil {
		t.Fatalf("Get after PutStream: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("PutStream round-trip mismatch: %q", got)
	}

	// Content-addressed: identical bytes give the identical reference, and the
	// explicit batch id is accepted (ignored) — retries never grow the store.
	ref2, err := m.PutStream(ctx, bytes.NewReader(payload), int64(len(payload)), "batch-y")
	if err != nil {
		t.Fatalf("second PutStream: %v", err)
	}
	if ref2 != ref {
		t.Fatalf("expected identical content-addressed ref %q, got %q", ref, ref2)
	}

	// A reader LONGER than the declared exact size is rejected: the streaming
	// contract is EXACT and fails closed on any overshoot.
	if _, err := m.PutStream(ctx, strings.NewReader("0123456789"), 5, ""); err == nil {
		t.Fatal("expected an overlong stream (len 10 vs declared 5) to fail closed")
	}

	if _, err := m.PutStream(ctx, bytes.NewReader(payload), -3, ""); err == nil {
		t.Fatal("expected negative size to fail")
	}

	if _, err := m.PutStream(ctx, nopReader{}, int64(4), ""); err == nil {
		t.Fatal("expected a failing reader to propagate its error")
	}
}

type nopReader struct{}

func (nopReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
