package spec_test

import (
	"strings"
	"testing"

	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/spec"
)

// TestProvenanceOperationIDMirrorMatchesPublishGrammar is the byte-parity
// proof that spec.IsValidPublicationOperationID (the decode-time provenance
// validator, which cannot import publish without a cycle) and
// publish.ValidateOperationID (the single application authority) accept
// EXACTLY the same values — a persisted provenance operation ID can never be
// a value the data-plane grammar would reject, and vice versa.
func TestProvenanceOperationIDMirrorMatchesPublishGrammar(t *testing.T) {
	t.Parallel()
	// Every single byte as an operation-ID candidate.
	for b := 0; b <= 255; b++ {
		s := string([]byte{byte(b)})
		want := publish.ValidateOperationID(s) == nil
		if got := spec.IsValidPublicationOperationID(s); got != want {
			t.Fatalf("byte %#x: mirror=%v publish=%v must agree", b, got, want)
		}
	}
	// Boundary lengths and multi-byte strings.
	for _, s := range []string{
		"",
		"a",
		strings.Repeat("k", 127),
		strings.Repeat("k", 128),
		strings.Repeat("k", 129),
		`a"b`, `a\b`, "a<b", "a>b", "a&b",
		"é", "日本語", "op-\u2028x", "op-\u2029x",
		"a b", "a\tb", "a~b", "a\x7fb",
		"op-t14-key-0001", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	} {
		want := publish.ValidateOperationID(s) == nil
		if got := spec.IsValidPublicationOperationID(s); got != want {
			t.Fatalf("%q: mirror=%v publish=%v must agree", s, got, want)
		}
	}
}
