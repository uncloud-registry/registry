package registry

import "testing"

// TestAcceptAccepts is the unit-level matrix for the Distribution Accept
// negotiation. It exercises the most-specific-range precedence rule and the
// valid-q parsing contract directly on acceptAccepts, independently of the
// HTTP layer.
func TestAcceptAccepts(t *testing.T) {
	// stored is the exact representation we would serve for a request.
	const stored = "application/vnd.oci.image.index.v1+json"

	cases := []struct {
		name   string
		accept string
		want   bool
	}{
		{"absent accepts anything", "", true},
		{"blank accepts anything", "   ", true},
		{"exact match", stored, true},
		{"exact non-match rejected", "application/vnd.oci.image.manifest.v1+json", false},
		{"type wildcard matches", "application/*", true},
		{"other type wildcard rejected", "text/*", false},
		{"global wildcard matches", "*/*", true},

		// q=0 semantics
		{"exact q=0 refused", stored + ";q=0", false},
		{"exact q=0.0 refused", stored + "; q=0.0", false},
		{"global q=0 alone refused", "*/*;q=0", false},

		// Most-specific precedence: exact q=0 must override a positive
		// wildcard (and vice versa an exact positive must override a wildcard
		// q=0), independent of order.
		{"exact q=0 overrides global positive", stored + ";q=0, */*;q=1", false},
		{"global positive then exact q=0 (order independence)", "*/*;q=1, " + stored + ";q=0", false},
		{"type-wildcard q=0 overrides global positive", "application/*;q=0, */*;q=1", false},
		{"global positive then type-wildcard q=0", "*/*;q=1, application/*;q=0", false},
		{"exact positive overrides global q=0", "*/*;q=0, " + stored + ";q=1", true},
		{"global q=0 then exact positive (order independence)", stored + ";q=1, */*;q=0", true},
		{"exact q=0 overrides type-wildcard positive", stored + ";q=0, application/*;q=1", false},
		{"type-wildcard positive loses to exact q=1 and gains nothing", "text/*;q=1, application/*;q=1, " + stored + ";q=1", true},

		// Duplicates at the same specificity: a q=0 excludes even if another
		// duplicate carries q=1.
		{"duplicate exact one q=0 refused", stored + ";q=0, " + stored + ";q=1", false},
		{"duplicate exact both positive accepted", stored + ";q=1, " + stored + ";q=0.5", true},

		// Parameters other than q are ignored for matching.
		{"exact with extra param accepted", stored + ";profile=v1;q=1", true},
		{"exact with params and q=0 refused", stored + ";profile=v1;q=0", false},

		// Malformed / out-of-range q values skip the item (do not poison).
		{"malformed q skipped with other match", stored + ";q=abc, */*;q=1", true},
		{"malformed q only match refused", stored + ";q=abc", false},
		{"out-of-range q=2 skipped only match refused", stored + ";q=2", false},
		{"out-of-range q=-1 skipped", "*/*;q=-1", false},

		// Malformed media ranges are skipped.
		{"malformed type-only range skipped", "application", false},
		{"malformed subtype-only range skipped regardless", "*;q=1", false},
		{"concrete subtype under wildcard type skipped", "application/vnd.oci.image.index.v1+json, */vnd.oci.image.index.v1+json", true},

		// Non-matching concrete quieted by matching wildcard.
		{"non-matching concrete plus matching wildcard", "text/plain, application/*", true},
		{"non-matching concrete and global q=0", "text/plain, */*;q=0", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := acceptAccepts(tc.accept, stored); got != tc.want {
				t.Fatalf("acceptAccepts(%q) = %v, want %v", tc.accept, got, tc.want)
			}
		})
	}
}
