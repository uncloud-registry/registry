package registry

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/uncloud-registry/registry/internal/resolve"
)

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

		// Strict RFC 9110 qvalue grammar: NaN, partial/non-digit forms, signs,
		// exponents, and excess fractional precision are ALL rejected (each
		// skips its item rather than poisoning a matching sibling).
		{"q=NaN skipped only match refused", stored + ";q=NaN", false},
		{"q=.5 skipped only match refused", stored + ";q=.5", false},
		{"q=+0.5 skipped only match refused", stored + ";q=+0.5", false},
		{"q=+1 skipped only match refused", stored + ";q=+1", false},
		{"q=1e0 skipped only match refused", stored + ";q=1e0", false},
		{"q=2.0 skipped only match refused", stored + ";q=2.0", false},
		{"q=1.0000 excess precision skipped with positive wildcard", stored + ";q=1.0000, */*;q=1", true},
		{"q=1.0000 excess precision only match refused", stored + ";q=1.0000", false},
		{"q=0.1234 excess precision skipped only match refused", stored + ";q=0.1234", false},
		{"q=1. trailing dot valid", stored + ";q=1.", true},
		{"q=1.000 exact three zeros valid", stored + ";q=1.000", true},
		{"q=0.5 valid", stored + ";q=0.5", true},
		{"q= 0.001 valid", stored + "; q=0.001", true},
		{"q=0.999 valid", stored + ";q=0.999", true},

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

// TestParseQvalue pins the exact RFC 9110 §14.8.1 qvalue grammar. The parser
// must reject NaN, ".5", "+0.5", "-1", "2", exponents, a fourth fractional
// digit, surplus precision, empty/malformed tokens, and any trailing garbage —
// and accept "0", "1", and their bounded fractional forms.
func TestParseQvalue(t *testing.T) {
	valid := map[string]float64{
		"0":     0,
		"1":     1,
		"0.":    0,
		"1.":    1,
		"0.0":   0,
		"0.5":   0.5,
		"1.0":   1,
		"1.00":  1,
		"1.000": 1,
		"0.001": 0.001,
		"0.999": 0.999,
		" 0.5 ": 0.5,
	}
	for raw, want := range valid {
		if got, ok := parseQvalue(raw); !ok || got != want {
			t.Fatalf("parseQvalue(%q) = %v, %v; want %v, true", raw, got, ok, want)
		}
	}
	invalid := []string{
		"", " ", ".", ".5", "5", "2", "01", "1.1", "1.01", "2.0", "0.1234",
		"1.0000", "NaN", "nan", "+0.5", "-0.5", "+1", "-1", "1e0", "1e-1",
		"0x5", "0..5", "0.5.0", "0.5e1", "1.e0", "1,0", "0 5", "1.00000",
	}
	for _, raw := range invalid {
		if _, ok := parseQvalue(raw); ok {
			t.Fatalf("parseQvalue(%q) must be rejected", raw)
		}
	}
}

// TestAcceptAcceptsValues combines ALL Accept field lines in order before the
// comma-list is parsed, so most-specific-range precedence holds across lines.
func TestAcceptAcceptsValues(t *testing.T) {
	const stored = "application/vnd.oci.image.manifest.v1+json"
	cases := []struct {
		name   string
		values []string
		want   bool
	}{
		{"no Accept lines", nil, true},
		{"two complementary exact lines", []string{"text/plain", stored}, true},
		{"exact q=0 on second line beats global q=1 on first", []string{"*/*;q=1", stored + ";q=0"}, false},
		{"exact q=1 on first line beats global q=0 on second", []string{stored + ";q=1", "*/*;q=0"}, true},
		{"wildcard split across two lines", []string{"application/*;q=0", "*/*;q=1"}, false},
		{"exact positive second line beats first-line global q=0", []string{"*/*;q=0", stored + ";q=1"}, true},
		{"malformed q on one line skipped, wildcard on other serves", []string{stored + ";q=NaN", "*/*;q=1"}, true},
		{"blank line plus exact", []string{"   ", stored}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := acceptAcceptsValues(tc.values, stored); got != tc.want {
				t.Fatalf("acceptAcceptsValues(%v) = %v, want %v", tc.values, got, tc.want)
			}
		})
	}
}

// TestHandlerManifestAcceptOnWire proves the REAL HTTP path combines every
// Accept header field line (via Header.Values) and applies the strict qvalue
// grammar, unlike the previous single-line Header.Get + unrestricted
// ParseFloat implementation.
func TestHandlerManifestAcceptOnWire(t *testing.T) {
	t.Parallel()
	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()
	seedRegistryDocuments(t, docs, feeds)
	handler, _ := newTestHandler(t, docs, feeds)
	server := httptest.NewServer(handler)
	defer server.Close()

	// Acceptable: an explicit exact manifest match on the SECOND field line
	// while the first line is an unrelated type — both must be combined.
	if status := manifestGetStatus(t, server.URL, "text/plain", "application/vnd.oci.image.manifest.v1+json"); status != http.StatusOK {
		t.Fatalf("multi-line combined match must serve, got %d", status)
	}
	// Precise-over-global precedence ACROSS lines: exact q=0 on line 2 beats
	// a positive global wildcard on line 1.
	if status := manifestGetStatus(t, server.URL, "*/*;q=1", "application/vnd.oci.image.manifest.v1+json;q=0"); status != http.StatusNotFound {
		t.Fatalf("exact q=0 on a later line must refuse, got %d", status)
	}
	// Malformed excess-precision qvalue on the only matching line is refused.
	if status := manifestGetStatus(t, server.URL, "application/vnd.oci.image.manifest.v1+json;q=1.0000"); status != http.StatusNotFound {
		t.Fatalf("excess-precision qvalue must refuse the only match, got %d", status)
	}
	// Malformed qvalue is skipped rather than poisoning a positive wildcard.
	if status := manifestGetStatus(t, server.URL, "application/vnd.oci.image.manifest.v1+json;q=NaN", "*/*;q=1"); status != http.StatusOK {
		t.Fatalf("malformed qvalue must skip while wildcard serves, got %d", status)
	}
	// A single unrelated Accept refuses the representation.
	if status := manifestGetStatus(t, server.URL, "text/plain"); status != http.StatusNotFound {
		t.Fatalf("single non-matching Accept must refuse, got %d", status)
	}
}

// manifestGetStatus issues a GET for the seeded `latest` manifest with the
// given Accept header values as SEPARATE header field lines and returns the
// status code.
func manifestGetStatus(t *testing.T, baseURL string, acceptLines ...string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, baseURL+"/v2/backend/api/manifests/latest", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Host = testServiceHost
	for _, line := range acceptLines {
		req.Header.Add("Accept", line)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()
	return resp.StatusCode
}
