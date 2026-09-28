package publish

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestParsePlatformFeatureBounds proves BOTH platform feature lists
// (os.features and features) are super-bounded at parse time: an array with
// more than maxPlatformFeatures entries, or a single entry longer than
// maxPlatformStringLen bytes, is rejected typed as an invalid platform — even
// though such a body is otherwise well-formed JSON. The bound is data-free
// (never echoes an entry value).
func TestParsePlatformFeatureBounds(t *testing.T) {
	for _, field := range []string{"os.features", "features"} {
		field := field
		t.Run(field, func(t *testing.T) {
			// Too many entries: maxPlatformFeatures + 1.
			overCount := maxPlatformFeatures + 1
			items := make([]string, 0, overCount)
			for i := 0; i < overCount; i++ {
				items = append(items, fmt.Sprintf(`"x%d"`, i))
			}
			body := indexBodyWithPlatformField(field, "["+strings.Join(items, ",")+"]")
			if err := parseIndexField(t, body); !isInvalidPlatform(err) {
				t.Fatalf("oversize %s count must be rejected as invalid_platform, got %v", field, err)
			}

			// A single entry longer than maxPlatformStringLen bytes.
			tooLong := strings.Repeat("f", maxPlatformStringLen+1)
			body = indexBodyWithPlatformField(field, fmt.Sprintf(`["%s"]`, tooLong))
			if err := parseIndexField(t, body); !isInvalidPlatform(err) {
				t.Fatalf("oversize %s entry must be rejected as invalid_platform, got %v", field, err)
			}

			// AT the bound it is still accepted (a maxPlatformStringLen entry
			// and maxPlatformFeatures entries are valid).
			maxItems := make([]string, 0, maxPlatformFeatures)
			for i := 0; i < maxPlatformFeatures; i++ {
				maxItems = append(maxItems, fmt.Sprintf(`"y%d"`, i))
			}
			maxEntryItem := fmt.Sprintf(`["%s"]`, strings.Repeat("g", maxPlatformStringLen))
			for _, body := range []string{
				indexBodyWithPlatformField(field, "["+strings.Join(maxItems, ",")+"]"),
				indexBodyWithPlatformField(field, maxEntryItem),
			} {
				if err := parseIndexField(t, body); err != nil {
					t.Fatalf("at-the-bound %s must be accepted, got %v", field, err)
				}
			}
		})
	}
}

// indexBodyWithPlatformField builds an OCI image-index body whose single child
// carries the given platform feature field set to the given JSON array text.
func indexBodyWithPlatformField(field, arrayJSON string) string {
	return fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"size":512,"digest":%q,"platform":{"architecture":"amd64","os":"linux",%q:%s}}]}`,
		ociIndexMT, ociManifestMT, dig('b'), field, arrayJSON)
}

// parseIndexField parses an index body under the OCI index media type.
func parseIndexField(t *testing.T, body string) error {
	t.Helper()
	_, err := ParseArtifact(ociIndexMT, []byte(body))
	return err
}

func isInvalidPlatform(err error) bool {
	var ve *ValidationError
	return errors.As(err, &ve) && ve.Kind == ErrKindInvalidPlatform
}
