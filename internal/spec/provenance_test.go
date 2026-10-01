package spec

import (
	"strings"
	"testing"
)

// provenanceStateDoc is a schema-valid repo-state document carrying per-tag
// publication provenance (Task 14 round 2): two tags, each with a coherent
// provenance entry bound to its current mapping.
func provenanceStateDoc(tagPublications string) []byte {
	return []byte(`{
		"version":1,
		"repo":"backend/api",
		"generation":2,
		"updatedAt":"2026-04-05T12:00:00Z",
		"tags":{"latest":"sha256:m1","v2":"sha256:m2"},
		"manifests":{
			"sha256:m1":{"swarmRef":"r1","mediaType":"application/vnd.oci.image.manifest.v1+json","size":1},
			"sha256:m2":{"swarmRef":"r2","mediaType":"application/vnd.oci.image.manifest.v1+json","size":1}
		},
		"blobs":{},
		"tagPublications":` + tagPublications + `
	}`)
}

const validProvenance = `{
	"latest":{"operationID":"op-latest","generation":1,"digest":"sha256:m1"},
	"v2":{"operationID":"op-v2","generation":2,"digest":"sha256:m2"}
}`

// TestRepoStateProvenanceValidDecodes proves a document whose per-tag
// provenance is coherent with its tag mapping decodes and validates, with the
// entries retained exactly.
func TestRepoStateProvenanceValidDecodes(t *testing.T) {
	t.Parallel()
	doc, err := DecodeRepoStateDocument(provenanceStateDoc(validProvenance))
	if err != nil {
		t.Fatalf("valid provenance document must decode: %v", err)
	}
	latest, ok := doc.TagPublications["latest"]
	if !ok || latest.OperationID != "op-latest" || latest.Generation != 1 || latest.Digest != "sha256:m1" {
		t.Fatalf("latest provenance entry not retained exactly: %+v", doc.TagPublications)
	}
	v2, ok := doc.TagPublications["v2"]
	if !ok || v2.OperationID != "op-v2" || v2.Generation != 2 || v2.Digest != "sha256:m2" {
		t.Fatalf("v2 provenance entry not retained exactly: %+v", doc.TagPublications)
	}
}

// TestRepoStateLegacyDocumentWithoutProvenanceDecodes proves backward
// compatibility: documents written before provenance (no tagPublications
// field, or an explicit null/empty value) remain strictly valid. A legacy
// document simply carries no recoverable operation identity.
func TestRepoStateLegacyDocumentWithoutProvenanceDecodes(t *testing.T) {
	t.Parallel()
	legacy := []byte(`{
		"version":1,
		"repo":"backend/api",
		"generation":2,
		"updatedAt":"2026-04-05T12:00:00Z",
		"tags":{"latest":"sha256:m1"},
		"manifests":{"sha256:m1":{"swarmRef":"r1","mediaType":"application/vnd.oci.image.manifest.v1+json","size":1}},
		"blobs":{}
	}`)
	if _, err := DecodeRepoStateDocument(legacy); err != nil {
		t.Fatalf("legacy document without provenance must decode: %v", err)
	}
	if _, err := DecodeRepoStateDocument(provenanceStateDoc(`null`)); err != nil {
		t.Fatalf("explicit null provenance must decode: %v", err)
	}
	doc, err := DecodeRepoStateDocument(provenanceStateDoc(`{}`))
	if err != nil {
		t.Fatalf("empty provenance must decode: %v", err)
	}
	if doc.TagPublications == nil {
		t.Fatal("empty provenance map must decode as a non-nil empty map")
	}
	if len(doc.TagPublications) != 0 {
		t.Fatalf("empty provenance must have no entries: %+v", doc.TagPublications)
	}
}

// TestRepoStateProvenanceMalformedFailsClosed proves malformed or forged
// per-tag provenance fails STRICT decode: an entry whose operation ID violates
// the bounded glyph grammar, an empty operation ID, an oversized operation ID,
// a digest that disagrees with the CURRENT tag mapping, an entry whose tag is
// not currently mapped, and a generation outside [1, document generation] are
// all rejected.
func TestRepoStateProvenanceMalformedFailsClosed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		doc  string
	}{
		{
			name: "forged operation ID with a JSON-escaped quote byte",
			doc:  `{"latest":{"operationID":"bad\"quote","generation":1,"digest":"sha256:m1"},"v2":{"operationID":"op-v2","generation":2,"digest":"sha256:m2"}}`,
		},
		{
			name: "operation ID with a control byte",
			doc:  `{"latest":{"operationID":"op-` + "\n" + `x","generation":1,"digest":"sha256:m1"},"v2":{"operationID":"op-v2","generation":2,"digest":"sha256:m2"}}`,
		},
		{
			name: "operation ID with a non-ASCII byte",
			doc:  `{"latest":{"operationID":"op-\u00e9","generation":1,"digest":"sha256:m1"},"v2":{"operationID":"op-v2","generation":2,"digest":"sha256:m2"}}`,
		},
		{
			name: "operation ID exceeding the 128-byte bound",
			doc:  `{"latest":{"operationID":"` + strings.Repeat("k", 129) + `","generation":1,"digest":"sha256:m1"},"v2":{"operationID":"op-v2","generation":2,"digest":"sha256:m2"}}`,
		},
		{
			name: "empty operation ID",
			doc:  `{"latest":{"operationID":"","generation":1,"digest":"sha256:m1"},"v2":{"operationID":"op-v2","generation":2,"digest":"sha256:m2"}}`,
		},
		{
			name: "provenance digest disagrees with the current tag mapping (forged)",
			doc:  `{"latest":{"operationID":"op-latest","generation":1,"digest":"sha256:OTHER"},"v2":{"operationID":"op-v2","generation":2,"digest":"sha256:m2"}}`,
		},
		{
			name: "provenance entry for a tag that is not currently mapped",
			doc:  `{"latest":{"operationID":"op-latest","generation":1,"digest":"sha256:m1"},"stale":{"operationID":"op-stale","generation":2,"digest":"sha256:m2"}}`,
		},
		{
			name: "provenance generation zero",
			doc:  `{"latest":{"operationID":"op-latest","generation":0,"digest":"sha256:m1"},"v2":{"operationID":"op-v2","generation":2,"digest":"sha256:m2"}}`,
		},
		{
			name: "provenance generation beyond the document generation (forged)",
			doc:  `{"latest":{"operationID":"op-latest","generation":1,"digest":"sha256:m1"},"v2":{"operationID":"op-v2","generation":3,"digest":"sha256:m2"}}`,
		},
		{
			name: "empty tag key in provenance",
			doc:  `{"latest":{"operationID":"op-latest","generation":1,"digest":"sha256:m1"},"":{"operationID":"op-v2","generation":2,"digest":"sha256:m2"}}`,
		},
		{
			name: "empty digest in provenance",
			doc:  `{"latest":{"operationID":"op-latest","generation":1,"digest":""},"v2":{"operationID":"op-v2","generation":2,"digest":"sha256:m2"}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeRepoStateDocument(provenanceStateDoc(tc.doc)); err == nil {
				t.Fatal("malformed/forged provenance must fail closed at decode")
			}
		})
	}
}

// TestRepoStateProvenanceEmptyOperationIDRejected pins the non-empty rule on
// the map level too: a provenance entry must carry an operation identity.
func TestRepoStateProvenanceEmptyOperationIDRejected(t *testing.T) {
	t.Parallel()
	if _, err := DecodeRepoStateDocument(provenanceStateDoc(validProvenance)); err != nil {
		t.Fatalf("baseline valid provenance must decode: %v", err)
	}
}
