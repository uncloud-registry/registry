package spec

import "testing"

func TestDecodeStampPolicyDocument(t *testing.T) {
	t.Parallel()

	doc, err := DecodeStampPolicyDocument([]byte(`{
		"version":1,
		"defaultPolicy":{"batchID":"batch-default","allowPushFor":["org:alice:writer"]},
		"repos":{
			"backend/api":{"batchID":"batch-repo","allowPushFor":["user:alice"]}
		}
	}`))
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if doc.DefaultPolicy.BatchID != "batch-default" {
		t.Fatalf("unexpected default batch: %s", doc.DefaultPolicy.BatchID)
	}
}

func TestRepoStateRequiresTaggedManifestEntries(t *testing.T) {
	t.Parallel()

	_, err := DecodeRepoStateDocument([]byte(`{
		"version":1,
		"repo":"backend/api",
		"generation":1,
		"updatedAt":"2026-04-06T00:00:00Z",
		"tags":{"latest":"sha256:missing"},
		"manifests":{},
		"blobs":{}
	}`))
	if err == nil {
		t.Fatal("expected repo state validation error")
	}
}
