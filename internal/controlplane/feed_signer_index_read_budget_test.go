package controlplane

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/spec"
)

// Round 5/5 regression: the FeedSigner's independent index-child verification
// must enforce the shared aggregate read budget AT THE READ BOUNDARY, not
// after each read completes. Each distinct child body is read with a per-call
// bound of min(MaxArtifactBodyBytes, remaining aggregate budget,
// declared size + 1) COMPUTED BEFORE the read — the same discipline the
// registry's read-after-write verification applies — so a crafted target
// repo-state document that declares small child sizes but serves real larger
// bodies (digests matching the ACTUAL bodies) can never force the signer's
// verification reads past the aggregate bound.

// recordingBytesReader wraps the world's bounded object reader and records
// EVERY ReadBounded call: the ref, the exact per-call maxBytes bound the
// signer passed, and the bytes actually returned. Tests assert on this record
// — the real per-call bound at the read boundary — never just on call counts.
type recordingBytesReader struct {
	inner *memoryBytesReader
	mu    sync.Mutex
	calls []recordedBytesRead
}

type recordedBytesRead struct {
	ref      string
	maxBytes int64
	returned int64
}

func (r *recordingBytesReader) ReadBounded(ctx context.Context, ref string, maxBytes int64) ([]byte, error) {
	data, err := r.inner.ReadBounded(ctx, ref, maxBytes)
	var returned int64
	if err == nil {
		returned = int64(len(data))
	}
	r.mu.Lock()
	r.calls = append(r.calls, recordedBytesRead{ref: ref, maxBytes: maxBytes, returned: returned})
	r.mu.Unlock()
	return data, err
}

// childCalls returns the recorded reads whose ref is one of the given swarm
// refs (the child manifest objects), in call order.
func (r *recordingBytesReader) childCalls(swarmRefs ...string) []recordedBytesRead {
	want := make(map[string]bool, len(swarmRefs))
	for _, s := range swarmRefs {
		want[s] = true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]recordedBytesRead, 0, len(r.calls))
	for _, c := range r.calls {
		if want[c.ref] {
			out = append(out, c)
		}
	}
	return out
}

// makeIndexChildren builds n DISTINCT real single-platform child fixtures.
// Each is a real committed manifest: a real body, the body's real digest, and
// a real SwarmRef (unique per child). When declared is non-nil, the child's
// index reference AND committed record declare declared(i) instead of the
// real body length — the crafted shape where the declared size and the served
// body disagree while the digest still matches the actual body.
func makeIndexChildren(t *testing.T, n int, declared func(i int) int64) ([]indexChildFixture, map[string]spec.ManifestDescriptor) {
	t.Helper()
	children := make([]indexChildFixture, 0, n)
	manifests := make(map[string]spec.ManifestDescriptor, n)
	for i := 0; i < n; i++ {
		// Distinct SwarmRef via the swarm byte; distinct body (hence distinct
		// digest) via the config size; the config digest byte cycles the
		// lowercase-hex alphabet (the strict parser requires canonical
		// sha256:<64 lowercase hex> digest strings) while the size keeps every
		// body unique.
		c := makeChild(t, byte('A'+byte(i)), "0123456789abcdef"[byte(i%16)], int64(1000+i))
		size := c.ref.Size
		if declared != nil {
			size = declared(i)
		}
		children = append(children, indexChildFixture{
			body: c.body, digest: c.digest, manifest: c.manifest,
			ref: publish.Descriptor{MediaType: c.ref.MediaType, Digest: c.ref.Digest, Size: size},
		})
		manifests[c.digest] = spec.ManifestDescriptor{SwarmRef: c.manifest.SwarmRef, MediaType: c.manifest.MediaType, Size: size}
	}
	return children, manifests
}

// indexReadBudgetWorld seeds a signer fixture whose current state already has
// the children committed at their RECORDED (possibly crafted) sizes, whose
// target adds the operated index, and where both the index body and every
// child body are served through the bounded /bytes reader at the exact
// SwarmRefs the documents record. File-backed store for -race -count=N
// repeat isolation.
func indexReadBudgetWorld(t *testing.T, tag string, children []indexChildFixture, manifests map[string]spec.ManifestDescriptor, fx indexFixture) (*feedTestWorld, publish.FeedCommitRequest) {
	t.Helper()
	req := validCommitReq(1, "batch-1")
	w := newFeedTestWorldFile(t, req, feedDocSet{
		currentRef: refHex('b'), currentGen: 1, targetRef: refHex('a'), targetGen: 2, stampRef: refHex('c'),
	})
	req.RegistryID = w.registry.ID
	w.fillTopic(&req)
	req.ExpectedGeneration = 1
	generated := publish.ComputeOperationID(req.RegistryID, req.Owner, testRepo, tag, fx.digest, req.ExpectedGeneration)
	req.OperationID = generated
	w.docs.Documents[refHex('b')] = transitionDoc(t, testRepo, 1,
		map[string]string{}, map[string]spec.TagPublication{}, manifests, map[string]spec.BlobDescriptor{})
	targetManifests := operatedManifests(manifests, artifactFixture{body: fx.body, digest: fx.digest, manifest: fx.manifest})
	w.docs.Documents[refHex('a')] = transitionDoc(t, testRepo, 2,
		map[string]string{tag: fx.digest},
		map[string]spec.TagPublication{tag: {OperationID: generated, Generation: 2, Digest: fx.digest}},
		targetManifests, map[string]spec.BlobDescriptor{})
	w.bytes.serve(fx.manifest.SwarmRef, fx.body)
	for _, c := range children {
		w.bytes.serve(c.manifest.SwarmRef, c.body)
	}
	return w, req
}

func childSwarmRefs(children []indexChildFixture) []string {
	out := make([]string, 0, len(children))
	for _, c := range children {
		out = append(out, c.manifest.SwarmRef)
	}
	return out
}

// TestFeedSignerIndexChildReadsBoundedBeforeAggregateBudget is the crafted
// many-child amplification regression: 64 distinct children whose index
// references AND committed records all declare a small size, while every
// served body is REAL and larger (its digest matches the actual body). The
// signer must reject the FIRST child at the read boundary — the reader is
// handed the tight declared+1 bound, never the flat per-read cap — as a
// data-free backend error with ZERO external updates and ZERO oversized bytes
// crossing the read. Without the pre-read budget bound this test fails: the
// flat bound would be passed per call and the oversized body would be pulled
// before the aggregate/length checks could see it.
func TestFeedSignerIndexChildReadsBoundedBeforeAggregateBudget(t *testing.T) {
	const tag = "latest"
	const declaredSize = int64(100)
	const n = 64 // "many" — far beyond any plausible index, well under the 4096 distinct cap
	children, manifests := makeIndexChildren(t, n, func(int) int64 { return declaredSize })
	for i, c := range children {
		if int64(len(c.body)) <= declaredSize {
			t.Fatalf("fixture child %d: served body (%d bytes) must exceed the declared size (%d) for the crafted case", i, len(c.body), declaredSize)
		}
	}
	fx := buildIndex(t, "amd64", children...)
	w, req := indexReadBudgetWorld(t, tag, children, manifests, fx)
	recorder := &recordingBytesReader{inner: w.bytes}
	signer, updater := w.countingSigner()
	signer.Bytes = recorder

	_, err := signer.Commit(context.Background(), req)
	if !errors.Is(err, errFeedSignerBackend) {
		t.Fatalf("oversized child body must be rejected at the bounded read as a data-free backend error, got %v", err)
	}
	if n := updater.count(); n != 0 {
		t.Fatalf("bounded child rejection must cause ZERO external updates, got %d", n)
	}

	calls := recorder.childCalls(childSwarmRefs(children)...)
	if len(calls) != 1 {
		t.Fatalf("the crafted many-child index must be rejected at the FIRST child read, got %d child reads", len(calls))
	}
	want := indexChildReadBound(declaredSize, int64(publish.MaxAggregateIndexChildBytes))
	if calls[0].maxBytes != want {
		t.Fatalf("first child read must pass the tight pre-read bound (%d = declared+1 within budget), got %d (a flat per-read pass would be %d)",
			want, calls[0].maxBytes, publish.MaxArtifactBodyBytes)
	}
	if calls[0].maxBytes == int64(publish.MaxArtifactBodyBytes) {
		t.Fatalf("child read must never be issued with the flat %d per-read bound", publish.MaxArtifactBodyBytes)
	}
	var returned, boundSum int64
	for _, c := range calls {
		returned += c.returned
		boundSum += c.maxBytes
	}
	if returned != 0 {
		t.Fatalf("no oversized child body may cross the read boundary, got %d returned bytes", returned)
	}
	if boundSum > int64(publish.MaxAggregateIndexChildBytes) {
		t.Fatalf("sum of per-call child read bounds (%d) must stay within the aggregate budget (%d)", boundSum, publish.MaxAggregateIndexChildBytes)
	}
}

// TestFeedSignerIndexManyChildrenRespectPerCallAndAggregateBounds proves the
// bounded regime on the ACCEPT path with many children: every index reference
// (each listed TWICE) declares the real body length, and the recorded child
// reads must show (a) exactly one read per DISTINCT child — a repeated digest
// never double-counts the budget — and (b) every per-call maxBytes equal to
// min(MaxArtifactBodyBytes, remaining aggregate budget, declared size + 1)
// re-derived from the recorded reads, with the total returned bytes within
// the aggregate budget. Under the pre-fix code each recorded child call would
// carry the flat 4 MiB bound and this test fails.
func TestFeedSignerIndexManyChildrenRespectPerCallAndAggregateBounds(t *testing.T) {
	const tag = "latest"
	const n = 48
	children, manifests := makeIndexChildren(t, n, nil) // declared == real body length
	dups := make([]indexChildFixture, 0, 2*n)
	dups = append(dups, children...)
	dups = append(dups, children...) // every child listed twice
	fx := buildIndex(t, "amd64", dups...)
	w, req := indexReadBudgetWorld(t, tag, children, manifests, fx)
	recorder := &recordingBytesReader{inner: w.bytes}
	signer, updater := w.countingSigner()
	signer.Bytes = recorder

	result, err := signer.Commit(context.Background(), req)
	if err != nil {
		t.Fatalf("valid many-child index must be accepted by the signer: %v", err)
	}
	if result.Feed != w.repoTopic || result.Reference != refHex('a') {
		t.Fatalf("unexpected result: %+v", result)
	}
	if n := updater.count(); n != 1 {
		t.Fatalf("expected exactly 1 external feed update, got %d", n)
	}

	calls := recorder.childCalls(childSwarmRefs(children)...)
	if len(calls) != n {
		t.Fatalf("each DISTINCT child must be read exactly once (duplicates deduped and not double-counted), got %d reads for %d distinct children", len(calls), n)
	}
	var verified, returned int64
	for i, c := range calls {
		declared := children[i].ref.Size
		if c.returned != declared {
			t.Fatalf("child %d: returned %d bytes, want the declared %d", i, c.returned, declared)
		}
		remaining := int64(publish.MaxAggregateIndexChildBytes) - verified
		want := min(int64(publish.MaxArtifactBodyBytes), remaining, declared+1)
		if c.maxBytes != want {
			t.Fatalf("child %d: per-call read bound %d, want min(MaxArtifactBodyBytes, remaining=%d, declared+1) = %d",
				i, c.maxBytes, remaining, want)
		}
		if want == int64(publish.MaxArtifactBodyBytes) && declared+1 < int64(publish.MaxArtifactBodyBytes) {
			t.Fatalf("child %d: bound must come from the declared size, not the flat per-read cap", i)
		}
		verified += c.returned
		returned += c.returned
	}
	if returned > int64(publish.MaxAggregateIndexChildBytes) {
		t.Fatalf("total bytes pulled across all children (%d) must stay within the aggregate budget (%d)", returned, publish.MaxAggregateIndexChildBytes)
	}
}

// TestIndexChildReadBound pins the pure per-read bound computation:
// min(MaxArtifactBodyBytes, remaining, declaredSize + 1), overflow-safe and
// never negative.
func TestIndexChildReadBound(t *testing.T) {
	const perRead = int64(publish.MaxArtifactBodyBytes)
	const budget = int64(publish.MaxAggregateIndexChildBytes)
	cases := []struct {
		name                string
		declared, remaining int64
		want                int64
	}{
		{"small declared within budget", 100, budget, 101},
		{"remaining caps the bound", 100, 50, 50},
		{"remaining equals the tight bound", 100, 101, 101},
		{"zero declared gets +1 mismatch room", 0, budget, 1},
		{"declared beyond the per-read cap", perRead + 5, budget, perRead},
		{"declared at the per-read cap", perRead, budget, perRead},
		{"remaining smaller than declared", perRead + 1000, 1000, 1000},
		{"no remaining means no aggregate term", 100, 0, 101},
		{"negative remaining ignored", 100, -5, 101},
		{"negative declared ignored", -1, budget, perRead},
		{"max-int declared is overflow-safe", int64(^uint64(0) >> 1), budget, perRead},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := indexChildReadBound(tc.declared, tc.remaining); got != tc.want {
				t.Fatalf("indexChildReadBound(%d, %d) = %d, want %d", tc.declared, tc.remaining, got, tc.want)
			}
		})
	}
}
