package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/uncloud-registry/registry/internal/publish"
	"github.com/uncloud-registry/registry/internal/resolve"
	"github.com/uncloud-registry/registry/internal/spec"
)

// verificationFixture assembles a fully consistent post-commit world: the
// repo-state feed resolves to a valid generation-one document whose tag points
// at a manifest whose immutable object bytes and referenced blob records
// match the receipt and the build input. Mutators in the read-back matrix
// then break exactly one property at a time.
func verificationFixture(t *testing.T) (*resolve.MemoryFeedStore, *resolve.MemoryDocumentStore, publish.PublicationReceipt, publish.BuildInput, publish.Artifact) {
	t.Helper()

	docs := resolve.NewMemoryDocumentStore()
	feeds := resolve.NewMemoryFeedStore()

	configBody := []byte(`{"architecture":"amd64"}`)
	configDigest := publish.ComputeDigest(configBody)
	docs.Documents["config-ref"] = configBody

	manifestBody := []byte(`{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":` +
		fmt.Sprintf("%d", len(configBody)) + `,"digest":"` + configDigest + `"},"layers":[]}`)
	manifestDigest := publish.ComputeDigest(manifestBody)
	docs.Documents["manifest-ref"] = manifestBody

	state := spec.RepoStateDocument{
		Version:    1,
		Repo:       "backend/api",
		Generation: 1,
		UpdatedAt:  "2026-01-01T00:00:00Z",
		Tags:       map[string]string{"latest": manifestDigest},
		Manifests: map[string]spec.ManifestDescriptor{
			manifestDigest: {
				SwarmRef:  "manifest-ref",
				MediaType: publish.MediaTypeOCIManifest,
				Size:      int64(len(manifestBody)),
			},
		},
		Blobs: map[string]spec.BlobDescriptor{
			configDigest: {
				SwarmRef:  "config-ref",
				Size:      int64(len(configBody)),
				MediaType: "application/vnd.oci.image.config.v1+json",
			},
		},
		TagPublications: map[string]spec.TagPublication{
			"latest": {
				OperationID: "op-verify-test",
				Generation:  1,
				Digest:      manifestDigest,
			},
		},
	}
	putStateDoc(t, docs, "state-ref", state)

	feeds.Feeds[repoStateFeed()] = "state-ref"

	receipt := publish.PublicationReceipt{
		OperationID:        "op-verify-test",
		StateFeed:          repoStateFeed(),
		StateRef:           "state-ref",
		ManifestRef:        "manifest-ref",
		Owner:              "0xaliceowner",
		Repo:               "backend/api",
		Tag:                "latest",
		ManifestDigest:     manifestDigest,
		ExpectedGeneration: 0,
		Generation:         1,
	}

	input := publish.BuildInput{
		Repo:           "backend/api",
		Tag:            "latest",
		ManifestDigest: manifestDigest,
		ManifestJSON:   manifestBody,
		Manifest: spec.ManifestDescriptor{
			MediaType: publish.MediaTypeOCIManifest,
			Size:      int64(len(manifestBody)),
		},
	}

	artifact, err := publish.ParseArtifact(publish.MediaTypeOCIManifest, manifestBody)
	if err != nil {
		t.Fatalf("parse fixture manifest: %v", err)
	}
	return feeds, docs, receipt, input, artifact
}

func putStateDoc(t *testing.T, docs *resolve.MemoryDocumentStore, ref string, state spec.RepoStateDocument) {
	t.Helper()
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal state fixture: %v", err)
	}
	docs.Documents[ref] = data
}

// failingFeedResolver returns a fixed error from ResolveFeed so dependency
// classification can be tested without a network.
type failingFeedResolver struct{ err error }

func (f failingFeedResolver) ResolveFeed(context.Context, string) (string, error) { return "", f.err }

// failingDocReader returns a fixed error from Read so dependency classification
// can be tested without a network.
type failingDocReader struct{ err error }

func (f failingDocReader) Read(context.Context, string) ([]byte, error) { return nil, f.err }

// TestVerifyPublishedStateReadBackMatrix simulates every plan read-back case
// after a reported signer success: stale feed, wrong reference, wrong
// generation, wrong repo, wrong tag, wrong descriptor, malformed state,
// missing/tampered manifest object, missing/mismatched referenced blob,
// dependency failures, and the exact correct state. Only the correct state
// verifies.
func TestVerifyPublishedStateReadBackMatrix(t *testing.T) {
	otherDigest := publish.ComputeDigest([]byte("some other bytes"))

	cases := []struct {
		name    string
		mutate  func(feeds *resolve.MemoryFeedStore, docs *resolve.MemoryDocumentStore, receipt *publish.PublicationReceipt, input *publish.BuildInput)
		wantNil bool
	}{
		{
			name: "exact correct state verifies", wantNil: true,
			mutate: func(*resolve.MemoryFeedStore, *resolve.MemoryDocumentStore, *publish.PublicationReceipt, *publish.BuildInput) {
			},
		},
		{
			name: "stale feed points at a different reference",
			mutate: func(feeds *resolve.MemoryFeedStore, _ *resolve.MemoryDocumentStore, _ *publish.PublicationReceipt, _ *publish.BuildInput) {
				feeds.Feeds[repoStateFeed()] = "other-state-ref"
			},
		},
		{
			name: "feed lost after commit",
			mutate: func(feeds *resolve.MemoryFeedStore, _ *resolve.MemoryDocumentStore, _ *publish.PublicationReceipt, _ *publish.BuildInput) {
				delete(feeds.Feeds, repoStateFeed())
			},
		},
		{
			name: "document missing at resolved reference",
			mutate: func(feeds *resolve.MemoryFeedStore, _ *resolve.MemoryDocumentStore, _ *publish.PublicationReceipt, _ *publish.BuildInput) {
				feeds.Feeds[repoStateFeed()] = "missing-state-ref"
			},
		},
		{
			name: "malformed state document",
			mutate: func(_ *resolve.MemoryFeedStore, docs *resolve.MemoryDocumentStore, _ *publish.PublicationReceipt, _ *publish.BuildInput) {
				docs.Documents["state-ref"] = []byte(`not json at all`)
			},
		},
		{
			name: "wrong generation",
			mutate: func(_ *resolve.MemoryFeedStore, docs *resolve.MemoryDocumentStore, _ *publish.PublicationReceipt, _ *publish.BuildInput) {
				s := loadStateDoc(t, docs, "state-ref")
				s.Generation = 2
				putStateDoc(t, docs, "state-ref", s)
			},
		},
		{
			name: "wrong repo identity",
			mutate: func(_ *resolve.MemoryFeedStore, docs *resolve.MemoryDocumentStore, _ *publish.PublicationReceipt, _ *publish.BuildInput) {
				s := loadStateDoc(t, docs, "state-ref")
				s.Repo = "other/repo"
				putStateDoc(t, docs, "state-ref", s)
			},
		},
		{
			name: "tag does not point at the published manifest",
			mutate: func(_ *resolve.MemoryFeedStore, docs *resolve.MemoryDocumentStore, _ *publish.PublicationReceipt, _ *publish.BuildInput) {
				s := loadStateDoc(t, docs, "state-ref")
				s.Tags["latest"] = otherDigest
				putStateDoc(t, docs, "state-ref", s)
			},
		},
		{
			name: "manifest descriptor missing from state",
			mutate: func(_ *resolve.MemoryFeedStore, docs *resolve.MemoryDocumentStore, _ *publish.PublicationReceipt, input *publish.BuildInput) {
				s := loadStateDoc(t, docs, "state-ref")
				delete(s.Manifests, input.ManifestDigest)
				putStateDoc(t, docs, "state-ref", s)
			},
		},
		{
			name: "manifest media type mismatch",
			mutate: func(_ *resolve.MemoryFeedStore, docs *resolve.MemoryDocumentStore, _ *publish.PublicationReceipt, input *publish.BuildInput) {
				s := loadStateDoc(t, docs, "state-ref")
				m := s.Manifests[input.ManifestDigest]
				m.MediaType = "text/plain"
				s.Manifests[input.ManifestDigest] = m
				putStateDoc(t, docs, "state-ref", s)
			},
		},
		{
			name: "manifest size mismatch",
			mutate: func(_ *resolve.MemoryFeedStore, docs *resolve.MemoryDocumentStore, _ *publish.PublicationReceipt, input *publish.BuildInput) {
				s := loadStateDoc(t, docs, "state-ref")
				m := s.Manifests[input.ManifestDigest]
				m.Size = 1
				s.Manifests[input.ManifestDigest] = m
				putStateDoc(t, docs, "state-ref", s)
			},
		},
		{
			name: "manifest object reference mismatch",
			mutate: func(_ *resolve.MemoryFeedStore, docs *resolve.MemoryDocumentStore, _ *publish.PublicationReceipt, input *publish.BuildInput) {
				s := loadStateDoc(t, docs, "state-ref")
				m := s.Manifests[input.ManifestDigest]
				m.SwarmRef = "some-other-manifest-ref"
				s.Manifests[input.ManifestDigest] = m
				putStateDoc(t, docs, "state-ref", s)
			},
		},
		{
			name: "manifest object body tampered",
			mutate: func(_ *resolve.MemoryFeedStore, docs *resolve.MemoryDocumentStore, _ *publish.PublicationReceipt, _ *publish.BuildInput) {
				docs.Documents["manifest-ref"] = []byte(`tampered manifest bytes`)
			},
		},
		{
			name: "manifest object missing after commit",
			mutate: func(_ *resolve.MemoryFeedStore, docs *resolve.MemoryDocumentStore, _ *publish.PublicationReceipt, _ *publish.BuildInput) {
				delete(docs.Documents, "manifest-ref")
			},
		},
		{
			name: "referenced blob missing from published state",
			mutate: func(_ *resolve.MemoryFeedStore, docs *resolve.MemoryDocumentStore, _ *publish.PublicationReceipt, input *publish.BuildInput) {
				s := loadStateDoc(t, docs, "state-ref")
				for digest := range s.Blobs {
					if digest != input.ManifestDigest {
						delete(s.Blobs, digest)
					}
				}
				putStateDoc(t, docs, "state-ref", s)
			},
		},
		{
			name: "referenced blob size mismatch",
			mutate: func(_ *resolve.MemoryFeedStore, docs *resolve.MemoryDocumentStore, _ *publish.PublicationReceipt, input *publish.BuildInput) {
				s := loadStateDoc(t, docs, "state-ref")
				for digest, b := range s.Blobs {
					if digest == input.ManifestDigest {
						continue
					}
					b.Size = 1
					s.Blobs[digest] = b
				}
				putStateDoc(t, docs, "state-ref", s)
			},
		},
		{
			name: "referenced blob media type mismatch",
			mutate: func(_ *resolve.MemoryFeedStore, docs *resolve.MemoryDocumentStore, _ *publish.PublicationReceipt, input *publish.BuildInput) {
				s := loadStateDoc(t, docs, "state-ref")
				for digest, b := range s.Blobs {
					if digest == input.ManifestDigest {
						continue
					}
					b.MediaType = "text/plain"
					s.Blobs[digest] = b
				}
				putStateDoc(t, docs, "state-ref", s)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			feeds, docs, receipt, input, artifact := verificationFixture(t)
			tc.mutate(feeds, docs, &receipt, &input)
			err := VerifyPublishedState(context.Background(), feeds, docs, docs, receipt, input, artifact)
			if tc.wantNil {
				if err != nil {
					t.Fatalf("expected verified read-back, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected verification failure, got nil")
			}
			var igt *IntegrityError
			if !errors.As(err, &igt) {
				t.Fatalf("expected IntegrityError for %s, got %T: %v", tc.name, err, err)
			}
		})
	}
}

func loadStateDoc(t *testing.T, docs *resolve.MemoryDocumentStore, ref string) spec.RepoStateDocument {
	t.Helper()
	data, ok := docs.Documents[ref]
	if !ok {
		t.Fatalf("fixture doc %q missing", ref)
	}
	doc, err := spec.DecodeRepoStateDocument(data)
	if err != nil {
		t.Fatalf("decode fixture state: %v", err)
	}
	return doc
}

// TestVerifyPublishedStateDependencyClassification proves unavailable/timeout
// failures are DependencyError (503) while conclusive absence stays Integrity
// (502) — the resolver/document layer class is translated, never guessed.
func TestVerifyPublishedStateDependencyClassification(t *testing.T) {
	t.Run("feed resolve transport failure is dependency", func(t *testing.T) {
		_, _, receipt, input, artifact := verificationFixture(t)
		feeds := failingFeedResolver{err: errors.New("MARKER_NETWORK_1be9")}
		err := VerifyPublishedState(context.Background(), feeds, nil, nil, receipt, input, artifact)
		var dep *DependencyError
		if !errors.As(err, &dep) {
			t.Fatalf("expected DependencyError, got %T: %v", err, err)
		}
		status, code, message := classifyPublicationError(err)
		if status != http.StatusServiceUnavailable || code != ErrorCodeDependencyUnavailable {
			t.Fatalf("expected 503 %s, got %d %s (%s)", ErrorCodeDependencyUnavailable, status, code, message)
		}
		if strings.Contains(message, "MARKER_NETWORK_1be9") {
			t.Fatalf("public message leaks the injected cause marker: %s", message)
		}
	})

	t.Run("feed resolve deadline is dependency", func(t *testing.T) {
		_, _, receipt, input, artifact := verificationFixture(t)
		feeds := failingFeedResolver{err: context.DeadlineExceeded}
		err := VerifyPublishedState(context.Background(), feeds, nil, nil, receipt, input, artifact)
		var dep *DependencyError
		if !errors.As(err, &dep) {
			t.Fatalf("expected DependencyError, got %T: %v", err, err)
		}
	})

	t.Run("document read transport failure is dependency", func(t *testing.T) {
		feeds, _, receipt, input, artifact := verificationFixture(t)
		docs := failingDocReader{err: errors.New("MARKER_NETWORK_722d")}
		err := VerifyPublishedState(context.Background(), feeds, docs, nil, receipt, input, artifact)
		var dep *DependencyError
		if !errors.As(err, &dep) {
			t.Fatalf("expected DependencyError, got %T: %v", err, err)
		}
	})

	t.Run("document conclusively missing is integrity", func(t *testing.T) {
		feeds, _, receipt, input, artifact := verificationFixture(t)
		docs := failingDocReader{err: fmt.Errorf("read: %w", resolve.ErrDocumentNotFound)}
		err := VerifyPublishedState(context.Background(), feeds, docs, nil, receipt, input, artifact)
		var igt *IntegrityError
		if !errors.As(err, &igt) {
			t.Fatalf("expected IntegrityError, got %T: %v", err, err)
		}
	})
}

// TestVerifyRetriedPublicationStateMatrix proves the retry recognition
// verifier: a current state carrying the exact target AND the exact recorded
// provenance operation identity verifies; a state whose tag moved away, whose
// mapping was produced by a DIFFERENT operation, or that never advanced is NOT
// a retry (sentinel), and corruption stays Integrity.
func TestVerifyRetriedPublicationStateMatrix(t *testing.T) {
	t.Run("current state matches the target", func(t *testing.T) {
		feeds, docs, receipt, input, artifact := verificationFixture(t)
		err := VerifyPublishedRetryState(context.Background(), feeds, docs, docs, repoStateFeed(), "backend/api", "latest", input.ManifestDigest, receipt.OperationID, input, artifact)
		if err != nil {
			t.Fatalf("expected verified retry, got %v", err)
		}
	})

	t.Run("tag moved away is not a retry", func(t *testing.T) {
		feeds, docs, receipt, input, artifact := verificationFixture(t)
		s := loadStateDoc(t, docs, "state-ref")
		movedDigest := publish.ComputeDigest([]byte("moved digest"))
		// The moved target must itself be a VALID manifest in the document,
		// and (Task 14 round 2) the tag's provenance entry must move with it —
		// otherwise the document no longer decodes and the failure would be a
		// decode integrity error rather than the tag-moved sentinel.
		s.Tags["latest"] = movedDigest
		s.Manifests[movedDigest] = spec.ManifestDescriptor{
			SwarmRef:  "moved-manifest-ref",
			MediaType: publish.MediaTypeOCIManifest,
			Size:      12,
		}
		s.TagPublications["latest"] = spec.TagPublication{
			OperationID: "op-moved",
			Generation:  1,
			Digest:      movedDigest,
		}
		putStateDoc(t, docs, "state-ref", s)
		err := VerifyPublishedRetryState(context.Background(), feeds, docs, docs, repoStateFeed(), "backend/api", "latest", input.ManifestDigest, receipt.OperationID, input, artifact)
		if !errors.Is(err, ErrTargetNotCurrentState) {
			t.Fatalf("expected ErrTargetNotCurrentState, got %T: %v", err, err)
		}
	})

	t.Run("mapping recorded by a different operation is not a retry", func(t *testing.T) {
		feeds, docs, receipt, input, artifact := verificationFixture(t)
		// The tag still points at the SAME digest, but the durable provenance
		// records a DIFFERENT operation (the mapping was re-recorded). The
		// retry of the recorded operation must NOT be answered as success.
		s := loadStateDoc(t, docs, "state-ref")
		s.TagPublications["latest"] = spec.TagPublication{
			OperationID: "op-other",
			Generation:  1,
			Digest:      input.ManifestDigest,
		}
		putStateDoc(t, docs, "state-ref", s)
		err := VerifyPublishedRetryState(context.Background(), feeds, docs, docs, repoStateFeed(), "backend/api", "latest", input.ManifestDigest, receipt.OperationID, input, artifact)
		if !errors.Is(err, ErrTargetNotCurrentState) {
			t.Fatalf("expected ErrTargetNotCurrentState for a differently-recorded mapping, got %T: %v", err, err)
		}
	})

	t.Run("legacy document without provenance is not a retry", func(t *testing.T) {
		feeds, docs, receipt, input, artifact := verificationFixture(t)
		// A schema-valid document predating provenance carries the target
		// mapping but NO recoverable operation identity: the exact recorded op
		// ID is unknowable and must never be fabricated — not a retry.
		s := loadStateDoc(t, docs, "state-ref")
		s.TagPublications = nil
		putStateDoc(t, docs, "state-ref", s)
		if _, err := spec.DecodeRepoStateDocument(docs.Documents["state-ref"]); err != nil {
			t.Fatalf("legacy document must stay schema-valid: %v", err)
		}
		err := VerifyPublishedRetryState(context.Background(), feeds, docs, docs, repoStateFeed(), "backend/api", "latest", input.ManifestDigest, receipt.OperationID, input, artifact)
		if !errors.Is(err, ErrTargetNotCurrentState) {
			t.Fatalf("expected ErrTargetNotCurrentState for a legacy document, got %T: %v", err, err)
		}
	})

	t.Run("malformed state stays integrity", func(t *testing.T) {
		feeds, docs, receipt, input, artifact := verificationFixture(t)
		docs.Documents["state-ref"] = []byte(`garbage`)
		err := VerifyPublishedRetryState(context.Background(), feeds, docs, docs, repoStateFeed(), "backend/api", "latest", input.ManifestDigest, receipt.OperationID, input, artifact)
		var igt *IntegrityError
		if !errors.As(err, &igt) {
			t.Fatalf("expected IntegrityError, got %T: %v", err, err)
		}
	})

	t.Run("forged provenance operation ID stays integrity", func(t *testing.T) {
		feeds, docs, receipt, input, artifact := verificationFixture(t)
		// A forged provenance entry that violates strict decode (bad glyphs in
		// the operation ID) must fail closed as a decode integrity error and
		// NEVER be usable as a retry identity.
		s := loadStateDoc(t, docs, "state-ref")
		s.TagPublications["latest"] = spec.TagPublication{
			OperationID: `bad"quote`,
			Generation:  1,
			Digest:      input.ManifestDigest,
		}
		putStateDoc(t, docs, "state-ref", s)
		err := VerifyPublishedRetryState(context.Background(), feeds, docs, docs, repoStateFeed(), "backend/api", "latest", input.ManifestDigest, receipt.OperationID, input, artifact)
		var igt *IntegrityError
		if !errors.As(err, &igt) {
			t.Fatalf("expected IntegrityError for forged provenance, got %T: %v", err, err)
		}
	})

	t.Run("state that never advanced is integrity", func(t *testing.T) {
		feeds, docs, receipt, input, artifact := verificationFixture(t)
		s := loadStateDoc(t, docs, "state-ref")
		s.Generation = 0
		putStateDoc(t, docs, "state-ref", s)
		err := VerifyPublishedRetryState(context.Background(), feeds, docs, docs, repoStateFeed(), "backend/api", "latest", input.ManifestDigest, receipt.OperationID, input, artifact)
		var igt *IntegrityError
		if !errors.As(err, &igt) {
			t.Fatalf("expected IntegrityError, got %T: %v", err, err)
		}
	})

	t.Run("feed reveal dependency failure", func(t *testing.T) {
		_, _, receipt, input, artifact := verificationFixture(t)
		feeds := failingFeedResolver{err: context.DeadlineExceeded}
		err := VerifyPublishedRetryState(context.Background(), feeds, nil, nil, repoStateFeed(), "backend/api", "latest", input.ManifestDigest, receipt.OperationID, input, artifact)
		var dep *DependencyError
		if !errors.As(err, &dep) {
			t.Fatalf("expected DependencyError, got %T: %v", err, err)
		}
	})
}

// TestClassifyPublicationErrorMatrix is the single-mapper matrix: each error
// class maps to the exact stable (status, code, message) pair, wrapped causes
// classify through errors.As, and injected marker text never reaches any
// public message.
func TestClassifyPublicationErrorMatrix(t *testing.T) {
	marker := "MARKER_T14_9c41"

	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{name: "integrity", err: newIntegrityError(errors.New(marker)), wantStatus: http.StatusBadGateway, wantCode: ErrorCodePublicationUnverified},
		{name: "wrapped integrity", err: fmt.Errorf("outer: %w", newIntegrityError(errors.New(marker))), wantStatus: http.StatusBadGateway, wantCode: ErrorCodePublicationUnverified},
		{name: "dependency", err: newDependencyError(errors.New(marker)), wantStatus: http.StatusServiceUnavailable, wantCode: ErrorCodeDependencyUnavailable},
		{name: "conflict typed", err: newConflictError(errors.New(marker)), wantStatus: http.StatusConflict, wantCode: ErrorCodeManifestConflict},
		{name: "commit conflict sentinel", err: fmt.Errorf("commit: %w", publish.ErrCommitConflict), wantStatus: http.StatusConflict, wantCode: ErrorCodeManifestConflict},
		{name: "commit generation conflict sentinel", err: fmt.Errorf("commit: %w", publish.ErrCommitGenerationConflict), wantStatus: http.StatusConflict, wantCode: ErrorCodeManifestConflict},
		{name: "commit backend sentinel", err: fmt.Errorf("commit: %w", publish.ErrCommitBackend), wantStatus: http.StatusServiceUnavailable, wantCode: ErrorCodeDependencyUnavailable},
		{name: "commit unauthorized sentinel", err: publish.ErrCommitUnauthorized, wantStatus: http.StatusServiceUnavailable, wantCode: ErrorCodeDependencyUnavailable},
		{name: "commit unknown registry sentinel", err: publish.ErrCommitUnknownRegistry, wantStatus: http.StatusServiceUnavailable, wantCode: ErrorCodeDependencyUnavailable},
		{name: "context deadline", err: context.DeadlineExceeded, wantStatus: http.StatusServiceUnavailable, wantCode: ErrorCodeDependencyUnavailable},
		{name: "context canceled", err: context.Canceled, wantStatus: http.StatusServiceUnavailable, wantCode: ErrorCodeDependencyUnavailable},
		{name: "validation", err: &publish.ValidationError{Kind: publish.ErrKindDigestMismatch, Err: errors.New("digest mismatch")}, wantStatus: http.StatusBadRequest, wantCode: ErrorCodeManifestInvalid},
		{name: "unknown internal", err: errors.New(marker), wantStatus: http.StatusInternalServerError, wantCode: ErrorCodeInternal},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, code, message := classifyPublicationError(tc.err)
			if status != tc.wantStatus || code != tc.wantCode {
				t.Fatalf("expected %d %s, got %d %s (%s)", tc.wantStatus, tc.wantCode, status, code, message)
			}
			if strings.Contains(message, marker) {
				t.Fatalf("public message leaks injected marker %q: %s", marker, message)
			}
			if message == "" {
				t.Fatal("public message must never be empty")
			}
		})
	}
}

// TestTypedPublicationErrorsDataFreeSurface pins the ENTIRE externally
// traversable surface of the three typed classes to fixed, data-free values:
// Error() is the fixed generic message; Unwrap() returns ONLY the fixed safe
// class sentinel (never the private diagnostic cause); the full unwrap chain
// carries no injected marker; errors.Is matches the safe sentinel; errors.As
// still classifies the typed value; and the exported reflection surface
// exposes NO fields and NO accessors beyond Error and Unwrap.
func TestTypedPublicationErrorsDataFreeSurface(t *testing.T) {
	marker := "MARKER_T14_53e8"
	cases := []struct {
		name     string
		err      error
		want     string
		sentinel error
	}{
		{name: "integrity", err: newIntegrityError(errors.New(marker)), want: "published repository state could not be verified", sentinel: ErrPublicationUnverified},
		{name: "dependency", err: newDependencyError(errors.New(marker)), want: "a required service is temporarily unavailable", sentinel: ErrDependencyUnavailable},
		{name: "conflict", err: newConflictError(errors.New(marker)), want: "the repository publication conflicts with an existing operation", sentinel: ErrPublicationConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.want {
				t.Fatalf("typed error Error() must be the fixed generic message, got %q", got)
			}
			// Unwrap must yield the fixed safe sentinel, never the cause.
			if got := errors.Unwrap(tc.err); got != tc.sentinel {
				t.Fatalf("Unwrap must return the fixed safe class sentinel, got %T: %q", got, got)
			}
			// The FULL unwrap chain must be data-free: no marker anywhere.
			if chain := unwrapChainText(t, tc.err); strings.Contains(chain, marker) {
				t.Fatalf("unwrap chain leaks the raw cause marker: %q", chain)
			}
			if !errors.Is(tc.err, tc.sentinel) {
				t.Fatal("errors.Is must match the fixed safe class sentinel")
			}
			// Typed classification is preserved server-side.
			switch tc.name {
			case "integrity":
				var igt *IntegrityError
				if !errors.As(tc.err, &igt) {
					t.Fatal("errors.As must classify *IntegrityError")
				}
			case "dependency":
				var dep *DependencyError
				if !errors.As(tc.err, &dep) {
					t.Fatal("errors.As must classify *DependencyError")
				}
			case "conflict":
				var cfl *ConflictError
				if !errors.As(tc.err, &cfl) {
					t.Fatal("errors.As must classify *ConflictError")
				}
			}
			// No exported fields: the single retained cause is private.
			typ := reflect.TypeOf(tc.err).Elem()
			if typ.NumField() != 1 {
				t.Fatalf("expected exactly one private cause field, got %d", typ.NumField())
			}
			if field := typ.Field(0); field.PkgPath == "" {
				t.Fatalf("the cause field %s must be unexported", field.Name)
			}
			// No exported accessors beyond Error and Unwrap.
			if got := exportedMethodNames(reflect.TypeOf(tc.err)); !reflect.DeepEqual(got, []string{"Error", "Unwrap"}) {
				t.Fatalf("exported method surface must be exactly Error+Unwrap, got %v", got)
			}
		})
	}
}

// unwrapChainText walks the full unwrap chain and concatenates every
// Error() text, so a marker leak anywhere in the externally traversable chain
// is detectable.
func unwrapChainText(t *testing.T, err error) string {
	t.Helper()
	var parts []string
	for err != nil {
		parts = append(parts, err.Error())
		next := errors.Unwrap(err)
		if next == nil || next == err {
			break
		}
		err = next
	}
	return strings.Join(parts, " | ")
}

// exportedMethodNames returns the sorted names of a type's EXPORTED methods
// (reflection exposes only exported methods on the type itself).
func exportedMethodNames(t reflect.Type) []string {
	var names []string
	for i := 0; i < t.NumMethod(); i++ {
		names = append(names, t.Method(i).Name)
	}
	sort.Strings(names)
	return names
}

// TestVerifyPublishedStateProvenanceMismatchFailsClosed proves the
// read-after-write verification ALSO validates the committed document's
// per-tag publication provenance against the receipt: a committed state
// whose provenance entry is missing, disagrees on the operation ID, the
// applied generation, or the digest is an integrity failure — the 201 can
// never be produced for a document that does not durably record the exact
// operation the receipt names.
func TestVerifyPublishedStateProvenanceMismatchFailsClosed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*spec.RepoStateDocument)
	}{
		{name: "provenance entry missing", mutate: func(s *spec.RepoStateDocument) { delete(s.TagPublications, "latest") }},
		{name: "operation ID mismatch", mutate: func(s *spec.RepoStateDocument) {
			p := s.TagPublications["latest"]
			p.OperationID = "op-other"
			s.TagPublications["latest"] = p
		}},
		{name: "applied generation mismatch", mutate: func(s *spec.RepoStateDocument) {
			p := s.TagPublications["latest"]
			p.Generation = 99
			s.TagPublications["latest"] = p
		}},
		{name: "digest mismatch", mutate: func(s *spec.RepoStateDocument) {
			p := s.TagPublications["latest"]
			p.Digest = "sha256:other"
			s.TagPublications["latest"] = p
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			feeds, docs, receipt, input, artifact := verificationFixture(t)
			s := loadStateDoc(t, docs, "state-ref")
			tc.mutate(&s)
			putStateDoc(t, docs, "state-ref", s)
			err := VerifyPublishedState(context.Background(), feeds, docs, docs, receipt, input, artifact)
			var igt *IntegrityError
			if !errors.As(err, &igt) {
				t.Fatalf("expected IntegrityError, got %T: %v", err, err)
			}
			// The private cause may name the tag, but the error surface stays
			// fixed and the marker-less traversal holds.
			if err.Error() != "published repository state could not be verified" {
				t.Fatalf("public Error() must stay fixed, got %q", err.Error())
			}
		})
	}
}
