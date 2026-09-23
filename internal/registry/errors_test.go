package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
			err := VerifyPublishedState(context.Background(), feeds, docs, receipt, input, artifact)
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
		err := VerifyPublishedState(context.Background(), feeds, nil, receipt, input, artifact)
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
		err := VerifyPublishedState(context.Background(), feeds, nil, receipt, input, artifact)
		var dep *DependencyError
		if !errors.As(err, &dep) {
			t.Fatalf("expected DependencyError, got %T: %v", err, err)
		}
	})

	t.Run("document read transport failure is dependency", func(t *testing.T) {
		feeds, _, receipt, input, artifact := verificationFixture(t)
		docs := failingDocReader{err: errors.New("MARKER_NETWORK_722d")}
		err := VerifyPublishedState(context.Background(), feeds, docs, receipt, input, artifact)
		var dep *DependencyError
		if !errors.As(err, &dep) {
			t.Fatalf("expected DependencyError, got %T: %v", err, err)
		}
	})

	t.Run("document conclusively missing is integrity", func(t *testing.T) {
		feeds, _, receipt, input, artifact := verificationFixture(t)
		docs := failingDocReader{err: fmt.Errorf("read: %w", resolve.ErrDocumentNotFound)}
		err := VerifyPublishedState(context.Background(), feeds, docs, receipt, input, artifact)
		var igt *IntegrityError
		if !errors.As(err, &igt) {
			t.Fatalf("expected IntegrityError, got %T: %v", err, err)
		}
	})
}

// TestVerifyRetriedPublicationStateMatrix proves the retry recognition
// verifier: a current state carrying the exact target verifies; a state whose
// tag moved away is NOT a retry (sentinel), and corruption stays Integrity.
func TestVerifyRetriedPublicationStateMatrix(t *testing.T) {
	t.Run("current state matches the target", func(t *testing.T) {
		feeds, docs, _, input, artifact := verificationFixture(t)
		err := VerifyPublishedRetryState(context.Background(), feeds, docs, repoStateFeed(), "backend/api", "latest", input.ManifestDigest, input, artifact)
		if err != nil {
			t.Fatalf("expected verified retry, got %v", err)
		}
	})

	t.Run("tag moved away is not a retry", func(t *testing.T) {
		feeds, docs, _, input, artifact := verificationFixture(t)
		s := loadStateDoc(t, docs, "state-ref")
		movedDigest := publish.ComputeDigest([]byte("moved digest"))
		// The moved target must itself be a VALID manifest in the document,
		// otherwise the document no longer decodes and the failure would be a
		// decode integrity error rather than the tag-moved sentinel.
		s.Tags["latest"] = movedDigest
		s.Manifests[movedDigest] = spec.ManifestDescriptor{
			SwarmRef:  "moved-manifest-ref",
			MediaType: publish.MediaTypeOCIManifest,
			Size:      12,
		}
		putStateDoc(t, docs, "state-ref", s)
		err := VerifyPublishedRetryState(context.Background(), feeds, docs, repoStateFeed(), "backend/api", "latest", input.ManifestDigest, input, artifact)
		if !errors.Is(err, ErrTargetNotCurrentState) {
			t.Fatalf("expected ErrTargetNotCurrentState, got %T: %v", err, err)
		}
	})

	t.Run("malformed state stays integrity", func(t *testing.T) {
		feeds, docs, _, input, artifact := verificationFixture(t)
		docs.Documents["state-ref"] = []byte(`garbage`)
		err := VerifyPublishedRetryState(context.Background(), feeds, docs, repoStateFeed(), "backend/api", "latest", input.ManifestDigest, input, artifact)
		var igt *IntegrityError
		if !errors.As(err, &igt) {
			t.Fatalf("expected IntegrityError, got %T: %v", err, err)
		}
	})

	t.Run("state that never advanced is integrity", func(t *testing.T) {
		feeds, docs, _, input, artifact := verificationFixture(t)
		s := loadStateDoc(t, docs, "state-ref")
		s.Generation = 0
		putStateDoc(t, docs, "state-ref", s)
		err := VerifyPublishedRetryState(context.Background(), feeds, docs, repoStateFeed(), "backend/api", "latest", input.ManifestDigest, input, artifact)
		var igt *IntegrityError
		if !errors.As(err, &igt) {
			t.Fatalf("expected IntegrityError, got %T: %v", err, err)
		}
	})

	t.Run("feed reveal dependency failure", func(t *testing.T) {
		_, _, _, input, artifact := verificationFixture(t)
		feeds := failingFeedResolver{err: context.DeadlineExceeded}
		err := VerifyPublishedRetryState(context.Background(), feeds, nil, repoStateFeed(), "backend/api", "latest", input.ManifestDigest, input, artifact)
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
		{name: "integrity", err: &IntegrityError{Err: errors.New(marker)}, wantStatus: http.StatusBadGateway, wantCode: ErrorCodePublicationUnverified},
		{name: "wrapped integrity", err: fmt.Errorf("outer: %w", &IntegrityError{Err: errors.New(marker)}), wantStatus: http.StatusBadGateway, wantCode: ErrorCodePublicationUnverified},
		{name: "dependency", err: &DependencyError{Err: errors.New(marker)}, wantStatus: http.StatusServiceUnavailable, wantCode: ErrorCodeDependencyUnavailable},
		{name: "conflict typed", err: &ConflictError{Err: errors.New(marker)}, wantStatus: http.StatusConflict, wantCode: ErrorCodeManifestConflict},
		{name: "commit conflict sentinel", err: fmt.Errorf("commit: %w", publish.ErrCommitConflict), wantStatus: http.StatusConflict, wantCode: ErrorCodeManifestConflict},
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

// TestTypedPublicationErrorsFixedPublicText pins the data-free contract of the
// typed errors themselves: Error() is a fixed generic string that never
// includes the retained cause, while Unwrap() keeps the cause reachable
// server-side.
func TestTypedPublicationErrorsFixedPublicText(t *testing.T) {
	marker := "MARKER_T14_53e8"
	errorsCases := []struct {
		name string
		err  error
		want string
	}{
		{name: "integrity", err: &IntegrityError{Err: errors.New(marker)}, want: "published repository state could not be verified"},
		{name: "dependency", err: &DependencyError{Err: errors.New(marker)}, want: "a required service is temporarily unavailable"},
		{name: "conflict", err: &ConflictError{Err: errors.New(marker)}, want: "the repository publication conflicts with an existing operation"},
	}
	for _, tc := range errorsCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.want {
				t.Fatalf("typed error Error() must be the fixed generic message, got %q", got)
			}
			if strings.Contains(tc.err.Error(), marker) {
				t.Fatalf("typed error leaks the retained cause: %q", tc.err.Error())
			}
			if got := errors.Unwrap(tc.err); got == nil || !strings.Contains(got.Error(), marker) {
				t.Fatalf("cause must stay reachable server-side via Unwrap, got %v", got)
			}
		})
	}
}
